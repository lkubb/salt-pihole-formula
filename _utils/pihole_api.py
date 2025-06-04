import copy
import logging
import random
import time
from itertools import takewhile
from pathlib import Path

import requests
import salt.cache
import salt.exceptions
import salt.utils.dictupdate
import salt.utils.event
import salt.utils.json
import salt.utils.network
from requests.adapters import HTTPAdapter, Retry
from requests.exceptions import ConnectionError
from salt.exceptions import CommandExecutionError

try:
    from urllib3.util import create_urllib3_context

    URLLIB3V1 = False
except ImportError:
    # urllib <2
    from urllib3.util.ssl_ import create_urllib3_context

    URLLIB3V1 = True

log = logging.getLogger(__name__)


SESSION_CKEY = "__session"
CLIENT_CKEY = "_pihole_api_authd_client"
CLI_PW_PATH = Path("/etc/pihole/cli_pw")

HTTP_TOO_MANY_REQUESTS = 429

# Default timeout configuration
DEFAULT_CONNECT_TIMEOUT = 9.2
DEFAULT_READ_TIMEOUT = 30

# Default retry configuration
DEFAULT_MAX_RETRIES = 5
DEFAULT_BACKOFF_FACTOR = 0.1
DEFAULT_BACKOFF_MAX = 10.0
DEFAULT_BACKOFF_JITTER = 0.2
DEFAULT_RETRY_POST = False
DEFAULT_RESPECT_RETRY_AFTER = True
DEFAULT_RETRY_AFTER_MAX = 60
DEFAULT_RETRY_STATUS = (500, 502, 503, 504)

# Caps for retry configuration
MAX_MAX_RETRIES = 10
MAX_BACKOFF_FACTOR = 3.0
MAX_BACKOFF_MAX = 60.0
MAX_BACKOFF_JITTER = 5.0


def query(
    method,
    endpoint,
    opts,
    context,
    payload=None,
    raise_error=True,
    session=None,
    **kwargs,
):
    """
    Query the PiHole API. Supplemental arguments to ``requestes.request``
    can be passed as kwargs.

    method
        HTTP verb to use.

    endpoint
        API path to call (without leading ``/v1/``).

    opts
        Pass ``__opts__`` from the module.

    context
        Pass ``__context__`` from the module.

    payload
        Dictionary of payload values to send, if any.

    raise_error
        Whether to inspect the response code and raise exceptions.
        Defaults to True.

    session
        Override the internally managed session.
    """
    client, config = get_authd_client(opts, context, get_config=True)
    try:
        return client.request(
            method,
            endpoint,
            payload=payload,
            raise_error=raise_error,
            session=session,
            **kwargs,
        )
    except PiHoleAPIPermissionDeniedError:
        if not _check_clear(client, config):
            raise

    # in case our session got stale (I don't think this should happen at all)
    clear_cache(opts, context)
    client = get_authd_client(opts, context)
    return client.request(
        method,
        endpoint,
        payload=payload,
        raise_error=raise_error,
        session=session,
        **kwargs,
    )


def _check_clear(client, config):
    """
    Called when encountering a PiHoleAPISessionExpired.
    Decides whether to retry logging in.
    """
    try:
        # verify the current session is still valid
        if not client.session_valid(remote=True):
            return True
        session = client.auth.get_session()
        if session.auth_type and session.auth_type != config["auth"]["method"]:
            return True
    except PiHoleAPISessionExpired:
        return True
    return False


def get_authd_client(opts, context, get_config=False):
    """
    Returns an AuthenticatedPiHoleClient

    opts
        Pass ``__opts__`` from the module.

    context
        Pass ``__context__`` from the module.

    get_config
        Return a tuple of (client, config). Defaults to false.
    """

    def try_build():
        client = config = None
        retry = False
        try:
            client, config = _build_authd_client(opts)
        except (PiHoleAPIPermissionDeniedError, ConnectionError):  #  VaultConfigExpired
            clear_cache(opts, context, connection=True)
            retry = True
        return client, config, retry

    cbank = "pihole/connection"
    retry = False
    client = config = None

    # First, check if an already initialized instance is available
    # and still valid
    if cbank in context and CLIENT_CKEY in context[cbank]:
        log.debug("Fetching client instance and config from context")
        client, config = context[cbank][CLIENT_CKEY]
        if not client.session_valid(remote=False):
            log.debug("Cached client instance was invalid")
            client = config = None
            context[cbank].pop(CLIENT_CKEY)

    # Otherwise, try to build one from possibly cached data
    if client is None or config is None:
        try:
            client, config, retry = try_build()
            # Ensure a changed auth method is respected
            cur_auth_type = client.auth.get_session().auth_type
            if cur_auth_type and cur_auth_type != config["auth"]["method"]:
                raise PiHoleAPISessionExpired(client.auth.get_session())
        except PiHoleAPISessionExpired:
            clear_cache(opts, context, session=True)
            client, config, retry = try_build()

    # Check if the session needs to be and can be renewed.
    # Since this needs to check the possibly active session and does not care
    # about valid secrets, we need to inspect the actual session.
    if (
        not retry
        and config["auth"]["session_lifecycle"]["renew"]
        and not client.auth.get_session().is_valid(
            config["auth"]["session_lifecycle"]["minimum_ttl"]
        )
    ):
        log.debug("Renewing session")
        client.session_renew()

    # Check if the current session could not be renewed for a sufficient amount of time.
    if not retry and not client.session_valid(
        config["auth"]["session_lifecycle"]["minimum_ttl"] or 0, remote=False
    ):
        clear_cache(opts, context, session=True)
        client, config, retry = try_build()

    if retry:
        log.debug("Requesting new authentication credentials")
        client, config = _build_authd_client(opts, context)
        if not client.session_valid(
            config["auth"]["session_lifecycle"]["minimum_ttl"] or 0, remote=False
        ):
            if not config["auth"]["session_lifecycle"]["minimum_ttl"]:
                raise PiHoleAPIException(
                    "Could not build valid client. This is most likely a bug."
                )
            log.warning(
                "Configuration error: auth:session_lifecycle:minimum_ttl cannot be "
                "honored because fresh sessions are issued with less ttl. Continuing anyways."
            )

    if cbank not in context:
        context[cbank] = {}
    context[cbank][CLIENT_CKEY] = (client, config)

    if get_config:
        return client, config
    return client


def _build_authd_client(opts):
    config, embedded_session, unauthd_client = _get_connection_config(opts)
    # Sessions are cached in a distinct scope to enable cache per session
    session_cbank = "pihole/connection/session"
    session_cache = PiHoleAPIAuthCache(
        session_cbank,
        SESSION_CKEY,
        _get_cache_backend(config, opts),
        auth_cls=PiHoleAPISession,
        flush_exception=PiHoleAPISessionExpired,
    )

    client = None

    if config["auth"]["method"] == "session":
        auth = PiHoleAPISessionAuth(session=embedded_session, cache=session_cache)
    else:
        if config["auth"]["method"] == "password":
            password = config["auth"]["password"]
        elif config["auth"]["method"] == "cli":
            if not CLI_PW_PATH.is_file():
                raise CommandExecutionError(
                    f"Auth method `cli` selected, missing {CLI_PW_PATH}"
                )
            password = CLI_PW_PATH.read_text().strip()
        elif config["auth"]["method"] == "app":
            raise NotImplementedError("Not yet implemented")
            # TODO: Implement cached app password if it can be set locally, cache it
        else:
            raise salt.exceptions.SaltException("Connection configuration is invalid.")

        session_auth = PiHoleAPISessionAuth(cache=session_cache)
        auth = PiHoleAPIPasswordAuth(
            password,
            unauthd_client,
            config["auth"]["method"],
            cache=None,
            session_store=session_auth,
        )
    client = AuthenticatedPiHoleAPIClient(
        auth, session=unauthd_client.session, **config["server"], **config["client"]
    )

    return client, config


def clear_cache(opts, context, ckey=None, connection=True, session=False):
    """
    Clears the PiHole cache.
    Will ensure the current session is revoked by default.

    opts
        Pass ``__opts__``.

    context
        Pass ``__context__``.

    ckey
        Only clear this cache key instead of the whole cache bank.

    connection
        Only clear the cached data scoped to a connection. This
        is currently everything. Defaults to true.

    session
        Only clear the cached data scoped to a connection. This
        is currently everything. Defaults to false.
    """
    if connection:
        cbank = "pihole/connection"
    elif session:
        cbank = "pihole/connection/session"
    else:
        cbank = "pihole"
    if (
        not ckey
        or (not (connection or session) and ckey == "connection")
        or (session and ckey == SESSION_CKEY)
        or ((connection and not session) and ckey == "config")
    ):
        client, config = _build_revocation_client(opts)
        # config and client will both be None if the cached data is invalid
        if config:
            try:
                # Don't revoke the only session that is available to us
                if config["auth"]["method"] != "session":
                    if config["cache"]["clear_attempt_revocation"]:
                        client.session_revoke()
                    # Don't send expiry events for pillar compilation impersonation
                    if config["cache"]["expire_events"]:
                        scope = cbank.split("/")[-1]
                        _get_event(opts)(
                            data={"scope": scope}, tag=f"pihole/cache/{scope}/clear"
                        )
            except Exception as err:  # pylint: disable=broad-except
                log.error(
                    "Failed to revoke session or send event before clearing cache:\n"
                    f"{type(err).__name__}: {err}"
                )
    if cbank in context:
        if ckey is None:
            context.pop(cbank)
        else:
            context[cbank].pop(ckey, None)
            if connection and not session:
                # Ensure the active client gets recreated after altering the connection cache
                context[cbank].pop(CLIENT_CKEY, None)

    cache = salt.cache.factory(opts)
    if cache.contains(cbank, ckey):
        return cache.flush(cbank, ckey)

    # In case the cache driver was overridden
    local_opts = copy.copy(opts)
    opts["cache"] = "localfs"
    cache = salt.cache.factory(local_opts)
    return cache.flush(cbank, ckey)


def _get_event(opts):
    event = salt.utils.event.get_event(
        opts.get("__role", "minion"), sock_dir=opts["sock_dir"], opts=opts, listen=False
    )
    return event.fire_master


def _build_revocation_client(opts):
    """
    Tries to build an AuthenticatedPiHoleAPIClient solely from caches.
    This client is used to revoke all leases before forgetting about them.
    """
    # Disregard a possibly returned locally configured session since
    # it is cached with metadata if it has been used. Also, we do not want
    # to revoke statically configured sessions anyways.
    config, _, unauthd_client = _get_connection_config(opts)
    if config is None:
        return None, None

    # Sessions are cached in a distinct scope to enable cache per session
    session_cbank = "pihole/connection/session"
    session_cache = PiHoleAPIAuthCache(
        session_cbank,
        SESSION_CKEY,
        _get_cache_backend(config, opts),
        auth_cls=PiHoleAPISession,
    )

    session = session_cache.get(flush=False)

    if session is None:
        return None, None
    auth = PiHoleAPISessionAuth(session=session, cache=session_cache)
    client = AuthenticatedPiHoleAPIClient(
        auth, session=unauthd_client.session, **config["server"], **config["client"]
    )
    return client, config


def _get_connection_config(opts):
    # This module is based on the one from saltext-vault.
    # In the future, it could be allowed to pull config + an app password via
    # peer publishing and authenticate to a remote PiHole API on another minion.
    # For now, just support local config.
    return _use_local_config(opts)


def _use_local_config(opts):
    log.debug("Using PiHole connection details from local config.")
    config = parse_config(opts.get("pihole", {}))
    embedded_session = config["auth"].pop("session", None)
    if embedded_session:
        embedded_session = PiHoleAPISession(**embedded_session, auth_type="session")
    return (
        {
            "auth": config["auth"],
            "cache": config["cache"],
            "client": config["client"],
            "server": config["server"],
        },
        embedded_session,
        PiHoleAPIClient(**config["server"], **config["client"]),
    )


def _get_cache_backend(config, opts):
    if config["cache"]["backend"] == "session":
        return None
    if config["cache"]["backend"] in ("localfs", "disk", "file"):
        # cache.Cache does not allow setting the type of cache by param
        local_opts = copy.copy(opts)
        local_opts["cache"] = "localfs"
        return salt.cache.factory(local_opts)
    # this should usually resolve to localfs as well on minions,
    # but can be overridden by setting cache in the minion config
    return salt.cache.factory(opts)


class BaseCache:
    def __init__(self, cbank, cache_backend, flush_exception=None):
        self.cbank = cbank
        self.cache = cache_backend
        self.flush_exception = flush_exception

    def _ckey_exists(self, ckey, flush=True):  # pylint: disable=unused-argument
        return self.cache.contains(self.cbank, ckey)

    def _get_ckey(self, ckey, flush=True):
        if not self._ckey_exists(ckey, flush=flush):
            return None
        return self.cache.fetch(self.cbank, ckey) or None  # account for race conditions

    def _store_ckey(self, ckey, value):
        self.cache.store(self.cbank, ckey, value)

    def _flush(self, ckey=None):
        if not ckey and self.flush_exception is not None:
            # Flushing caches often requires an orchestrated effort
            # to ensure sessions are correctly terminated instead of left open.
            # There's a limit to the number of concurrent sessions.
            raise self.flush_exception(None)
        self.cache.flush(self.cbank, ckey)

    def _list(self):
        ckeys = self.cache.list(self.cbank)
        return set(ckeys)


class LeaseCacheMixin:
    """
    Mixin for auth and lease cache that checks validity
    and acts with hydrated objects
    """

    def __init__(self, *args, **kwargs):
        self.lease_cls = kwargs.pop("lease_cls", PiHoleAPISession)
        self.expire_events = kwargs.pop("expire_events", None)
        super().__init__(*args, **kwargs)

    def _check_validity(self, lease_data, valid_for=0):
        lease = self.lease_cls(**lease_data)
        if lease.is_valid(valid_for):
            log.debug("Using cached lease.")
            return lease
        if self.expire_events is not None:
            raise PiHoleAPISessionExpired(lease)
        return None


class DurationMixin:
    """
    Mixin that handles expiration with time
    """

    def __init__(
        self,
        /,
        validity: int,
        creation_time: int | None = None,
        valid_until: int | None = None,
        **kwargs,
    ):
        self.validity = validity
        self.creation_time = (
            creation_time if creation_time is not None else round(time.time())
        )

        self.valid_until = (
            valid_until if valid_until is not None else round(time.time()) + validity
        )
        super().__init__(**kwargs)

    def is_valid(self, valid_for=0, blur=0):
        """
        Checks whether the entity is valid

        valid_for
            Check whether the entity will still be valid in the future.
            Type is number of seconds. Defaults to 0.

        blur
            Allow undercutting ``valid_for`` for this amount of seconds.
            Defaults to 0.
        """
        if not self.validity:
            return True
        delta = self.valid_until - time.time() - valid_for
        if delta >= 0:
            return True
        return abs(delta) <= blur

    def used(self):
        self.valid_until = round(time.time()) + self.validity

    @property
    def ttl_left(self):
        return max(self.valid_until - round(time.time()), 0)


class DropInitKwargsMixin:
    """
    Mixin that breaks the chain of passing unhandled kwargs up the MRO.
    """

    def __init__(self, *args, **kwargs):  # pylint: disable=unused-argument
        super().__init__(*args)


class BaseLease(DurationMixin, DropInitKwargsMixin):
    """
    Base class for leases that expire with time.
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def __repr__(self):
        return repr(self.to_dict())

    def __eq__(self, other):
        try:
            data = other.__dict__
        except AttributeError:
            data = other
        return data == self.__dict__

    def with_renewed(self, **kwargs):
        """
        Partially update the contained data after lease renewal
        """
        attrs = copy.copy(self.__dict__)
        # ensure valid_until is reset properly
        attrs.pop("valid_until")
        attrs.update(kwargs)
        return type(self)(**attrs)

    def to_dict(self):
        """
        Return a dict of all contained attributes
        """
        return copy.deepcopy(self.__dict__)


class PiHoleAPISession(BaseLease):
    """
    Represents a logged in PiHole API session, similar to a token.
    """

    def __init__(
        self,
        /,
        totp: bool,
        sid: str,
        csrf: str,
        id: int | None = None,
        app: bool | None = None,
        cli: bool | None = None,
        auth_type: (
            str | None
        ) = None,  # as recorded by us, essentially app/cli/password/session
        **kwargs,
    ):
        super().__init__(**kwargs)
        self.totp = totp
        self.sid = sid
        self.csrf = csrf
        self.id = id
        if auth_type:
            if app is None:
                app = auth_type == "app"
            if cli is None:
                cli = auth_type == "cli"
        self.app = app
        self.cli = cli
        self.auth_type = auth_type

    def __str__(self):
        return self.sid


class InvalidPiHoleApiSession(PiHoleAPISession):
    def __init__(self, *args, **kwargs):  # pylint: disable=super-init-not-called
        pass

    def is_valid(self, valid_for=0):  # pylint: disable=unused-arguments
        return False


class PiHoleAPISessionAuth:
    """
    Container for authentication sessions
    """

    def __init__(self, cache=None, session=None):
        self.cache = cache
        if session is None and cache is not None:
            session = cache.get()
        if session is None:
            session = InvalidPiHoleApiSession()
        if isinstance(session, dict):
            session = PiHoleAPISession(**session)
        self.session = session

    def is_valid(self, valid_for=0):
        """
        Check whether the contained session is valid
        """
        return self.session.is_valid(valid_for)

    def get_session(self):
        """
        Get the contained session if it is valid, otherwise
        raises PiHoleAPISessionExpired
        """
        if self.session.is_valid():
            return self.session
        raise PiHoleAPISessionExpired(self.session)

    def used(self):
        """
        Increment the use counter for the contained session
        """
        self.session.used()
        self._write_cache()

    def update_session(self, auth):
        """
        Partially update the contained session (e.g. after renewal)
        """
        self.session = self.session.with_renewed(**auth)
        self._write_cache()

    def replace_session(self, session):
        """
        Completely replace the contained session with a new one
        """
        self.session = session
        self._write_cache()

    def _write_cache(self):
        if self.cache is not None:
            # Write the session indiscriminately since flushing
            # raises PiHoleAPISessionExpired.
            # This will be handled as part of the next request.
            self.cache.store(self.session)


class PiHoleAPIPasswordAuth:
    """
    Fetches sessions from a (CLI/App/General) password.
    """

    def __init__(self, password, client, auth_type, cache=None, session_store=None):
        self.password = password
        self.client = client
        self.auth_type = auth_type
        self.cache = cache
        if session_store is None:
            session_store = PiHoleAPISessionAuth()
        self.session = session_store

    def is_valid(self, valid_for=0):
        """
        Check whether the contained authentication data can be used
        to issue a valid session
        """
        return self.session.is_valid(valid_for) or True

    def get_session(self):
        """
        Return the session issued by the last login, if it is still valid, otherwise
        login with the contained AppRole, if it is valid. Otherwise,
        raises PiHoleAPISessionExpired
        """
        if self.session.is_valid():
            return self.session.get_session()
        return self._login()

    def used(self):
        """
        Increment the use counter for the currently used session
        """
        self.session.used()

    def update_session(self, auth):
        """
        Partially update the contained session (e.g. after renewal)
        """
        self.session.update_session(auth)

    def _login(self):
        log.debug(
            "PiHole API session expired. Recreating one by authenticating with password."
        )
        payload = {"password": self.password}
        res = self.client.post("auth", payload=payload)["session"]
        info = self.client.session_lookup(res["sid"])
        self.session.replace_session(PiHoleAPISession(**info, auth_type=self.auth_type))
        return self.session.get_session()


class PiHoleAPIAuthCache(LeaseCacheMixin, BaseCache):
    """
    Implements authentication secret-specific caches. Checks whether
    the cached secrets are still valid before returning.
    """

    def __init__(
        self,
        cbank,
        ckey,
        cache_backend,
        /,
        auth_cls=PiHoleAPISession,
        flush_exception=None,
    ):
        super().__init__(
            cbank,
            lease_cls=auth_cls,
            cache_backend=cache_backend,
            flush_exception=flush_exception,
        )
        self.ckey = ckey
        self.flush_exception = flush_exception

    def exists(self, flush=True):
        """
        Check whether data for this domain exists
        """
        return self._ckey_exists(self.ckey, flush=flush)

    def get(self, valid_for=0, flush=True):
        """
        Returns valid cached auth data or None.
        Flushes cache if invalid by default.
        """
        data = self._get_ckey(self.ckey, flush=flush)
        if data is None:
            return data
        ret = self._check_validity(data, valid_for=valid_for)
        if ret is None and flush:
            log.debug("Cached auth data not valid anymore. Flushing cache.")
            self.flush()
        return ret

    def store(self, value):
        """
        Store an auth credential in cache. Will overwrite possibly existing one.
        """
        try:
            value = value.to_dict()
        except AttributeError:
            pass
        return self._store_ckey(self.ckey, value)

    def flush(self, cbank=None):
        """
        Flush the cached auth credentials. If this is a session cache,
        flushing it will delete the whole session-scoped cache bank.
        """
        if self.lease_cls is PiHoleAPISession:
            # flush the whole cbank (session-scope) if this is a session cache
            ckey = None
        else:
            ckey = None if cbank else self.ckey
        return self._flush(ckey)


def parse_config(config, validate=True):
    """
    Returns a configuration dictionary that has all
    keys with defaults. Checks if required data is available.
    """
    default_config = {
        "auth": {
            # cli reads from /etc/pihole/cli_pw, which is an app password
            # that is generated by default (but can be disabled).
            # Other possibilities are:
            # * app (generate a new app password, needs to be able to write to /etc/pihole/pihole.toml)
            # * password (specify a static [app] password as separate "password")
            # * session (specify a SID as separate "session_id")
            "method": "cli",
            "session_lifecycle": {
                "minimum_ttl": 120,
                "renew": True,
            },
        },
        "cache": {
            "backend": "disk",
            "clear_attempt_revocation": True,
            "expire_events": False,
        },
        "client": {
            "connect_timeout": DEFAULT_CONNECT_TIMEOUT,
            "read_timeout": DEFAULT_READ_TIMEOUT,
            "max_retries": DEFAULT_MAX_RETRIES,
            "backoff_factor": DEFAULT_BACKOFF_FACTOR,
            "backoff_max": DEFAULT_BACKOFF_MAX,
            "backoff_jitter": DEFAULT_BACKOFF_JITTER,
            "retry_post": DEFAULT_RETRY_POST,
            "retry_status": list(DEFAULT_RETRY_STATUS),
            "respect_retry_after": DEFAULT_RESPECT_RETRY_AFTER,
            "retry_after_max": DEFAULT_RETRY_AFTER_MAX,
        },
        "server": {
            "verify": None,
        },
    }
    merged = salt.utils.dictupdate.merge(
        default_config,
        config,
        strategy="smart",
        merge_lists=False,
    )

    if "url" not in merged["server"]:
        # This should default to the local hostname since
        # we're managing the local node. There could be multiple
        # behind the same configured domain in case of keepalived usage, e.g.
        domain = salt.utils.network.get_fqhostname()
        # TODO: This should discover port/tls as well
        if not domain:
            try:
                conf = read_pihole_toml()
            except CommandExecutionError:
                conf = {"webserver": {"domain": "pi.hole"}}
            domain = conf.get("webserver", {}).get("domain", "pi.hole")
        merged["server"]["url"] = f"https://{domain}"

    if not validate:
        return merged

    try:
        if merged["auth"]["method"] in ("cli", "app"):
            pass
        elif merged["auth"]["method"] == "password":
            if "password" not in merged["auth"]:
                raise AssertionError("auth:password is required for password auth")
        elif merged["auth"]["method"] == "session":
            if "session" not in merged["auth"]:
                raise AssertionError("auth:session is required for session auth")
        else:
            raise AssertionError(
                f"`{merged['auth']['method']}` is not a valid auth method."
            )
    except AssertionError as err:
        raise salt.exceptions.InvalidConfigError(
            f"Invalid pihole configuration: {err}"
        ) from err
    return merged


class PiHoleAPIException(salt.exceptions.SaltException):
    """
    Base class for exceptions raised by this module
    """

    def __init__(self, res, *args, **kwargs):
        try:
            error = res.json().get("error", {})
        except AttributeError:
            error = res
        else:
            key = error.get("key") or "(unspecified)"
            message = error.get("message") or "(no description)"
            hint = error.get("hint") or "(no hint)"
            error = f"{key}: {message}"
            if hint:
                error += f"\nHint: {salt.utils.json.dumps(hint)}"
        super().__init__(error, *args, **kwargs)


class PiHoleAPISessionExpired(PiHoleAPIException):
    """
    Raised when a cached session is reported to be expired locally.
    """

    def __init__(self, session):
        super().__init__("Session expired")
        self.session = session


# https://docs.pi-hole.net/api/#error-handling
class PiHoleAPIInvocationError(PiHoleAPIException):
    """
    HTTP 400 and InvalidArgumentException for this module
    The request was unacceptable, often due to a missing required parameter
    """


class PiHoleAPIAuthRequiredError(PiHoleAPIException):
    """
    HTTP 401
    No session identity provided for endpoint requiring authorization
    """


class PiHoleAPIRequestFailedError(PiHoleAPIException):
    """
    HTTP 402
    The parameters were valid but the request failed
    """


class PiHoleAPIPermissionDeniedError(PiHoleAPIException):
    """
    HTTP 403
    The API key doesn't have permissions to perform the request
    """


class PiHoleAPINotFoundError(PiHoleAPIException):
    """
    HTTP 404
    The requested resource doesn't exist
    """


class PiHoleAPIUnsupportedOperationError(PiHoleAPIException):
    """
    HTTP 405
    """


class PiHoleAPIRateLimitExceededError(PiHoleAPIException):
    """
    HTTP 429
    Too many requests hit the API too quickly
    """


class PiHoleAPIServerError(PiHoleAPIException):
    """
    HTTP 500
    HTTP 502
    HTTP 503
    HTTP 504
    """


class PiHoleAPIAdapter(HTTPAdapter):
    """
    An adapter that

        * allows to restrict requests CA chain validation to a single
          root certificate without writing it to disk.
        * sets default values for timeout settings without having to
          specify it in every request.
    """

    def __init__(
        self, *args, verify=None, connect_timeout=None, read_timeout=None, **kwargs
    ):
        ca_cert_data = None
        try:
            if verify.strip().startswith("-----BEGIN CERTIFICATE"):
                ca_cert_data = verify
                verify = None
        except AttributeError:
            pass
        self.ca_cert_data = ca_cert_data
        self.verify = verify
        self.connect_timeout = connect_timeout or DEFAULT_CONNECT_TIMEOUT
        self.read_timeout = read_timeout or DEFAULT_READ_TIMEOUT
        super().__init__(*args, **kwargs)

    def init_poolmanager(
        self,
        connections,
        maxsize,
        block=requests.adapters.DEFAULT_POOLBLOCK,
        **pool_kwargs,
    ):
        if self.ca_cert_data is not None:
            ssl_context = create_urllib3_context()
            ssl_context.load_verify_locations(cadata=self.ca_cert_data)
            pool_kwargs["ssl_context"] = ssl_context
        return super().init_poolmanager(
            connections, maxsize, block=block, **pool_kwargs
        )

    def send(
        self, request, stream=False, timeout=None, verify=True, cert=None, proxies=None
    ):
        """
        Wrap sending the request to ensure ``verify`` and ``timeout`` is set
        as specified on every request. ``timeout`` can be overridden per request.
        """
        if self.verify is not None:
            verify = self.verify
        if timeout is None:
            timeout = (self.connect_timeout, self.read_timeout)
        return super().send(
            request,
            stream=stream,
            timeout=timeout,
            verify=verify,
            cert=cert,
            proxies=proxies,
        )


class PiHoleAPIRetry(Retry):
    """
    The PiHole API responds with HTTP 429 when rate limits have been hit.
    We want to always retry 429, regardless of the HTTP verb and the presence
    of the ``Retry-After`` header, thus we need to subclass the retry configuration class.
    For HTTP error responses, we do not want to retry immediately if the header was not set.

    We override the default exponential power-of-2 algorithm for calculating
    the backoff time with a Fibonacci one because we expect a relatively
    quick turnaround.
    """

    PHI = 1.618
    SQRT5 = 2.236

    def __init__(
        self,
        *args,
        backoff_jitter=0.0,
        backoff_max=Retry.DEFAULT_BACKOFF_MAX,
        retry_after_max=DEFAULT_RETRY_AFTER_MAX,
        **kwargs,
    ):
        """
        For ``urllib3<2``, backport ``backoff_max`` and ``backoff_jitter``.
        Also, allow limiting the value returned by ``Retry-After`` by
        specifying ``retry_after_max``.
        """
        if URLLIB3V1:
            self.backoff_max = backoff_max
            self.backoff_jitter = backoff_jitter
        else:
            kwargs["backoff_max"] = backoff_max
            kwargs["backoff_jitter"] = backoff_jitter
        self.retry_after_max = retry_after_max
        super().__init__(*args, **kwargs)

    def is_retry(self, method, status_code, has_retry_after=False):
        """
        HTTP 429 is always retryable (even for POST/PATCH), otherwise fall back
        to the configuration.
        """
        if status_code == HTTP_TOO_MANY_REQUESTS:
            return True
        return super().is_retry(method, status_code, has_retry_after=has_retry_after)

    def get_backoff_time(self):
        """
        When we're retrying HTTP error responses, ensure we don't execute the
        first retry immediately.
        Also overrides the default 2**n algorithm with one based on the Fibonacci sequence.
        On ``urllib3<2``, this also backports ``backoff_jitter`` and ``backoff_max``.
        """
        # We want to consider only the last consecutive errors sequence (Ignore redirects).
        consecutive_errors = list(
            takewhile(lambda x: x.redirect_location is None, reversed(self.history))
        )
        consecutive_errors_len = len(consecutive_errors)
        if consecutive_errors_len and consecutive_errors[0].status is not None:
            # Ensure we only immediately retry for local (connection/read) errors,
            # not when we got an HTTP response.
            consecutive_errors_len += 1
        if consecutive_errors_len <= 1:
            return 0
        # Approximate the nth Fibonacci number.
        # We want to begin with the 4th one (2).
        backoff_value = round(
            self.backoff_factor
            * round(self.PHI ** (consecutive_errors_len + 1) / self.SQRT5),
            1,
        )
        if self.backoff_jitter != 0.0:
            backoff_value += random.random() * self.backoff_jitter
        return float(max(0, min(self.backoff_max, backoff_value)))

    def get_retry_after(self, response):
        """
        The default implementation sleeps for as long as requested
        by the ``Retry-After`` header. We want to limit that somewhat
        to avoid sleeping until the end of the universe.
        """
        retry_after = response.headers.get("Retry-After")

        if retry_after is None:
            return None

        res = self.parse_retry_after(retry_after)
        if self.retry_after_max is None:
            return res
        return min(res, self.retry_after_max)

    def new(self, **kw):
        """
        Since we backport some params and introduce a new one,
        ensure all requests use the defined parameters, not the default ones.
        """
        ret = super().new(**kw)
        if URLLIB3V1:
            ret.backoff_jitter = self.backoff_jitter
            ret.backoff_max = self.backoff_max
        ret.retry_after_max = self.retry_after_max
        return ret


class PiHoleAPIClient:
    """
    Unauthenticated client for the PiHole API.
    Base class for authenticated client.
    """

    def __init__(
        self,
        url,
        verify=None,
        session=None,
        connect_timeout=DEFAULT_CONNECT_TIMEOUT,
        read_timeout=DEFAULT_READ_TIMEOUT,
        max_retries=DEFAULT_MAX_RETRIES,
        max_connect_retries=None,
        max_read_retries=None,
        max_status_retries=None,
        max_other_retries=None,
        backoff_factor=DEFAULT_BACKOFF_FACTOR,
        backoff_max=DEFAULT_BACKOFF_MAX,
        backoff_jitter=DEFAULT_BACKOFF_JITTER,
        retry_post=DEFAULT_RETRY_POST,
        respect_retry_after=DEFAULT_RESPECT_RETRY_AFTER,
        retry_status=DEFAULT_RETRY_STATUS,
        retry_after_max=DEFAULT_RETRY_AFTER_MAX,
    ):
        self.url = url
        self.verify = verify

        self.connect_timeout = connect_timeout
        self.read_timeout = read_timeout

        # Cap the retry-backoff values somewhat
        self.max_retries = max(0, min(max_retries, MAX_MAX_RETRIES))
        # When running locally and we have some errors, we want to
        # be able to skip retrying those since we're probably fixing them.
        # This applies to `other` (SSLError) and `connect` (API not running)
        self.max_connect_retries = (
            max(0, max_connect_retries) if max_connect_retries is not None else None
        )
        self.max_read_retries = (
            max(0, max_read_retries) if max_read_retries is not None else None
        )
        self.max_status_retries = (
            max(0, max_status_retries) if max_status_retries is not None else None
        )
        self.max_other_retries = (
            max(0, max_other_retries) if max_other_retries is not None else None
        )
        self.backoff_factor = max(0, min(backoff_factor, MAX_BACKOFF_FACTOR))
        self.backoff_max = max(0, min(backoff_max, MAX_BACKOFF_MAX))
        self.backoff_jitter = max(0, min(backoff_jitter, MAX_BACKOFF_JITTER))
        self.retry_post = bool(retry_post)
        self.respect_retry_after = bool(respect_retry_after)
        self.retry_after_max = (
            max(0, retry_after_max) if retry_after_max is not None else None
        )
        self.retry_status = tuple(retry_status) if retry_status is not None else None

        retry = PiHoleAPIRetry(
            total=self.max_retries,
            connect=self.max_connect_retries,
            read=self.max_read_retries,
            status=self.max_status_retries,
            other=self.max_other_retries,
            backoff_factor=self.backoff_factor,
            backoff_max=self.backoff_max,
            backoff_jitter=self.backoff_jitter,
            respect_retry_after_header=self.respect_retry_after,
            retry_after_max=self.retry_after_max,
            allowed_methods=None if retry_post else Retry.DEFAULT_ALLOWED_METHODS,
            raise_on_status=False,
            status_forcelist=self.retry_status,
        )

        if session is None:
            session = requests.Session()
            adapter = PiHoleAPIAdapter(
                max_retries=retry,
                verify=verify,
                connect_timeout=self.connect_timeout,
                read_timeout=self.read_timeout,
            )
            session.mount(url, adapter)
        else:
            # Sessions should only be inherited from other instances
            # of this class. A changed ``verify`` setting causes a fresh
            # client to be instantiated.
            # We want to keep the TCP connection alive, so we'll modify
            # the adapter in place.
            adapter = session.get_adapter(url)
            adapter.max_retries = retry
            adapter.connect_timeout = self.connect_timeout
            adapter.read_timeout = self.read_timeout
        self.session = session

    def delete(
        self, endpoint, raise_error=True, add_headers=None, payload=None, session=None
    ):
        """
        Wrapper for client.request("DELETE", ...)
        """
        return self.request(
            "DELETE",
            endpoint,
            raise_error=raise_error,
            add_headers=add_headers,
            payload=payload,
            session=session,
        )

    def get(
        self, endpoint, raise_error=True, add_headers=None, payload=None, session=None
    ):
        """
        Wrapper for client.request("GET", ...)
        """
        return self.request(
            "GET",
            endpoint,
            raise_error=raise_error,
            add_headers=add_headers,
            payload=payload,
            session=session,
        )

    def list(self, endpoint, raise_error=True, add_headers=None, session=None):
        """
        Wrapper for client.request("LIST", ...)
        TODO: configuration to enable GET requests with query parameters for LIST?
        """
        return self.request(
            "LIST",
            endpoint,
            raise_error=raise_error,
            add_headers=add_headers,
            session=session,
        )

    def put(
        self, endpoint, payload=None, raise_error=True, add_headers=None, session=None
    ):
        """
        Wrapper for client.request("PUT", ...)
        """
        return self.request(
            "PUT",
            endpoint,
            payload=payload,
            raise_error=raise_error,
            add_headers=add_headers,
            session=session,
        )

    def post(
        self, endpoint, payload=None, raise_error=True, add_headers=None, session=None
    ):
        """
        Wrapper for client.request("POST", ...)
        """
        return self.request(
            "POST",
            endpoint,
            payload=payload,
            raise_error=raise_error,
            add_headers=add_headers,
            session=session,
        )

    def patch(
        self, endpoint, payload, raise_error=True, add_headers=None, session=None
    ):
        """
        Wrapper for client.request("PATCH", ...)
        """
        return self.request(
            "PATCH",
            endpoint,
            payload=payload,
            raise_error=raise_error,
            add_headers=add_headers,
            session=session,
        )

    def request(
        self,
        method,
        endpoint,
        payload=None,
        raise_error=True,
        add_headers=None,
        session=None,
        **kwargs,
    ):
        """
        Issue a request against the PiHole API.
        Returns boolean when no data was returned, otherwise the decoded json data.
        """
        res = self.request_raw(
            method,
            endpoint,
            payload=payload,
            add_headers=add_headers,
            session=session,
            **kwargs,
        )
        if res.status_code == 204:
            return True
        if not res.ok and raise_error:
            self._raise_status(res)
        data = res.json()
        return data

    def request_raw(
        self,
        method,
        endpoint,
        /,
        payload=None,
        add_headers=None,
        session=None,
        **kwargs,
    ):
        """
        Issue a request against the PiHole API. Returns the raw response object.
        """
        url = self._get_url(endpoint)
        headers = self._get_headers(session)
        try:
            headers.update(add_headers)
        except TypeError:
            pass
        params = None
        if method.upper() in ("GET", "DELETE"):
            params = payload
            payload = None
        res = self.session.request(
            method,
            url,
            headers=headers,
            json=payload,
            params=params,
            **kwargs,
        )
        return res

    def session_valid(
        self, valid_for=0, remote=True
    ):  # pylint: disable=unused-argument
        return False

    def session_lookup(self, session=None):
        """
        Lookup session meta information.

        session
            The session to look up. Required.
        """
        if not session:
            raise PiHoleAPIInvocationError(
                "Unauthenticated client requires session to lookup"
            )
        core = self.request("GET", "auth", session=session)["session"]
        try:
            misc = next(
                session
                for session in self.request("GET", "auth/sessions", session=session)[
                    "sessions"
                ]
                if session.get("current_session")
            )
        except PiHoleAPIAuthRequiredError:
            misc = {}
            log.warning(
                "Using cli_pw or restricted app password, some functions might crash"
            )
        core.pop("message", None)
        misc.update(core)
        return misc

    def session_renew(self, session=None):
        """
        Renew a session.

        session
            The session that should be renewed. Required.
        """
        res = self.session_lookup(session)
        return res

    def session_revoke(self, session=None):
        """
        Revoke a session.

        session
            The session that should be revoked. Required.
        """
        if not session:
            raise PiHoleAPIInvocationError(
                "Unauthenticated client requires session to lookup"
            )
        endpoint = "auth"
        self.delete(endpoint, session=session)
        return True

    def get_config(self):
        """
        Returns PiHole server configuration used by this client.
        """
        return {
            "url": self.url,
            "verify": self.verify,
        }

    def _get_url(self, endpoint):
        endpoint = endpoint.strip("/")
        return f"{self.url}/api/{endpoint}"

    def _get_headers(self, session=None):  # pylint: disable=unused-argument
        headers = {"Content-Type": "application/json", "Accept": "application/json"}
        return headers

    def _raise_status(self, res):
        if res.status_code == 400:
            raise PiHoleAPIInvocationError(res)
        if res.status_code == 401:
            raise PiHoleAPIAuthRequiredError(res)
        if res.status_code == 402:
            raise PiHoleAPIRequestFailedError(res)
        if res.status_code == 403:
            raise PiHoleAPIPermissionDeniedError(res)
        if res.status_code == 404:
            raise PiHoleAPINotFoundError(res)
        if res.status_code == 405:
            raise PiHoleAPIUnsupportedOperationError(res)
        if res.status_code == HTTP_TOO_MANY_REQUESTS:
            raise PiHoleAPIRateLimitExceededError(res)
        if res.status_code in (500, 502, 503, 504):
            raise PiHoleAPIServerError(res)
        res.raise_for_status()


class AuthenticatedPiHoleAPIClient(PiHoleAPIClient):
    """
    Authenticated client for the PiHole API.
    This should be used for most operations.
    """

    auth = None

    def __init__(self, auth, url, **kwargs):
        self.auth = auth
        super().__init__(url, **kwargs)

    def request_raw(
        self,
        method,
        endpoint,
        /,
        payload=None,
        add_headers=None,
        session=None,
        **kwargs,
    ):
        """
        Issue a request against the PiHole API. Returns the raw response object.
        """
        res = super().request_raw(
            method,
            endpoint,
            payload=payload,
            add_headers=add_headers,
            session=session,
            **kwargs,
        )
        if session is None:
            self.auth.used()
        return res

    def session_valid(self, valid_for=0, remote=True):
        """
        Check whether this client's authentication information is
        still valid.

        remote
            Check with the remote PiHole API as well. Defaults to true.
        """
        if not self.auth.is_valid(valid_for):
            return False
        if not remote:
            return True
        try:
            return self.request("GET", "auth")["session"]["valid"]
        except PiHoleAPIAuthRequiredError:
            pass
        except Exception as err:  # pylint: disable=broad-except
            raise CommandExecutionError("Error while looking up self session.") from err
        return False

    def session_lookup(self, session=None):
        """
        Lookup session meta information.

        session
            The session to look up. If neither session nor accessor
            are specified, looks up the current session in use by
            this client.
        """
        core = self.request("GET", "auth", session=session)["session"]
        try:
            misc = next(
                session
                for session in self.request("GET", "auth/sessions", session=session)[
                    "sessions"
                ]
                if session.get("current_session")
            )
        except PiHoleAPIAuthRequiredError:
            misc = {}
            log.warning(
                "Using cli_pw or restricted app password, some functions might crash"
            )
        core.pop("message", None)
        misc.update(core)
        if session is None:
            self.auth.update_session(misc)
        return misc

    def session_renew(self, session=None):
        """
        Renew a session.

        session
            The session that should be renewed. Optional.
            If unset, renews the session currently in use by this client.
        """
        res = self.session_lookup(session)
        return res

    def session_revoke(self, session=None):
        """
        Revoke a session.

        session
            The session that should be revoked. Optional.
            If unset, revokes the session currently in use by this client.
        """
        endpoint = "auth"
        try:
            self.delete(endpoint, session=session)
        except (PiHoleAPIPermissionDeniedError, PiHoleAPINotFoundError):
            # if we're trying to revoke ourselves and this happens,
            # the session was already invalid
            if session:
                raise
            return False
        return True

    def _get_headers(self, session=None):
        headers = super()._get_headers()
        headers["X-FTL-SID"] = session or str(self.auth.get_session())
        return headers


def read_pihole_toml():
    pihole_toml = Path("/etc/pihole/pihole.toml")
    if not pihole_toml.is_file():
        raise CommandExecutionError(f"Missing {pihole_toml}")
    try:
        # py 3.11+
        import tomllib as toml

        decode_err = toml.TOMLDecodeError
    except ImportError:
        try:
            import toml

            decode_err = toml.TomlDecodeError
        except ImportError as err:
            raise CommandExecutionError(
                f"Missing toml lib for reading pihole.toml: {err}"
            ) from err
    try:
        with open(pihole_toml, "rb") as f:
            return toml.load(f)
    except decode_err as err:
        raise CommandExecutionError(f"Failed parsing pihole.toml: {err}") from err

"""
PiHole salt execution module
============================

Manage PiHole v6+ with Salt.

This module prefers to interface with the new PiHole API.
For many functions, there are fallbacks to using the local ``pihole`` CLI
or querying the gravity db via ``sqlite3`` directly.
For these functions, this module needs the sqlite3 library.
"""

import logging as logging_
import re
import shlex
from collections.abc import Mapping
from enum import Enum, auto
from functools import wraps
from pathlib import Path

import salt.utils.data
import salt.utils.dictupdate
import salt.utils.path
from salt.exceptions import CommandExecutionError, SaltInvocationError
from salt.utils import decorators

try:
    import sqlite3

    HAS_SQLITE3 = True
except ImportError:
    HAS_SQLITE3 = False

try:
    import pihole_api
    from pihole_api import PiHoleAPIException

    HAS_API = True

except ImportError:
    PiHoleAPIException = CommandExecutionError
    HAS_API = False

try:
    import pihole_pwhash

    HAS_HASH = True

except ImportError:
    HAS_HASH = False

try:
    from tomllib import dumps as toml_dumps
    from tomllib import load as _toml_load

    def toml_load(path, *args, **kwargs):
        """
        This replicates the toml module logic with the stdlib one
        """
        with open(path, "rb") as wfh:
            return _toml_load(wfh, *args, **kwargs)

    HAS_TOML = True
except ImportError:
    try:
        from toml import dumps as toml_dumps
        from toml import load as toml_load

        HAS_TOML = True
    except ImportError:
        HAS_TOML = False


log = logging_.getLogger(__name__)
__virtualname__ = "pihole"


# FIXME: As of v6, this can be changed in the config
PH_GRAVITY_DB = "/etc/pihole/gravity.db"
PH_DOMAINLIST_TYPES = {
    "black": 1,
    "white": 0,
    "rblack": 3,
    "rwhite": 2,
    "wblack": 3,
    "wwhite": 2,
}
PIHOLE_TOML = Path("/etc/pihole/pihole.toml")
PIHOLE_SERVICE = "pihole-FTL.service"


class Runtype(Enum):
    LOCAL = auto()
    REMOTE = auto()


class RequirementType(Enum):
    API = auto()
    CLI = auto()
    SQLITE = auto()
    TOML = auto()
    COMPOUND = auto()
    ONEOF = auto()
    APIERR = auto()
    MISC = auto()


class RequirementUnsatisfied(CommandExecutionError):
    reqtype: RequirementType

    def __init__(
        self,
        reqtype: RequirementType,
        ctx: list[tuple[RequirementType, str | None]] | str | None = None,
    ):
        # ctx is this weird because ExceptionGroups are missing on Python 3.10,
        # it's essentially both intended to polyfill these groups and provide context for singular ones
        super().__init__(self._reqtype_msg(reqtype))
        self.reqtype = reqtype

    def _reqtype_msg(
        self, reqtype: RequirementType, ctx: list[RequirementType] | str | None = None
    ) -> str:
        match reqtype:
            case RequirementType.API:
                return "Running this function requires the PiHole API util. Make sure it is importable by Salt."
            case RequirementType.CLI:
                return "Running this function requires the `pihole` CLI (i.e. it must be run on the PiHole node)."
            case RequirementType.SQLITE:
                return "Running this function requires the sqlite3 Python library. Make sure it is importable by Salt."
            case RequirementType.TOML:
                return "Running this function requires the toml Python library on Python <3.11. Make sure it is importable by Salt."
            case RequirementType.COMPOUND:
                msg = "Multiple requirements missing for running this function: "
                for req in ctx or []:
                    msg += f"\n  * {self._reqtype_msg(req)}"
                return msg
            case RequirementType.ONEOF:
                msg = "Running this function requires one of the following prerequisites, of which neither was satisfied: "
                for req in ctx or []:
                    msg += f"\n  * {self._reqtype_msg(req)}"
                return msg
            case RequirementType.APIERR:
                return f"Tried calling the PiHole API, which failed: {ctx or 'Unknown cause'}"
            case RequirementType.MISC:
                return str(ctx or "Unspecified error")


@decorators.memoize
def __which():
    return salt.utils.path.which("pihole")


@decorators.memoize
def _get_runtype() -> Runtype:
    if __which():
        return Runtype.LOCAL
    return Runtype.REMOTE


def __virtual__():
    match _get_runtype():
        case Runtype.LOCAL:
            try:
                ftl = _version_local()["ftl"]
            except Exception as err:  # pylint: disable=broad-except
                return False, f"Failed checking pihole version: {err}"
            if re.match(r"v[1-5]\.", ftl):
                return False, "Only supports PiHole >= v6"
            return __virtualname__
        case Runtype.REMOTE:
            if HAS_API:
                return True
            return (
                False,
                "Could not load pihole_api library and no `pihole` command in $PATH",
            )
    return (False, "internal error")


def _needs_api(func):
    @wraps(func)
    def needs_api(*args, **kwargs):
        if not HAS_API:
            raise RequirementUnsatisfied(RequirementType.API)
        return func(*args, **kwargs)

    return needs_api


def _needs_cli(func):
    @wraps(func)
    def needs_cli(*args, **kwargs):
        if _get_runtype() != Runtype.LOCAL:
            raise RequirementUnsatisfied(RequirementType.CLI)
        return func(*args, **kwargs)

    return needs_cli


def _needs_sqlite(func):
    @wraps(func)
    def needs_sqlite(*args, **kwargs):
        if not HAS_SQLITE3:
            raise RequirementUnsatisfied(RequirementType.SQLITE)
        return func(*args, **kwargs)

    return needs_sqlite


def _needs_toml(func):
    @wraps(func)
    def needs_api(*args, **kwargs):
        if not HAS_TOML:
            raise RequirementUnsatisfied(RequirementType.TOML)
        return func(*args, **kwargs)

    return needs_api


@_needs_sqlite
def _gravity_conn():
    """
    Return a Cursor object for the PiHole gravity database.
    """

    con = sqlite3.connect(PH_GRAVITY_DB, isolation_level=None)
    cur = con.cursor()
    return cur


@_needs_cli
def _pihole(subcmd, args=None):
    """
    Run arbitrary pihole commands.
    """

    if args is None:
        args = []

    if not isinstance(subcmd, list):
        subcmd = [subcmd]

    cmd = [__which()] + subcmd + args

    # shlex.join needs python >=3.8
    out = __salt__["cmd.run_all"](shlex.join(cmd))

    if out["retcode"]:
        raise CommandExecutionError("Failed running pihole.")

    return out["stdout"] or True


def _domain_to_wildcard(domain):
    r"""
    Helper for converting a plain domain to a regex-based wildcard entry.
    This is the way pihole does it (see ``ProcessDomainList`` in lists.sh):

    ``dom="(\\.|^)${dom//\./\\.}$"``

    Necessary for database lookup.
    """

    return r"(\.|^){}$".format(domain.replace(".", r"\."))


def _try_funcs(funcs: tuple[callable, ...], *args, **kwargs):
    errs = []
    for func in funcs:
        try:
            return func(*args, **kwargs)
        except RequirementUnsatisfied as err:
            errs.append((err.reqtype, None))
        except (IOError, PiHoleAPIException) as err:
            log.error(
                f"Failed querying PiHole api: {err}",
                exc_info_on_loglevel=logging_.DEBUG,
            )
            errs.append((RequirementType.APIERR, str(err)))
    raise RequirementUnsatisfied(RequirementType.ONEOF, errs)


def _adlist_list_api(status):
    payload = {"type": "block"}
    res = api("GET", "lists", payload=payload)["lists"]
    if status is not None:
        return [item["address"] for item in res if item["enabled"] is status]
    return [item["address"] for item in res]


def _adlist_list_local(status):
    query = "select `address` from `adlist`"

    if status is not None:
        query += " where `enabled` = " + str(int(bool(status)))

    # this actually requires sqlite as well
    out = __salt__["sqlite3.fetch"](PH_GRAVITY_DB, query)
    return [x[0] for x in out]


def adlist_list(status=None):
    """
    List all registered adlists.

    CLI Example:

    .. code-block:: bash

        salt '*' pihole.adlist_list

    status
        Optionally only show enabled (True) or disabled (False) lists.
    """

    return _try_funcs((_adlist_list_api, _adlist_list_local), status)


def _subscription_add_api(url, enabled, comment):
    payload = {
        "address": url,
        "type": "block",
        "comment": comment,
        "groups": [],  # not sure if this works, might need 0
        "enabled": enabled,
    }
    return api("POST", "lists", payload=payload)


def _subscription_add_local(url, enabled, comment):
    # The official salt execution module does not support parameter substitution
    # FIXME: I think this might need to add something like
    # INSERT INTO domainlist_by_group VALUES(id,0);
    cur = _gravity_conn()
    query = "insert into `adlist` (`address`, `enabled`, `comment`) VALUES (?, ?, ?);"
    cur.execute(query, (url, enabled, comment))
    return True


def adlist_add(url, enabled=True, comment="Managed by Salt", now=True):
    """
    Add an adlist to PiHole.

    CLI Example:

    .. code-block:: bash

        salt '*' pihole.adlist_add https://my.custom.ad/list.txt

    url
        The address of the adlist.

    enabled
        Whether the adlist should be added in enabled state. Defaults to True.

    comment
        An optional comment, defaults to "Managed by Salt".

    now
        Whether to reload pihole-FTL after the operation. Defaults to True.
    """
    if url in adlist_list():
        raise CommandExecutionError("The specified adlist is already present.")

    res = _try_funcs(
        (_subscription_add_api, _subscription_add_local), url, enabled, comment
    )

    if now:
        restartdns()
    return res or True


def _adlist_toggle_api(url, state):
    cur = api("GET", f"lists/{url}")["lists"]
    if not cur:
        raise CommandExecutionError(f"List {url} not found")
    cur = cur[0]
    payload = {
        "comment": cur["comment"],
        "type": "block",
        "groups": cur["groups"],
        "enabled": state,
    }
    return api("PUT", f"lists/{url}", payload=payload)


def _adlist_toggle_local(url, state):
    # The official salt execution module does not support parameter substitution
    cur = _gravity_conn()
    query = "update `adlist` set `enabled` = ? where `address` = ?"
    cur.execute(query, (str(int(bool(state))), url))
    return True


def adlist_disable(url, now=True):
    """
    Disable an adlist.

    CLI Example:

    .. code-block:: bash

        salt '*' pihole.adlist_disable https://my.custom.ad/list.txt

    url
        The address of the adlist.

    now
        Whether to reload pihole-FTL after the operation. Defaults to True.
    """

    if url not in adlist_list():
        raise CommandExecutionError("The specified adlist does not exist.")
    if url in adlist_list(False):
        raise CommandExecutionError("The specified adlist is already disabled.")

    res = _try_funcs((_adlist_toggle_api, _adlist_toggle_local), url, False)

    if now:
        restartdns()
    return res or True


def adlist_enable(url, now=True):
    """
    Enable an adlist.

    CLI Example:

    .. code-block:: bash

        salt '*' pihole.adlist_enable https://my.custom.ad/list.txt

    url
        The address of the adlist.

    now
        Whether to reload pihole-FTL after the operation. Defaults to True.
    """

    if url not in adlist_list():
        raise CommandExecutionError("The specified adlist does not exist.")
    if url in adlist_list(True):
        raise CommandExecutionError("The specified adlist is already enabled.")

    res = _try_funcs((_adlist_toggle_api, _adlist_toggle_local), url, True)

    if now:
        restartdns()
    return res or True


def _adlist_remove_api(url):
    payload = {"type": "block"}
    return api("DELETE", f"lists/{url}", payload=payload)


def _adlist_remove_local(url):
    # The official salt execution module does not support parameter substitution
    cur = _gravity_conn()
    query = "delete from `adlist` where `address` = ?"
    cur.execute(query, (url,))
    return True


def adlist_remove(url, now=True):
    """
    Remove an adlist from PiHole.

    CLI Example:

    .. code-block:: bash

        salt '*' pihole.adlist_remove https://my.custom.ad/list.txt

    url
        The address of the adlist.

    now
        Whether to reload pihole-FTL after the operation. Defaults to True.
    """

    if url not in adlist_list():
        raise CommandExecutionError("The specified adlist is already absent.")

    res = _try_funcs((_adlist_remove_api, _adlist_remove_local), url)

    if now:
        restartdns()
    return res or True


@_needs_cli
def admin(cmd, *args):
    """
    Run arbitrary ``pihole -a`` (``pihole admin``) commands.

    CLI Example:

    .. code-block:: bash

        salt '*' pihole.admin teleporter myname.tar.gz

    cmd
        The command to run.

    args
        List of arguments to ``pihole admin``.
    """

    return _pihole(["admin", cmd], list(args))


@_needs_api
def api(
    method,
    endpoint,
    payload=None,
    raise_error=True,
    session=None,
    **kwargs,
):
    """
    Run arbitrary PiHole API queries.
    Misc kwargs are passed through to requests.

    method
        HTTP verb to use.

    endpoint
        API path to call (without leading ``/api/``).

    payload
        Dictionary of payload values to send, if any.

    raise_error
        Whether to inspect the response code and raise exceptions.
        Defaults to True.

    session
        Override the internally managed session.
    """
    sanitized_kwargs = {k: v for k, v in kwargs.items() if not k.startswith("_")}
    try:
        return pihole_api.query(
            method,
            endpoint,
            __opts__,
            __context__,
            payload=payload,
            raise_error=raise_error,
            session=session,
            # TODO: Override retry config per request
            # max_other_retries=0 if _get_runtype() == Runtype.LOCAL else None,
            **sanitized_kwargs,
        )
    except pihole_api.PiHoleAPIException as err:
        raise CommandExecutionError(f"{type(err).__name__}: {err}") from err


def arpflush():
    """
    Flush information stored in Pi-hole's network tables.

    CLI Example:

    .. code-block:: bash

        salt '*' pihole.arpflush
    """
    return (
        _try_funcs(
            (lambda: api("POST", "action/flush/arp"), lambda: _pihole("arpflush"))
        )
        or True
    )


def _list_add_api(typ, domains, regex, wildcard):
    kind = "exact"
    if regex:
        kind = "regex"
    elif wildcard:
        kind = "regex"
        domains = [_domain_to_wildcard(domain) for domain in domains]

    endpoint = f"domains/{typ}/{kind}"
    payload = {
        "domain": domains,
        "comment": None,
        "groups": [0],
        "enabled": True,
    }
    return api("POST", endpoint, payload=payload)


def _list_add_local(typ, domains, regex, wildcard, init_args=None):
    args = init_args or []
    kind = None
    if regex:
        kind = "regex"
    elif wildcard:
        kind = "wild"
    cmd = typ
    if kind:
        if typ == "allow":
            cmd = f"--allow-{kind}"
        else:
            cmd = f"--{kind}"
    return _pihole(cmd, args + domains)


def blacklist(domains, regex=False, wildcard=False, now=True):
    r"""
    Add domains to PiHole's blacklists.

    CLI Example:

    .. code-block:: bash

        salt '*' pihole.blacklist specific.domain.com
        salt '*' pihole.blacklist ads.com wildcard=true
        salt '*' pihole.blacklist '(ads|tracking)\.site\.io' regex=true

    domains
        Single domain or list of domains to add to the blacklist.

    regex
        Whether the domains should be interpreted as regular expressions.
        Defaults to False. Cannot be combined with wildcard.

    wildcard
        Whether all subdomains should be matched as well. Defaults to False.
        Cannot be combined with regex.

    now
        Whether to reload pihole-FTL after the operation. Defaults to True.
    """
    if regex and wildcard:
        raise SaltInvocationError(
            "`regex` and `wildcard` params are mutually exclusive."
        )
    if not now:
        log.warning(
            "PiHole v6+ does not expose the --noreload parameter, ignoring now=False"
        )

    if not isinstance(domains, list):
        domains = [domains]

    return (
        _try_funcs((_list_add_api, _list_add_local), "deny", domains, regex, wildcard)
        or True
    )


def blacklist_clear(now=True):  # pylint: disable=unused-argument
    """
    Clear all blacklist entries (``pihole blacklist --nuke``).

    CLI Example:

    .. code-block:: bash

        salt '*' pihole.blacklist_clear
    """
    # FIXME: This is not exposed directly
    #        Possibly use /domains:batchDelete after listing
    raise NotImplementedError(
        "PiHole v6 does not expose this directly, need implementation"
    )


def _list_rm_api(typ, domains, regex, wildcard, **_):
    kind = "exact"
    if regex:
        kind = "regex"
    elif wildcard:
        kind = "regex"
        domains = [_domain_to_wildcard(domain) for domain in domains]

    payload = [{"item": domain, "type": typ, "kind": kind} for domain in domains]
    return api("POST", "domains:batchDelete", payload=payload) or True


def blacklist_rm(domains, regex=False, wildcard=False, now=True):
    r"""
    Remove domains from PiHole's blacklists.

    CLI Example:

    .. code-block:: bash

        salt '*' pihole.blacklist_rm specific.domain.com
        salt '*' pihole.blacklist_rm ads.com wildcard=true
        salt '*' pihole.blacklist_rm '(ads|tracking)\.site\.io' regex=true

    domains
        Single domain or list of domains to remove from the blacklist.

    regex
        Whether the domains should be interpreted as regular expressions.
        Defaults to False. Cannot be combined with wildcard.

    wildcard
        Whether all subdomains should be matched as well. Defaults to False.
        Cannot be combined with regex.

    now
        Whether to reload pihole-FTL after the operation. Defaults to True.
    """
    if regex and wildcard:
        raise SaltInvocationError(
            "`regex` and `wildcard` params are mutually exclusive."
        )
    if not now:
        log.warning(
            "PiHole v6+ does not expose the --noreload parameter, ignoring now=False"
        )

    if not isinstance(domains, list):
        domains = [domains]

    return (
        _try_funcs(
            (_list_rm_api, _list_add_local),
            "deny",
            domains,
            regex,
            wildcard,
            init_args=["remove"],
        )
        or True
    )


VALID_DESCRIPTION_FIELDS = (
    "allowed",
    "default",
    "description",
    "flags",
    "modified",
    "type",
    "value",
)


@_needs_api
def config_describe(sub=None, fields=None, keep_single_key=False):
    """
    Describe a single config or a tree of configurations.

    CLI Example:

    .. code-block:: bash

        salt '*' pihole.config_describe dns.hosts
        salt '*' pihole.config_describe dns

    sub
        Subpath to query, delimited by dots. Optional.

    fields
        List of fields to include in the description.
        Available: allowed, default, description, flags, modified, type, value
        Defaults to ``[description]``. Can be specified as a comma-separated list (string).

    keep_single_key
        When the query is for a singular configuration item, this function
        returns the requested values only. Set this to true to disable special behavior,
        i.e. return a mapping of a single key to its requested values like for multiple ones.
    """
    fields = fields or ["description"]
    if not isinstance(fields, list):
        fields = fields.split(",")
    if not set(fields).issubset(VALID_DESCRIPTION_FIELDS):
        unknown = set(fields).difference(VALID_DESCRIPTION_FIELDS)
        raise SaltInvocationError(
            f"Invalid field spec. Unknown fields: {', '.join(unknown)}"
        )
    res = config_get(sub, detailed=True)
    ret = {}

    def _render_description(item, parents=None):
        parents = parents or []
        if "description" in item and "value" in item:
            rendered = {field: item[field] for field in fields}
            if len(rendered) == 1:
                rendered = rendered[fields[0]]
            ret[".".join(parents)] = rendered
            return
        for key, val in item.items():
            _render_description(val, parents + [key])

    parents = sub.split(".") if sub is not None else []
    _render_description(res, parents)
    if not keep_single_key and len(ret) == 1:
        return ret[next(iter(ret))]
    return ret


def _config_get_api(sub, detailed):
    path = ["config"]
    payload = {}
    if sub:
        path += sub.strip(".").split(".")
    if detailed:
        payload["detailed"] = True
    endpoint = "/".join(path)
    res = api("GET", endpoint, payload=payload)

    for part in path:
        res = res[part]
    return res


@_needs_toml
def _config_get_local(sub, detailed):
    if detailed:
        raise CommandExecutionError(
            "Cannot return detailed config information with CLI, only with API"
        )
    if not PIHOLE_TOML.exists():
        return {}
    data = toml_load(PIHOLE_TOML)
    if not sub:
        return data
    return salt.utils.data.traverse_dict_and_list(data, sub, delimiter=".")


def config_get(sub=None, detailed=False):
    """
    Query the complete configuration or a subpath of it.

    CLI Example:

    .. code-block:: bash

        salt '*' pihole.config_get
        salt '*' pihole.config_get dns.hosts

    sub
        Subpath to query, delimited by dots. Optional.

    detailed
        Return detailed information about the configuration.
        Defaults to false.
    """
    return _try_funcs((_config_get_api, _config_get_local), sub, detailed)


def config_reset(conf):
    """
    Reset a subpath configuration to its default value.

    CLI Example:

    .. code-block:: bash

        salt '*' pihole.config_reset dns.expandHosts

    conf
        Subpath to reset, delimited by dots.
    """
    inspect = config_describe(conf, ["default", "modified"], keep_single_key=True)
    if len(inspect) != 1:
        # We could do it, but this seems dangerous.
        raise CommandExecutionError(
            "Cannot reset a tree of configuration values. Ensure you're specifying a single configuration entry."
        )
    if not inspect[conf]["modified"]:
        return False
    return config_set(conf, inspect[conf]["default"])


@_needs_toml
def _write_pihole_toml(config):
    out = toml_dumps(config)
    __salt__["file.write"](str(PIHOLE_TOML), *out.splitlines())


def _config_set_api(conf, val):
    param = {}
    salt.utils.dictupdate.set_dict_key_value(param, conf, val, delimiter=".")
    res = api("PATCH", "config", payload={"config": param})
    return res


@_needs_toml
def _config_set_local(conf, val):
    cur = _config_get_local(None, False)
    salt.utils.dictupdate.set_dict_key_value(cur, conf, val, delimiter=".")
    _write_pihole_toml(cur)
    # The API returns the whole new config as well
    return cur


def config_set(conf, val):
    """
    Set a subpath configuration.

    CLI Example:

    .. code-block:: bash

        salt '*' pihole.config_set dns.expandHosts true

    conf
        Subpath to set, delimited by dots.

    val
        Value to set the config to.
    """
    return _try_funcs((_config_set_api, _config_set_local), conf, val) or True


def _config_update_api(config):
    return api("PATCH", "config", payload={"config": config})


@_needs_toml
def _config_update_local(config):
    # Making the config read-only before would still write the whole config
    cur = _config_get_local(None, False)
    upd = salt.utils.dictupdate.merge_recurse(cur, config)
    _write_pihole_toml(upd)
    # The API returns the whole new config as well
    return upd


def _filter_none(data):
    return {
        k: _filter_none(v) if isinstance(v, Mapping) else v
        for k, v in data.items()
        if v is not None
    }


def config_update(config):
    """
    Update the whole configuration.
    Values set to ``null``/``None`` are ignored.

    CLI Example:

    .. code-block:: bash

        salt '*' pihole.config_update '{dns: {expandHosts: true}, webserver: {port: 80or,443os, api: {app_sudo: true}}}'

    config
        The nested dictionary of pihole.toml configuration values.
    """
    return _try_funcs((_config_update_api, _config_update_local), _filter_none(config))


def _config_item_add_api(conf, item):
    path = ["config"]
    path += conf.strip(".").split(".")
    path.append(item)
    endpoint = "/".join(path)
    res = api("PUT", endpoint)
    return res or True


def _config_item_add_local(conf, item):
    cur = _config_get_local(conf, False)
    if not isinstance(cur, list):
        raise CommandExecutionError(
            f"Specified config {conf} is not a list, but a {type(cur)}"
        )
    # TODO: Unsure what the API does about duplicates
    cur.append(item)
    return _config_set_local(conf, cur)


def config_item_add(conf, item):
    """
    To a list of config items, add another one.

    CLI Example:

    .. code-block:: bash

        salt '*' pihole.config_item_add dns.hosts "1.2.3.4 foo.bar.baz"

    conf
        Subpath of the config item to add to, delimited by dots.

    item
        The item to add to the list.
    """
    return (
        _try_funcs((_config_item_add_api, _config_item_add_local), conf, item) or True
    )


def _config_item_rm_api(conf, item):
    path = ["config"]
    path += conf.strip(".").split(".")
    path.append(item)
    endpoint = "/".join(path)
    res = api("DELETE", endpoint)
    return res or True


def _config_item_rm_local(conf, item):
    cur = _config_get_local(conf, False)
    if not isinstance(cur, list):
        raise CommandExecutionError(
            f"Specified config {conf} is not a list, but a {type(cur)}"
        )
    # TODO: Unsure what the API does about duplicates
    cur.remove(item)
    return _config_set_local(conf, cur)


def config_item_rm(conf, item):
    """
    From a list of config items, delete one.

    CLI Example:

    .. code-block:: bash

        salt '*' pihole.config_item_rm dns.hosts "1.2.3.4 foo.bar.baz"

    conf
        Subpath of the config item to remove from, delimited by dots.

    item
        The item to remove from the list.
    """
    return _try_funcs((_config_item_rm_api, _config_item_rm_local), conf, item) or True


def custom_cname_add(domain, target, force=False, now=True):
    """
    Add a custom CNAME record to PiHole.

    CLI Example:

    .. code-block:: bash

        salt '*' pihole.custom_cname_add some.source.domain some.pihole.controlled.domain

    domain
        The domain the custom CNAME record is valid for.

    target
        The CNAME target domain. It needs to be in PiHole's cache or control.

    force
        If the domain already has a custom CNAME entry, this operation will fail.
        To update the entry, set force to True.

    now
        Whether to reload pihole-FTL after the operation. Defaults to True.
    """
    current = custom_cname_list(with_val=True)

    if domain in current:
        if not force:
            raise CommandExecutionError(
                f"A mapping for {domain} already exists. Set force=true to update it."
            )
        if current[domain].startswith(f"{domain},{target}"):
            return True
        config_item_rm("dns.cname_records", current[domain])

    res = config_item_add("dns.cname_records", f"{domain},{target}")
    if now:
        restartdns()
    return res or True


def custom_cname_list(by_target=False, with_val=False):
    """
    List all custom CNAME records.

    CLI Example:

    .. code-block:: bash

        salt '*' pihole.custom_cname_list

    by_target
        If the return dictionary should have the targets as keys.
        Defaults to False.

    with_val
        Values are the complete config value, not the target only.
        Defaults to false.
    """
    out = {}
    for cname in config_get("dns.cname_records"):
        src, tgt, *_ = cname.split(",")
        if by_target:
            if tgt not in out:
                out[tgt] = []
            out[tgt].append(cname if with_val else src)
        else:
            out[src] = cname if with_val else tgt
    return out


def custom_cname_remove(domain, target=None, now=True):
    """
    Remove a custom CNAME record from PiHole.

    CLI Example:

    .. code-block:: bash

        salt '*' pihole.custom_cname_remove some.source.domain

    domain
        The domain the custom CNAME record is valid for.

    target
        Optionally specify the CNAME target domain. This acts as a failsafe.
        If unspecified, the CNAME record will be removed regardless of target.

    now
        Whether to reload pihole-FTL after the operation. Defaults to True.
    """
    cnames = custom_cname_list(with_val=True)

    if domain not in cnames:
        raise CommandExecutionError(
            f"{domain} does not exist in PiHole custom CNAME config."
        )

    if target and not cnames[domain].startswith(f"{domain},{target}"):
        raise CommandExecutionError(f"{domain} does not map to {target}.")

    res = config_item_rm("dns.cname_records", cnames[domain])
    if now:
        restartdns()
    return res or True


def custom_dns_list(ip_keys=False, with_val=False):
    """
    List all custom A/AAAA records.

    CLI Example:

    .. code-block:: bash

        salt '*' pihole.custom_dns_list

    ip_keys
        If the return dictionary should have the target IPs as keys.
        Defaults to False.
    """
    out = {}

    for host in config_get("dns.hosts"):
        ip, domain = re.split(r"\s+", host)
        if ip_keys:
            if ip not in out:
                out[ip] = []
            out[ip].append(host if with_val else domain)
        else:
            out[domain] = host if with_val else ip

    return out


def custom_dns_add(domain, ip, force=False, now=True):
    """
    Add a custom A/AAAA record to PiHole.

    CLI Example:

    .. code-block:: bash

        salt '*' pihole.custom_dns_add my.local.domain 10.1.0.1

    domain
        The domain the custom A/AAAA record is valid for.

    ip
        The IP address the lookup should resolve to.

    force
        If the domain already has a custom A/AAAA entry, this operation will fail.
        To update the entry, set force to True.

    now
        Whether to reload pihole-FTL after the operation. Defaults to True.
    """
    current = custom_dns_list(with_val=True)

    if domain in current:
        if not force:
            raise CommandExecutionError(
                f"A mapping for {domain} already exists. Set force=true to update it."
            )
        if current[domain] == f"{domain} {ip}":
            return True
        config_item_rm("dns.hosts", current[domain])

    res = config_item_add("dns.hosts", f"{domain} {ip}")
    if now:
        restartdns()
    return res or True


def custom_dns_remove(domain, ip=None, now=True):
    """
    Remove a custom A/AAAA record from PiHole.

    CLI Example:

    .. code-block:: bash

        salt '*' pihole.custom_dns_remove my.local.domain

    domain
        The domain the custom A/AAAA record is valid for.

    ip
        Optionally specify the IP address the entry resolved to. This acts as a failsafe.
        If unspecified, the A/AAAA record will be removed regardless of target IP address.

    now
        Whether to reload pihole-FTL after the operation. Defaults to True.
    """
    hosts = custom_dns_list(with_val=True)

    if domain not in hosts:
        raise CommandExecutionError(
            f"{domain} does not exist in PiHole custom hosts config."
        )

    if ip and not hosts[domain].startswith(f"{domain} {ip}"):
        raise CommandExecutionError(f"{domain} does not map to {ip}.")

    res = config_item_rm("dns.hosts", hosts[domain])
    if now:
        restartdns()
    return res or True


def _disable_api(interval):
    return api("POST", "dns/blocking", payload={"blocking": False, "timer": interval})


def _disable_local(interval):
    args = []
    if interval is not None:
        if str(interval)[-1] not in ["m", "s"]:
            interval = str(interval) + "s"
        args.append(interval)
    return _pihole("disable", args)


def disable(interval=None):
    """
    Disable all DNS filtering.

    CLI Example:

    .. code-block:: bash

        salt '*' pihole.disable 1m

    interval
        Optionally disable filtering only for a limited time interval. Recognizes
        "m"/"s" suffixes. If no suffix is passed, will default to seconds.
    """
    return _try_funcs((_disable_api, _disable_local), interval) or True


def _domainlist_list_api(types):
    if types == "all":
        # short circuit
        return [domain["domain"] for domain in api("GET", "domains")["domains"]]

    if not isinstance(types, list):
        types = [types]
    types = list(
        set("r" + typ[1:] if typ in ("wwhite", "wblack") else typ for typ in types)
    )
    res = []

    for domain in api("GET", "domains")["domains"]:
        if types == "all":
            res.append(domain["domain"])
            continue
        flt = "black" if domain["type"] == "deny" else "white"
        if domain["kind"] == "regex":
            flt = "r" + flt
        if flt in types:
            res.append(domain["domain"])

    return res


@_needs_sqlite
def _domainlist_list_local(types):
    query = "select `domain` from `domainlist`"

    if types != "all":
        if not isinstance(types, list):
            types = [types]
        types = [str(PH_DOMAINLIST_TYPES[f]) for f in types]
        query += " where `type` in ({})".format(",".join(types))

    return __salt__["sqlite3.fetch"](PH_GRAVITY_DB, query)


def domainlist_list(types="all"):
    """
    List all domains in PiHole's whitelist/blacklist.

    CLI Example:

    .. code-block:: bash

        salt '*' pihole.domainlist_list
        salt '*' pihole.domainlist_list [black, wblack]

    types
        Only show entries of a specific type. Valid types are:
        black (plain blacklist), rblack (regex blacklist, includes wildmatches),
        white (plain whitelist), rwhite (regex whitelist, includes wildmatches)
        Can be set to a single type or a list of types to filter for.
        Defaults to "all", which dumps all domains that have an entry
        in either the blacklist or whitelist.
    """
    return _try_funcs((_domainlist_list_api, _domainlist_list_local), types)


def _domainlist_count_api(domains, of_type):
    typ = None
    kind = None
    wild = False

    if not of_type:
        # short circuit
        return len(
            list(
                domain
                for domain in api("GET", "domains")["domains"]
                if domain["domain"] in domains
            )
        )

    if of_type.endswith("black"):
        typ = "deny"
        if of_type in ("rblack", "wblack"):
            kind = "regex"
            wild = of_type == "wblack"
        else:
            kind = "exact"
    else:
        typ = "allow"
        if of_type in ("rwhite", "wwhite"):
            kind = "regex"
            wild = of_type == "wwhite"
        else:
            kind = "exact"
    endpoint = f"domains/{typ}/{kind}"
    if wild:
        domains = [_domain_to_wildcard(domain) for domain in domains]
    return len(
        list(
            domain
            for domain in api("GET", endpoint)["domains"]
            if domain["domain"] in domains
        )
    )


def _domainlist_count_local(domains, of_type):
    # SQLITE_MAX_VARIABLE_NUMBER is 999 for sqlite < v3.32.0,
    # after 32766. This should be enough for our query, hence
    # no length check of domains list.

    query = (
        "select count(*) from `domainlist` where `domain` in ("
        + ",".join("?" * len(domains))
        + ")"
    )
    params = domains

    if of_type is not None:
        query += " and `type` = ?"
        if of_type in ["wblack", "wwhite"]:
            params = [_domain_to_wildcard(domain) for domain in domains]
        params.append(PH_DOMAINLIST_TYPES[of_type])

    # The official salt execution module does not support parameter substitution
    cur = _gravity_conn()
    cur.execute(query, params)
    return cur.fetchone()[0]


def domainlist_count(domains, of_type=None):
    """
    Count the number of specified domains that are present in the database.
    Mostly for internal use.

    CLI Example:

    .. code-block:: bash

        salt '*' pihole.domainlist_count my.blocked.domain black

    of_type
        Optionally filter for a specific type. Valid types are:
        black (plain blacklist), wblack (wildcard blacklist), rblack (regex blacklist),
        white (plain whitelist), wwhite (wildcard whitelist), rwhite (regex whitelist)
    """
    if not isinstance(domains, list):
        domains = [domains]

    return _try_funcs(
        (_domainlist_count_api, _domainlist_count_local), domains, of_type
    )


def enable(interval=None):
    """
    Enable DNS filtering.

    CLI Example:

    .. code-block:: bash

        salt '*' pihole.enable
    """
    args = []

    if interval is not None:
        if str(interval)[-1] not in ["m", "s"]:
            interval = str(interval) + "s"
        args.append(interval)

    return _try_funcs(
        (
            lambda: api(
                "POST", "dns/blocking", payload={"blocking": True, "timer": interval}
            ),
            lambda: _pihole("enable", args),
        )
    )


def _group_list_api(status):
    res = api("GET", "groups")["groups"]
    if status is not None:
        return [group["name"] for group in res if group["enabled"] is status]
    return [group["name"] for group in res]


@_needs_sqlite
def _group_list_local(status):
    query = "select `name` from `group`"

    if status is not None:
        query += " where `enabled` = " + str(int(bool(status)))

    # this actually requires sqlite as well
    res = __salt__["sqlite3.fetch"](PH_GRAVITY_DB, query)
    return [x[0] for x in res]


def group_list(status=None):
    """
    List PiHole groups.

    CLI Example:

    .. code-block:: bash

        salt '*' pihole.group_list

    status
        Optionally only show enabled (True) or disabled (False) groups.
    """
    return _try_funcs((_group_list_api, _group_list_local), status)


def _group_add_api(name, enabled, description):
    payload = {
        "name": name,
        "comment": description,
        "enabled": enabled,
    }
    return api("POST", "groups", payload=payload)


@_needs_sqlite
def _group_add_local(name, enabled, description):
    # The official salt execution module does not support parameter substitution
    cur = _gravity_conn()
    query = "insert into `group` (`name`, `enabled`, `description`) VALUES (?, ?, ?)"
    cur.execute(query, (name, enabled, description))


def group_add(name, enabled=True, description="Managed by Salt", now=True):
    """
    Add a group to PiHole.

    CLI Example:

    .. code-block:: bash

        salt '*' pihole.group_add children

    name
        The name of the group.

    enabled
        Whether the group should be added in enabled state. Defaults to True.

    description
        An optional description, defaults to "Managed by Salt".

    now
        Whether to reload pihole-FTL after the operation. Defaults to True.
    """

    if name in group_list():
        raise CommandExecutionError("The specified group is already present.")

    _try_funcs((_group_add_api, _group_add_local), name, enabled, description)

    if now:
        restartdns()
    return True


def _group_toggle_api(name, status):
    curr = api("GET", f"groups/{name}")["groups"][0]
    payload = {
        "name": name,
        "comment": curr["comment"],
        "enabled": status,
    }
    return api("PUT", f"groups/{name}", payload=payload)


@_needs_sqlite
def _group_toggle_local(name, status):
    status = str(int(status))
    cur = _gravity_conn()
    query = f"update `group` set `enabled` = {status} where `name` = ?"
    cur.execute(query, (name,))


def group_disable(name, now=True):
    """
    Disable a PiHole group.

    CLI Example:

    .. code-block:: bash

        salt '*' pihole.group_disable children

    name
        The name of the group.

    now
        Whether to reload pihole-FTL after the operation. Defaults to True.
    """

    if name not in group_list():
        raise CommandExecutionError("The specified group does not exist.")
    if name in group_list(False):
        raise CommandExecutionError("The specified group is already disabled.")

    _try_funcs((_group_toggle_api, _group_toggle_local), name, False)

    if now:
        restartdns()
    return True


def group_enable(name, now=True):
    """
    Enable a PiHole group.

    CLI Example:

    .. code-block:: bash

        salt '*' pihole.group_enable children

    name
        The name of the group.

    now
        Whether to reload pihole-FTL after the operation. Defaults to True.
    """

    if name not in group_list():
        raise CommandExecutionError("The specified group does not exist.")
    if name in group_list(True):
        raise CommandExecutionError("The specified group is already enabled.")

    _try_funcs((_group_toggle_api, _group_toggle_local), name, True)

    if now:
        restartdns()
    return True


def _group_remove_api(name):
    return api("DELETE", f"groups/{name}")


@_needs_sqlite
def _group_remove_local(name):
    # The official salt execution module does not support parameter substitution
    cur = _gravity_conn()
    query = "delete from `group` where `name` = ?"
    cur.execute(query, (name,))


@_needs_sqlite
def group_remove(name, now=True):
    """
    Remove a group from PiHole.

    CLI Example:

    .. code-block:: bash

        salt '*' pihole.group_remove children

    name
        The name of the group.

    now
        Whether to reload pihole-FTL after the operation. Defaults to True.
    """

    if name not in group_list():
        raise CommandExecutionError("The specified group does not exist.")

    _try_funcs((_group_remove_api, _group_remove_local), name)

    if now:
        restartdns()
    return True


def logging(enabled=True, flush=True):  # pylint: disable=unused-argument
    """
    Unsupported on PiHole v6+. Use the config options.
    """
    raise NotImplementedError("Unsupported on PiHole v6+. Use the config options.")


def password_api_set(new):
    """
    Set the API password.
    """
    return config_set("webserver.api.password", new)


def password_api_remove():
    """
    Remove the API password.
    """
    return config_set("webserver.api.password", "")


def password_api_verify(password):
    """
    Verify the API password.
    """
    if not HAS_HASH:
        raise CommandExecutionError(
            "Cannot verify password, missing pihole_pwhash util module"
        )
    pwhash = config_get("webserver.api.pwhash")
    try:
        return pihole_pwhash.verify(pwhash, password)
    except ValueError:
        # not set/wrongly set
        return False


def password_app_generate(to_path=None):
    """
    Generate a new app password.

    .. warning::
        Generating a new application password invalidates all currently active sessions.

    to_path
        Instead of returning the generated password, write it to this path.
    """
    res = api("GET", "auth/app")["app"]
    config_set("webserver.api.app_pwhash", res["hash"])
    if not to_path:
        return res["password"]
    __salt__["file.touch"](to_path)
    __salt__["file.set_mode"](to_path, "0600")
    __salt__["file.write"](to_path, res["password"])
    return True


def reloaddns():
    """
    Reload Pi-hole subsystems.
    Only update lists and flush cache, do not restart the DNS server.
    This is sufficient when the gravity database has been updated.
    Custom CNAME/A/AAAA records need a full restart. This is apparently
    not necessary for static DHCP leases.

    CLI Example:

    .. code-block:: bash

        salt '*' pihole.reloaddns
    """
    return _pihole("reloaddns")


def reloadlists():
    """
    Only update lists without flushing cache or restarting the DNS server.

    CLI Example:

    .. code-block:: bash

        salt '*' pihole.reloadlists
    """
    return _pihole("reloadlists")


def _restartdns_local():
    if not __salt__["service.available"](PIHOLE_SERVICE):
        raise RequirementUnsatisfied(RequirementType.CLI)
    return __salt__["service.restart"](PIHOLE_SERVICE)


def restartdns():
    """
    Restart Pi-hole subsystems.

    CLI Example:

    .. code-block:: bash

        salt '*' pihole.restartdns
    """
    return _try_funcs((lambda: api("POST", "action/restartdns"), _restartdns_local))


def status():
    """
    Run ``pihole status``.

    CLI Example:

    .. code-block:: bash

        salt '*' pihole.status
    """

    return _pihole("status")


def static_dhcp_list():
    """
    List all static DHCP entries.

    Currently, they cannot be managed with this module.

    CLI Example:

    .. code-block:: bash

        salt '*' pihole.static_dhcp_list
    """
    # TODO: config_get dhcp.hosts
    # Possible values are:
    #     Array of static leases each on in one of the following forms:
    #     "[<hwaddr>][,id:<client_id>|*][,set:<tag>][,tag:<tag>][,<ipaddr>][,<hostname>][,<lease_time>][,ignore]"
    raise NotImplementedError("This is not implemented yet for PiHole v6+.")

    # out = {}
    #
    # if not Path(PH_STATIC_DHCP).exists():
    #     return out
    #
    # parsed = __salt__["dnsmasq.get_config"](PH_STATIC_DHCP)
    # mappings = parsed.get("dhcp-host", [])
    # mappings = [mappings] if not isinstance(mappings, list) else mappings
    #
    # for m in mappings:
    #     mac, *conf = m.split(",")
    #     if len(conf) > 1:
    #         ip, host = conf
    #     elif salt.utils.network.is_ip(conf[0]):
    #         ip, host = conf[0], None
    #     else:
    #         ip, host = None, conf[0]
    #     out[mac] = {"host": host, "ip": ip}
    # return out


def update():
    """
    Update PiHole to the most recent version.

    CLI Example:

    .. code-block:: bash

        salt '*' pihole.update
    """

    return _pihole("updatePihole")


def update_check():
    """
    Check whether PiHole is at the most recent version.

    CLI Example:

    .. code-block:: bash

        salt '*' pihole.update_check
    """

    return "Everything is up to date!" in _pihole("updatePihole", ["--check-only"])


def update_gravity():
    """
    Update the list of ad-serving domains. (-> Sync from adlists).

    CLI Example:

    .. code-block:: bash

        salt '*' pihole.update_gravity
    """
    return (
        _try_funcs(
            (lambda: api("POST", "action/gravity"), lambda: _pihole("updateGravity"))
        )
        or True
    )


def _version_api():
    info = api("GET", "info/version")["version"]
    return {
        "core": info["core"]["local"]["version"],
        "ftl": info["ftl"]["local"]["version"],
        "web": info["web"]["local"]["version"],
    }


def _version_local():
    out = _pihole("version")

    core = re.findall(r"Core version is v([0-9\.]+)", out)[0]
    ftl = re.findall(r"FTL version is v([0-9\.]+)", out)[0]
    web = re.findall(r"Web version is v([0-9\.]+)", out)[0]

    return {"core": core, "ftl": ftl, "web": web}


def version():
    """
    Return the versions of PiHole's subsystems.

    CLI Example:

    .. code-block:: bash

        salt '*' pihole.version
    """
    return _try_funcs((_version_api, _version_local))


def whitelist(domains, regex=False, wildcard=False, now=True):
    r"""
    Add domains to PiHole's whitelists.

    CLI Example:

    .. code-block:: bash

        salt '*' pihole.whitelist specific.domain.com
        salt '*' pihole.whitelist ads.com wildcard=true
        salt '*' pihole.whitelist '(ads|tracking)\.site\.io' regex=true

    domains
        Single domain or list of domains to add to the whitelist.

    regex
        Whether the domains should be interpreted as regular expressions.
        Defaults to False. Cannot be combined with wildcard.

    wildcard
        Whether all subdomains should be matched as well. Defaults to False.
        Cannot be combined with regex.

    now
        Whether to reload pihole-FTL after the operation. Defaults to True.
    """
    if regex and wildcard:
        raise SaltInvocationError(
            "`regex` and `wildcard` params are mutually exclusive."
        )
    if not now:
        log.warning(
            "PiHole v6+ does not expose the --noreload parameter, ignoring now=False"
        )

    if not isinstance(domains, list):
        domains = [domains]

    return (
        _try_funcs((_list_add_api, _list_add_local), "allow", domains, regex, wildcard)
        or True
    )


def whitelist_clear(now=True):  # pylint: disable=unused-argument
    """
    Clear all whitelist entries (``pihole whitelist --nuke``).

    CLI Example:

    .. code-block:: bash

        salt '*' pihole.whitelist_clear
    """
    # FIXME: This is not exposed directly
    #        Possibly use /domains:batchDelete after listing
    raise NotImplementedError(
        "PiHole v6 does not expose this directly, need implementation"
    )


def whitelist_rm(domains, regex=False, wildcard=False, now=True):
    r"""
    Remove domains from PiHole's whitelists.

    CLI Example:

    .. code-block:: bash

        salt '*' pihole.whitelist_rm specific.domain.com
        salt '*' pihole.whitelist_rm ads.com wildcard=true
        salt '*' pihole.whitelist_rm '(ads|tracking)\.site\.io' regex=true

    domains
        Single domain or list of domains to remove from the whitelist.

    regex
        Whether the domains should be interpreted as regular expressions.
        Defaults to False. Cannot be combined with wildcard.

    wildcard
        Whether all subdomains should be matched as well. Defaults to False.
        Cannot be combined with regex.

    now
        Whether to reload pihole-FTL after the operation. Defaults to True.
    """
    if regex and wildcard:
        raise SaltInvocationError(
            "`regex` and `wildcard` params are mutually exclusive."
        )
    if not now:
        log.warning(
            "PiHole v6+ does not expose the --noreload parameter, ignoring now=False"
        )

    if not isinstance(domains, list):
        domains = [domains]

    return (
        _try_funcs(
            (_list_rm_api, _list_add_local),
            "allow",
            domains,
            regex,
            wildcard,
            init_args=["remove"],
        )
        or True
    )

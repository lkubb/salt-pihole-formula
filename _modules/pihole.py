"""
PiHole salt execution module
============================

Manage PiHole with Salt.

For some functions, this module needs the sqlite3 library.
"""

import logging
import re
import shlex
from functools import wraps
from pathlib import Path

import salt.utils.decorators as decorators
import salt.utils.path
from salt.exceptions import CommandExecutionError, SaltInvocationError

try:
    import sqlite3

    HAS_SQLITE3 = True
except ImportError:
    HAS_SQLITE3 = False

log = logging.getLogger(__name__)
__virtualname__ = "pihole"


# PiHole actually mostly hardcodes those currently
PH_CUSTOM_DNS = "/etc/pihole/custom.list"
PH_CUSTOM_CNAME = "/etc/dnsmasq.d/05-pihole-custom-cname.conf"
PH_GRAVITY_DB = "/etc/pihole/gravity.db"
PH_STATIC_DHCP = "/etc/dnsmasq.d/04-pihole-static-dhcp.conf"
PH_DOMAINLIST_TYPES = {
    "black": 1,
    "white": 0,
    "rblack": 3,
    "rwhite": 2,
    "wblack": 3,
    "wwhite": 2,
}


@decorators.memoize
def __which():
    return salt.utils.path.which("pihole")


def __virtual__():
    if __which():
        return __virtualname__
    return (False, "Could not find `pihole` in your $PATH.")


def _needs_sqlite(func):
    @wraps(func)
    def needs_sqlite(*args, **kwargs):
        if not HAS_SQLITE3:
            raise SaltInvocationError(
                "Running this function requires sqlite3 library. Make sure it is importable by Salt."
            )
        return func(*args, **kwargs)

    return needs_sqlite


def _gravity_conn():
    """
    Return a Cursor object for the PiHole gravity database.
    """

    con = sqlite3.connect(PH_GRAVITY_DB, isolation_level=None)
    cur = con.cursor()
    return cur


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


def adlist_list(status=None):
    """
    List all registered adlists.

    CLI Example:

    .. code-block:: bash

        salt '*' pihole.adlist_list

    status
        Optionally only show enabled (True) or disabled (False) lists.
    """

    query = "select `address` from `adlist`"

    if status is not None:
        query += " where `enabled` = " + str(int(bool(status)))

    # this actually requires sqlite as well
    out = __salt__["sqlite3.fetch"](PH_GRAVITY_DB, query)
    return [x[0] for x in out]


@_needs_sqlite
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

    # The official salt execution module does not support parameter substitution
    cur = _gravity_conn()
    query = "insert into `adlist` (`address`, `enabled`, `comment`) VALUES (?, ?, ?)"
    cur.execute(query, (url, enabled, comment))

    if now:
        restartdns()
    return True


@_needs_sqlite
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

    # The official salt execution module does not support parameter substitution
    cur = _gravity_conn()
    query = "update `adlist` set `enabled` = 0 where `address` = ?"
    cur.execute(query, (url,))

    if now:
        restartdns()
    return True


@_needs_sqlite
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

    # The official salt execution module does not support parameter substitution
    cur = _gravity_conn()
    query = "update `adlist` set `enabled` = 1 where `address` = ?"
    cur.execute(query, (url,))

    if now:
        restartdns()
    return True


@_needs_sqlite
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

    # The official salt execution module does not support parameter substitution
    cur = _gravity_conn()
    query = "delete from `adlist` where `address` = ?"
    cur.execute(query, (url,))

    if now:
        restartdns()
    return True


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


def arpflush():
    """
    Flush information stored in Pi-hole's network tables.

    CLI Example:

    .. code-block:: bash

        salt '*' pihole.arpflush
    """

    return _pihole("arpflush")


def blacklist(domains, regex=False, wildcard=False, now=True, init_args=None):
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

    init_args
        List of arguments that should be present before adding the ones relevant
        to this function. Mostly for internal use.
    """

    args = init_args or []
    cmd = "blacklist"

    if regex and wildcard:
        raise SaltInvocationError(
            "`regex` and `wildcard` params are mutually exclusive."
        )

    if regex:
        cmd = "regex"
    elif wildcard:
        cmd = "wildcard"

    if not now:
        args.append("--noreload")

    if not isinstance(domains, list):
        domains = [domains]

    return _pihole(cmd, args + domains)


def blacklist_clear(now=True):
    """
    Clear all blacklist entries (``pihole blacklist --nuke``).

    CLI Example:

    .. code-block:: bash

        salt '*' pihole.blacklist_clear
    """

    args = ["--nuke"]

    if not now:
        args.append("--noreload")

    return _pihole("blacklist", args)


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

    args = ["--delmode"]
    return blacklist(domains, regex=regex, wildcard=wildcard, now=now, init_args=args)


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

    # There is ``pihole admin addcustomcname <domain> <target> <reload>`` as well.
    update = False
    current = custom_cname_list()

    if domain in current:
        if not force:
            raise CommandExecutionError(
                f"A mapping for {domain} already exists. Set force=true to update it."
            )
        if current[domain] == target:
            return True
        update = True

    if update:
        res = __salt__["file.replace"](
            PH_CUSTOM_CNAME,
            pattern=r"^cname={},{}$".format(
                re.escape(domain), re.escape(current[domain])
            ),
            repl=f"cname={domain},{target}",
            # dnsmasq reads all files, not only those with .conf
            backup=False,
        )
    else:
        if not Path(PH_CUSTOM_CNAME).exists():
            Path(PH_CUSTOM_CNAME).touch()
        res = __salt__["file.append"](PH_CUSTOM_CNAME, f"cname={domain},{target}\n")

    if not res:
        raise CommandExecutionError(
            "No changes were reported, even though there should be."
        )
    if now:
        restartdns()
    return True


def custom_cname_list(by_target=False):
    """
    List all custom CNAME records.

    CLI Example:

    .. code-block:: bash

        salt '*' pihole.custom_cname_list

    by_target
        If the return dictionary should have the targets as keys.
        Defaults to False.
    """

    out = {}

    if not Path(PH_CUSTOM_CNAME).exists():
        return out

    parsed = __salt__["dnsmasq.get_config"](PH_CUSTOM_CNAME)
    cnames = parsed.get("cname", [])
    cnames = [cnames] if not isinstance(cnames, list) else cnames

    for cname in cnames:
        src, tgt = cname.split(",")
        if by_target:
            if tgt not in out:
                out[tgt] = []
            out[tgt].append(src)
        else:
            out[src] = tgt
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

    # There is ``pihole admin removecustomcname <domain> <target> <reload>`` as well.
    cnames = custom_cname_list()

    if domain not in cnames:
        raise CommandExecutionError(
            f"{domain} does not exist in PiHole custom CNAME file."
        )

    if target and cnames[domain] != target:
        raise CommandExecutionError(f"{domain} does not map to {target}.")

    res = __salt__["file.replace"](
        PH_CUSTOM_CNAME,
        pattern=r"^cname={},{}$".format(
            re.escape(domain), re.escape(target or cnames[domain])
        ),
        repl="",
        # dnsmasq reads all files, not only those with .conf
        backup=False,
    )

    if not res:
        raise CommandExecutionError(
            "No changes were reported, even though there should be."
        )
    if now:
        restartdns()
    return True


def custom_dns_list(ip_keys=False):
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

    if not Path(PH_CUSTOM_DNS).exists():
        return out

    parsed = __salt__["dnsutil.parse_hosts"](PH_CUSTOM_DNS)
    if ip_keys:
        return parsed

    for ip, domains in parsed.items():
        for domain in domains:
            out[domain] = ip
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

    # There is ``pihole admin addcustomdns <ip> <domain> <reload>`` as well.
    update = False
    current = custom_dns_list()

    if domain in current:
        if not force:
            raise CommandExecutionError(
                f"A mapping for {domain} already exists. Set force=true to update it."
            )
        if current[domain] == ip:
            return True
        update = True

    if update:
        res = __salt__["file.replace"](
            PH_CUSTOM_DNS,
            pattern=r"^{} {}$".format(re.escape(current[domain]), re.escape(domain)),
            repl=f"{ip} {domain}",
            backup=False,
        )
    else:
        if not Path(PH_CUSTOM_DNS).exists():
            Path(PH_CUSTOM_DNS).touch()
        res = __salt__["file.append"](PH_CUSTOM_DNS, f"{ip} {domain}\n")

    if not res:
        raise CommandExecutionError(
            "No changes were reported, even though there should be."
        )
    if now:
        restartdns()
    return True


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

    # There is ``pihole admin removecustomdns <ip> <domain> <reload>`` as well.
    hosts = custom_dns_list()

    if domain not in hosts:
        raise CommandExecutionError(
            f"{domain} does not exist in PiHole local DNS file."
        )

    if ip and hosts[domain] != ip:
        raise CommandExecutionError(f"{domain} does not map to {ip}.")

    res = __salt__["file.replace"](
        PH_CUSTOM_DNS,
        pattern=r"^{} {}\n$".format(re.escape(ip or hosts[domain]), re.escape(domain)),
        repl="",
        backup=False,
    )

    if not res:
        raise CommandExecutionError(
            "No changes were reported, even though there should be."
        )
    if now:
        restartdns()
    return True


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
    args = []

    if interval is not None:
        if str(interval)[-1] not in ["m", "s"]:
            interval = str(interval) + "s"
        args.append(interval)

    return _pihole("disable", args)


def domainlist_list(types="all"):
    """
    List all domains in PiHole's whitelist/blacklist.

    CLI Example:

    .. code-block:: bash

        salt '*' pihole.domainlist_list
        salt '*' pihole.domainlist_list [black, wblack]

    types
        Only show entries of a specific type. Valid types are:
        black (plain blacklist), wblack (wildcard blacklist), rblack (regex blacklist),
        white (plain whitelist), wwhite (wildcard whitelist), rwhite (regex whitelist)
        Can be set to a single type or a list of types to filter for.
        Defaults to "all", which dumps all domains that have an entry
        in either the blacklist or whitelist.
    """
    query = "select `domain` from `domainlist`"

    if "all" != types:
        if not isinstance(types, list):
            types = [types]
        types = [str(PH_DOMAINLIST_TYPES[f]) for f in types]
        query += " where `type` in ({})".format(",".join(types))

    return __salt__["sqlite3.fetch"](PH_GRAVITY_DB, query)


@_needs_sqlite
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


def enable():
    """
    Enable DNS filtering.

    CLI Example:

    .. code-block:: bash

        salt '*' pihole.enable
    """
    return _pihole("enable")


def group_list(status=None):
    """
    List PiHole groups.

    CLI Example:

    .. code-block:: bash

        salt '*' pihole.group_list

    status
        Optionally only show enabled (True) or disabled (False) groups.
    """

    query = "select `name` from `group`"

    if status is not None:
        query += " where `enabled` = " + str(int(bool(status)))

    # this actually requires sqlite as well
    res = __salt__["sqlite3.fetch"](PH_GRAVITY_DB, query)
    return [x[0] for x in res]


@_needs_sqlite
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

    # The official salt execution module does not support parameter substitution
    cur = _gravity_conn()
    query = "insert into `group` (`name`, `enabled`, `description`) VALUES (?, ?, ?)"
    cur.execute(query, (name, enabled, description))

    if now:
        restartdns()
    return True


@_needs_sqlite
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

    # The official salt execution module does not support parameter substitution
    cur = _gravity_conn()
    query = "update `group` set `enabled` = 0 where `name` = ?"
    cur.execute(query, (name,))

    if now:
        restartdns()
    return True


@_needs_sqlite
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

    # The official salt execution module does not support parameter substitution
    cur = _gravity_conn()
    query = "update `group` set `enabled` = 1 where `name` = ?"
    cur.execute(query, (name,))

    if now:
        restartdns()
    return True


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

    # The official salt execution module does not support parameter substitution
    cur = _gravity_conn()
    query = "delete from `group` where `name` = ?"
    cur.execute(query, (name,))

    if now:
        restartdns()
    return True


def logging(enabled=True, flush=True):
    """
    Manage PiHole logging status.

    CLI Example:

    .. code-block:: bash

        salt '*' pihole.logging false

    enabled
        Whether to enable or disable logging. Defaults to True.

    flush
        When enabled is False, whether to flush the log at
        ``/var/log/pihole/pihole.log``. Defaults to True.
    """

    args = ["on" if enabled else "off"]

    if not enabled and not flush:
        args.append("noflush")

    return _pihole("logging", args)


def restartdns(reload_only=False, reload_lists_only=False):
    """
    Restart Pi-hole subsystems.

    CLI Example:

    .. code-block:: bash

        salt '*' pihole.restartdns

    reload_only
        Only update lists and flush cache, do not restart the DNS server.
        This is sufficient when the gravity database has been updated.
        Custom CNAME/A/AAAA records need a full restart. This is apparently
        not necessary for static DHCP leases.
        Defaults to False.

    reload_lists_only
        Only update lists without flushing cache or restarting the DNS server.
        Defaults to False.
    """

    args = []

    if reload_only:
        args = ["reload"]
    elif reload_lists_only:
        args = ["reload-lists"]

    return _pihole("restartdns", args)


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

    # @TODO: ``pihole addstaticdhcp <mac> <ip=noip> <hostname=nohost>``
    # would need validation, as custom CNAME/A/AAAA do as well
    out = {}

    if not Path(PH_STATIC_DHCP).exists():
        return out

    parsed = __salt__["dnsmasq.get_config"](PH_STATIC_DHCP)
    mappings = parsed.get("dhcp-host", [])
    mappings = [mappings] if not isinstance(mappings, list) else mappings

    for m in mappingss:
        mac, *conf = m.split(",")
        if len(conf) > 1:
            ip, host = conf
        elif salt.utils.network.is_ip(conf[0]):
            ip, host = conf[0], None
        else:
            ip, host = None, conf[0]
        out[mac] = {"host": host, "ip": ip}
    return out


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

    return _pihole("updateGravity")


def version():
    """
    Return the versions of PiHole's subsystems.

    CLI Example:

    .. code-block:: bash

        salt '*' pihole.version
    """

    out = _pihole("version")

    admin = re.findall(r"AdminLTE version is v([0-9\.]+)", out)[0]
    ftl = re.findall(r"FTL version is v([0-9\.]+)", out)[0]
    ph = re.findall(r"Pi-hole version is v([0-9\.]+)", out)[0]

    return {"admin": admin, "ftl": ftl, "pihole": ph}


def whitelist(domains, regex=False, wildcard=False, now=True, init_args=None):
    r"""
    Add domains to PiHole's whitelists.

    CLI Example:

    .. code-block:: bash

        salt '*' pihole.whitelist specific.domain.com
        salt '*' pihole.whitelist surely-no.ads.com wildcard=true
        salt '*' pihole.whitelist '(blog|www)\.site\.io' regex=true

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

    init_args
        List of arguments that should be present before adding the ones relevant
        to this function. Mostly for internal use.
    """

    args = init_args or []
    cmd = "whitelist"

    if not now:
        args.append("--noreload")

    if regex and wildcard:
        raise SaltInvocationError(
            "`regex` and `wildcard` params are mutually exclusive."
        )

    if regex:
        cmd = "--white-regex"
    elif wildcard:
        cmd = "--white-wild"

    if not isinstance(domains, list):
        domains = [domains]

    return _pihole(cmd, args + domains)


def whitelist_clear(now=True):
    """
    Clear all whitelist entries (``pihole whitelist --nuke``).

    CLI Example:

    .. code-block:: bash

        salt '*' pihole.whitelist_clear
    """
    args = ["--nuke"]

    if not now:
        args.append("--noreload")

    return _pihole("whitelist", args)


def whitelist_rm(domains, regex=False, wildcard=False, now=True):
    r"""
    Remove domains from PiHole's whitelists.

    CLI Example:

    .. code-block:: bash

        salt '*' pihole.whitelist_rm specific.domain.com
        salt '*' pihole.whitelist_rm surely-no.ads.com wildcard=true
        salt '*' pihole.whitelist_rm '(blog|www)\.site\.io' regex=true

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

    args = ["--delmode"]
    return whitelist(domains, regex=regex, wildcard=wildcard, now=now, init_args=args)

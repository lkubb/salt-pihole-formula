"""
PiHole salt state module
========================

Manage PiHole with Salt.
"""

import logging
from collections.abc import Mapping

from salt.exceptions import CommandExecutionError, SaltInvocationError
from salt.utils.dictdiffer import recursive_diff

log = logging.getLogger(__name__)


def adlist(name, enabled=True, comment="Managed by Salt"):
    """
    Make sure an adlist is present in PiHole.

    name
        The address of the adlist.

    enabled
        Whether the adlist should be enabled. Defaults to True.

    comment
        An optional comment, defaults to "Managed by Salt".
        This will only apply when the list is added for the first time.
    """

    ret = {"name": name, "result": True, "comment": [], "changes": {}}
    verb = "enable" if enabled else "disable"

    try:
        is_installed = name in __salt__["pihole.adlist_list"]()
        is_enabled = (
            name in __salt__["pihole.adlist_list"](True) if is_installed else False
        )

        if is_installed and is_enabled == enabled:
            ret["comment"] = f"Adlist is already present and {verb}d"
            return ret

        if not is_installed:
            if __opts__["test"]:
                ret["result"] = None
                ret["comment"] = f"Adlist would have been installed in {verb}d state."
            else:
                __salt__["pihole.adlist_add"](
                    name, enabled=enabled, comment=comment, now=False
                )
                ret["comment"] = f"Adlist has been installed in {verb}d state."
            ret["changes"]["installed"] = name
        else:
            if __opts__["test"]:
                ret["result"] = None
                ret["comment"] = f"Adlist would have been {verb}d."
            else:
                __salt__[f"pihole.adlist_{verb}"](name, now=False)
                ret["comment"] = f"Adlist has been {verb}d."
            ret["changes"][f"{verb}d"] = name

        if __opts__["test"]:
            return ret

        is_installed_now = name in __salt__["pihole.adlist_list"]()
        is_enabled_now = (
            name in __salt__["pihole.adlist_list"](True) if is_installed_now else False
        )

        if not is_installed_now:
            ret["result"] = False
            ret["comment"] = [
                "There were no errors, but the adlist is still not present."
            ]
            ret["changes"] = {}
        elif not is_enabled_now == enabled:
            ret["result"] = False
            ret["comment"] = [
                f"There were no errors, but the adlist is still not {verb}d."
            ]
            ret["changes"] = {}

    except (CommandExecutionError, SaltInvocationError) as e:
        ret["result"] = False
        ret["comment"].append(str(e))

    return ret


def adlist_absent(name):
    """
    Make sure an adlist is absent from PiHole.

    name
        The address of the adlist.
    """

    ret = {"name": name, "result": True, "comment": [], "changes": {}}

    try:
        if name not in __salt__["pihole.adlist_list"]():
            ret["comment"] = "Adlist is already absent."
            return ret

        ret["changes"]["removed"] = name

        if __opts__["test"]:
            ret["result"] = None
            ret["comment"] = "Adlist would have been removed."
            return ret

        __salt__["pihole.adlist_remove"](name, now=False)
        ret["comment"] = "Adlist has been removed."

        if name in __salt__["pihole.adlist_list"]():
            ret["result"] = False
            ret["comment"] = "There were no errors, but the adlist is still present."
            ret["changes"] = {}

    except (CommandExecutionError, SaltInvocationError) as e:
        ret["result"] = False
        ret["comment"] = str(e)
        ret["changes"] = {}

    return ret


def api_password_managed(name=None, pillar=None, password=None):
    """
    Make sure the API password is set as specified.
    If no password is specified, will generate a random
    one if none has been set to initialize it.

    .. hint::
        You can still reset it to a chosen one afterwards or pass
        the empty string ("") to ``password`` to remove it.

    name
        Irrelevant, only included for technical reasons.

    pillar
        A pillar path to retrieve the password from.
        Recommended since it avoids unnecessary cache writes.

    value
        The plaintext password. Not recommended, use ``pillar`` instead.
    """
    ret = {
        "name": name,
        "result": True,
        "comment": "The API password is already set as specified",
        "changes": {},
    }

    randomized = False

    try:
        if pillar:
            password = __salt__["pillar.get"](pillar)
        elif password is not None:
            pass
        else:
            password, randomized = (
                __salt__["random.get_str"](32, punctuation=False),
                True,
            )

        if password == "":
            cur = __salt__["pihole.config_get"]("webserver.api.pwhash")
            if cur == password:
                return ret
            ret["changes"]["added"] = True
        elif randomized:
            if __salt__["pihole.config_get"]("webserver.api.pwhash") != "":
                ret["comment"] = (
                    "API password has already been initialized, no password specified"
                )
            ret["changes"]["randomized"] = True
        else:
            if __salt__["pihole.password_api_verify"](password):
                return ret
            ret["changes"]["replaced"] = True
        if __opts__["test"]:
            ret["result"] = None
            ret["comment"] = (
                "Would have " + next(iter(ret["changes"])) + " the app password"
            )
            return ret
        __salt__["pihole.password_api_set"](password)
        ret["comment"] = next(iter(ret["changes"])).capitalize() + " the app password"
    except (CommandExecutionError, SaltInvocationError) as err:
        ret["result"] = False
        ret["comment"] = str(err)
        ret["changes"] = {}

    return ret


def blacklist(name=None, domains=None, regex=False, wildcard=False):
    """
    Make sure domains are present in PiHole's blacklists.

    name
        Single domain that should be present in the blacklist.
        You can specify multiple in ``domains``, this is ignored then.

    domains
        Single domain or list of domains that should be present in the blacklist.

    regex
        Whether the domains should be interpreted as regular expressions.
        Defaults to False. Cannot be combined with wildcard.

    wildcard
        Whether all subdomains should be matched as well. Defaults to False.
        Cannot be combined with regex.
    """

    return _domainlist_present(
        name, domains=domains, regex=regex, wildcard=wildcard, blacklist=True
    )


def blacklist_absent(name=None, domains=None, regex=False, wildcard=False):
    """
    Make sure domains are absent from PiHole's blacklists.

    name
        Single domain that should be absent from the blacklist.
        You can specify multiple in ``domains``, this is ignored then.

    domains
        Single domain or list of domains that should be absent from the blacklist.

    regex
        Whether the domains should be interpreted as regular expressions.
        Defaults to False. Cannot be combined with wildcard.

    wildcard
        Whether all subdomains should be matched as well. Defaults to False.
        Cannot be combined with regex.
    """

    return _domainlist_absent(
        name, domains=domains, regex=regex, wildcard=wildcard, blacklist=True
    )


def cname(name, target):
    """
    Make sure a custom CNAME record is present in PiHole.

    name
        The domain the custom CNAME record is valid for.

    target
        The CNAME target domain. It needs to be in PiHole's cache or control.
    """

    ret = {"name": name, "result": True, "comment": [], "changes": {}}

    try:
        cur = __salt__["pihole.custom_cname_list"]()
        is_present = name in cur
        is_correct = target == cur[name] if is_present else True

        if is_present and is_correct:
            ret["comment"] = (
                "The custom CNAME record is already present and points to the correct target."
            )
            return ret

        if not is_present:
            ret["changes"]["added"] = name
            if __opts__["test"]:
                ret["result"] = None
                ret["comment"] = "Custom CNAME record would have been created."
            else:
                __salt__["pihole.custom_cname_add"](name, target, now=False)
                ret["comment"] = "Custom CNAME record has been created."

        if not is_correct:
            ret["changes"]["updated"] = name
            if __opts__["test"]:
                ret["result"] = None
                ret["comment"] = "Custom CNAME record would have been updated."
            else:
                __salt__["pihole.custom_cname_add"](name, target, force=True, now=False)
                ret["comment"] = "Custom CNAME record has been updated."

        if __opts__["test"]:
            return ret

        cur_new = __salt__["pihole.custom_cname_list"]()

        if not is_present and name not in cur_new:
            ret["result"] = False
            ret["comment"] = "There were no errors, but the entry is still absent."
            ret["changes"] = {}
        elif not is_correct and cur_new[name] != target:
            ret["result"] = False
            ret["comment"] = "There were no errors, but the entry is still incorrect."
            ret["changes"] = {}

    except (CommandExecutionError, SaltInvocationError) as e:
        ret["result"] = False
        ret["comment"] = str(e)
        ret["changes"] = {}

    return ret


def cname_absent(name, target=None):
    """
    Make sure a custom CNAME record is absent from PiHole.

    name
        The domain the custom CNAME record is valid for.

    target
        The CNAME target domain. Acts as a failsafe. If unspecified,
        will remove the entry regardless of target.
    """

    ret = {"name": name, "result": True, "comment": [], "changes": {}}

    try:
        cur = __salt__["pihole.custom_cname_list"]()

        if name not in cur:
            ret["comment"] = "Custom CNAME record is already absent."
            return ret

        if target is not None and cur[name] != target:
            ret["comment"] = (
                "Custom CNAME record exists, but the target does not match. Skipping."
            )
            return ret

        ret["changes"]["removed"] = name

        if __opts__["test"]:
            ret["result"] = None
            ret["comment"] = "Custom CNAME record would have been removed."
            return ret

        __salt__["pihole.custom_cname_remove"](name, target, now=False)
        ret["comment"] = "Custom CNAME record has been removed."

        if name in __salt__["pihole.custom_cname_list"]():
            ret["result"] = False
            ret["comment"] = (
                "There were no errors, but the CNAME record is still present."
            )
            ret["changes"] = {}

    except (CommandExecutionError, SaltInvocationError) as e:
        ret["result"] = False
        ret["comment"] = str(e)
        ret["changes"] = {}

    return ret


def _filter_none(data):
    return {
        k: _filter_none(v) if isinstance(v, Mapping) else v
        for k, v in data.items()
        if v is not None
    }


def config_managed(name, config):
    """
    Ensure the configuration is set as specified.
    """
    ret = {
        "name": name,
        "result": True,
        "comment": "The config is already set as specified",
        "changes": {},
    }

    try:
        config = _filter_none(config)
        cur = __salt__["pihole.config_get"]()
        diff = recursive_diff(cur, config).diffs
        if not diff:
            return ret
        ret["changes"] = diff
        if __opts__["test"]:
            ret["result"] = None
            ret["comment"] = "Would have updated the configuration"
            return ret
        __salt__["pihole.config_update"](config)
        ret["comment"] = "Updated the configuration"
    except (CommandExecutionError, SaltInvocationError) as err:
        ret["result"] = False
        ret["comment"] = str(err)
        ret["changes"] = {}

    return ret


def custom_dns(name, ip):
    """
    Make sure a custom A/AAAA record is present in PiHole.

    name
        The domain the custom A/AAAA record is valid for.

    ip
        The IP address the lookup should resolve to.
    """

    ret = {"name": name, "result": True, "comment": [], "changes": {}}

    try:
        cur = __salt__["pihole.custom_dns_list"]()
        is_present = name in cur
        is_correct = ip == cur[name] if is_present else True

        if is_present and is_correct:
            ret["comment"] = (
                "The custom A/AAAA record is already present and points to the correct IP address."
            )
            return ret

        if not is_present:
            ret["changes"]["added"] = name
            if __opts__["test"]:
                ret["result"] = None
                ret["comment"] = "Custom A/AAAA record would have been created."
            else:
                __salt__["pihole.custom_dns_add"](name, ip, now=False)
                ret["comment"] = "Custom A/AAAA record has been created."
        else:
            ret["changes"]["updated"] = name
            if __opts__["test"]:
                ret["result"] = None
                ret["comment"] = "Custom A/AAAA record would have been updated."
            else:
                __salt__["pihole.custom_dns_add"](name, ip, force=True, now=False)
                ret["comment"] = "Custom A/AAAA record has been updated."

        if __opts__["test"]:
            return ret

        cur_new = __salt__["pihole.custom_dns_list"]()

        if not is_present and name not in cur_new:
            ret["result"] = False
            ret["comment"] = "There were no errors, but the entry is still absent."
            ret["changes"] = {}
        elif not is_correct and cur_new[name] != ip:
            ret["result"] = False
            ret["comment"] = "There were no errors, but the entry is still incorrect."
            ret["changes"] = {}

    except (CommandExecutionError, SaltInvocationError) as e:
        ret["result"] = False
        ret["comment"] = str(e)
        ret["changes"] = {}

    return ret


def custom_dns_absent(name, ip=None):
    """
    Make sure a custom A/AAAA record is absent from PiHole.

    name
        The domain the custom A/AAAA record is valid for.

    ip
        Optionally specify the IP address the entry resolved to. This acts as a failsafe.
        If unspecified, the A/AAAA record will be removed regardless of target IP address.
    """

    ret = {"name": name, "result": True, "comment": [], "changes": {}}

    try:
        cur = __salt__["pihole.custom_dns_list"]()
        if name not in cur:
            ret["comment"] = "Custom A/AAAA record is already absent."
            return ret

        if ip is not None and cur[name] != ip:
            ret["comment"] = (
                "Custom A/AAAA record is present, but does not point to the specified IP address. Skipping."
            )
            return ret

        ret["changes"]["removed"] = name

        if __opts__["test"]:
            ret["result"] = None
            ret["comment"] = "Custom A/AAAA record would have been removed."
            return ret

        __salt__["pihole.custom_dns_remove"](name, ip, now=False)
        ret["comment"] = "Custom A/AAAA record has been removed."

        if name in __salt__["pihole.custom_dns_list"]():
            ret["result"] = False
            ret["comment"] = (
                "There were no errors, but the A/AAAA record is still present."
            )
            ret["changes"] = {}

    except (CommandExecutionError, SaltInvocationError) as e:
        ret["result"] = False
        ret["comment"] = str(e)
        ret["changes"] = {}

    return ret


def group(name, enabled=True, description="Managed by Salt"):
    """
    Make sure a group is present in PiHole.

    name
        The name of the group.

    enabled
        Whether the group should be enabled. Defaults to True.

    description
        An optional description, defaults to "Managed by Salt". Will only be set
        on first creation.
    """

    ret = {"name": name, "result": True, "comment": [], "changes": {}}
    verb = "enable" if enabled else "disable"

    try:
        is_present = name in __salt__["pihole.group_list"]()
        is_enabled = (
            name in __salt__["pihole.group_list"](True) if is_present else False
        )

        if is_present and is_enabled == enabled:
            ret["comment"] = f"Group is already present and {verb}d"
            return ret

        if not is_present:
            if __opts__["test"]:
                ret["result"] = None
                ret["comment"] = "Group would have been created."
            else:
                __salt__["pihole.group_add"](
                    name, enabled=enabled, description=description, now=False
                )
                ret["comment"] = "Group has been created."
            ret["changes"]["created"] = name
        else:
            if __opts__["test"]:
                ret["result"] = None
                ret["comment"] = f"Group would have been {verb}d."
            else:
                __salt__[f"pihole.group_{verb}"](name, now=False)
                ret["comment"] = f"Group has been {verb}d."
            ret["changes"][f"{verb}d"] = name

        if __opts__["test"]:
            return ret

        is_present_now = name in __salt__["pihole.group_list"]()
        is_enabled_now = (
            name in __salt__["pihole.group_list"](True) if is_present_now else False
        )

        if not is_present_now:
            ret["result"] = False
            ret["comment"] = [
                "There were no errors, but the group is still not present."
            ]
            ret["changes"] = {}
        elif not is_enabled_now == enabled:
            ret["result"] = False
            ret["comment"] = [
                f"There were no errors, but the group is still not {verb}d."
            ]
            ret["changes"] = {}

    except (CommandExecutionError, SaltInvocationError) as e:
        ret["result"] = False
        ret["comment"].append(str(e))

    return ret


def group_absent(name):
    """
    Make sure a group is absent from PiHole.

    name
        The name of the group.
    """

    ret = {"name": name, "result": True, "comment": [], "changes": {}}

    try:
        if name not in __salt__["pihole.group_list"]():
            ret["comment"] = "Group is already absent."
            return ret

        ret["changes"]["removed"] = name

        if __opts__["test"]:
            ret["result"] = None
            ret["comment"] = "Group would have been removed."
            return ret

        __salt__["pihole.group_remove"](name, now=False)
        ret["comment"] = "Group has been removed."

        if name in __salt__["pihole.group_list"]():
            ret["result"] = False
            ret["comment"] = "There were no errors, but the group is still present."
            ret["changes"] = {}

    except (CommandExecutionError, SaltInvocationError) as e:
        ret["result"] = False
        ret["comment"] = str(e)
        ret["changes"] = {}

    return ret


def uptodate(name):
    """
    Make sure all PiHole subsystems are up to date.

    name
        Irrelevant.
    """
    ret = {"name": name, "result": True, "comment": [], "changes": {}}

    try:
        if __salt__["pihole.update_check"]():
            ret["comment"] = "All PiHole components are already up to date."
            return ret

        ret["changes"]["updated"] = "all"
        if __opts__["test"]:
            ret["result"] = None
            ret["comment"] = "All PiHole components would have been upgraded."
            return ret

        out = __salt__["pihole.update"]()
        ret["comment"] = "All PiHole components have been upgraded."

        if not __salt__["pihole.update_check"]():
            ret["result"] = False
            ret["comment"] = (
                f"There were no errors, but not all PiHole are up to date still. Upgrade output was:\n\n{out}"
            )

    except (CommandExecutionError, SaltInvocationError) as e:
        ret["result"] = False
        ret["comment"] = str(e)
        ret["changes"] = {}

    return ret


def whitelist(name=None, domains=None, regex=False, wildcard=False):
    """
    Make sure domains are present in PiHole's whitelists.

    name
        Single domain that should be present in the whitelist.
        You can specify multiple in ``domains``, this is ignored then.

    domains
        Single domain or list of domains that should be present in the whitelist.

    regex
        Whether the domains should be interpreted as regular expressions.
        Defaults to False. Cannot be combined with wildcard.

    wildcard
        Whether all subdomains should be matched as well. Defaults to False.
        Cannot be combined with regex.
    """

    return _domainlist_present(
        name, domains=domains, regex=regex, wildcard=wildcard, blacklist=False
    )


def whitelist_absent(name=None, domains=None, regex=False, wildcard=False):
    """
    Make sure domains are absent from PiHole's whitelists.

    name
        Single domain that should be absent from the whitelist.
        You can specify multiple in ``domains``, this is ignored then.

    domains
        Single domain or list of domains that should be absent from the whitelist.

    regex
        Whether the domains should be interpreted as regular expressions.
        Defaults to False. Cannot be combined with wildcard.

    wildcard
        Whether all subdomains should be matched as well. Defaults to False.
        Cannot be combined with regex.
    """

    return _domainlist_absent(
        name, domains=domains, regex=regex, wildcard=wildcard, blacklist=False
    )


def _domainlist_absent(name, domains, regex, wildcard, blacklist=True):
    """
    DRY helper for domainlist absent states.
    """
    ret = {"name": name, "result": True, "comment": [], "changes": {}}

    if regex and wildcard:
        ret["result"] = False
        ret["comment"] = "regex and wildcard are mutually exclusive."
        return ret

    domains = domains or [name]
    which_list = "black" if blacklist else "white"

    of_type = which_list
    if regex:
        of_type = "r" + of_type
    elif wildcard:
        of_type = "w" + of_type

    try:
        changes = []
        for domain in domains:
            if __salt__["pihole.domainlist_count"](domain, of_type):
                changes.append(domain)

        if not changes:
            ret["comment"] = f"All domains are absent from the {which_list}list."
            return ret

        ret["changes"]["removed"] = changes
        if __opts__["test"]:
            ret["comment"] = (
                "A total of {} domains would have been removed from the {}list.".format(
                    len(changes), which_list
                )
            )
            return ret

        __salt__[f"pihole.{which_list}list_rm"](
            domains, regex=regex, wildcard=wildcard, now=False
        )
        ret["comment"] = (
            "A total of {} domains have been removed from the {}list.".format(
                len(changes), which_list
            )
        )

        if __salt__["pihole.domainlist_count"](domains, of_type):
            ret["result"] = False
            ret["comment"] = (
                "There were no errors, but still some of the {} present domains could be found of the specified type.".format(
                    len(changes)
                )
            )
            ret["changes"] = {}

    except (CommandExecutionError, SaltInvocationError) as e:
        ret["result"] = False
        ret["comment"] = str(e)
        ret["changes"] = {}

    return ret


def _domainlist_present(name, domains, regex, wildcard, blacklist=True):
    """
    DRY helper for domainlist present states.
    """
    ret = {"name": name, "result": True, "comment": [], "changes": {}}

    if regex and wildcard:
        ret["result"] = False
        ret["comment"] = "regex and wildcard are mutually exclusive."
        return ret

    domains = domains or [name]
    which_list = "black" if blacklist else "white"

    of_type = which_list
    if regex:
        of_type = "r" + of_type
    elif wildcard:
        of_type = "w" + of_type

    try:
        changes = []
        for domain in domains:
            if not __salt__["pihole.domainlist_count"](domain, of_type):
                changes.append(domain)

        if not changes:
            ret["comment"] = "All domains are present with the correct configuration."
            return ret

        ret["changes"]["added"] = changes
        if __opts__["test"]:
            ret["comment"] = (
                "A total of {} domains would have been added to the {}list.".format(
                    len(changes), which_list
                )
            )
            return ret

        __salt__[f"pihole.{which_list}list"](
            domains, regex=regex, wildcard=wildcard, now=False
        )
        ret["comment"] = "A total of {} domains have been added to the {}list.".format(
            len(changes), which_list
        )

        if not len(domains) == __salt__["pihole.domainlist_count"](domains, of_type):
            ret["result"] = False
            ret["comment"] = (
                "There were no errors, but still not all {} missing domains could be found of the correct type.".format(
                    len(changes)
                )
            )
            ret["changes"] = {}

    except (CommandExecutionError, SaltInvocationError) as e:
        ret["result"] = False
        ret["comment"] = str(e)
        ret["changes"] = {}

    return ret

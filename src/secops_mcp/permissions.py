"""Safety model shared by all tool modules: dry-run defaults and explicit
CONFIRM_<TOOL_NAME> tokens on destructive tools. Mirrors git-steer's
permissions.ts.

Usage in a tool module:

    from secops_mcp.permissions import require_confirm, DestructiveActionError

    @mcp.tool()
    def host_isolate(target_host: str, confirm: str | None = None) -> str:
        require_confirm("host_isolate", confirm)
        ...
"""

from __future__ import annotations

# Tools that always require an explicit confirm token, regardless of
# per-alert-type policy in config/policies.yaml.
DESTRUCTIVE_TOOLS = {
    "host_isolate",
    "credential_rotate",
}

# Resources no remediation tool may ever touch, regardless of policy or
# confirm token -- these are specifically the things that cause a
# self-inflicted access lockout (see memory: operate-via-mcp-only, and this
# session's own SSH-access saga on the security VM). Matched as a
# case-insensitive substring against whatever a tool is about to act on
# (service name, package name, playbook extra_vars), so "openssh-server" and
# "ssh" both catch, but this is deliberately narrow -- it's an anti-lockout
# list, not a general "important services" list. Docker itself is not on
# here: restarting the daemon doesn't stop running containers (verified this
# session), so it's not a lockout risk of the same kind.
PROTECTED_RESOURCES = {
    "ssh",
    "sshd",
    "openssh",
    "netplan",
    "networkmanager",
    "network-manager",
    "systemd-networkd",
    "ufw",
    "iptables",
    "nftables",
    "firewalld",
    "sudoers",
    "pam.d",
    "pam_",
}


class DestructiveActionError(RuntimeError):
    pass


class ProtectedResourceError(RuntimeError):
    pass


def check_not_protected(*values: object) -> None:
    """Raise if any value names, or contains as a substring, a protected
    resource. Call this before any remediation tool acts on a service,
    package, or config path -- see PROTECTED_RESOURCES for why each entry
    is on the list. This is a hard block, not a policy the caller can
    override with dry_run=False or a confirm token: those control whether
    an *allowed* action executes, not whether a lockout-risk action is
    allowed at all.

    Non-string values (bools, ints, lists in extra_vars) are skipped rather
    than stringified -- this checks names/paths, not arbitrary data.
    """
    for value in values:
        if not isinstance(value, str) or not value:
            continue
        lowered = value.lower()
        for protected in PROTECTED_RESOURCES:
            if protected in lowered:
                raise ProtectedResourceError(
                    f"refusing to act on {value!r}: matches protected resource "
                    f"{protected!r}. Remediation tools will never touch SSH, "
                    "network, firewall, or sudo/PAM configuration -- that's a "
                    "hard block, not something dry_run or confirm can bypass."
                )


def confirm_token(tool_name: str) -> str:
    return f"CONFIRM_{tool_name.upper()}"


def require_confirm(tool_name: str, confirm: str | None) -> None:
    """Raise unless `confirm` exactly matches CONFIRM_<TOOL_NAME>.

    Call this as the first line of any tool in DESTRUCTIVE_TOOLS (or any
    tool a policy has escalated to "confirm" — see state.load_policies()).
    """
    expected = confirm_token(tool_name)
    if confirm != expected:
        raise DestructiveActionError(
            f"{tool_name} is destructive and took no action. "
            f"Re-run with confirm={expected!r} to proceed."
        )


def resolve_dry_run(tool_name: str, dry_run: bool | None) -> bool:
    """Destructive/remediation tools default to dry_run=True when the
    caller doesn't say otherwise — an LLM can't accidentally trigger a
    write just by omitting the argument.
    """
    if dry_run is None:
        return True
    return dry_run

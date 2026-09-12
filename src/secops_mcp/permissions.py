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


class DestructiveActionError(RuntimeError):
    pass


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

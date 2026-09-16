"""Ansible execution layer. This is the only module that writes to
managed hosts — everything else in tools/ is read-only.

Safety model (see permissions.py and README.md):
    - ansible_run_playbook and the wrapper tools below default to
      dry_run=True (resolve_dry_run).
    - host_isolate and credential_rotate are in permissions.DESTRUCTIVE_TOOLS
      and require confirm="CONFIRM_<TOOL_NAME>" even with dry_run=False.
    - Every call is logged to state/audit.jsonl via state.append_audit,
      dry-run or not.

TODO: replace _execute_playbook's body with a real ansible-runner
invocation once playbooks/*.yml are implemented and an inventory exists
(config/managed-hosts.yaml is the source of truth for what's targetable;
ANSIBLE_INVENTORY_PATH in .env points ansible-runner at the actual
Ansible inventory).
"""

from __future__ import annotations

from typing import Any

from secops_mcp.permissions import (
    ProtectedResourceError,
    check_not_protected,
    require_confirm,
    resolve_dry_run,
)
from secops_mcp.server import mcp
from secops_mcp.state import ROOT, append_audit, is_managed_host, load_managed_hosts

PLAYBOOK_DIR = ROOT / "playbooks"


def _execute_playbook(
    playbook: str, target_host: str, dry_run: bool, extra_vars: dict[str, Any] | None = None
) -> dict[str, Any]:
    if not is_managed_host(target_host):
        raise ValueError(f"{target_host!r} is not in config/managed-hosts.yaml")
    # Hard block, checked before dry-run short-circuits below, so a dry-run
    # preview also surfaces "this would be refused" rather than looking safe.
    check_not_protected(playbook, target_host, *(extra_vars or {}).values())
    path = PLAYBOOK_DIR / playbook
    if not path.exists():
        raise FileNotFoundError(f"no such playbook: {playbook}")
    if dry_run:
        return {
            "playbook": playbook,
            "target_host": target_host,
            "dry_run": True,
            "would_run": f"ansible-playbook {path} --check --limit {target_host}",
        }
    raise NotImplementedError(
        f"real execution of {playbook} against {target_host} not yet wired up "
        "(ansible-runner integration is TODO)"
    )


@mcp.tool()
def ansible_list_playbooks() -> str:
    """List available remediation playbooks in playbooks/."""
    return "\n".join(sorted(p.name for p in PLAYBOOK_DIR.glob("*.yml")))


@mcp.tool()
def ansible_run_playbook(
    playbook: str, target_host: str, dry_run: bool | None = None
) -> str:
    """Run an arbitrary playbook from playbooks/ against a managed host.

    Args:
        playbook: Filename under playbooks/, e.g. "service-restart.yml".
        target_host: Name or address from config/managed-hosts.yaml.
        dry_run: Defaults to True (runs with --check, no changes made).
    """
    dr = resolve_dry_run("ansible_run_playbook", dry_run)
    result = _execute_playbook(playbook, target_host, dr)
    append_audit(
        "ansible_run_playbook", {"playbook": playbook, "target_host": target_host}, dr, result
    )
    return str(result)


@mcp.tool()
def host_isolate(
    target_host: str, confirm: str | None = None, dry_run: bool | None = None
) -> str:
    """Quarantine a compromised host (playbooks/host-isolate.yml). Destructive.

    Args:
        target_host: Name or address from config/managed-hosts.yaml.
        confirm: Must be "CONFIRM_HOST_ISOLATE" to actually run.
        dry_run: Defaults to True.
    """
    require_confirm("host_isolate", confirm)
    dr = resolve_dry_run("host_isolate", dry_run)
    result = _execute_playbook("host-isolate.yml", target_host, dr)
    append_audit("host_isolate", {"target_host": target_host}, dr, result)
    return str(result)


@mcp.tool()
def host_quarantine_lift(target_host: str, dry_run: bool | None = None) -> str:
    """Reverse a prior host_isolate (playbooks/host-quarantine-lift.yml).

    Args:
        target_host: Name or address from config/managed-hosts.yaml.
        dry_run: Defaults to True.
    """
    dr = resolve_dry_run("host_quarantine_lift", dry_run)
    result = _execute_playbook("host-quarantine-lift.yml", target_host, dr)
    append_audit("host_quarantine_lift", {"target_host": target_host}, dr, result)
    return str(result)


@mcp.tool()
def credential_rotate(
    target_host: str, account: str, confirm: str | None = None, dry_run: bool | None = None
) -> str:
    """Rotate a flagged account's credential (playbooks/credential-rotate.yml). Destructive.

    Args:
        target_host: Name or address from config/managed-hosts.yaml.
        account: The local/service account whose credential should be rotated.
        confirm: Must be "CONFIRM_CREDENTIAL_ROTATE" to actually run.
        dry_run: Defaults to True.
    """
    require_confirm("credential_rotate", confirm)
    dr = resolve_dry_run("credential_rotate", dry_run)
    result = _execute_playbook(
        "credential-rotate.yml", target_host, dr, {"account": account}
    )
    append_audit(
        "credential_rotate", {"target_host": target_host, "account": account}, dr, result
    )
    return str(result)


@mcp.tool()
def service_restart(target_host: str, service: str, dry_run: bool | None = None) -> str:
    """Restart a flagged container/service (playbooks/service-restart.yml).

    Allowed to run unattended per config/policies.yaml (checkmk.service_crit: auto).

    Args:
        target_host: Name or address from config/managed-hosts.yaml.
        service: Service/container name to restart.
        dry_run: Defaults to True.
    """
    dr = resolve_dry_run("service_restart", dry_run)
    result = _execute_playbook(
        "service-restart.yml", target_host, dr, {"service": service}
    )
    append_audit(
        "service_restart", {"target_host": target_host, "service": service}, dr, result
    )
    return str(result)


def _refuse_if_running_kernel(target_host: str, package: str) -> None:
    """Extra guard specific to kernel packages, on top of PROTECTED_RESOURCES:
    refuse to remove a linux-image-* package if it's the kernel that host is
    currently booted into. vuln_triage_kernel's "active_kernel" bucket is a
    real-risk-needs-upgrade case, not a removal case -- removing a running
    kernel leaves nothing to boot into. Only "stale_kernel" packages (an
    older, not-currently-booted linux-image-*) are safe to remove.

    Queries the same wazuh-states-vulnerabilities-* data vuln_triage_kernel
    uses, scoped to target_host, so this stays correct if the host reboots
    onto a different kernel between a triage run and this call.

    Fails safe: if there's no way to positively verify this host's running
    kernel (no wazuh_agent_name mapping in managed-hosts.yaml, or Wazuh has
    no data for that agent -- e.g. vm104-security, which deliberately runs
    no wazuh-agent), this refuses rather than assuming the package is safe
    to remove. An empty result set must never read as "not the running
    kernel" -- that was a real bug caught in testing (managed-hosts.yaml's
    `name` doesn't match Wazuh's agent.name, so the naive lookup silently
    found zero findings and let a running-kernel removal through).
    """
    if not package.startswith("linux-image-"):
        return

    host_entry = next(
        (h for h in load_managed_hosts().get("hosts", [])
         if target_host in (h.get("name"), h.get("address"))),
        None,
    )
    agent_name = (host_entry or {}).get("wazuh_agent_name")
    if not agent_name:
        raise ProtectedResourceError(
            f"refusing to remove {package!r} on {target_host!r}: no wazuh_agent_name "
            "mapping for this host in config/managed-hosts.yaml, so its running "
            "kernel can't be verified. Add the mapping (or verify manually) "
            "before this package can be removed."
        )

    from secops_mcp.tools.vuln_triage import classify, get_indexer_client

    findings = get_indexer_client().search_vulnerabilities(agent_name=agent_name, limit=5000)
    if not findings:
        raise ProtectedResourceError(
            f"refusing to remove {package!r} on {target_host!r}: Wazuh has no "
            f"vulnerability data at all for agent {agent_name!r}, so its running "
            "kernel can't be verified. An empty result must never be read as "
            "'safe to remove' -- fix the data gap before retrying."
        )
    active_packages = {
        f["package"]["name"] for f in classify(findings)["active_kernel"]
    }
    if package in active_packages:
        raise ProtectedResourceError(
            f"refusing to remove {package!r} on {target_host!r}: this is the "
            "kernel that host is currently running (per Wazuh's host.os.kernel), "
            "not a stale package. Removing it would leave the host unable to "
            "boot. If it genuinely needs replacing, that's a kernel upgrade + "
            "reboot, not a package removal."
        )


@mcp.tool()
def package_remediate(
    target_host: str, package: str, action: str = "remove", dry_run: bool | None = None
) -> str:
    """Remediate a flagged package (playbooks/package-remediate.yml).

    Built for vuln_triage_kernel's "stale_kernel" bucket: old linux-image-*
    packages left behind by apt upgrades that aren't the running kernel, so
    removing them is just cleanup, not risk reduction against live exposure.
    Refuses (via PROTECTED_RESOURCES) to touch anything SSH/network/firewall/
    sudo-related, and separately refuses to remove a linux-image-* package
    that matches the host's actually-running kernel -- see
    _refuse_if_running_kernel.

    Args:
        target_host: Name or address from config/managed-hosts.yaml.
        package: Package name to act on (e.g. "linux-image-7.0.0-28-generic").
        action: "remove" or "upgrade". Defaults to "remove".
        dry_run: Defaults to True.
    """
    _refuse_if_running_kernel(target_host, package)
    dr = resolve_dry_run("package_remediate", dry_run)
    result = _execute_playbook(
        "package-remediate.yml", target_host, dr, {"package": package, "action": action}
    )
    append_audit(
        "package_remediate",
        {"target_host": target_host, "package": package, "action": action},
        dr,
        result,
    )
    return str(result)


@mcp.tool()
def ansible_job_status(job_id: str) -> str:
    """Status/output of a past or running playbook execution.

    Args:
        job_id: Job id returned by ansible_run_playbook (once real execution
            is implemented — currently dry-run only, so no job ids exist yet).
    """
    raise NotImplementedError("ansible_job_status: no job runner yet (dry-run only)")

"""Vulnerability triage. Read-only.

Separates real risk from noise in Wazuh's vulnerability-detector output.
The specific noise pattern this targets: apt keeps old kernel packages
installed after upgrades (they're not autoremoved by default), so a fleet
that's actually current on patches can still show hundreds of "Critical"
kernel CVEs for versions nothing is actually running. Each vulnerability
document in wazuh-states-vulnerabilities-* already carries host.os.kernel
(the kernel that host is currently booted into) right alongside
package.name/package.version, so this classification needs no host access
at all -- it's a pure data-shape check against what Wazuh already collected.
"""

from __future__ import annotations

import json
from collections import Counter, defaultdict
from typing import Any

from secops_mcp.clients.wazuh import WazuhIndexerClient
from secops_mcp.server import mcp

_indexer: WazuhIndexerClient | None = None


def get_indexer_client() -> WazuhIndexerClient:
    global _indexer
    if _indexer is None:
        _indexer = WazuhIndexerClient.from_env()
    return _indexer


def classify(findings: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    """Split raw wazuh-states-vulnerabilities-* findings into active_kernel /
    stale_kernel / other. Public (no leading underscore) because
    tools/ansible.py's package_remediate guard reuses this exact
    classification to refuse removing a host's actually-running kernel.
    """
    active_kernel: list[dict[str, Any]] = []
    stale_kernel: list[dict[str, Any]] = []
    other: list[dict[str, Any]] = []

    for f in findings:
        pkg_name = (f.get("package") or {}).get("name", "")
        if not pkg_name.startswith("linux-image-"):
            other.append(f)
            continue
        running_kernel = (f.get("host") or {}).get("os", {}).get("kernel", "")
        if running_kernel and pkg_name == f"linux-image-{running_kernel}":
            active_kernel.append(f)
        else:
            stale_kernel.append(f)

    return {"active_kernel": active_kernel, "stale_kernel": stale_kernel, "other": other}


def _summarize_bucket(findings: list[dict[str, Any]]) -> dict[str, Any]:
    cves = {f.get("vulnerability", {}).get("id") for f in findings}
    by_agent = Counter(f.get("agent", {}).get("name") for f in findings)
    by_package: dict[str, set[str]] = defaultdict(set)
    for f in findings:
        pkg = f.get("package") or {}
        by_package[pkg.get("name", "?")].add(pkg.get("version", "?"))
    return {
        "finding_count": len(findings),
        "unique_cves": len(cves - {None}),
        "by_agent": dict(by_agent),
        "packages": {k: sorted(v) for k, v in by_package.items()},
    }


@mcp.tool()
def vuln_triage_kernel(agent_name: str | None = None, limit: int = 5000) -> str:
    """Classify vulnerability-detector findings into real vs. noise.

    Kernel packages (linux-image-*) are split by whether they match the
    host's actually-running kernel (host.os.kernel from the same finding):
    "active_kernel" is real attack surface, "stale_kernel" is installed-but-
    not-booted packages that are safe to leave for now and only worth
    cleaning up for hygiene/disk space -- not urgent remediation. Everything
    non-kernel (firefox, openssl, etc.) passes through as "other" unfiltered,
    since there's no equivalent noise pattern for those.

    Args:
        agent_name: Restrict to one agent (e.g. "ubuntu"). Omit for all.
        limit: Maximum raw findings to fetch before classifying.
    """
    findings = get_indexer_client().search_vulnerabilities(agent_name=agent_name, limit=limit)
    buckets = classify(findings)
    result = {
        "total_findings": len(findings),
        "active_kernel": _summarize_bucket(buckets["active_kernel"]),
        "stale_kernel": _summarize_bucket(buckets["stale_kernel"]),
        "other": _summarize_bucket(buckets["other"]),
    }
    return json.dumps(result, indent=2, default=str)

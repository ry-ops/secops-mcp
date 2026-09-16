"""Wazuh tools. Read-only.

Configuration (see .env.example):
    WAZUH_API_URL/USER/PASSWORD          manager API (55000): agents, RBAC
    WAZUH_INDEXER_URL/USER/PASSWORD      indexer/OpenSearch (9200): alerts
"""

from __future__ import annotations

import json

from secops_mcp.clients.wazuh import WazuhIndexerClient, WazuhManagerClient
from secops_mcp.server import mcp

_manager: WazuhManagerClient | None = None
_indexer: WazuhIndexerClient | None = None


def _mgr() -> WazuhManagerClient:
    global _manager
    if _manager is None:
        _manager = WazuhManagerClient.from_env()
    return _manager


def _idx() -> WazuhIndexerClient:
    global _indexer
    if _indexer is None:
        _indexer = WazuhIndexerClient.from_env()
    return _indexer


@mcp.tool()
def wazuh_list_alerts(level_min: int = 0, limit: int = 50) -> str:
    """List recent Wazuh alerts at or above a minimum rule level.

    Args:
        level_min: Minimum Wazuh rule level (0-15 scale).
        limit: Maximum alerts to return.
    """
    alerts = _idx().search_alerts(level_min=level_min, limit=limit)
    return json.dumps(alerts, indent=2, default=str)


@mcp.tool()
def wazuh_list_vulnerabilities(agent_name: str | None = None, limit: int = 1000) -> str:
    """Raw vulnerability-detector findings from the indexer. Prefer
    vuln_triage_kernel (tools/vuln_triage.py) for kernel-package findings --
    it separates active-kernel risk from stale-package noise using the same
    data this returns.

    Args:
        agent_name: Restrict to one agent (e.g. "ubuntu"). Omit for all.
        limit: Maximum findings to return.
    """
    findings = _idx().search_vulnerabilities(agent_name=agent_name, limit=limit)
    return json.dumps(findings, indent=2, default=str)


@mcp.tool()
def wazuh_agent_status(agent_id: str | None = None) -> str:
    """Connection/health status for one Wazuh agent, or all agents if omitted.

    Args:
        agent_id: Wazuh agent id (e.g. "001"). Omit for all agents.
    """
    if agent_id:
        data = _mgr().get("/agents", params={"agents_list": agent_id})
    else:
        data = _mgr().get("/agents")
    return json.dumps(data, indent=2, default=str)

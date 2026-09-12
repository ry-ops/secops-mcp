"""Wazuh API client + tools. Read-only.

Configuration (environment variables, see .env.example):
    WAZUH_API_URL, WAZUH_API_USER, WAZUH_API_PASSWORD

TODO: implement WazuhClient (auth is a JWT fetched from /security/user/authenticate,
then Bearer on subsequent calls; token expires ~15min, needs refresh).
"""

from __future__ import annotations

from secops_mcp.server import mcp


@mcp.tool()
def wazuh_list_alerts(level_min: int = 0, limit: int = 50) -> str:
    """List recent Wazuh alerts at or above a minimum rule level.

    Args:
        level_min: Minimum Wazuh rule level (0-15 scale).
        limit: Maximum alerts to return.
    """
    raise NotImplementedError("wazuh_list_alerts: WazuhClient not yet implemented")


@mcp.tool()
def wazuh_agent_status(agent_id: str | None = None) -> str:
    """Connection/health status for one Wazuh agent, or all agents if omitted.

    Args:
        agent_id: Wazuh agent id. Omit for all agents.
    """
    raise NotImplementedError("wazuh_agent_status: WazuhClient not yet implemented")

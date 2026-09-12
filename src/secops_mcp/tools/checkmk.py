"""Checkmk REST API client + tools. Read-only.

Configuration: CHECKMK_API_URL, CHECKMK_API_USER, CHECKMK_API_SECRET
(see .env.example). Checkmk's REST API uses HTTP basic auth with an
automation user's secret, docs at <site>/check_mk/api/1.0/openapi-swagger-ui.

TODO: implement CheckmkClient.
"""

from __future__ import annotations

from secops_mcp.server import mcp


@mcp.tool()
def checkmk_list_problems(state: str = "crit") -> str:
    """List hosts/services currently in a problem state.

    Args:
        state: "crit", "warn", or "unknown".
    """
    raise NotImplementedError("checkmk_list_problems: CheckmkClient not yet implemented")


@mcp.tool()
def checkmk_host_status(host: str) -> str:
    """Full status for one host: all services and their states.

    Args:
        host: Checkmk host name.
    """
    raise NotImplementedError("checkmk_host_status: CheckmkClient not yet implemented")

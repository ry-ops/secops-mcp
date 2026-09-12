"""Checkmk REST API tools. Read-only.

Configuration: CHECKMK_API_URL, CHECKMK_API_USER, CHECKMK_API_SECRET
(see .env.example). Checkmk's REST API uses HTTP basic auth with an
automation user's secret, docs at <site>/check_mk/api/1.0/openapi-swagger-ui.
"""

from __future__ import annotations

import json

from secops_mcp.clients.checkmk import CheckmkClient
from secops_mcp.server import mcp

_client: CheckmkClient | None = None


def _cmk() -> CheckmkClient:
    global _client
    if _client is None:
        _client = CheckmkClient.from_env()
    return _client


@mcp.tool()
def checkmk_list_problems(state: str = "crit") -> str:
    """List services currently in a problem state.

    Args:
        state: "crit", "warn", or "unknown".
    """
    problems = _cmk().list_service_problems(state=state)
    return json.dumps(problems, indent=2, default=str)


@mcp.tool()
def checkmk_host_status(host: str) -> str:
    """Full status for one host: all services and their states.

    Args:
        host: Checkmk host name.
    """
    services = _cmk().host_status(host)
    return json.dumps(services, indent=2, default=str)

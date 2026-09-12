"""Sandfly API client + tools. Read-only.

Configuration: SANDFLY_API_URL, SANDFLY_API_USER, SANDFLY_API_PASSWORD
(see .env.example). Sandfly's REST API authenticates like Wazuh's manager
API — POST username/password, get a JWT back — rather than a static token,
despite the tool name below dating from before that was confirmed.
"""

from __future__ import annotations

import json

from secops_mcp.clients.sandfly import SandflyClient
from secops_mcp.server import mcp

_client: SandflyClient | None = None

_SEVERITY_WORDS = {
    "critical": 5,
    "high": 4,
    "medium": 3,
    "low": 2,
    "informational": 1,
    "info": 1,
    "none": 0,
}


def _sfly() -> SandflyClient:
    global _client
    if _client is None:
        _client = SandflyClient.from_env()
    return _client


def _severity_to_int(severity_min: str | None) -> int:
    if severity_min is None:
        return 0
    try:
        return int(severity_min)
    except ValueError:
        pass
    key = severity_min.strip().lower()
    if key not in _SEVERITY_WORDS:
        raise ValueError(
            f"unrecognized severity {severity_min!r}; use one of "
            f"{sorted(_SEVERITY_WORDS)} or an integer 0-5"
        )
    return _SEVERITY_WORDS[key]


@mcp.tool()
def sandfly_list_findings(severity_min: str | None = None, limit: int = 50) -> str:
    """List recent Sandfly scan findings (rootkits, anomalies, drift) that
    actually triggered — passing checks are excluded regardless of severity.

    Args:
        severity_min: Minimum severity to include — "critical", "high",
            "medium", "low", "informational", or an integer 0-5 (5 highest).
        limit: Maximum findings to return.
    """
    findings = _sfly().search_findings(severity_min=_severity_to_int(severity_min), limit=limit)
    return json.dumps(findings, indent=2, default=str)

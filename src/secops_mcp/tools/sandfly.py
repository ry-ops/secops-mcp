"""Sandfly API client + tools. Read-only.

Configuration: SANDFLY_API_URL, SANDFLY_API_TOKEN (see .env.example).

TODO: implement SandflyClient once Sandfly is deployed on VM104
(see memory: security-stack — Sandfly listed as "pending").
"""

from __future__ import annotations

from secops_mcp.server import mcp


@mcp.tool()
def sandfly_list_findings(severity_min: str | None = None, limit: int = 50) -> str:
    """List recent Sandfly scan findings (rootkits, anomalies, drift).

    Args:
        severity_min: Minimum severity to include, e.g. "medium".
        limit: Maximum findings to return.
    """
    raise NotImplementedError("sandfly_list_findings: SandflyClient not yet implemented")

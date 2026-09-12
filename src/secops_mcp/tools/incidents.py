"""Incident lifecycle tracking and audit log queries.

Incidents are correlated alerts from Wazuh/Sandfly/Checkmk (see the
not-yet-implemented alert_correlate) plus whatever remediation was taken.
Stored append-only in state/incidents.jsonl; state.jsonl records aren't
mutated in place, a later record with the same incident_id supersedes
earlier ones for that id.
"""

from __future__ import annotations

import json
import uuid

from secops_mcp.server import mcp
from secops_mcp.state import STATE_DIR, append_incident


@mcp.tool()
def incident_open(title: str, source: str, severity: str, details: str = "") -> str:
    """Open a new incident.

    Args:
        title: Short human-readable summary.
        source: Which system raised this — "wazuh", "sandfly", "checkmk", or "correlated".
        severity: e.g. "low", "medium", "high", "critical".
        details: Freeform context (alert ids, host, etc).
    """
    incident_id = str(uuid.uuid4())
    record = {
        "incident_id": incident_id,
        "status": "open",
        "title": title,
        "source": source,
        "severity": severity,
        "details": details,
    }
    append_incident(record)
    return json.dumps(record)


@mcp.tool()
def incident_update(incident_id: str, note: str, status: str | None = None) -> str:
    """Append a note to an incident, optionally changing its status.

    Args:
        incident_id: Id returned by incident_open.
        note: What happened / what was done.
        status: New status, e.g. "investigating", "remediated", "closed".
    """
    record = {"incident_id": incident_id, "note": note}
    if status:
        record["status"] = status
    append_incident(record)
    return json.dumps(record)


@mcp.tool()
def incident_close(incident_id: str, resolution: str) -> str:
    """Close an incident with a final resolution note.

    Args:
        incident_id: Id returned by incident_open.
        resolution: How it was resolved.
    """
    record = {"incident_id": incident_id, "status": "closed", "resolution": resolution}
    append_incident(record)
    return json.dumps(record)


@mcp.tool()
def audit_log_query(tool: str | None = None, limit: int = 50) -> str:
    """Search past tool-call audit records (dry-run and real).

    Args:
        tool: Filter to one tool name. Omit for all.
        limit: Maximum records to return, most recent first.
    """
    path = STATE_DIR / "audit.jsonl"
    if not path.exists():
        return "[]"
    lines = path.read_text().splitlines()
    records = [json.loads(line) for line in lines if line.strip()]
    if tool:
        records = [r for r in records if r.get("tool") == tool]
    return json.dumps(records[-limit:], indent=2)


@mcp.tool()
def steer_status() -> str:
    """Health snapshot: last sync time per alert source, incident/audit counts."""
    cache_path = STATE_DIR / "cache.json"
    cache = json.loads(cache_path.read_text()) if cache_path.exists() else {}

    def _count(name: str) -> int:
        p = STATE_DIR / name
        return len(p.read_text().splitlines()) if p.exists() else 0

    return json.dumps(
        {
            "sources": cache,
            "incident_records": _count("incidents.jsonl"),
            "audit_records": _count("audit.jsonl"),
        },
        indent=2,
    )

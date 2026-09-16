"""Importing this package registers every tool module's @mcp.tool()
functions against the shared server instance (see server.py).
"""

from . import ansible, checkmk, incidents, notify, sandfly, vuln_triage, wazuh  # noqa: F401

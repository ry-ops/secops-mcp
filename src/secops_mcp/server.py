"""SecOps MCP server.

Turns Wazuh, Sandfly, and Checkmk alerts into reviewable (and, once
policy allows, automated) Ansible remediation. See README.md for the
architecture and safety model.

Configuration: see .env.example.

Transport (environment variables):
    MCP_TRANSPORT  "stdio" (default, for Claude Desktop/Code local use) or
                   "streamable-http" (for the containerized deployment on
                   VM108, reachable over the network).
    MCP_HOST       default "0.0.0.0" (only used for streamable-http)
    MCP_PORT       default 8000 (only used for streamable-http)
"""

from __future__ import annotations

import os

from dotenv import load_dotenv
from mcp.server.mcpserver import MCPServer

# In the container, Portainer injects env vars directly and no .env file
# exists — load_dotenv() is then a harmless no-op. Locally, it picks up
# ./.env for development.
load_dotenv()

mcp = MCPServer("secops")

# Imported for side effects: each module registers its tools against `mcp`.
from secops_mcp import tools  # noqa: E402,F401


def main() -> None:
    transport = os.environ.get("MCP_TRANSPORT", "stdio")
    if transport == "streamable-http":
        mcp.run(
            transport="streamable-http",
            host=os.environ.get("MCP_HOST", "0.0.0.0"),
            port=int(os.environ.get("MCP_PORT", "8000")),
        )
    else:
        mcp.run(transport="stdio")


if __name__ == "__main__":
    main()

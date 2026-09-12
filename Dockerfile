FROM python:3.12-slim

WORKDIR /app

RUN useradd --create-home --uid 1000 secops

COPY pyproject.toml README.md ./
COPY src ./src
COPY playbooks ./playbooks
COPY config ./config

RUN pip install --no-cache-dir .

# state/ is a volume (see docker-compose.yml) so the audit trail survives
# container restarts/redeploys.
RUN mkdir -p /app/state && chown -R secops:secops /app

USER secops

ENV MCP_TRANSPORT=streamable-http \
    MCP_HOST=0.0.0.0 \
    MCP_PORT=8000 \
    SECOPS_ROOT=/app

EXPOSE 8000

CMD ["secops-mcp"]

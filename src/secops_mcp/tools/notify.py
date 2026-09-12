"""Slack notifications. Webhook URL restricted to Slack's own domains,
same allowlist approach as git-steer.
"""

from __future__ import annotations

import os

import httpx

from secops_mcp.server import mcp

ALLOWED_WEBHOOK_HOSTS = {"hooks.slack.com", "hooks.slack-gov.com"}


@mcp.tool()
def slack_notify(message: str) -> str:
    """Post a message to the configured Slack webhook.

    Args:
        message: Text to post.
    """
    url = os.environ.get("SLACK_WEBHOOK_URL")
    if not url:
        raise ValueError("SLACK_WEBHOOK_URL is not set")
    host = httpx.URL(url).host
    if host not in ALLOWED_WEBHOOK_HOSTS:
        raise ValueError(f"refusing to post to non-Slack host: {host}")
    resp = httpx.post(url, json={"text": message}, timeout=10)
    resp.raise_for_status()
    return "sent"

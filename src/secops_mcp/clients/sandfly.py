"""Thin HTTP client for Sandfly Security, mirroring clients/wazuh.py's style.

Auth: POST /auth/login with {username, password} returns a short-lived JWT
access_token (no separate "API key" concept — this Sandfly license is on
the free tier, which caps the instance at a single user account, so the
existing admin user is what's authenticated as; see memory
portainer-via-chrome-devtools / secops-mcp for how that credential was
obtained). On a 401 the client re-authenticates once and retries, same
pattern as WazuhManagerClient.
"""

from __future__ import annotations

import os
from typing import Any

import httpx


class SandflyError(RuntimeError):
    """Raised for configuration problems and non-2xx API responses."""


def _env_bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in ("1", "true", "yes", "on")


class SandflyClient:
    """Wraps the Sandfly REST API (default port 8443, base path /v4)."""

    def __init__(
        self,
        base_url: str,
        user: str,
        password: str,
        verify_ssl: bool = False,
        timeout: float = 30.0,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self._user = user
        self._password = password
        self._http = httpx.Client(base_url=self.base_url, verify=verify_ssl, timeout=timeout)
        self._token: str | None = None

    @classmethod
    def from_env(cls) -> "SandflyClient":
        try:
            base_url = os.environ["SANDFLY_API_URL"]
            user = os.environ["SANDFLY_API_USER"]
            password = os.environ["SANDFLY_API_PASSWORD"]
        except KeyError as exc:
            raise SandflyError(f"missing required environment variable: {exc.args[0]}") from exc
        return cls(
            base_url,
            user,
            password,
            verify_ssl=_env_bool("SANDFLY_VERIFY_SSL", False),
            timeout=float(os.environ.get("SANDFLY_TIMEOUT", "30")),
        )

    def _authenticate(self) -> None:
        resp = self._http.post(
            "/auth/login", json={"username": self._user, "password": self._password}
        )
        if resp.status_code >= 400:
            raise SandflyError(
                f"authentication failed: HTTP {resp.status_code}: {resp.text.strip()}"
            )
        self._token = resp.json()["access_token"]

    def _post(self, path: str, json: dict[str, Any]) -> Any:
        if self._token is None:
            self._authenticate()
        resp = self._http.post(
            path, json=json, headers={"Authorization": f"Bearer {self._token}"}
        )
        if resp.status_code == 401:
            self._authenticate()
            resp = self._http.post(
                path, json=json, headers={"Authorization": f"Bearer {self._token}"}
            )
        if resp.status_code >= 400:
            raise SandflyError(f"POST {path} -> HTTP {resp.status_code}: {resp.text.strip()}")
        return resp.json()

    def search_findings(self, severity_min: int = 0, limit: int = 50) -> list[dict[str, Any]]:
        """Findings at or above a minimum severity (0-5, 5 highest) that
        actually triggered.

        A triggered finding has data.status == "alert" (not "pass") — this
        is filtered server-side, not by fetching a page and checking
        client-side: the overwhelming majority of results are routine
        passing checks, so an unsorted/unfiltered page of any reasonable
        size can easily come back with zero alerts even when hundreds
        exist, if they happen to sit outside that page's slice.
        """
        body = {
            "size": min(limit, 200),
            "page": 1,
            "filter": {
                "items": [
                    {"field": "data.status", "operator": "equals", "value": "alert"},
                    {"field": "data.severity", "operator": ">=", "value": severity_min},
                ],
                "logicOperator": "and",
            },
        }
        findings: list[dict[str, Any]] = []
        while len(findings) < limit:
            data = self._post("/results", body)
            rows = data.get("data") or []
            findings.extend(rows)
            if not data.get("more_results") or not rows:
                break
            body["page"] += 1
        return findings[:limit]

    def close(self) -> None:
        self._http.close()

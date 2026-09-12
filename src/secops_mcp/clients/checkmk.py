"""Thin HTTP client for the Checkmk REST API (v1.0), mirroring
clients/wazuh.py's style.

Auth is HTTP header `Authorization: Bearer <automation_user> <secret>` —
Checkmk's own non-standard Bearer format, not a JWT. The automation user's
secret doesn't expire, so there's no re-authenticate-on-401 dance here.
"""

from __future__ import annotations

import json
import os
from typing import Any

import httpx


class CheckmkError(RuntimeError):
    """Raised for configuration problems and non-2xx API responses."""


def _env_bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in ("1", "true", "yes", "on")


# Checkmk service/host state codes (Nagios-derived).
SERVICE_STATE = {"ok": 0, "warn": 1, "crit": 2, "unknown": 3}
HOST_STATE = {"up": 0, "down": 1, "unreachable": 2}


class CheckmkClient:
    """Wraps the Checkmk REST API (default: http://<host>:8080/<site>/check_mk/api/1.0)."""

    def __init__(
        self,
        base_url: str,
        user: str,
        secret: str,
        verify_ssl: bool = False,
        timeout: float = 30.0,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self._http = httpx.Client(
            base_url=self.base_url,
            headers={
                "Authorization": f"Bearer {user} {secret}",
                "Accept": "application/json",
            },
            verify=verify_ssl,
            timeout=timeout,
        )

    @classmethod
    def from_env(cls) -> "CheckmkClient":
        try:
            base_url = os.environ["CHECKMK_API_URL"]
            user = os.environ["CHECKMK_API_USER"]
            secret = os.environ["CHECKMK_API_SECRET"]
        except KeyError as exc:
            raise CheckmkError(f"missing required environment variable: {exc.args[0]}") from exc
        return cls(base_url, user, secret, verify_ssl=_env_bool("CHECKMK_VERIFY_SSL", False))

    def _get(self, path: str, params: dict[str, Any] | None = None) -> Any:
        resp = self._http.get(path, params=params)
        if resp.status_code >= 400:
            raise CheckmkError(f"GET {path} -> HTTP {resp.status_code}: {resp.text.strip()}")
        return resp.json()

    def list_service_problems(self, state: str = "crit") -> list[dict[str, Any]]:
        """Services at or above a given problem state (crit worse than warn
        worse than unknown is not a real ordering in Checkmk, so this
        matches the exact state rather than a >= threshold like Wazuh/Sandfly).
        """
        key = state.strip().lower()
        if key not in SERVICE_STATE or key == "ok":
            raise ValueError(f"state must be one of {sorted(k for k in SERVICE_STATE if k != 'ok')}")
        query = {"op": "=", "left": "state", "right": str(SERVICE_STATE[key])}
        params = [
            ("query", json.dumps(query)),
            ("columns", "host_name"),
            ("columns", "description"),
            ("columns", "state"),
            ("columns", "plugin_output"),
        ]
        data = self._get("/domain-types/service/collections/all", params=params)
        return data.get("value", [])

    def host_status(self, host: str) -> list[dict[str, Any]]:
        """All services and their states for one host."""
        query = {"op": "=", "left": "host_name", "right": host}
        params = [
            ("query", json.dumps(query)),
            ("columns", "description"),
            ("columns", "state"),
            ("columns", "plugin_output"),
        ]
        data = self._get("/domain-types/service/collections/all", params=params)
        return data.get("value", [])

    def close(self) -> None:
        self._http.close()

"""Thin HTTP clients for Wazuh, mirroring proxmox_mcp.client's style.

Two separate APIs, two separate clients:
    WazuhManagerClient  -- port 55000, JWT auth, agents/rules/management.
    WazuhIndexerClient  -- port 9200, basic auth, OpenSearch -- this is
                           where alerts actually live (wazuh-alerts-* index).
"""

from __future__ import annotations

import logging
import os
from typing import Any

import httpx

logging.getLogger("httpx").setLevel(logging.WARNING)


class WazuhError(RuntimeError):
    """Raised for configuration problems and non-2xx API responses."""


def _env_bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in ("1", "true", "yes", "on")


class WazuhManagerClient:
    """Wraps the Wazuh manager API (port 55000).

    Auth is a JWT fetched from /security/user/authenticate via HTTP basic
    auth, then sent as a Bearer token on subsequent requests. Tokens expire
    (~15 min); on a 401 the client re-authenticates once and retries.
    """

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
    def from_env(cls) -> "WazuhManagerClient":
        try:
            base_url = os.environ["WAZUH_API_URL"]
            user = os.environ["WAZUH_API_USER"]
            password = os.environ["WAZUH_API_PASSWORD"]
        except KeyError as exc:
            raise WazuhError(f"missing required environment variable: {exc.args[0]}") from exc
        return cls(
            base_url,
            user,
            password,
            verify_ssl=_env_bool("WAZUH_VERIFY_SSL", False),
            timeout=float(os.environ.get("WAZUH_TIMEOUT", "30")),
        )

    def _authenticate(self) -> None:
        resp = self._http.post("/security/user/authenticate", auth=(self._user, self._password))
        if resp.status_code >= 400:
            raise WazuhError(
                f"authentication failed: HTTP {resp.status_code}: {resp.text.strip()}"
            )
        self._token = resp.json()["data"]["token"]

    def get(self, path: str, **kwargs: Any) -> Any:
        if self._token is None:
            self._authenticate()
        resp = self._http.get(path, headers={"Authorization": f"Bearer {self._token}"}, **kwargs)
        if resp.status_code == 401:
            self._authenticate()
            resp = self._http.get(
                path, headers={"Authorization": f"Bearer {self._token}"}, **kwargs
            )
        if resp.status_code >= 400:
            raise WazuhError(f"GET {path} -> HTTP {resp.status_code}: {resp.text.strip()}")
        return resp.json().get("data")

    def close(self) -> None:
        self._http.close()


class WazuhIndexerClient:
    """Wraps the Wazuh indexer (OpenSearch, port 9200) for alert search."""

    def __init__(
        self,
        base_url: str,
        user: str,
        password: str,
        verify_ssl: bool = False,
        timeout: float = 30.0,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self._http = httpx.Client(
            base_url=self.base_url, auth=(user, password), verify=verify_ssl, timeout=timeout
        )

    @classmethod
    def from_env(cls) -> "WazuhIndexerClient":
        try:
            base_url = os.environ["WAZUH_INDEXER_URL"]
            user = os.environ["WAZUH_INDEXER_USER"]
            password = os.environ["WAZUH_INDEXER_PASSWORD"]
        except KeyError as exc:
            raise WazuhError(f"missing required environment variable: {exc.args[0]}") from exc
        return cls(base_url, user, password, verify_ssl=_env_bool("WAZUH_VERIFY_SSL", False))

    def search_alerts(self, level_min: int = 0, limit: int = 50) -> list[dict[str, Any]]:
        body = {
            "size": limit,
            "sort": [{"timestamp": {"order": "desc"}}],
            "query": {"range": {"rule.level": {"gte": level_min}}},
        }
        resp = self._http.post("/wazuh-alerts-*/_search", json=body)
        if resp.status_code >= 400:
            raise WazuhError(f"alert search -> HTTP {resp.status_code}: {resp.text.strip()}")
        hits = resp.json()["hits"]["hits"]
        return [h["_source"] for h in hits]

    def search_vulnerabilities(
        self, agent_name: str | None = None, limit: int = 1000
    ) -> list[dict[str, Any]]:
        """Vulnerability-detector findings from wazuh-states-vulnerabilities-*.

        Each hit already carries host.os.kernel (the actually-running kernel
        for that agent) alongside package.name/package.version — that's what
        lets kernel-package triage happen without touching the host at all,
        see tools/vuln_triage.py.

        Paginates with search_after on _id since this index runs into the
        thousands of hits; a single unpaged query would silently truncate at
        whatever index.max_result_window is set to.
        """
        body: dict[str, Any] = {
            "size": min(limit, 1000),
            "sort": [{"_id": "asc"}],
            "query": {"match_all": {}},
        }
        if agent_name:
            body["query"] = {"term": {"agent.name": agent_name}}

        findings: list[dict[str, Any]] = []
        search_after: list[Any] | None = None
        while len(findings) < limit:
            if search_after is not None:
                body["search_after"] = search_after
            resp = self._http.post("/wazuh-states-vulnerabilities-*/_search", json=body)
            if resp.status_code >= 400:
                raise WazuhError(
                    f"vulnerability search -> HTTP {resp.status_code}: {resp.text.strip()}"
                )
            hits = resp.json()["hits"]["hits"]
            if not hits:
                break
            findings.extend(h["_source"] for h in hits)
            search_after = hits[-1]["sort"]
        return findings[:limit]

    def close(self) -> None:
        self._http.close()

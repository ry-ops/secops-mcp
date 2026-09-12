"""Append-only JSONL state and policy loading.

state/incidents.jsonl and state/audit.jsonl are the audit trail described
in README.md. Every tool call goes through append_audit(); incident
lifecycle tools additionally go through append_incident().
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml

# In the container this package is `pip install`ed into site-packages, so it
# can no longer locate config/ and state/ by walking up from __file__ (that
# only works for an editable/source-tree run). SECOPS_ROOT (set to /app in
# the Dockerfile) is the source of truth there; the parents[2] walk-up
# remains the default for local `uv run` / dev use.
_default_root = Path(__file__).resolve().parents[2]
ROOT = Path(os.environ.get("SECOPS_ROOT", _default_root))
CONFIG_DIR = ROOT / "config"
STATE_DIR = ROOT / "state"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _append_jsonl(path: Path, record: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a") as f:
        f.write(json.dumps(record, sort_keys=True, default=str) + "\n")


def append_audit(tool: str, args: dict[str, Any], dry_run: bool, result: Any) -> None:
    _append_jsonl(
        STATE_DIR / "audit.jsonl",
        {
            "timestamp": _now(),
            "tool": tool,
            "args": args,
            "dry_run": dry_run,
            "result": result,
        },
    )


def append_incident(record: dict[str, Any]) -> None:
    _append_jsonl(STATE_DIR / "incidents.jsonl", {"timestamp": _now(), **record})


def load_yaml(name: str) -> dict[str, Any]:
    path = CONFIG_DIR / name
    if not path.exists():
        return {}
    with path.open() as f:
        return yaml.safe_load(f) or {}


def load_policies() -> dict[str, Any]:
    return load_yaml("policies.yaml")


def load_managed_hosts() -> dict[str, Any]:
    return load_yaml("managed-hosts.yaml")


def is_managed_host(name_or_address: str) -> bool:
    hosts = load_managed_hosts().get("hosts", [])
    return any(
        name_or_address in (h.get("name"), h.get("address")) for h in hosts
    )

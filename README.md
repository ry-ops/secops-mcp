# SecOps

MCP server that turns Wazuh, Sandfly, and Checkmk alerts into reviewable
(and eventually automated) remediation, using Ansible as the execution
layer. Runs as a persistent service on VM108 (docker host, 10.88.140.133).

## Philosophy: local is the compute plane

This is modeled on [git-steer](https://github.com/ry-ops/git-steer)'s
pattern — MCP tool interface, dry-run-by-default on anything that changes
state, explicit `CONFIRM_<TOOL>` strings before destructive actions, and
git-as-audit-log — but inverted on where compute happens. git-steer keeps
"zero local footprint" because it's steering GitHub's account and wants to
avoid loading down a laptop, offloading all execution to GitHub Actions
runners. A homelab has no equivalent free/ephemeral compute, and it already
runs 24/7 infrastructure — so here, **local *is* the runtime**: this
service runs continuously on VM108, and Ansible (also on VM108) is the
thing that actually executes remediation, rather than a cloud runner.

```
+----------------------------------------------------------------+
|                    VM108 (docker, 10.88.140.133)                |
|                                                                  |
|   secops-mcp (this service)                                     |
|     +-- tools/wazuh.py     -> Wazuh API      (read: alerts)     |
|     +-- tools/sandfly.py   -> Sandfly API    (read: findings)   |
|     +-- tools/checkmk.py   -> Checkmk REST   (read: problems)   |
|     +-- tools/ansible.py   -> ansible-runner (write: playbooks) |
|     +-- tools/incidents.py -> state/*.jsonl  (audit trail)      |
|     +-- tools/notify.py    -> Slack webhook                     |
|                                                                  |
|   playbooks/  (Ansible, executed by tools/ansible.py)           |
|   config/      policies.yaml, managed-hosts.yaml, sources.yaml  |
|   state/       incidents.jsonl, audit.jsonl, cache.json         |
|     (git-tracked, append-only — audit trail, not offloaded      |
|      state; this repo can still be pushed to a private GitHub   |
|      repo purely for backup/history, unlike git-steer where     |
|      the state repo IS the database)                            |
+----------------------------------------------------------------+
        ^                    ^                    ^
        |                    |                    |
   VM104 (security)     VM104 (security)     VM108 (checkmk)
   Wazuh :443           Sandfly              10.88.140.133
```

Deliberately **not** re-wrapping the existing `proxmox` and `unifi-network`
MCP servers here. Anything that needs to touch a VM or the network goes
through an Ansible playbook (which can itself call the Proxmox/UniFi APIs),
so there is one consistent audit trail for destructive actions instead of
one split across ad-hoc MCP calls and playbook runs.

## Safety model

- **Dry-run by default.** `ansible_run_playbook` and any tool that changes
  state defaults to `dry_run: true` unless the caller explicitly opts out.
- **Explicit confirm on destructive tools.** `host_isolate`,
  `credential_rotate`, and similar tools require a `confirm` parameter set
  to `CONFIRM_<TOOL_NAME>` — without it, the tool reports what it *would*
  do and takes no action.
- **Policy-gated.** `config/policies.yaml` defines, per alert type/severity,
  whether a remediation may run unattended or must wait for a human to
  approve via the confirm token.
- **Everything logged.** Every tool call (dry-run or real) appends to
  `state/audit.jsonl`.

## Status

Deployed as a Portainer git-stack on VM108 (see `docker-compose.yml`).

Implemented and live-tested:
- Wazuh client (`clients/wazuh.py`) — manager API + indexer, real alerts and
  vulnerability-detector findings (`wazuh-states-vulnerabilities-*`)
- Sandfly client (`clients/sandfly.py`) — real findings (currently none active)
- Checkmk client (`clients/checkmk.py`) — real host/service status
- Policy engine (`src/secops_mcp/permissions.py`), including
  `PROTECTED_RESOURCES` — a hard, non-bypassable block on any remediation
  tool touching SSH/network/firewall/sudo config, checked before every
  playbook run regardless of dry_run or confirm tokens
- Kernel-vulnerability triage (`tools/vuln_triage.py`,
  `runbooks/kernel-vulnerability-triage.md`) — separates real kernel exposure
  from stale-package noise; `package_remediate` (`tools/ansible.py`) won't
  remove a host's actually-running kernel, and fails safe (refuses) rather
  than assuming safety when it can't verify a host's kernel state

Not yet implemented:
- Real `ansible-runner` execution (`tools/ansible.py` — dry-run only)
- Actual playbook logic in `playbooks/*.yml` (all TODO stubs)

`runbooks/` holds human-readable triage docs for specific recurring alert
patterns (e.g. a given Wazuh rule id firing on a given service) — a lookup
layer above the machine-executed `playbooks/`, until `tools/incidents.py`
grows a way to match an incoming alert against one automatically.

## Quick start

```bash
uv sync
uv run secops-mcp
```

Add to Claude Desktop / Claude Code MCP config once the server entry point
exists, same as the `proxmox` and `unifi-network` servers.

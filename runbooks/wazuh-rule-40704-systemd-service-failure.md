# Runbook: Wazuh rule 40704 — "Systemd: Service exited due to a failure"

**Status:** the case study below (`snap.firmware-updater.firmware-notifier.service`
on `ubuntu`/10.88.145.178) is applied — local rule `100010` is live in
`local_rules.xml` on the manager as of 2026-09-13, verified via the
dashboard's Ruleset Test (matches to id 100010/level 0, no alert generated).
Classified as case 1 (headless host) without SSH-level confirmation of the
journal line beyond what Wazuh itself captured — revisit if this host later
turns out to need working firmware notifications.

**Trigger:** Wazuh rule id `40704`, level 5, group `systemd`. Fires on any
`systemd[N]: <unit>: Main process exited, code=exited, status=<N>/FAILURE`
line ingested from journald. This is a broad rule — it catches *every*
failing systemd unit on every agent, so don't blanket-suppress the rule
itself. Triage the specific unit, then scope any suppression to that one
unit on that one agent.

## Don't skip triage

A unit failing 5x on a fixed multi-hour cadence (a timer-driven unit) reads
very differently from one crash-looping every few seconds. Confirm which
you're looking at before deciding this is noise — rule 40704 is exactly the
kind of alert you can accidentally train yourself to ignore, and then miss
a real service dying behind it.

## Diagnose

Run on the affected agent (not through Wazuh — Wazuh only has the log line,
not live system state):

```bash
# What did the failing run actually say?
journalctl -u <unit> -n 50 --no-pager

# Is this a scheduled (timer-driven) unit, or a long-running daemon that crashed?
systemctl list-timers --all | grep <service-basename>
systemctl status <unit>

# AppArmor/snap denials in the same window as the failure?
journalctl -k --since "<failure timestamp>" | grep -i -E "apparmor|DENIED|<service-basename>"
```

## Case study: `snap.firmware-updater.firmware-notifier.service`

Seen on `ubuntu` (10.88.145.178, agent 003), firing every ~3 hours,
`status=1/FAILURE`. Full log line:

```
systemd[1342]: snap.firmware-updater.firmware-notifier.service: Main process exited, code=exited, status=1/FAILURE
```

**What it is:** the notifier component of Ubuntu 24.04+'s `firmware-updater`
snap. Runs on a timer, asks `fwupd` for pending firmware updates, and tries
to pop a desktop notification if any exist. The ~3-hour cadence is the
*timer*, not a crash loop — each invocation independently exits non-zero.

**Two ways this resolves, and they lead to opposite fixes:**

1. **Headless host, no desktop session.** No session D-Bus / notification
   daemon to talk to → the notifier has nothing to notify through and
   exits 1. Harmless, but will fire forever until acted on.
2. **A host that *should* have working firmware updates**, and `fwupd`
   itself is broken — can't reach LVFS, D-Bus activation failing, snap
   confinement/AppArmor denial, etc. Real problem, don't suppress.

The journal line from `journalctl -u snap.firmware-updater.firmware-notifier.service`
distinguishes the two immediately — it names the actual failure (missing
notification daemon vs. an fwupd/network/confinement error).

**Fix if headless (case 1)** — the notifier has no reason to run there:

```bash
# Remove the snap entirely if there's no reason to keep firmware tooling on a server:
sudo snap remove firmware-updater

# Or keep fwupd/the snap, just stop the notifier specifically:
sudo systemctl mask snap.firmware-updater.firmware-notifier.service
sudo systemctl stop  snap.firmware-updater.firmware-notifier.timer 2>/dev/null
sudo systemctl mask  snap.firmware-updater.firmware-notifier.timer 2>/dev/null
```

Firmware can still be managed via `fwupdmgr` directly; this only stops the
box from trying to render desktop toasts it has no session for.

**Fix if it should be notifying (case 2)** — chase the cause the journal
names instead of masking anything: `sudo systemctl enable --now fwupd`,
confirm LVFS reachability through this network's segmentation/firewall, and
check for AppArmor denials against the snap.

## Tune Wazuh once you've classified it

Scope suppression to the specific unit + agent, not the whole rule — this
keeps 40704 alerting on every other service failure fleet-wide. Also scope
by `<hostname>` (the agent name), not just the unit name, in case another
agent runs the same snap for a reason that isn't benign there:

```xml
<!-- local_rules.xml on the Wazuh manager -->
<group name="local,systemd,">
  <rule id="100010" level="0">
    <if_sid>40704</if_sid>
    <hostname>ubuntu</hostname>
    <match>snap.firmware-updater.firmware-notifier.service</match>
    <description>Suppressed: firmware-notifier fails on headless host (benign)</description>
  </rule>
</group>
```

`level="0"` means evaluated but not alerted. Use `level="1"` or `2` instead
if you want it to still show up in searches/dashboards but drop below your
alerting threshold.

**This is a live change to the Wazuh manager's ruleset** — applied via the
Wazuh dashboard's Rules → Custom rules → `local_rules.xml` editor (Save,
then Reload — a ruleset hot-reload, no manager restart/agent disruption),
not via SSH into VM104 (off-limits, see memory `operate-via-mcp-only`) and
not via secops-mcp itself (nothing wires that up yet — see
`src/secops_mcp/tools/ansible.py`'s TODO on real execution). Validate any
future edit the same way: the dashboard's "Ruleset Test" tool against the
exact log line, with the session cleared first — it caches decode/rule
state across tests in the same dialog, so a stale session can make an
already-reloaded rule look like it isn't matching yet.

## Where this fits in secops-mcp's alert-handling flow

This is the first documented case in what should become a general pattern:
alert type → classification questions → scoped fix → scoped Wazuh tuning.
As more of these accumulate under `runbooks/`, `tools/incidents.py`'s
correlation/triage tools should grow a way to match an incoming alert
against a known runbook by rule id or description pattern, rather than
starting from scratch each time.

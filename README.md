# Stellar Alert + Case Syslog Daemon

A long-running Python daemon that pulls **Stellar Cyber alerts and cases** from the Stellar API and forwards them to a remote collector over **TCP as newline-delimited JSON (NDJSON)**.

Each stream (alert / case) can be enabled independently. Only streams with full CLI configuration are fetched and sent.

---

## Features

- **Alert**: incremental fetch from Elasticsearch (`aella-ser-*`) → durable queue → TCP send
- **Case**: incremental fetch from REST API (`/connect/api/v1/cases`) → durable queue → TCP send
- **Optional streams**: enable alert only, case only, or both
- **Persistent state**: SQLite queue + checkpoints survive restarts
- **Checkpoints after send**: updated only after successful TCP transmission
- **Send logs**: summary written to local files after each drain batch is committed
- **Single instance**: file lock prevents duplicate processes
- **Graceful shutdown**: SIGINT / SIGTERM (press twice to force exit)
- **No third-party packages**: Python standard library only

---

## Requirements

| Item | Detail |
|------|--------|
| OS | Linux (uses `fcntl` for locking) |
| Python | 3.9+ (Ubuntu 22.04 default `python3` is fine) |
| Packages | None (`pip install` not required) |
| Network | Outbound HTTPS to Stellar host; outbound TCP to syslog destination |
| Credentials | Stellar All-Access API token |

---

## Quick Start

### Alert only

```bash
python3 Stellar_Alert_Case_Syslog.py \
  --alert-interval 60 \
  --alert-syslog-ip 10.10.10.20 \
  --alert-syslog-port 5142
```

### Case only

```bash
python3 Stellar_Alert_Case_Syslog.py \
  --case-interval 300 \
  --case-syslog-ip 10.10.10.20 \
  --case-syslog-port 5143
```

### Both alert and case

```bash
python3 Stellar_Alert_Case_Syslog.py \
  --alert-interval 60 \
  --alert-syslog-ip 10.10.10.20 \
  --alert-syslog-port 5142 \
  --case-interval 300 \
  --case-syslog-ip 10.10.10.20 \
  --case-syslog-port 5143
```

At least **one stream** must be fully configured or the daemon exits with an error.

---

## Stream Enable Rules

Each stream requires **all three** options together:

| Stream | Required options |
|--------|------------------|
| Alert | `--alert-interval`, `--alert-syslog-ip`, `--alert-syslog-port` |
| Case | `--case-interval`, `--case-syslog-ip`, `--case-syslog-port` |

- If any option in a set is missing → **error** (partial config not allowed)
- If a stream's options are omitted entirely → that stream is **disabled** (no fetch, no send, no purge)

---

## Command-Line Options

### Stellar API

| Option | Default | Description |
|--------|---------|-------------|
| `--host` | `xdr.ooo` | Stellar Cyber host |
| `--userid` | (see script) | API user email for Basic auth |
| `--token` | (see script) | All-Access API token |

### Alert (all three required to enable)

| Option | Description |
|--------|-------------|
| `--alert-interval SEC` | Fetch/send cycle interval (seconds) |
| `--alert-syslog-ip IP` | Destination IP |
| `--alert-syslog-port PORT` | Destination TCP port |

### Case (all three required to enable)

| Option | Description |
|--------|-------------|
| `--case-interval SEC` | Fetch/send cycle interval (seconds) |
| `--case-syslog-ip IP` | Destination IP |
| `--case-syslog-port PORT` | Destination TCP port |

### General

| Option | Default | Description |
|--------|---------|-------------|
| `--initial-lookback-hours` | `48` | First-run lookback when `--backfill` is not set |
| `--backfill DAYS` | off | Re-fetch/send last N days every cycle (test/replay; ignores checkpoints) |
| `--case-min-score` | `10` | Minimum case score filter |
| `--case-include-summary` / `--no-case-include-summary` | on | Include case summary in API response |
| `--case-format-summary` / `--no-case-format-summary` | on | Format case summary text |
| `--case-fetch-limit` | `200` | Cases per API page |
| `--db-path` | `~/.local/state/stellar_alert_case/queue.db` | SQLite database path |
| `--log-dir` | `~/.local/state/stellar_alert_case/logs` | Send log directory |
| `--lock-path` | `~/.local/state/stellar_alert_case/stellar_alert_case.lock` | Lock file path |
| `--debug` | off | Verbose alert/case logs to stderr (HTTP noise excluded) |

---

## Output Format

Data is sent as **NDJSON**: one JSON object per line, UTF-8, LF-terminated.

This is **not** RFC 5424 syslog text. Receivers must parse line-by-line JSON.

**Alert** example fields: `event_name`, `timestamp_utc`, `aella_tuples`, …  
**Case** example fields: `_id`, `name`, `created_at`, `score`, `ticket_id`, …

Alert and case may use the **same IP and port**; distinguish them by JSON fields on the receiver side.

---

## How It Works

```
[Enabled stream cycle]
  1. Fetch from Stellar API (incremental or backfill window)
  2. Enqueue into SQLite (dedupe by document/case _id)
  3. Drain queue: TCP send → mark sent=1
  4. Commit DB
  5. Advance checkpoint (after successful send)
  6. Write send summary logs
```

### Checkpoints

| Stream | Key | Updated when |
|--------|-----|--------------|
| Alert | `alert_search_after` | After drain commit (`[timestamp, _id]`) |
| Case | `case_last_created_at` | After drain commit (max `created_at` sent) |

With `--backfill`, checkpoints are **not** updated.

### Deduplication

- **Alert**: ES document `_id` (primary key in `alert_queue`)
- **Case**: case `_id` (primary key in `case_queue`)

In normal mode, duplicate IDs are skipped. In `--backfill` mode, existing rows are reset to `sent=0` for re-transmission.

### Throughput limits (per cycle)

| Limit | Value |
|-------|-------|
| Fetch pages | up to 10 × 200 records |
| Send | up to 2,000 records |

Overflow is handled in subsequent cycles via the queue.

---

## Local Files

| Path | Purpose |
|------|---------|
| `~/.local/state/stellar_alert_case/queue.db` | Queue + checkpoints |
| `~/.local/state/stellar_alert_case/logs/stellar_alerts_YYYYMMDD_HH.log` | Alert send summary |
| `~/.local/state/stellar_alert_case/logs/stellar_cases_YYYYMMDD_HH.log` | Case send summary |
| `~/.local/state/stellar_alert_case/stellar_alert_case.lock` | Single-instance lock |

Send log entries (after successful transmission):

- **Alert**: `sent_at`, `aella_tuples`, `event_name`, `timestamp_utc`
- **Case**: `sent_at`, `_id`, `name`, `created_at`, `score`

Sent rows in the DB are purged every **7 days** (per enabled stream). Send log files are **not** auto-deleted—use logrotate if needed.

---

## Running as a Service (systemd)

Example unit file `/etc/systemd/system/stellar-alert-case.service`:

```ini
[Unit]
Description=Stellar Cyber Alert + Case Syslog daemon
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=aella
Group=aella
WorkingDirectory=/home/aella/kt
ExecStart=/usr/bin/python3 /home/aella/kt/Stellar_Alert_Case_Syslog.py \
  --token YOUR_ALL_ACCESS_TOKEN \
  --alert-interval 60 \
  --alert-syslog-ip 10.10.10.20 \
  --alert-syslog-port 5142 \
  --case-interval 300 \
  --case-syslog-ip 10.10.10.20 \
  --case-syslog-port 5143
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now stellar-alert-case.service
journalctl -u stellar-alert-case.service -f
```

Omit alert or case options from `ExecStart` to disable that stream.

---

## Debug Mode

```bash
python3 Stellar_Alert_Case_Syslog.py --debug \
  --alert-interval 60 --alert-syslog-ip 10.10.10.20 --alert-syslog-port 5142
```

- Logs go to **stderr**
- Only `[alert]` / `[case]` tags
- Large HTTP/IDS payload fields are excluded from debug output

Redirect if needed: `2> debug.log`

---

## Backfill Mode (Testing Only)

```bash
python3 Stellar_Alert_Case_Syslog.py --backfill 3 \
  --alert-interval 60 --alert-syslog-ip 10.10.10.20 --alert-syslog-port 5142 \
  --case-interval 300 --case-syslog-ip 10.10.10.20 --case-syslog-port 5143
```

- Every cycle re-fetches and re-sends the last **N days**
- Checkpoints are ignored
- **Not recommended for production** (high load and duplicate traffic)

---

## Operational Notes

- **Token security**: avoid hardcoding tokens in the script; pass `--token` or use a protected env file with systemd.
- **TLS verification**: HTTPS certificate verification is disabled in code (`VERIFY_HTTPS = False`).
- **Time sync**: use NTP; checkpoints rely on millisecond timestamps.
- **Monitoring**: watch for `[alert] cycle error` / `[case] cycle error`, queue growth, and send log activity.
- **Same port**: alert + case on one TCP port works; ensure the receiver parses both JSON shapes.
- **Second instance**: exits with `Another instance is already running.`

---

## Troubleshooting

| Symptom | Check |
|---------|-------|
| No case/alert traffic | Stream options complete? Firewall open? Token valid? |
| `Another instance is already running` | Stop existing process or stale lock holder |
| Slow catch-up | Normal if backlog > 2,000/cycle; monitor queue pending |
| Receiver sees nothing | Confirm TCP listener on destination port; format is NDJSON not syslog |
| Re-send historical data | One-time `--backfill N`, then run without it |

---

## Related Scripts

| File | Description |
|------|-------------|
| `Stellar_Alert_Case_Syslog.py` | Main daemon (alert + case) |
| `Stellar_Alert_Syslog.py` | Legacy alert-only script |
| `Get-Stellar-Case.py` | Standalone case fetch utility (uses `requests`) |
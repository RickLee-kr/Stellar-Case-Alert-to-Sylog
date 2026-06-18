Stellar Alert + Case Syslog Daemon
A long-running Python daemon that pulls Stellar Cyber alerts and cases from the Stellar API and forwards them to a remote collector over TCP as newline-delimited JSON (NDJSON).

Each stream (alert / case) can be enabled independently. Only streams with full CLI configuration are fetched and sent.

Features
Alert: incremental fetch from Elasticsearch (aella-ser-*) → durable queue → TCP send
Case: incremental fetch from REST API (/connect/api/v1/cases) → durable queue → TCP send
Optional streams: enable alert only, case only, or both
Persistent state: SQLite queue + checkpoints survive restarts
Checkpoints after send: updated only after successful TCP transmission
Send logs: summary written to local files after each drain batch is committed
Single instance: file lock prevents duplicate processes
Graceful shutdown: SIGINT / SIGTERM (press twice to force exit)
No third-party packages: Python standard library only

Requirements
Item	Detail
OS Linux (uses fcntl for locking)
Python 3.9+ (Ubuntu 22.04 default python3 is fine)
Packages None (pip install not required)
Network Outbound HTTPS to Stellar host; outbound TCP to syslog destination
Credentials Stellar All-Access API token

Quick Start
Alert only
python3 Stellar_Alert_Case_Syslog.py \
  --alert-interval 60 \
  --alert-syslog-ip 10.10.10.20 \
  --alert-syslog-port 5142
  
Case only
python3 Stellar_Alert_Case_Syslog.py \
  --case-interval 300 \
  --case-syslog-ip 10.10.10.20 \
  --case-syslog-port 5143

Both alert and case
python3 Stellar_Alert_Case_Syslog.py \
  --alert-interval 60 \
  --alert-syslog-ip 10.10.10.20 \
  --alert-syslog-port 5142 \
  --case-interval 300 \
  --case-syslog-ip 10.10.10.20 \
  --case-syslog-port 5143
At least one stream must be fully configured or the daemon exits with an error.

Local Files
Path	Purpose
~/.local/state/stellar_alert_case/queue.db   Queue + checkpoints
~/.local/state/stellar_alert_case/logs/stellar_alerts_YYYYMMDD_HH.log   Alert send summary
~/.local/state/stellar_alert_case/logs/stellar_cases_YYYYMMDD_HH.log   Case send summary
~/.local/state/stellar_alert_case/stellar_alert_case.lock   Single-instance lock

Running as a Service (systemd)

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

sudo systemctl daemon-reload

sudo systemctl enable --now stellar-alert-case.service

journalctl -u stellar-alert-case.service -f

Debug Mode

python3 Stellar_Alert_Case_Syslog.py --debug \
  --alert-interval 60 --alert-syslog-ip 10.10.10.20 --alert-syslog-port 5142

Backfill Mode (Testing Only)

python3 Stellar_Alert_Case_Syslog.py --backfill 3 \
  --alert-interval 60 --alert-syslog-ip 10.10.10.20 --alert-syslog-port 5142 \
  --case-interval 300 --case-syslog-ip 10.10.10.20 --case-syslog-port 5143

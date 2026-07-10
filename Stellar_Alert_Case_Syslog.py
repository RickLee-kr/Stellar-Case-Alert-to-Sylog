#!/usr/bin/env python3
"""
Stellar Cyber Alert + Case → Syslog daemon.

- Alert: ES incremental fetch → durable queue → TCP (JSON per line)
- Case:  REST API incremental fetch → durable queue → TCP (JSON per line)
- SQLite DB persists across restarts (queue + checkpoints).
- Alert incremental fetch uses a closed-window watermark (fetch checkpoint); send marks queue rows sent=1 only.
- Case checkpoint advances after successful TCP send (modified_at).
- Operational event log (stellar_events_*.log): stellar_api vs syslog_sink failures.
- With --backfill N: every cycle fetches and sends the last N days (checkpoints ignored).
"""

import argparse
import base64
import fcntl
import json
import os
import random
import re
import signal
import socket
import sqlite3
import ssl
import sys
import time
import uuid
from datetime import datetime, timezone, timedelta
from typing import Any, Callable, Dict, List, Optional, Tuple
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urlunparse
from urllib.request import Request, urlopen

# ============================================================
# Defaults (overridden by CLI arguments)
# ============================================================

HOST = "xdr.ooo"
USERID = "ruda@rick.kr"
ALL_ACCESS_TOKEN = "gOVtgdxveQWc5TIcZAFbC4D0WDXtnLQESmov34gCkEWUv23BtuOid6H6iFhV0CoVYIpf4Ou0OJIHHleBER43Uw"

ALERT_INTERVAL_SEC = None
CASE_INTERVAL_SEC = None

ALERT_SYSLOG_IP = None
ALERT_SYSLOG_PORT = None
CASE_SYSLOG_IP = None
CASE_SYSLOG_PORT = None

ALERT_ENABLED = False
CASE_ENABLED = False

INITIAL_LOOKBACK_HOURS = 0
INITIAL_LOOKBACK_ZERO_MINUTES = 1  # default first-run lookback when checkpoint is absent
BACKFILL_DAYS = None  # set by --backfill (test mode)

CASE_MIN_SCORE = 10
CASE_INCLUDE_SUMMARY = True
CASE_FORMAT_SUMMARY = False
CASE_FETCH_LIMIT = 200
CASE_FETCH_TIMEOUT_SEC = 90

FETCH_SIZE = 200
MAX_FETCH_PAGES_PER_CYCLE = 10
MAX_SEND_PER_CYCLE = 2000

DB_PATH = os.path.expanduser("~/.local/state/stellar_alert_case/queue.db")
LOG_DIR = os.path.expanduser("~/.local/state/stellar_alert_case/logs")
LOCK_PATH = os.path.expanduser("~/.local/state/stellar_alert_case/stellar_alert_case.lock")

MAX_TOTAL_RETRY_SEC = 45.0
RETRY_BASE_SEC = 1.0
RETRY_MAX_SEC = 15.0
RETRY_JITTER_RATIO = 0.2

VERIFY_HTTPS = False

PURGE_EVERY_DAYS = 7
VACUUM_AFTER_PURGE = True

ALERT_FETCH_OVERLAP_MS = 5000  # legacy; incremental fetch uses closed-window watermark instead
ALERT_FETCH_STABILITY_LAG_SEC = 120
ALERT_SENT_RETENTION_MINUTES = 10

SEND_LOG_RETENTION_DAYS = 65
SEND_LOG_PURGE_INTERVAL_SEC = 86400

SINK_FAILURE_RETRY_WINDOW_SEC = 600
SINK_RECOVERY_PROBE_INTERVAL_SEC = 60

KST = timezone(timedelta(hours=9))

_shutdown = False
_signal_count = 0
DEBUG = False


class ShutdownRequested(Exception):
    """Raised when SIGINT/SIGTERM requests daemon shutdown."""


class SinkTransmissionError(Exception):
    """Raised when the TCP syslog destination is unreachable or send fails."""


class CaseFetchError(RuntimeError):
    """Raised when the Cases API fetch fails (timeout, HTTP error, JSON decode)."""

    def __init__(self, kind: str, message: str, http_code: Optional[int] = None) -> None:
        super().__init__(message)
        self.kind = kind
        self.http_code = http_code


# Hourly send-log handles (alert / case)
_log_state: Dict[str, Dict[str, Any]] = {
    "alert": {"hour_key": None, "fp": None, "prefix": "stellar_alerts"},
    "case":  {"hour_key": None, "fp": None, "prefix": "stellar_cases"},
}

# Daily operational event log (API vs syslog sink failures)
_event_log_state: Dict[str, Any] = {"day_key": None, "fp": None}

# Hourly alert fetch/enqueue trace log (one JSON line per ES hit)
_alert_fetch_log_state: Dict[str, Any] = {"hour_key": None, "fp": None}

# ============================================================
# Utility
# ============================================================

def now_ms() -> int:
    return int(time.time() * 1000)


def ensure_dir(path: str) -> None:
    d = os.path.dirname(path)
    if d and not os.path.isdir(d):
        os.makedirs(d, exist_ok=True)


def initial_lookback_ms() -> int:
    if BACKFILL_DAYS is not None and BACKFILL_DAYS > 0:
        return BACKFILL_DAYS * 24 * 3600 * 1000
    if INITIAL_LOOKBACK_HOURS == 0:
        return INITIAL_LOOKBACK_ZERO_MINUTES * 60 * 1000
    return INITIAL_LOOKBACK_HOURS * 3600 * 1000


def lookback_label() -> str:
    if BACKFILL_DAYS is not None and BACKFILL_DAYS > 0:
        return f"{BACKFILL_DAYS}d (backfill)"
    if INITIAL_LOOKBACK_HOURS == 0:
        return f"{INITIAL_LOOKBACK_ZERO_MINUTES}m"
    return f"{INITIAL_LOOKBACK_HOURS}h"


def backfill_mode() -> bool:
    return BACKFILL_DAYS is not None and BACKFILL_DAYS > 0


def stream_enabled(stream: str) -> bool:
    return ALERT_ENABLED if stream == "alert" else CASE_ENABLED


def validate_stream_cli(args) -> Optional[str]:
    """Return an error message if stream CLI options are inconsistent."""
    streams = {
        "alert": (args.alert_interval, args.alert_syslog_ip, args.alert_syslog_port),
        "case":  (args.case_interval,  args.case_syslog_ip,  args.case_syslog_port),
    }
    labels = {
        "alert": ("--alert-interval", "--alert-syslog-ip", "--alert-syslog-port"),
        "case":  ("--case-interval",  "--case-syslog-ip",  "--case-syslog-port"),
    }
    enabled = 0
    for name, values in streams.items():
        provided = [v is not None for v in values]
        if any(provided) and not all(provided):
            missing = [labels[name][i] for i, ok in enumerate(provided) if not ok]
            return (
                f"{name}: all of {', '.join(labels[name])} are required together "
                f"(missing: {', '.join(missing)})"
            )
        if all(provided):
            interval = values[0]
            if interval < 1:
                return f"{labels[name][0]} must be a positive integer (seconds)"
            enabled += 1
    if enabled == 0:
        return (
            "enable at least one stream: provide all alert options "
            "(--alert-interval, --alert-syslog-ip, --alert-syslog-port) and/or "
            "all case options (--case-interval, --case-syslog-ip, --case-syslog-port)"
        )
    return None


def backfill_cutoff_ms() -> int:
    return now_ms() - initial_lookback_ms()


def queue_insert(
    conn: sqlite3.Connection,
    table: str,
    event_id: str,
    sort_ts: int,
    sort_id: str,
    payload_text: str,
    inserted_at: int,
) -> bool:
    """Insert into case_queue. In backfill mode, re-queue for resend."""
    if backfill_mode():
        cur = conn.execute(
            f"INSERT INTO {table}(event_id, sort_ts, sort_id, payload, sent, inserted_at) "
            "VALUES(?, ?, ?, ?, 0, ?) "
            "ON CONFLICT(event_id) DO UPDATE SET "
            "sort_ts=excluded.sort_ts, sort_id=excluded.sort_id, "
            "payload=excluded.payload, sent=0",
            (event_id, sort_ts, sort_id, payload_text, inserted_at),
        )
    else:
        cur = conn.execute(
            f"INSERT OR IGNORE INTO {table}(event_id, sort_ts, sort_id, payload, sent, inserted_at) "
            "VALUES(?, ?, ?, ?, 0, ?)",
            (event_id, sort_ts, sort_id, payload_text, inserted_at),
        )
    return cur.rowcount > 0


def _alert_stellar_uuid_from_src(src: dict) -> Optional[str]:
    su = src.get("stellar_uuid")
    if su not in (None, ""):
        return str(su)
    return None


def _alert_find_existing_by_stellar_uuid(
    conn: sqlite3.Connection, stellar_uuid: str,
) -> Optional[str]:
    row = conn.execute(
        "SELECT event_id FROM alert_queue WHERE stellar_uuid=? LIMIT 1",
        (stellar_uuid,),
    ).fetchone()
    if row:
        return str(row[0])
    row = conn.execute(
        "SELECT event_id FROM alert_queue "
        "WHERE (stellar_uuid IS NULL OR stellar_uuid='') "
        "AND json_extract(payload, '$.stellar_uuid')=? LIMIT 1",
        (stellar_uuid,),
    ).fetchone()
    return str(row[0]) if row else None


def alert_queue_insert(
    conn: sqlite3.Connection,
    event_id: str,
    sort_ts: int,
    sort_id: str,
    payload_text: str,
    inserted_at: int,
    stellar_uuid: Optional[str] = None,
) -> Tuple[str, bool, Optional[str]]:
    """
    Insert into alert_queue with event_id and optional stellar_uuid idempotency.

    Returns (reason, inserted, existing_event_id) where reason is one of:
      new, duplicate_document_id, duplicate_stellar_uuid, backfill_requeued
    """
    su = stellar_uuid if stellar_uuid not in (None, "") else None

    if backfill_mode():
        conn.execute(
            "INSERT INTO alert_queue("
            "event_id, sort_ts, sort_id, payload, sent, inserted_at, stellar_uuid, "
            "send_attempt_count, last_sent_at"
            ") VALUES(?, ?, ?, ?, 0, ?, ?, 0, NULL) "
            "ON CONFLICT(event_id) DO UPDATE SET "
            "sort_ts=excluded.sort_ts, sort_id=excluded.sort_id, "
            "payload=excluded.payload, sent=0, stellar_uuid=excluded.stellar_uuid",
            (event_id, sort_ts, sort_id, payload_text, inserted_at, su),
        )
        return "backfill_requeued", True, None

    if su:
        existing = _alert_find_existing_by_stellar_uuid(conn, su)
        if existing and existing != str(event_id):
            return "duplicate_stellar_uuid", False, existing

    cur = conn.execute(
        "INSERT OR IGNORE INTO alert_queue("
        "event_id, sort_ts, sort_id, payload, sent, inserted_at, stellar_uuid, "
        "send_attempt_count, last_sent_at"
        ") VALUES(?, ?, ?, ?, 0, ?, ?, 0, NULL)",
        (event_id, sort_ts, sort_id, payload_text, inserted_at, su),
    )
    if cur.rowcount > 0:
        return "new", True, None
    return "duplicate_document_id", False, str(event_id)


def _make_batch_id() -> str:
    return datetime.now(KST).strftime("%Y%m%d%H%M%S") + "-" + uuid.uuid4().hex[:8]


# Alert fields omitted from --debug output (HTTP/browser/IDS payload noise).
_DEBUG_ALERT_OMIT = frozenset({
    "actual", "ids", "xdr_event", "payload_details", "metadata", "detected_values",
    "detected_fields", "request", "response", "headers", "body", "user_agent",
    "url", "uri", "http", "http_request", "http_response", "raw", "raw_data",
    "raw_msg", "msg", "message", "data", "events", "flow", "file", "files",
    "process", "processes", "registry", "dns", "tls", "ssl", "email",
})

_DEBUG_ALERT_SUMMARY_KEYS = (
    "anomaly_id", "anomaly_tag", "severity", "score", "srcip", "dstip",
    "srcport", "dstport", "appid_name", "direction", "engid", "tenant_name", "cust_id",
    "srcip_host", "dstip_host", "engid_name",
)

_DEBUG_CASE_SUMMARY_KEYS = (
    "_id", "name", "created_at", "modified_at", "score", "status", "severity",
    "size", "ticket_id", "tenant_name", "summary", "tags", "assignee_name",
)


def _truncate_debug(value: Any, max_len: int = 240) -> Any:
    if isinstance(value, str) and len(value) > max_len:
        return value[: max_len - 3] + "..."
    return value


def _resolve_alert_event_name(obj: dict) -> Optional[str]:
    name = obj.get("event_name")
    if name:
        return str(name)
    xdr = obj.get("xdr_event")
    if isinstance(xdr, dict):
        for key in ("name", "display_name"):
            val = xdr.get(key)
            if val:
                return str(val)
    return None


def _epoch_ms_to_kst_iso(ms: Any) -> Optional[str]:
    try:
        dt = datetime.fromtimestamp(int(ms) / 1000, tz=timezone.utc).astimezone(KST)
        return dt.isoformat(timespec="milliseconds")
    except (TypeError, ValueError, OSError):
        return None


def _epoch_ms_to_utc_iso(ms: Any) -> Optional[str]:
    try:
        dt = datetime.fromtimestamp(int(ms) / 1000, tz=timezone.utc)
        return dt.isoformat(timespec="milliseconds")
    except (TypeError, ValueError, OSError):
        return None


def _utc_iso_to_kst_iso(value: Any) -> Optional[str]:
    if value is None:
        return None
    if isinstance(value, (int, float)):
        return _epoch_ms_to_kst_iso(value)
    try:
        s = str(value).strip()
        if not s:
            return None
        if s.endswith("Z"):
            s = s[:-1] + "+00:00"
        dt = datetime.fromisoformat(s)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(KST).isoformat(timespec="milliseconds")
    except (TypeError, ValueError):
        return None


STELLAR_RECORD_TYPE_ALERT = "alert"
STELLAR_RECORD_TYPE_CASE = "case"

_CASE_KILL_CHAIN_STAGE_FIELDS = (
    "initial_attempts",
    "persistent_foothold",
    "exploration",
    "propagation",
    "exfiltration_impact",
)

def _normalize_case_kill_chain_label(label: Any) -> str:
    if label is None:
        return ""
    s = str(label).strip().lower()
    s = s.replace("&", " and ")
    s = re.sub(r"[-_]+", " ", s)
    s = re.sub(r"[^a-z0-9\s]", "", s)
    s = re.sub(r"\s+", " ", s).strip()
    s = re.sub(r"\band\b", "", s)
    return re.sub(r"\s+", " ", s).strip()


_CASE_KILL_CHAIN_STAGE_LABELS = {
    _normalize_case_kill_chain_label("Initial Attempts"): "initial_attempts",
    _normalize_case_kill_chain_label("Persistent Foothold"): "persistent_foothold",
    _normalize_case_kill_chain_label("Exploration"): "exploration",
    _normalize_case_kill_chain_label("Propagation"): "propagation",
    _normalize_case_kill_chain_label("Exfiltration & Impact"): "exfiltration_impact",
}

_CASE_KILL_CHAIN_STAGES_RE = re.compile(
    r"xdr\s+kill\s+chain\s+stages?\s*:\s*(.+)",
    re.IGNORECASE,
)

_CASE_KILL_CHAIN_STAGE_DICT_KEYS = (
    "stages",
    "kill_chain_stages",
    "xdr_kill_chain_stages",
    "killChainStages",
)

_CASE_KILL_CHAIN_NESTED_DICT_KEYS = (
    "kill_chain",
    "killChain",
    "xdr_kill_chain",
    "xdrKillChain",
    "kill_chain_summary",
    "killChainSummary",
)


def _case_kill_chain_stages_zero() -> Dict[str, int]:
    return {name: 0 for name in _CASE_KILL_CHAIN_STAGE_FIELDS}


def _case_kill_chain_stage_active(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value != 0
    if isinstance(value, str):
        return value.strip().lower() in ("1", "true", "yes", "y", "on")
    return bool(value)


def _case_kill_chain_apply_label(result: Dict[str, int], label: Any) -> None:
    if label is None:
        return
    field = _CASE_KILL_CHAIN_STAGE_LABELS.get(_normalize_case_kill_chain_label(label))
    if field:
        result[field] = 1


def _case_kill_chain_apply_stages_value(result: Dict[str, int], stages: Any) -> None:
    if isinstance(stages, dict):
        for label, value in stages.items():
            if _case_kill_chain_stage_active(value):
                _case_kill_chain_apply_label(result, label)
    elif isinstance(stages, list):
        for item in stages:
            if isinstance(item, dict):
                label = item.get("name") or item.get("label") or item.get("stage")
                if label is None:
                    continue
                active = item.get("active", item.get("value", True))
                if _case_kill_chain_stage_active(active):
                    _case_kill_chain_apply_label(result, label)
            else:
                _case_kill_chain_apply_label(result, item)


def _case_kill_chain_apply_stages_from_dict_container(
    result: Dict[str, int], container: dict,
) -> None:
    for key in _CASE_KILL_CHAIN_STAGE_DICT_KEYS:
        stages = container.get(key)
        if stages is not None:
            _case_kill_chain_apply_stages_value(result, stages)


def _parse_case_kill_chain_stages_from_dict(summary: dict) -> Dict[str, int]:
    result = _case_kill_chain_stages_zero()
    _case_kill_chain_apply_stages_from_dict_container(result, summary)
    for key in _CASE_KILL_CHAIN_NESTED_DICT_KEYS:
        nested = summary.get(key)
        if isinstance(nested, dict):
            _case_kill_chain_apply_stages_from_dict_container(result, nested)
    return result


def _parse_case_kill_chain_stages_from_string(summary: str) -> Dict[str, int]:
    result = _case_kill_chain_stages_zero()
    for line in summary.splitlines():
        match = _CASE_KILL_CHAIN_STAGES_RE.search(line)
        if not match:
            continue
        stages_part = match.group(1).strip()
        if stages_part:
            for stage_name in stages_part.split(","):
                _case_kill_chain_apply_label(result, stage_name.strip())
        return result
    match = _CASE_KILL_CHAIN_STAGES_RE.search(summary)
    if match:
        stages_part = match.group(1).strip()
        if stages_part:
            for stage_name in stages_part.split(","):
                _case_kill_chain_apply_label(result, stage_name.strip())
    return result


def parse_case_kill_chain_stages(summary: Any) -> Dict[str, int]:
    """
    Parse XDR Kill Chain Stages from a case summary.

    Supports formatted string summaries (``Observed N XDR Kill Chain Stages: ...``)
    and dict summaries (``{"stages": {...}}`` or ``{"stages": [...]}``).
    Returns all-zero ints when summary is missing or no stages are found.
    """
    if summary is None:
        return _case_kill_chain_stages_zero()
    if isinstance(summary, dict):
        return _parse_case_kill_chain_stages_from_dict(summary)
    if isinstance(summary, str):
        if not summary.strip():
            return _case_kill_chain_stages_zero()
        return _parse_case_kill_chain_stages_from_string(summary)
    return _case_kill_chain_stages_zero()


def _case_existing_kill_chain_fields(src: dict) -> Dict[str, int]:
    result = _case_kill_chain_stages_zero()
    for key in _CASE_KILL_CHAIN_STAGE_FIELDS:
        try:
            val = int(src.get(key, 0) or 0)
            result[key] = 1 if val != 0 else 0
        except (TypeError, ValueError):
            result[key] = 0
    return result


def _case_resolve_kill_chain_fields(src: dict) -> Tuple[Dict[str, int], str]:
    summary = src.get("summary")
    parsed = parse_case_kill_chain_stages(summary)

    if any(parsed.values()):
        if isinstance(summary, str):
            return parsed, "summary_string"
        if isinstance(summary, dict):
            return parsed, "summary_dict"
        return parsed, "summary"

    existing = _case_existing_kill_chain_fields(src)
    if any(existing.values()):
        return existing, "existing_payload_fields"

    if summary is None:
        return parsed, "missing_summary"

    return parsed, "unparsed_summary"


def _case_kill_chain_outbound_fields(outbound: dict) -> Dict[str, int]:
    return {name: outbound.get(name, 0) for name in _CASE_KILL_CHAIN_STAGE_FIELDS}


# TEMP(diagnostic): remove after production kill-chain root-cause is closed.
def _case_summary_diagnostic_fields(payload: dict) -> Dict[str, Any]:
    """Build summary/kill-chain diagnostic fields for send log and debug output."""
    if not isinstance(payload, dict):
        return {
            "summary_present": False,
            "summary_type": "NoneType",
            "summary_first_line": None,
            "parsed_kill_chain_stages": _case_kill_chain_stages_zero(),
            "kill_chain_parse_source": "non_dict_payload",
        }
    summary = payload.get("summary")
    parsed, source = _case_resolve_kill_chain_fields(payload)
    lines = summary.splitlines() if isinstance(summary, str) else []
    fields: Dict[str, Any] = {
        "summary_present": summary is not None,
        "summary_type": type(summary).__name__ if summary is not None else "NoneType",
        "summary_first_line": lines[0] if lines else None,
        "parsed_kill_chain_stages": parsed,
        "kill_chain_parse_source": payload.get("kill_chain_parse_source") or source,
    }
    if payload.get("summary_fetch_fallback"):
        fields["summary_fetch_fallback"] = True
    return fields


def _alert_syslog_payload(src: Any) -> dict:
    """Shallow-copy alert payload and add stellar_record_type for syslog (does not mutate src)."""
    outbound = dict(src) if isinstance(src, dict) else {"raw": src}
    outbound["stellar_record_type"] = STELLAR_RECORD_TYPE_ALERT
    return outbound


def _case_syslog_payload(src: Any) -> dict:
    """Shallow-copy case payload and add stellar_record_type for syslog (does not mutate src)."""
    outbound = dict(src) if isinstance(src, dict) else {"raw": src}
    outbound["stellar_record_type"] = STELLAR_RECORD_TYPE_CASE
    if isinstance(src, dict):
        kill_chain_fields, parse_source = _case_resolve_kill_chain_fields(src)
        outbound.update(kill_chain_fields)
        outbound["kill_chain_parse_source"] = src.get("kill_chain_parse_source") or parse_source
        if src.get("summary_fetch_fallback"):
            outbound["summary_fetch_fallback"] = True
        for src_key, utc_key in (
            ("created_at", "created_at_utc"),
            ("modified_at", "modified_at_utc"),
        ):
            ts = _epoch_ms_to_utc_iso(src.get(src_key))
            if ts is not None:
                outbound[utc_key] = ts
    return outbound


def _alert_send_log_fields(obj: dict, meta: Optional[dict] = None) -> dict:
    """Build ordered alert send-log fields (stellar_record_type + stellar_uuid first)."""
    meta = meta or {}
    payload = obj if meta.get("payload") is None else meta.get("payload", obj)
    if not isinstance(payload, dict):
        payload = {}

    fields: Dict[str, Any] = {}

    def put(key: str, value: Any) -> None:
        if value is not None:
            fields[key] = value

    put("stellar_record_type", payload.get("stellar_record_type") or STELLAR_RECORD_TYPE_ALERT)
    put("stellar_uuid", payload.get("stellar_uuid"))
    put("event_id", meta.get("event_id"))
    put("sort_ts", meta.get("sort_ts"))
    put("sort_id", meta.get("sort_id"))
    put("batch_id", meta.get("batch_id"))
    put("send_attempt_count", meta.get("send_attempt_count"))
    if meta.get("backfill"):
        put("backfill", True)

    put("orig_id", payload.get("orig_id"))
    put("orig_index", payload.get("orig_index"))
    put("timestamp_utc", payload.get("timestamp_utc"))

    event_name = _resolve_alert_event_name(payload)
    put("event_name", event_name)

    ts_kst = _utc_iso_to_kst_iso(payload.get("timestamp_utc"))
    put("timestamp_kst", ts_kst)

    for key in ("srcip", "dstip", "srcip_host", "dstip_host", "engid_name"):
        put(key, payload.get(key))

    return fields


def _case_send_log_fields(obj: dict, meta: Optional[dict] = None) -> dict:
    meta = meta or {}
    payload = obj if meta.get("payload") is None else meta.get("payload", obj)
    if not isinstance(payload, dict):
        payload = {}

    fields: Dict[str, Any] = {}
    fields["stellar_record_type"] = (
        payload.get("stellar_record_type") if isinstance(payload, dict) else None
    ) or STELLAR_RECORD_TYPE_CASE
    event_id = meta.get("event_id") or payload.get("_id")
    if event_id is not None:
        fields["event_id"] = event_id
    for key in ("sort_ts", "sort_id", "batch_id", "send_attempt_count"):
        if meta.get(key) is not None:
            fields[key] = meta.get(key)
    if meta.get("backfill"):
        fields["backfill"] = True
    for key in ("_id", "name", "score"):
        val = payload.get(key)
        if val is not None:
            fields[key] = val
    for key in ("modified_at", "created_at"):
        ts = _epoch_ms_to_kst_iso(payload.get(key))
        if ts is not None:
            fields[key] = ts
    for key in _CASE_KILL_CHAIN_STAGE_FIELDS:
        val = payload.get(key)
        if isinstance(val, int):
            fields[key] = val
        elif val is not None:
            try:
                fields[key] = int(val)
            except (TypeError, ValueError):
                fields[key] = 0
        else:
            fields[key] = 0
    # TEMP(diagnostic): remove after production kill-chain root-cause is closed.
    fields.update(_case_summary_diagnostic_fields(payload))
    return fields


def _debug_alert_summary(src: dict) -> dict:
    summary = _alert_send_log_fields(src)
    for k in _DEBUG_ALERT_SUMMARY_KEYS:
        if src.get(k) is not None:
            summary[k] = src.get(k)
    for key, value in src.items():
        if key in summary or key in _DEBUG_ALERT_OMIT:
            continue
        if isinstance(value, (dict, list)):
            continue
        if isinstance(value, str) and len(value) > 120:
            continue
        summary[key] = value
    return summary


def _debug_case_summary(case: dict) -> dict:
    summary = {k: _truncate_debug(v) for k, v in _case_send_log_fields(case).items()}
    for k in _DEBUG_CASE_SUMMARY_KEYS:
        if k in ("modified_at", "created_at"):
            continue
        if case.get(k) is not None:
            summary[k] = _truncate_debug(case.get(k))
    return summary


def debug_log(tag: str, message: str, **fields) -> None:
    """Print alert/case runtime info to stderr when --debug is enabled."""
    if not DEBUG or tag not in ("alert", "case"):
        return
    ts = datetime.now(KST).isoformat(timespec="seconds")
    lines = [f"[DEBUG {ts}] [{tag}] {message}"]
    for key, value in fields.items():
        if key == "payload" and isinstance(value, dict):
            if tag == "alert":
                value = _debug_alert_summary(value)
            elif tag == "case":
                value = _debug_case_summary(value)
        if isinstance(value, dict):
            rendered = json.dumps(value, ensure_ascii=False, indent=2)
            lines.append(f"  {key}:\n{rendered}")
        elif isinstance(value, list):
            lines.append(f"  {key}: [{len(value)} items]")
        else:
            lines.append(f"  {key}: {value}")
    print("\n".join(lines), file=sys.stderr, flush=True)


def queue_pending_count(conn: sqlite3.Connection, table: str) -> int:
    row = conn.execute(f"SELECT COUNT(*) FROM {table} WHERE sent=0").fetchone()
    return int(row[0]) if row else 0


def _jitter(delay: float) -> float:
    j = delay * RETRY_JITTER_RATIO
    return max(0.05, delay + random.uniform(-j, j))


def shutdown_requested() -> bool:
    return _shutdown


def check_shutdown() -> None:
    if _shutdown:
        raise ShutdownRequested()


def interruptible_sleep(seconds: float) -> None:
    if seconds <= 0:
        return
    end = time.time() + seconds
    while time.time() < end:
        check_shutdown()
        time.sleep(min(0.25, end - time.time()))


def with_backoff(op: Callable, *, max_total_sec: float = MAX_TOTAL_RETRY_SEC):
    start = time.time()
    attempt = 0
    last_exc = None
    while True:
        check_shutdown()
        attempt += 1
        try:
            return op()
        except ShutdownRequested:
            raise
        except Exception as e:
            last_exc = e
            if time.time() - start >= max_total_sec:
                raise last_exc
            delay = min(RETRY_MAX_SEC, RETRY_BASE_SEC * (2 ** max(0, attempt - 1)))
            interruptible_sleep(_jitter(delay))


# ============================================================
# DB (alert_queue + case_queue + kv; legacy wipe once if incompatible)
# ============================================================

SCHEMA_VERSION = "alert_case_v3"

ALERT_QUEUE_EXTRA_COLS = (
    ("dedup_key", "TEXT"),
    ("send_attempt_count", "INTEGER NOT NULL DEFAULT 0"),
    ("last_sent_at", "INTEGER"),
    ("stellar_uuid", "TEXT"),
)


def db_wipe() -> None:
    for suffix in ("", "-wal", "-shm"):
        path = DB_PATH + suffix if suffix else DB_PATH
        if os.path.isfile(path):
            os.remove(path)


def _table_names(conn: sqlite3.Connection) -> set:
    rows = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table'"
    ).fetchall()
    return {row[0] for row in rows}


def _has_current_schema(conn: sqlite3.Connection) -> bool:
    return {"alert_queue", "case_queue", "kv"}.issubset(_table_names(conn))


def db_prepare() -> None:
    """
    Open or create the DB.

    - New path: create tables and continue.
    - Current schema: keep queue, checkpoints, unsent rows across restarts.
    - Legacy/incompatible (e.g. old ``queue`` table from Stellar_Alert_Syslog.py):
      wipe once and recreate — only when this script cannot use the existing file.
    """
    if not os.path.isfile(DB_PATH):
        conn = db_connect()
        try:
            db_init(conn)
            kv_set(conn, "schema_version", SCHEMA_VERSION)
            debug_log("db", "created new database", path=DB_PATH)
        finally:
            conn.close()
        return

    conn = db_connect()
    try:
        if _has_current_schema(conn):
            db_migrate(conn)
            if kv_get(conn, "schema_version") != SCHEMA_VERSION:
                kv_set(conn, "schema_version", SCHEMA_VERSION)
            debug_log(
                "db", "opened existing database",
                path=DB_PATH,
                alert_pending=queue_pending_count(conn, "alert_queue"),
                case_pending=queue_pending_count(conn, "case_queue"),
            )
            return

        tables = _table_names(conn)
        legacy = "queue" in tables and "alert_queue" not in tables
        reason = "legacy alert-only DB" if legacy else "incompatible schema"
        print(f"DB reset ({reason}): {DB_PATH}", file=sys.stderr)
    finally:
        conn.close()

    db_wipe()
    conn = db_connect()
    try:
        db_init(conn)
        kv_set(conn, "schema_version", SCHEMA_VERSION)
    finally:
        conn.close()


def db_connect() -> sqlite3.Connection:
    ensure_dir(DB_PATH)
    conn = sqlite3.connect(DB_PATH)
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA synchronous=NORMAL;")
    return conn


def _queue_column_names(conn: sqlite3.Connection, table: str) -> set:
    rows = conn.execute(f"PRAGMA table_info({table})").fetchall()
    return {row[1] for row in rows}


def db_migrate(conn: sqlite3.Connection) -> None:
    """Add optional alert_queue columns and indexes without wiping existing data."""
    cols = _queue_column_names(conn, "alert_queue")
    for name, typedef in ALERT_QUEUE_EXTRA_COLS:
        if name not in cols:
            conn.execute(f"ALTER TABLE alert_queue ADD COLUMN {name} {typedef}")
    conn.execute("DROP INDEX IF EXISTS idx_alert_queue_dedup_key")
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_alert_queue_stellar_uuid "
        "ON alert_queue(stellar_uuid) WHERE stellar_uuid IS NOT NULL AND stellar_uuid != ''"
    )
    conn.commit()


def _create_queue_table(conn: sqlite3.Connection, table: str) -> None:
    if table == "alert_queue":
        conn.execute("""
            CREATE TABLE IF NOT EXISTS alert_queue (
                event_id TEXT PRIMARY KEY,
                sort_ts INTEGER NOT NULL,
                sort_id TEXT NOT NULL,
                payload TEXT NOT NULL,
                sent INTEGER NOT NULL DEFAULT 0,
                inserted_at INTEGER NOT NULL,
                dedup_key TEXT,
                send_attempt_count INTEGER NOT NULL DEFAULT 0,
                last_sent_at INTEGER,
                stellar_uuid TEXT
            )
        """)
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_alert_queue_stellar_uuid "
            "ON alert_queue(stellar_uuid) WHERE stellar_uuid IS NOT NULL AND stellar_uuid != ''"
        )
        return
    conn.execute(f"""
        CREATE TABLE IF NOT EXISTS {table} (
            event_id TEXT PRIMARY KEY,
            sort_ts INTEGER NOT NULL,
            sort_id TEXT NOT NULL,
            payload TEXT NOT NULL,
            sent INTEGER NOT NULL DEFAULT 0,
            inserted_at INTEGER NOT NULL
        )
    """)


def db_init(conn: sqlite3.Connection) -> None:
    _create_queue_table(conn, "alert_queue")
    _create_queue_table(conn, "case_queue")
    conn.execute("""
        CREATE TABLE IF NOT EXISTS kv (
            k TEXT PRIMARY KEY,
            v TEXT NOT NULL
        )
    """)
    conn.commit()
    db_migrate(conn)


def backfill_prepare(conn: sqlite3.Connection) -> None:
    """Backfill mode: clear checkpoints on start (fetch window is enforced each cycle)."""
    conn.execute(
        "DELETE FROM kv WHERE k IN (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        ("alert_search_after", "alert_last_event_id", "alert_fetch_watermark_ms",
         "alert_fetch_window_state", "case_last_modified_at", "case_last_created_at",
         "alert_last_purge_ts", "case_last_purge_ts", "send_log_last_purge_ts"),
    )
    conn.commit()


def kv_get(conn: sqlite3.Connection, key: str) -> Optional[str]:
    row = conn.execute("SELECT v FROM kv WHERE k=?", (key,)).fetchone()
    return row[0] if row else None


def kv_set(conn: sqlite3.Connection, key: str, value: str) -> None:
    conn.execute(
        "INSERT INTO kv(k, v) VALUES(?, ?) ON CONFLICT(k) DO UPDATE SET v=excluded.v",
        (key, value),
    )
    conn.commit()


# ============================================================
# HTTP
# ============================================================

def make_ssl_context() -> ssl.SSLContext:
    if VERIFY_HTTPS:
        return ssl.create_default_context()
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


SSL_CTX = make_ssl_context()


def http_post(url: str, headers: dict, data_bytes: bytes, timeout: int = 20):
    req = Request(url, data=data_bytes, headers=headers, method="POST")
    try:
        with urlopen(req, context=SSL_CTX, timeout=timeout) as resp:
            return resp.getcode(), resp.read()
    except HTTPError as e:
        return e.code, e.read()


def http_get(url: str, headers: dict, data_bytes: Optional[bytes] = None, timeout: int = 25):
    req = Request(url, data=data_bytes, headers=headers, method="GET")
    try:
        with urlopen(req, context=SSL_CTX, timeout=timeout) as resp:
            return resp.getcode(), resp.read()
    except HTTPError as e:
        return e.code, e.read()


def get_access_token() -> str:
    if not USERID or "@" not in USERID:
        raise RuntimeError("USERID must be an email address for Basic auth.")
    if not ALL_ACCESS_TOKEN:
        raise RuntimeError("ALL_ACCESS_TOKEN is required.")

    auth = base64.b64encode(f"{USERID}:{ALL_ACCESS_TOKEN}".encode("utf-8")).decode("utf-8")
    headers = {
        "Authorization": "Basic " + auth,
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept": "application/json",
    }
    url = urlunparse(("https", HOST, "/connect/api/v1/access_token", "", "", ""))
    code, body = http_post(url, headers, b"", timeout=20)
    if code != 200:
        raise RuntimeError(f"Auth failed HTTP {code}: {body[:200]!r}")
    obj = json.loads(body.decode("utf-8"))
    debug_log("auth", "access token obtained", host=HOST, userid=USERID)
    return obj["access_token"]


# ============================================================
# TCP sink: one JSON object per line (LF framing)
# ============================================================

def tcp_connect_sink(ip: str, port: int):
    s = socket.create_connection((ip, port), timeout=10)
    s.settimeout(10)
    s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    return s


def json_line_send(sock, json_obj: dict) -> None:
    line = json.dumps(json_obj, ensure_ascii=False, separators=(",", ":")) + "\n"
    sock.sendall(line.encode("utf-8"))


def tcp_probe_sink(ip: str, port: int) -> bool:
    try:
        s = tcp_connect_sink(ip, port)
        s.close()
        return True
    except OSError:
        return False


def _send_json_on_sink(sock, ip: str, port: int, json_obj: dict):
    try:
        json_line_send(sock, json_obj)
        return sock
    except (BrokenPipeError, ConnectionResetError, OSError):
        try:
            sock.close()
        except Exception:
            pass
        try:
            sock = tcp_connect_sink(ip, port)
            json_line_send(sock, json_obj)
            return sock
        except OSError as e:
            raise SinkTransmissionError(f"send failed: {e}") from e


# Per-stream syslog receiver health (alert / case are independent).
_sink_health: Dict[str, Dict[str, Any]] = {
    "alert": {"mode": "normal", "failure_started": None, "retry_attempt": 0, "next_wake": 0.0},
    "case":  {"mode": "normal", "failure_started": None, "retry_attempt": 0, "next_wake": 0.0},
}


def _sink_target(stream: str) -> tuple:
    if stream == "alert":
        return ALERT_SYSLOG_IP, ALERT_SYSLOG_PORT
    return CASE_SYSLOG_IP, CASE_SYSLOG_PORT


def _sink_retry_delay_sec(retry_attempt: int) -> float:
    """Wait before next retry: 0→60s, 1→300s, 2→600s, … (+300s each step)."""
    if retry_attempt <= 0:
        return 60.0
    if retry_attempt == 1:
        return 300.0
    return 300.0 + (retry_attempt - 1) * 300.0


def sink_probe(stream: str) -> bool:
    ip, port = _sink_target(stream)
    return tcp_probe_sink(ip, port)


def sink_on_failure(stream: str, now: float, error: Optional[str] = None) -> None:
    h = _sink_health[stream]
    if h["mode"] != "normal":
        return
    h["mode"] = "retrying"
    h["failure_started"] = now
    h["retry_attempt"] = 0
    delay = _sink_retry_delay_sec(0)
    h["next_wake"] = now + delay
    ip, port = _sink_target(stream)
    print(
        f"[{stream}] [syslog_sink] receiver unreachable ({ip}:{port}); "
        f"retrying queued data for up to {SINK_FAILURE_RETRY_WINDOW_SEC // 60} minutes "
        f"(next retry in {delay:.0f}s)",
        file=sys.stderr,
    )
    log_operational_event(
        stream, "syslog_sink", "transmit_failed",
        f"Cannot send to syslog receiver {ip}:{port}",
        error=error, destination=f"{ip}:{port}",
        sink_mode="retrying", next_retry_in_sec=delay,
    )
    debug_log(stream, "sink enter retrying", next_retry_in_sec=delay)


def sink_on_retry_failed(stream: str, now: float, error: Optional[str] = None) -> None:
    h = _sink_health[stream]
    h["retry_attempt"] += 1
    started = h["failure_started"] or now
    elapsed = now - started
    ip, port = _sink_target(stream)
    if elapsed >= SINK_FAILURE_RETRY_WINDOW_SEC:
        h["mode"] = "paused"
        h["next_wake"] = now + SINK_RECOVERY_PROBE_INTERVAL_SEC
        print(
            f"[{stream}] [syslog_sink] receiver still down ({ip}:{port}) after "
            f"{SINK_FAILURE_RETRY_WINDOW_SEC // 60} minutes; pausing fetch "
            f"(probe every {SINK_RECOVERY_PROBE_INTERVAL_SEC}s)",
            file=sys.stderr,
        )
        log_operational_event(
            stream, "syslog_sink", "sink_paused",
            f"Syslog receiver unavailable for {int(elapsed)}s; fetch paused",
            error=error, destination=f"{ip}:{port}",
            sink_mode="paused", elapsed_sec=round(elapsed, 1),
            retry_attempts=h["retry_attempt"],
        )
        debug_log(stream, "sink enter paused", elapsed_sec=round(elapsed, 1))
        return
    delay = _sink_retry_delay_sec(h["retry_attempt"])
    h["next_wake"] = now + delay
    log_operational_event(
        stream, "syslog_sink", "retry_failed",
        f"Syslog send retry failed; next attempt in {delay:.0f}s",
        error=error, destination=f"{ip}:{port}",
        sink_mode="retrying", retry_attempt=h["retry_attempt"],
        next_retry_in_sec=delay, elapsed_sec=round(elapsed, 1),
    )
    debug_log(
        stream, "sink retry failed",
        attempt=h["retry_attempt"],
        next_retry_in_sec=delay,
        elapsed_sec=round(elapsed, 1),
    )


def sink_on_success(stream: str) -> None:
    h = _sink_health[stream]
    prev_mode = h["mode"]
    if prev_mode != "normal":
        ip, port = _sink_target(stream)
        print(f"[{stream}] [syslog_sink] receiver recovered ({ip}:{port})", file=sys.stderr)
        log_operational_event(
            stream, "syslog_sink", "recovered",
            f"Syslog receiver {ip}:{port} is reachable again",
            destination=f"{ip}:{port}",
            previous_sink_mode=prev_mode, sink_mode="normal",
        )
        debug_log(stream, "sink recovered", previous_mode=prev_mode)
    h["mode"] = "normal"
    h["failure_started"] = None
    h["retry_attempt"] = 0
    h["next_wake"] = 0.0


def stream_next_wake(stream: str, now: float, interval_sec: int) -> float:
    h = _sink_health[stream]
    if h["mode"] == "paused":
        return now + SINK_RECOVERY_PROBE_INTERVAL_SEC
    if h["mode"] == "retrying":
        return h["next_wake"]
    return now + interval_sec


# ============================================================
# Send log (hourly rotation, separate files per stream; written after drain commit)
# ============================================================

def ensure_log_dir() -> None:
    if LOG_DIR and not os.path.isdir(LOG_DIR):
        os.makedirs(LOG_DIR, exist_ok=True)


def _log_hour_key_now() -> str:
    return datetime.now(KST).strftime("%Y%m%d_%H")


def _open_log_for_stream(stream: str, hour_key: str) -> None:
    ensure_log_dir()
    st = _log_state[stream]
    if st["fp"]:
        st["fp"].close()
    path = os.path.join(LOG_DIR, f"{st['prefix']}_{hour_key}.log")
    st["fp"] = open(path, "a", encoding="utf-8")
    st["hour_key"] = hour_key


def log_sent(stream: str, wrapper: dict) -> None:
    hour_key = _log_hour_key_now()
    st = _log_state[stream]
    if hour_key != st["hour_key"] or st["fp"] is None:
        _open_log_for_stream(stream, hour_key)

    payload = wrapper.get("payload")
    if stream == "alert":
        body = _alert_send_log_fields(payload if isinstance(payload, dict) else {}, wrapper)
    elif stream == "case":
        body = _case_send_log_fields(payload if isinstance(payload, dict) else {}, wrapper)
    else:
        body = {}

    entry: Dict[str, Any] = {}
    if "event_id" in body:
        entry["event_id"] = body["event_id"]
    entry["sent_at"] = datetime.now(KST).isoformat(timespec="milliseconds")
    for key, value in body.items():
        if key != "event_id":
            entry[key] = value
    st["fp"].write(json.dumps(entry, ensure_ascii=False, separators=(",", ":")) + "\n")
    st["fp"].flush()


def flush_sent_log_entries(stream: str, entries: list) -> None:
    """Write send-log file entries after a drain batch is fully committed."""
    for wrapper in entries:
        if isinstance(wrapper, dict):
            log_sent(stream, wrapper)


def _open_alert_fetch_log(hour_key: str) -> None:
    ensure_log_dir()
    st = _alert_fetch_log_state
    if st["fp"]:
        st["fp"].close()
    path = os.path.join(LOG_DIR, f"stellar_alert_fetch_{hour_key}.log")
    st["fp"] = open(path, "a", encoding="utf-8")
    st["hour_key"] = hour_key


def log_alert_fetch_enqueue(entry: dict) -> None:
    """Append one JSON line to stellar_alert_fetch_YYYYMMDD_HH.log."""
    if not LOG_DIR:
        return
    hour_key = _log_hour_key_now()
    st = _alert_fetch_log_state
    if hour_key != st["hour_key"] or st["fp"] is None:
        _open_alert_fetch_log(hour_key)
    st["fp"].write(json.dumps(entry, ensure_ascii=False, separators=(",", ":")) + "\n")
    st["fp"].flush()


def close_alert_fetch_log() -> None:
    st = _alert_fetch_log_state
    if st["fp"]:
        st["fp"].close()
    st["fp"] = None
    st["hour_key"] = None


def _alert_malformed_missing_fields(hit: dict) -> List[str]:
    missing: List[str] = []
    if not hit.get("_id"):
        missing.append("missing_event_id")
    if not isinstance(hit.get("_source"), dict):
        missing.append("missing_source")
    sortv = hit.get("sort")
    if not isinstance(sortv, list):
        missing.append("missing_sort")
    elif len(sortv) != 2:
        missing.append("invalid_sort_length")
    return missing


def _alert_hit_source_fields(src: Optional[dict]) -> Dict[str, Any]:
    if not isinstance(src, dict):
        return {}
    return {
        "stellar_uuid": src.get("stellar_uuid"),
        "orig_id": src.get("orig_id"),
        "event_name": _resolve_alert_event_name(src),
    }


def _build_alert_fetch_log_entry(
    result: str,
    *,
    event_id: Any = None,
    src: Optional[dict] = None,
    sort_ts: Any = None,
    sort_id: Any = None,
    existing_event_id: Optional[str] = None,
    missing_fields: Optional[List[str]] = None,
) -> dict:
    entry: Dict[str, Any] = {
        "at": datetime.now(KST).isoformat(timespec="milliseconds"),
        "stage": "fetch_enqueue",
        "result": result,
        "event_id": event_id,
        "sort_ts": sort_ts,
        "sort_id": sort_id,
        "existing_event_id": existing_event_id,
        "missing_fields": missing_fields if missing_fields is not None else [],
    }
    entry.update(_alert_hit_source_fields(src))
    return entry


def _alert_enqueue_hit(
    conn: sqlite3.Connection,
    hit: dict,
    inserted_at: int,
) -> dict:
    """
    Enqueue one ES alert hit and return fetch_enqueue log entry + counters.

    counters keys: inserted, duplicate_document_id, duplicate_stellar_uuid, malformed_hit
    """
    missing_fields = _alert_malformed_missing_fields(hit)
    event_id = hit.get("_id")
    src = hit.get("_source")
    sortv = hit.get("sort")
    sort_ts = sortv[0] if isinstance(sortv, list) and len(sortv) >= 1 else None
    sort_id = sortv[1] if isinstance(sortv, list) and len(sortv) >= 2 else None

    if missing_fields:
        entry = _build_alert_fetch_log_entry(
            "malformed_hit",
            event_id=event_id,
            src=src if isinstance(src, dict) else None,
            sort_ts=sort_ts,
            sort_id=sort_id,
            missing_fields=missing_fields,
        )
        return {
            "entry": entry,
            "counters": {"malformed_hit": 1},
            "inserted": False,
            "reason": "malformed_hit",
            "backfill_requeued": False,
        }

    payload_text = json.dumps(src, ensure_ascii=False, separators=(",", ":"))
    stellar_uuid = _alert_stellar_uuid_from_src(src)
    reason, inserted, existing_event_id = alert_queue_insert(
        conn, str(event_id), int(sort_ts), str(sort_id),
        payload_text, inserted_at, stellar_uuid,
    )

    if inserted:
        result = "inserted"
        counters = {"inserted": 1}
        if reason == "backfill_requeued":
            counters["backfill_requeued"] = 1
    elif reason == "duplicate_stellar_uuid":
        result = "duplicate_stellar_uuid"
        counters = {"duplicate_stellar_uuid": 1}
    else:
        result = "duplicate_document_id"
        counters = {"duplicate_document_id": 1}

    entry = _build_alert_fetch_log_entry(
        result,
        event_id=event_id,
        src=src,
        sort_ts=sort_ts,
        sort_id=sort_id,
        existing_event_id=existing_event_id,
    )
    return {
        "entry": entry,
        "counters": counters,
        "inserted": inserted,
        "reason": reason,
        "backfill_requeued": reason == "backfill_requeued",
        "log_fields": _alert_send_log_fields(src, {
            "event_id": event_id,
            "sort_ts": sort_ts,
            "sort_id": sort_id,
        }),
    }


def close_send_logs() -> None:
    for st in _log_state.values():
        if st["fp"]:
            st["fp"].close()
        st["fp"] = None
        st["hour_key"] = None
    close_alert_fetch_log()
    close_operational_log()


def _event_log_day_key_now() -> str:
    return datetime.now(KST).strftime("%Y%m%d")


def _open_operational_log(day_key: str) -> None:
    ensure_log_dir()
    st = _event_log_state
    if st["fp"]:
        st["fp"].close()
    path = os.path.join(LOG_DIR, f"stellar_events_{day_key}.log")
    st["fp"] = open(path, "a", encoding="utf-8")
    st["day_key"] = day_key


def log_operational_event(
    stream: str,
    category: str,
    event: str,
    message: str,
    **fields,
) -> None:
    """
    Append one JSON event line to stellar_events_YYYYMMDD.log.

    category: 'stellar_api' (fetch/auth) or 'syslog_sink' (TCP receiver)
    """
    if not LOG_DIR:
        return
    day_key = _event_log_day_key_now()
    st = _event_log_state
    if day_key != st["day_key"] or st["fp"] is None:
        _open_operational_log(day_key)

    entry: Dict[str, Any] = {
        "at": datetime.now(KST).isoformat(timespec="milliseconds"),
        "stream": stream,
        "category": category,
        "event": event,
        "message": message,
    }
    for key, value in fields.items():
        if value is not None:
            entry[key] = value
    st["fp"].write(json.dumps(entry, ensure_ascii=False, separators=(",", ":")) + "\n")
    st["fp"].flush()


def close_operational_log() -> None:
    st = _event_log_state
    if st["fp"]:
        st["fp"].close()
    st["fp"] = None
    st["day_key"] = None


def _event_log_file_date(path: str) -> Optional[datetime]:
    name = os.path.basename(path)
    if name.startswith("stellar_events_") and name.endswith(".log"):
        try:
            return datetime.strptime(name[len("stellar_events_"):-4], "%Y%m%d").replace(tzinfo=KST)
        except ValueError:
            return None
    return None


def _send_log_file_start(path: str) -> Optional[datetime]:
    """Parse KST hour start from stellar_alerts_YYYYMMDD_HH.log / stellar_cases_..."""
    name = os.path.basename(path)
    for prefix in ("stellar_alerts_", "stellar_cases_", "stellar_alert_fetch_"):
        if name.startswith(prefix) and name.endswith(".log"):
            stem = name[len(prefix):-4]
            try:
                return datetime.strptime(stem, "%Y%m%d_%H").replace(tzinfo=KST)
            except ValueError:
                return None
    return None


def purge_send_logs_if_due(conn: sqlite3.Connection) -> None:
    """Delete send/event log files older than SEND_LOG_RETENTION_DAYS."""
    if not LOG_DIR or not os.path.isdir(LOG_DIR):
        return

    now = int(time.time())
    last = kv_get(conn, "send_log_last_purge_ts")
    last_ts = int(last) if last and last.isdigit() else 0
    if last_ts and (now - last_ts) < SEND_LOG_PURGE_INTERVAL_SEC:
        return

    cutoff = datetime.now(KST) - timedelta(days=SEND_LOG_RETENTION_DAYS)
    deleted = 0
    for name in os.listdir(LOG_DIR):
        if not name.endswith(".log"):
            continue
        path = os.path.join(LOG_DIR, name)
        if not os.path.isfile(path):
            continue
        file_start = _send_log_file_start(path)
        if file_start is None:
            file_start = _event_log_file_date(path)
        if file_start is None or file_start >= cutoff:
            continue
        try:
            os.remove(path)
            deleted += 1
        except OSError:
            pass

    if deleted:
        debug_log(
            "purge", "removed old log files",
            deleted=deleted,
            retention_days=SEND_LOG_RETENTION_DAYS,
            log_dir=LOG_DIR,
        )
    kv_set(conn, "send_log_last_purge_ts", str(now))


# ============================================================
# Alert fetch / send
# ============================================================

def _alert_checkpoint_read(conn: sqlite3.Connection) -> dict:
    """Legacy send checkpoint (debug/log compat only; not used for incremental fetch)."""
    ck_raw = kv_get(conn, "alert_search_after")
    search_after = None
    if ck_raw:
        try:
            parsed = json.loads(ck_raw)
            if isinstance(parsed, list) and len(parsed) == 2:
                search_after = parsed
        except Exception:
            pass
    return {
        "search_after": search_after,
        "last_event_id": kv_get(conn, "alert_last_event_id"),
    }


def _alert_fetch_watermark_read(conn: sqlite3.Connection) -> Optional[int]:
    raw = kv_get(conn, "alert_fetch_watermark_ms")
    if raw and str(raw).isdigit():
        return int(raw)
    return None


def _alert_fetch_watermark_bootstrap(conn: sqlite3.Connection) -> None:
    """One-time upgrade: seed fetch watermark from legacy alert_search_after write_time."""
    if kv_get(conn, "alert_fetch_watermark_ms"):
        return
    ck_raw = kv_get(conn, "alert_search_after")
    if not ck_raw:
        return
    try:
        parsed = json.loads(ck_raw)
        if isinstance(parsed, list) and len(parsed) >= 1:
            kv_set(conn, "alert_fetch_watermark_ms", str(int(parsed[0])))
    except Exception:
        pass


def _alert_fetch_lower_bound_ms(conn: sqlite3.Connection) -> int:
    wm = _alert_fetch_watermark_read(conn)
    if wm is not None:
        return wm
    return now_ms() - initial_lookback_ms()


def _alert_fetch_stable_upper_bound_ms() -> int:
    return now_ms() - ALERT_FETCH_STABILITY_LAG_SEC * 1000


def _alert_fetch_window_state_read(conn: sqlite3.Connection) -> Optional[dict]:
    """
    In-progress closed-window pagination (lower, upper, search_after).
    Cleared when the window is fully exhausted and watermark advances.
    """
    raw = kv_get(conn, "alert_fetch_window_state")
    if not raw:
        return None
    try:
        state = json.loads(raw)
    except Exception:
        return None
    if not isinstance(state, dict):
        return None
    try:
        lower = int(state["lower_bound_ms"])
        upper = int(state["upper_bound_ms"])
        search_after = state.get("search_after")
    except (KeyError, TypeError, ValueError):
        return None
    if upper <= lower:
        return None
    if search_after is not None:
        if not isinstance(search_after, list) or len(search_after) != 2:
            return None
    wm = _alert_fetch_watermark_read(conn)
    if wm is not None and lower != wm:
        return None
    return {
        "lower_bound_ms": lower,
        "upper_bound_ms": upper,
        "search_after": search_after,
    }


def _alert_fetch_window_state_save(
    conn: sqlite3.Connection,
    lower_bound_ms: int,
    upper_bound_ms: int,
    search_after: list,
) -> None:
    kv_set(
        conn,
        "alert_fetch_window_state",
        json.dumps({
            "lower_bound_ms": int(lower_bound_ms),
            "upper_bound_ms": int(upper_bound_ms),
            "search_after": search_after,
        }),
    )


def _alert_fetch_window_state_clear(conn: sqlite3.Connection) -> None:
    conn.execute("DELETE FROM kv WHERE k=?", ("alert_fetch_window_state",))
    conn.commit()


def _alert_fetch_watermark_format(conn: sqlite3.Connection) -> str:
    wm = _alert_fetch_watermark_read(conn)
    if wm is None:
        return "none"
    return f"alert_fetch_watermark_ms={wm}"


def _alert_checkpoint_format(ck: dict) -> str:
    sa = ck.get("search_after")
    eid = ck.get("last_event_id")
    if sa is None:
        return "none"
    return f"search_after={sa}, last_event_id={eid or '?'}"


def fetch_alert_page(
    jwt: str,
    search_after=None,
    gte_write_time=None,
    gt_write_time=None,
    lte_write_time=None,
):
    url = f"https://{HOST}/connect/api/data/aella-ser-*/_search"
    headers = {
        "Accept": "application/json",
        "Content-Type": "application/json",
        "Authorization": f"Bearer {jwt}",
    }
    payload: Dict[str, Any] = {
        "size": FETCH_SIZE,
        "sort": [{"write_time": "asc"}, {"_id": "asc"}],
        "query": {"bool": {"filter": []}},
    }
    if gte_write_time is not None:
        payload["query"]["bool"]["filter"].append({
            "range": {"write_time": {"gte": int(gte_write_time), "format": "epoch_millis"}},
        })
    elif gt_write_time is not None or lte_write_time is not None:
        range_clause: Dict[str, Any] = {"format": "epoch_millis"}
        if gt_write_time is not None:
            range_clause["gt"] = int(gt_write_time)
        if lte_write_time is not None:
            range_clause["lte"] = int(lte_write_time)
        payload["query"]["bool"]["filter"].append({"range": {"write_time": range_clause}})
    if search_after is not None:
        payload["search_after"] = search_after

    code, body = http_get(url, headers, data_bytes=json.dumps(payload).encode("utf-8"), timeout=25)
    if code != 200:
        raise RuntimeError(f"Alert search failed HTTP {code}: {body[:200]!r}")
    return json.loads(body.decode("utf-8"))


def _alert_fetch_process_page(
    conn: sqlite3.Connection,
    hits: List[dict],
) -> Tuple[int, int, int, int, int]:
    """Enqueue one ES page. Returns (inserted, dup_doc, dup_uuid, malformed, backfill_requeued)."""
    now_inserted_at = now_ms()
    page_new = 0
    page_dup_document_id = 0
    page_dup_stellar_uuid = 0
    page_malformed = 0
    backfill_requeued = 0
    for h in hits:
        outcome = _alert_enqueue_hit(conn, h, now_inserted_at)
        log_alert_fetch_enqueue(outcome["entry"])

        counters = outcome["counters"]
        if counters.get("malformed_hit"):
            page_malformed += 1
            debug_log(
                "alert", "skipped malformed hit",
                **{k: outcome["entry"].get(k) for k in (
                    "event_id", "sort_ts", "sort_id", "missing_fields",
                )},
            )
            continue

        log_fields = outcome.get("log_fields", {})
        if outcome["inserted"]:
            page_new += 1
            if outcome["backfill_requeued"]:
                backfill_requeued += 1
            debug_log(
                "alert", f"enqueued ({outcome['reason']})",
                **log_fields,
                payload=h.get("_source"),
            )
        elif outcome["reason"] == "duplicate_stellar_uuid":
            page_dup_stellar_uuid += 1
            debug_log(
                "alert", "skipped duplicate (stellar_uuid)",
                existing_event_id=outcome["entry"].get("existing_event_id"),
                **log_fields,
            )
        else:
            page_dup_document_id += 1
            debug_log(
                "alert", "skipped duplicate (document_id)",
                existing_event_id=outcome["entry"].get("existing_event_id"),
                **log_fields,
            )

    conn.commit()
    return page_new, page_dup_document_id, page_dup_stellar_uuid, page_malformed, backfill_requeued


def alert_fetch_and_enqueue(conn: sqlite3.Connection) -> dict:
    page_search_after = None
    gte_write_time = None
    lower_bound_ms: Optional[int] = None
    upper_bound_ms: Optional[int] = None
    fetch_watermark_before: Optional[int] = None
    fetch_skipped = False
    fetch_window_resumed = False

    if backfill_mode():
        gte_write_time = backfill_cutoff_ms()
        debug_log(
            "alert", "fetch started",
            backfill=True,
            gte_write_time_ms=gte_write_time,
        )
    else:
        _alert_fetch_watermark_bootstrap(conn)
        fetch_watermark_before = _alert_fetch_watermark_read(conn)
        window_state = _alert_fetch_window_state_read(conn)
        if window_state is not None:
            lower_bound_ms = window_state["lower_bound_ms"]
            upper_bound_ms = window_state["upper_bound_ms"]
            page_search_after = window_state.get("search_after")
            fetch_window_resumed = True
        else:
            lower_bound_ms = _alert_fetch_lower_bound_ms(conn)
            upper_bound_ms = _alert_fetch_stable_upper_bound_ms()
        if upper_bound_ms <= lower_bound_ms:
            fetch_skipped = True
            debug_log(
                "alert", "fetch skipped (stability window not closed)",
                fetch_watermark_before=fetch_watermark_before,
                fetch_lower_bound_ms=lower_bound_ms,
                fetch_upper_bound_ms=upper_bound_ms,
                stability_lag_sec=ALERT_FETCH_STABILITY_LAG_SEC,
                fetch_window_resumed=fetch_window_resumed,
            )
            return {
                "pages": 0,
                "hits_seen": 0,
                "inserted": 0,
                "new_enqueued": 0,
                "duplicate_document_id": 0,
                "duplicate_stellar_uuid": 0,
                "malformed_hit": 0,
                "skipped_total": 0,
                "backfill_requeued": 0,
                "queue_pending": queue_pending_count(conn, "alert_queue"),
                "fetch_skipped": True,
                "fetch_window_resumed": fetch_window_resumed,
                "fetch_window_search_after": page_search_after,
                "fetch_watermark_before": fetch_watermark_before,
                "fetch_watermark_after": fetch_watermark_before,
                "fetch_lower_bound_ms": lower_bound_ms,
                "fetch_upper_bound_ms": upper_bound_ms,
                "stability_lag_sec": ALERT_FETCH_STABILITY_LAG_SEC,
            }
        debug_log(
            "alert", "fetch started",
            backfill=False,
            fetch_watermark_before=fetch_watermark_before,
            fetch_lower_bound_ms=lower_bound_ms,
            fetch_upper_bound_ms=upper_bound_ms,
            stability_lag_sec=ALERT_FETCH_STABILITY_LAG_SEC,
            fetch_window_resumed=fetch_window_resumed,
            fetch_window_search_after=page_search_after,
            lookback=lookback_label() if fetch_watermark_before is None and not fetch_window_resumed else None,
        )

    jwt = with_backoff(get_access_token)
    hits_seen = 0
    inserted_count = 0
    dup_document_id = 0
    dup_stellar_uuid = 0
    malformed_count = 0
    backfill_requeued = 0
    pages = 0
    window_exhausted = False
    last_page_size = 0

    while pages < MAX_FETCH_PAGES_PER_CYCLE:
        check_shutdown()
        if backfill_mode():
            res = with_backoff(
                lambda sa=page_search_after, gte=gte_write_time: fetch_alert_page(
                    jwt, search_after=sa, gte_write_time=gte,
                ),
            )
        else:
            res = with_backoff(
                lambda sa=page_search_after, lo=lower_bound_ms, hi=upper_bound_ms: fetch_alert_page(
                    jwt,
                    search_after=sa,
                    gt_write_time=lo,
                    lte_write_time=hi,
                ),
            )
        hits = res.get("hits", {}).get("hits", [])
        if not hits:
            debug_log("alert", "fetch page empty", page=pages + 1)
            window_exhausted = True
            break

        pages += 1
        last_page_size = len(hits)
        page_new, page_dup_doc, page_dup_uuid, page_malformed, page_bf_rq = (
            _alert_fetch_process_page(conn, hits)
        )
        inserted_count += page_new
        dup_document_id += page_dup_doc
        dup_stellar_uuid += page_dup_uuid
        malformed_count += page_malformed
        backfill_requeued += page_bf_rq
        debug_log(
            "alert", "fetch page complete",
            page=pages,
            hits=len(hits),
            inserted=page_new,
            duplicate_document_id=page_dup_doc,
            duplicate_stellar_uuid=page_dup_uuid,
            malformed_hit=page_malformed,
            skipped_total=page_dup_doc + page_dup_uuid + page_malformed,
        )
        last_sort = hits[-1].get("sort")
        if isinstance(last_sort, list) and len(last_sort) == 2:
            page_search_after = last_sort
        else:
            break

        hits_seen += len(hits)
        if len(hits) < FETCH_SIZE:
            window_exhausted = True
            break

    fetch_watermark_after = fetch_watermark_before
    if (
        not backfill_mode()
        and upper_bound_ms is not None
        and window_exhausted
    ):
        kv_set(conn, "alert_fetch_watermark_ms", str(upper_bound_ms))
        _alert_fetch_window_state_clear(conn)
        fetch_watermark_after = upper_bound_ms
        debug_log(
            "alert", "fetch watermark advanced",
            fetch_watermark_before=fetch_watermark_before,
            fetch_watermark_after=fetch_watermark_after,
            fetch_upper_bound_ms=upper_bound_ms,
        )
    elif (
        not backfill_mode()
        and upper_bound_ms is not None
        and lower_bound_ms is not None
        and pages > 0
        and page_search_after is not None
        and not window_exhausted
    ):
        _alert_fetch_window_state_save(
            conn, lower_bound_ms, upper_bound_ms, page_search_after,
        )
        debug_log(
            "alert", "fetch window pagination saved",
            pages=pages,
            fetch_watermark_before=fetch_watermark_before,
            fetch_lower_bound_ms=lower_bound_ms,
            fetch_upper_bound_ms=upper_bound_ms,
            fetch_window_search_after=page_search_after,
        )
    elif (
        not backfill_mode()
        and pages > 0
        and last_page_size >= FETCH_SIZE
        and not window_exhausted
    ):
        debug_log(
            "alert", "fetch watermark held (page limit reached, no search_after)",
            pages=pages,
            fetch_watermark_before=fetch_watermark_before,
            fetch_upper_bound_ms=upper_bound_ms,
        )

    skipped_total = dup_document_id + dup_stellar_uuid + malformed_count
    stats = {
        "pages": pages,
        "hits_seen": hits_seen,
        "inserted": inserted_count,
        "new_enqueued": inserted_count,
        "duplicate_document_id": dup_document_id,
        "duplicate_stellar_uuid": dup_stellar_uuid,
        "malformed_hit": malformed_count,
        "skipped_total": skipped_total,
        "backfill_requeued": backfill_requeued,
        "queue_pending": queue_pending_count(conn, "alert_queue"),
        "fetch_skipped": fetch_skipped,
        "fetch_window_resumed": fetch_window_resumed,
        "fetch_window_search_after": page_search_after if not backfill_mode() else None,
        "fetch_watermark_before": fetch_watermark_before,
        "fetch_watermark_after": fetch_watermark_after,
        "fetch_lower_bound_ms": lower_bound_ms,
        "fetch_upper_bound_ms": upper_bound_ms,
        "stability_lag_sec": ALERT_FETCH_STABILITY_LAG_SEC if not backfill_mode() else None,
    }
    debug_log("alert", "fetch finished", **stats)
    return stats


def _alert_sort_key(sort_ts, sort_id) -> tuple:
    return (int(sort_ts), str(sort_id))


def alert_advance_checkpoint(
    conn: sqlite3.Connection, sort_ts, sort_id, event_id: Optional[str] = None,
) -> None:
    if backfill_mode():
        return
    ck = kv_get(conn, "alert_search_after")
    new_key = _alert_sort_key(sort_ts, sort_id)
    if ck:
        try:
            current = json.loads(ck)
            if isinstance(current, list) and len(current) == 2:
                if _alert_sort_key(current[0], current[1]) >= new_key:
                    return
        except Exception:
            pass
    search_after = [sort_ts, sort_id]
    kv_set(conn, "alert_search_after", json.dumps(search_after))
    if event_id:
        kv_set(conn, "alert_last_event_id", str(event_id))
    debug_log(
        "alert", "checkpoint advanced",
        search_after=search_after,
        last_event_id=event_id,
    )


def _print_alert_drain_summary(
    fetch_stats: Optional[dict],
    drain_stats: dict,
    checkpoint_before: dict,
    checkpoint_after: dict,
) -> None:
    fs = fetch_stats or {}
    ds = drain_stats
    parts = [
        f"hits={fs.get('hits_seen', 0)}",
        f"enqueued={fs.get('inserted', fs.get('new_enqueued', 0))}",
        f"dup_document_id={fs.get('duplicate_document_id', 0)}",
        f"dup_stellar_uuid={fs.get('duplicate_stellar_uuid', 0)}",
        f"malformed={fs.get('malformed_hit', 0)}",
        f"skipped_total={fs.get('skipped_total', 0)}",
        f"pages={fs.get('pages', 0)}",
        f"fetch_wm_before={fs.get('fetch_watermark_before', '-')}",
        f"fetch_wm_after={fs.get('fetch_watermark_after', '-')}",
        f"fetch_lo={fs.get('fetch_lower_bound_ms', '-')}",
        f"fetch_hi={fs.get('fetch_upper_bound_ms', '-')}",
        f"stability_lag_sec={fs.get('stability_lag_sec', '-')}",
        f"sent={ds.get('sent', 0)}",
        f"pending={ds.get('queue_pending', 0)}",
        f"batch_id={ds.get('batch_id', '-')}",
        f"legacy_ck_before={_alert_checkpoint_format(checkpoint_before)}",
        f"legacy_ck_after={_alert_checkpoint_format(checkpoint_after)}",
    ]
    if backfill_mode():
        parts.append("backfill=true")
    if fs.get("fetch_skipped"):
        parts.append("fetch_skipped=true")
    if fs.get("backfill_requeued"):
        parts.append(f"backfill_requeued={fs['backfill_requeued']}")
    print(f"[alert] drain summary: {', '.join(parts)}", file=sys.stderr, flush=True)
    debug_log(
        "alert", "drain summary",
        fetched_hits=fs.get("hits_seen", 0),
        newly_enqueued=fs.get("inserted", fs.get("new_enqueued", 0)),
        duplicate_document_id=fs.get("duplicate_document_id", 0),
        duplicate_stellar_uuid=fs.get("duplicate_stellar_uuid", 0),
        malformed_hit=fs.get("malformed_hit", 0),
        skipped_total=fs.get("skipped_total", 0),
        pages=fs.get("pages", 0),
        fetch_watermark_before=fs.get("fetch_watermark_before"),
        fetch_watermark_after=fs.get("fetch_watermark_after"),
        fetch_lower_bound_ms=fs.get("fetch_lower_bound_ms"),
        fetch_upper_bound_ms=fs.get("fetch_upper_bound_ms"),
        stability_lag_sec=fs.get("stability_lag_sec"),
        fetch_skipped=fs.get("fetch_skipped", False),
        sent=ds.get("sent", 0),
        queue_pending=ds.get("queue_pending", 0),
        batch_id=ds.get("batch_id"),
        checkpoint_before=_alert_checkpoint_format(checkpoint_before),
        checkpoint_after=_alert_checkpoint_format(checkpoint_after),
        backfill=backfill_mode(),
    )


def alert_drain_queue(
    conn: sqlite3.Connection,
    fetch_stats: Optional[dict] = None,
) -> dict:
    pending = queue_pending_count(conn, "alert_queue")
    checkpoint_before = _alert_checkpoint_read(conn)
    batch_id = _make_batch_id()
    debug_log(
        "alert", "drain started",
        pending=pending,
        batch_id=batch_id,
        checkpoint=_alert_checkpoint_format(checkpoint_before),
        destination=f"{ALERT_SYSLOG_IP}:{ALERT_SYSLOG_PORT}",
    )
    if pending == 0:
        stats = {"sent": 0, "batch_id": batch_id, "queue_pending": 0}
        _print_alert_drain_summary(fetch_stats, stats, checkpoint_before, checkpoint_before)
        debug_log("alert", "drain finished", sent=0, batch_id=batch_id)
        return stats

    try:
        sock = tcp_connect_sink(ALERT_SYSLOG_IP, ALERT_SYSLOG_PORT)
    except OSError as e:
        raise SinkTransmissionError(f"connect failed: {e}") from e
    debug_log("alert", "tcp connected", destination=f"{ALERT_SYSLOG_IP}:{ALERT_SYSLOG_PORT}")
    sent = 0
    last_sent_sort_ts = None
    last_sent_sort_id = None
    last_sent_event_id = None
    sent_log_entries: List[dict] = []
    try:
        rows = conn.execute(
            "SELECT event_id, sort_ts, sort_id, payload, send_attempt_count "
            "FROM alert_queue WHERE sent=0 "
            "ORDER BY sort_ts ASC, sort_id ASC LIMIT ?",
            (MAX_SEND_PER_CYCLE,),
        ).fetchall()

        for event_id, sort_ts, sort_id, payload_text, attempt_count in rows:
            check_shutdown()
            try:
                obj = json.loads(payload_text)
            except Exception:
                obj = {"raw": payload_text}

            outbound = _alert_syslog_payload(obj)

            def _send_once(o=outbound):
                nonlocal sock
                check_shutdown()
                sock = _send_json_on_sink(sock, ALERT_SYSLOG_IP, ALERT_SYSLOG_PORT, o)

            _send_once()
            new_attempt = int(attempt_count or 0) + 1
            sent_at_ms = now_ms()
            conn.execute(
                "UPDATE alert_queue SET sent=1, send_attempt_count=?, last_sent_at=? "
                "WHERE event_id=?",
                (new_attempt, sent_at_ms, event_id),
            )
            last_sent_sort_ts = sort_ts
            last_sent_sort_id = sort_id
            last_sent_event_id = event_id
            wrapper = {
                "event_id": event_id,
                "sort_ts": sort_ts,
                "sort_id": sort_id,
                "payload": outbound,
                "batch_id": batch_id,
                "send_attempt_count": new_attempt,
                "backfill": backfill_mode(),
            }
            sent_log_entries.append(wrapper)
            debug_log(
                "alert", "sent json",
                **_alert_send_log_fields(wrapper["payload"], wrapper),
                payload=wrapper["payload"],
            )
            sent += 1
            # Commit each successful send so partial batch failure retains progress.
            conn.commit()
            flush_sent_log_entries("alert", [wrapper])

        checkpoint_after = _alert_checkpoint_read(conn)
        stats = {
            "sent": sent,
            "batch_id": batch_id,
            "queue_pending": queue_pending_count(conn, "alert_queue"),
        }
        _print_alert_drain_summary(fetch_stats, stats, checkpoint_before, checkpoint_after)
        debug_log(
            "alert", "drain finished",
            sent=sent,
            batch_id=batch_id,
            queue_pending=stats["queue_pending"],
        )
        return stats
    finally:
        try:
            sock.close()
        except Exception:
            pass


# ============================================================
# Case fetch / send
# ============================================================

def _case_fetch_build_url(
    jwt: str,
    from_ts: int,
    skip: int,
    *,
    include_summary: bool,
    format_summary: bool,
) -> Tuple[str, dict]:
    params = {
        "FROM~modified_at": str(from_ts),
        "min_score": str(CASE_MIN_SCORE),
        "sort": "modified_at",
        "order": "asc",
        "limit": str(CASE_FETCH_LIMIT),
        "include_summary": "true" if include_summary else "false",
        "format_summary": "true" if format_summary else "false",
    }
    if skip > 0:
        params["skip"] = str(skip)
    qs = urlencode(params)
    url = f"https://{HOST}/connect/api/v1/cases?{qs}"
    headers = {"Authorization": f"Bearer {jwt}", "Accept": "application/json"}
    return url, headers


def _case_fetch_http(url: str, headers: dict) -> bytes:
    """GET Cases API page; raise CaseFetchError with a distinct kind on failure."""
    try:
        code, body = http_get(url, headers, timeout=CASE_FETCH_TIMEOUT_SEC)
    except TimeoutError as e:
        raise CaseFetchError(
            "timeout",
            f"Case fetch timeout after {CASE_FETCH_TIMEOUT_SEC}s",
        ) from e
    except URLError as e:
        reason = e.reason
        if isinstance(reason, (TimeoutError, socket.timeout)):
            raise CaseFetchError(
                "timeout",
                f"Case fetch timeout after {CASE_FETCH_TIMEOUT_SEC}s",
            ) from e
        if isinstance(reason, ConnectionResetError):
            raise CaseFetchError("connection", f"Case fetch connection reset: {e}") from e
        raise CaseFetchError("connection", f"Case fetch connection error: {e}") from e
    except OSError as e:
        raise CaseFetchError("connection", f"Case fetch connection error: {e}") from e

    if code != 200:
        snippet = body[:200] if body else b""
        raise CaseFetchError(
            "http_error",
            f"Case fetch failed HTTP {code}: {snippet!r}",
            http_code=code,
        )
    return body


def _case_fetch_log_error(kind: str, message: str, http_code: Optional[int] = None) -> None:
    event = {
        "timeout": "case_fetch_timeout",
        "http_error": "case_fetch_http_error",
        "json_error": "case_fetch_json_error",
        "connection": "case_fetch_connection_error",
    }.get(kind, "case_fetch_error")
    log_operational_event(
        "case", "stellar_api", event, message,
        error=message, http_code=http_code,
        include_summary=CASE_INCLUDE_SUMMARY,
        format_summary=CASE_FORMAT_SUMMARY,
        fetch_timeout_sec=CASE_FETCH_TIMEOUT_SEC,
    )


def fetch_cases_page(
    jwt: str,
    from_ts: int,
    skip: int = 0,
    *,
    include_summary: Optional[bool] = None,
    format_summary: Optional[bool] = None,
) -> dict:
    inc = CASE_INCLUDE_SUMMARY if include_summary is None else include_summary
    fmt = CASE_FORMAT_SUMMARY if format_summary is None else format_summary
    url, headers = _case_fetch_build_url(
        jwt, from_ts, skip, include_summary=inc, format_summary=fmt,
    )
    body = _case_fetch_http(url, headers)
    try:
        return json.loads(body.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as e:
        msg = "Case fetch JSON decode failed"
        _case_fetch_log_error("json_error", msg)
        raise CaseFetchError("json_error", msg) from e


def _case_fetch_page_for_enqueue(
    jwt: str, from_ts: int, skip: int = 0,
) -> Tuple[dict, bool]:
    """
    Fetch one Cases API page for enqueue.

    Returns (response_dict, summary_fallback_used).
    When include_summary is enabled and the summary request times out or
    returns HTTP 5xx, retries once with include_summary=false.
    """
    if not CASE_INCLUDE_SUMMARY:
        return fetch_cases_page(jwt, from_ts, skip), False

    try:
        return fetch_cases_page(jwt, from_ts, skip), False
    except CaseFetchError as e:
        retry = e.kind == "timeout" or (
            e.kind == "http_error"
            and e.http_code is not None
            and e.http_code >= 500
        )
        if not retry:
            _case_fetch_log_error(e.kind, str(e), e.http_code)
            raise RuntimeError(str(e)) from e

        msg = (
            f"Case fetch with summary failed ({e.kind}); "
            f"retrying same page with include_summary=false"
        )
        print(f"[case] [stellar_api] {msg}", file=sys.stderr)
        _case_fetch_log_error(e.kind, str(e), e.http_code)
        log_operational_event(
            "case", "stellar_api", "case_fetch_summary_fallback",
            msg,
            error=str(e), http_code=e.http_code,
            skip=skip, from_modified_at_ms=from_ts,
        )
        debug_log(
            "case", "summary fetch fallback",
            skip=skip, error_kind=e.kind, http_code=e.http_code,
        )

        res = fetch_cases_page(jwt, from_ts, skip, include_summary=False)
        data = res.get("data", {})
        for case in data.get("cases", []):
            if isinstance(case, dict):
                case["summary_fetch_fallback"] = True
                case["kill_chain_parse_source"] = "missing_summary"
        return res, True


def _case_checkpoint_get(conn: sqlite3.Connection) -> Optional[str]:
    return kv_get(conn, "case_last_modified_at") or kv_get(conn, "case_last_created_at")


def case_fetch_from_ts(conn: sqlite3.Connection) -> int:
    """Lower bound (ms) for case API FROM~modified_at."""
    if backfill_mode():
        return backfill_cutoff_ms()
    ck = _case_checkpoint_get(conn)
    if ck and ck.isdigit():
        return int(ck) + 1
    return now_ms() - initial_lookback_ms()


def case_fetch_and_enqueue(conn: sqlite3.Connection) -> int:
    ck = _case_checkpoint_get(conn)
    from_ts = case_fetch_from_ts(conn)

    jwt = with_backoff(get_access_token)
    inserted = 0
    new_count = 0
    dup_count = 0
    skip = 0
    pages = 0

    debug_log(
        "case", "fetch started",
        backfill=backfill_mode(),
        from_modified_at_ms=from_ts,
        checkpoint_ms=None if backfill_mode() else (int(ck) if ck and ck.isdigit() else None),
        min_score=CASE_MIN_SCORE,
        include_summary=CASE_INCLUDE_SUMMARY,
        format_summary=CASE_FORMAT_SUMMARY,
        lookback=lookback_label() if backfill_mode() or ck is None else None,
    )

    while pages < MAX_FETCH_PAGES_PER_CYCLE:
        check_shutdown()
        res, summary_fallback = with_backoff(
            lambda s=skip: _case_fetch_page_for_enqueue(jwt, from_ts, skip=s),
        )
        if summary_fallback:
            debug_log(
                "case", "fetch page used summary fallback",
                page=pages + 1, skip=skip,
            )
        data = res.get("data", {})
        cases = data.get("cases", [])
        if not cases:
            debug_log("case", "fetch page empty", page=pages + 1, skip=skip)
            break

        pages += 1
        now_inserted_at = now_ms()
        page_new = 0
        page_dup = 0
        for case in cases:
            if not isinstance(case, dict):
                debug_log("case", "skipped non-dict entry")
                continue
            case_id = case.get("_id")
            modified_at = case.get("modified_at") or case.get("created_at")
            if not case_id or modified_at is None:
                debug_log("case", "skipped malformed case", case_id=case_id, modified_at=modified_at)
                continue
            try:
                sort_ts = int(modified_at)
            except (TypeError, ValueError):
                debug_log("case", "skipped invalid modified_at", case_id=case_id, modified_at=modified_at)
                continue

            payload_text = json.dumps(case, ensure_ascii=False, separators=(",", ":"))
            conn.execute(
                "INSERT INTO case_queue(event_id, sort_ts, sort_id, payload, sent, inserted_at) "
                "VALUES(?, ?, ?, ?, 0, ?) "
                "ON CONFLICT(event_id) DO UPDATE SET "
                "sort_ts=excluded.sort_ts, sort_id=excluded.sort_id, "
                "payload=excluded.payload, sent=0",
                (str(case_id), sort_ts, str(case_id), payload_text, now_inserted_at),
            )
            page_new += 1
            if DEBUG:
                summary = case.get("summary")
                parsed, source = _case_resolve_kill_chain_fields(case)
                debug_log(
                    "case",
                    "case fetch summary diagnostic",
                    case_id=case_id,
                    name=case.get("name"),
                    score=case.get("score"),
                    include_summary=CASE_INCLUDE_SUMMARY,
                    format_summary=CASE_FORMAT_SUMMARY,
                    summary_present=summary is not None,
                    summary_type=type(summary).__name__ if summary is not None else "NoneType",
                    summary_first_line=(
                        summary.splitlines()[0]
                        if isinstance(summary, str) and summary.splitlines()
                        else None
                    ),
                    summary_keys=list(summary.keys()) if isinstance(summary, dict) else None,
                    parsed_kill_chain_stages=parsed,
                    kill_chain_parse_source=case.get("kill_chain_parse_source") or source,
                    summary_fetch_fallback=case.get("summary_fetch_fallback"),
                )
            debug_log(
                "case", "enqueued (new)" if not backfill_mode() else "enqueued (backfill)",
                case_id=case_id,
                name=case.get("name"),
                modified_at=modified_at,
                score=case.get("score"),
                status=case.get("status"),
                payload=case,
            )

        conn.commit()
        new_count += page_new
        dup_count += page_dup
        inserted += len(cases)
        total = data.get("total", 0)
        debug_log(
            "case", "fetch page complete",
            page=pages, skip=skip, cases=len(cases),
            total_reported=total, new=page_new, duplicate=page_dup,
        )
        skip += len(cases)
        if skip >= total or len(cases) < CASE_FETCH_LIMIT:
            break

    debug_log(
        "case", "fetch finished",
        pages=pages, cases_seen=inserted,
        new_enqueued=new_count, duplicates_skipped=dup_count,
        queue_pending=queue_pending_count(conn, "case_queue"),
    )
    return new_count


def case_advance_checkpoint(conn: sqlite3.Connection, max_modified_at: int) -> None:
    if backfill_mode():
        return
    ck = _case_checkpoint_get(conn)
    current = int(ck) if ck and ck.isdigit() else 0
    if max_modified_at > current:
        kv_set(conn, "case_last_modified_at", str(max_modified_at))
        debug_log("case", "checkpoint advanced", case_last_modified_at=max_modified_at)


def case_drain_queue(conn: sqlite3.Connection) -> int:
    pending = queue_pending_count(conn, "case_queue")
    batch_id = _make_batch_id()
    debug_log(
        "case", "drain started",
        pending=pending, batch_id=batch_id,
        destination=f"{CASE_SYSLOG_IP}:{CASE_SYSLOG_PORT}",
    )
    if pending == 0:
        debug_log("case", "drain finished", sent=0, batch_id=batch_id)
        return 0

    try:
        sock = tcp_connect_sink(CASE_SYSLOG_IP, CASE_SYSLOG_PORT)
    except OSError as e:
        raise SinkTransmissionError(f"connect failed: {e}") from e
    debug_log("case", "tcp connected", destination=f"{CASE_SYSLOG_IP}:{CASE_SYSLOG_PORT}")
    sent = 0
    max_sent_modified_at = 0
    sent_log_entries: List[dict] = []
    try:
        rows = conn.execute(
            "SELECT event_id, sort_ts, sort_id, payload FROM case_queue WHERE sent=0 "
            "ORDER BY sort_ts ASC, sort_id ASC LIMIT ?",
            (MAX_SEND_PER_CYCLE,),
        ).fetchall()

        for event_id, sort_ts, sort_id, payload_text in rows:
            check_shutdown()
            try:
                obj = json.loads(payload_text)
            except Exception:
                obj = {"raw": payload_text}

            outbound = _case_syslog_payload(obj)

            if DEBUG:
                summary = obj.get("summary") if isinstance(obj, dict) else None
                parsed, source = (
                    _case_resolve_kill_chain_fields(obj)
                    if isinstance(obj, dict)
                    else (_case_kill_chain_stages_zero(), "non_dict_payload")
                )
                debug_log(
                    "case",
                    "kill chain parse diagnostic",
                    event_id=event_id,
                    name=obj.get("name") if isinstance(obj, dict) else None,
                    score=obj.get("score") if isinstance(obj, dict) else None,
                    summary_present=summary is not None,
                    summary_type=type(summary).__name__ if summary is not None else "NoneType",
                    summary_first_line=(
                        summary.splitlines()[0]
                        if isinstance(summary, str) and summary.splitlines()
                        else None
                    ),
                    summary_keys=list(summary.keys()) if isinstance(summary, dict) else None,
                    parsed_kill_chain_stages=parsed,
                    kill_chain_parse_source=(
                        obj.get("kill_chain_parse_source") or source
                        if isinstance(obj, dict) else source
                    ),
                    outbound_kill_chain_fields=_case_kill_chain_outbound_fields(outbound),
                    syslog_payload_kill_chain_fields=_case_kill_chain_outbound_fields(outbound),
                    summary_fetch_fallback=(
                        obj.get("summary_fetch_fallback") if isinstance(obj, dict) else None
                    ),
                )

            def _send_once(o=outbound):
                nonlocal sock
                check_shutdown()
                sock = _send_json_on_sink(sock, CASE_SYSLOG_IP, CASE_SYSLOG_PORT, o)

            _send_once()
            conn.execute("UPDATE case_queue SET sent=1 WHERE event_id=?", (event_id,))
            max_sent_modified_at = max(max_sent_modified_at, int(sort_ts))
            wrapper = {
                "event_id": event_id,
                "sort_ts": sort_ts,
                "sort_id": sort_id,
                "payload": outbound,
                "batch_id": batch_id,
                "send_attempt_count": 1,
                "backfill": backfill_mode(),
            }
            sent_log_entries.append(wrapper)
            debug_log(
                "case", "sent json",
                **_case_send_log_fields(wrapper["payload"], wrapper),
                status=wrapper["payload"].get("status") if isinstance(wrapper["payload"], dict) else None,
                payload=wrapper["payload"],
            )
            sent += 1

        conn.commit()
        if max_sent_modified_at > 0:
            case_advance_checkpoint(conn, max_sent_modified_at)
        flush_sent_log_entries("case", sent_log_entries)
        debug_log(
            "case", "drain finished",
            sent=sent, batch_id=batch_id,
            queue_pending=queue_pending_count(conn, "case_queue"),
        )
        return sent
    finally:
        try:
            sock.close()
        except Exception:
            pass


# ============================================================
# Purge (per queue table)
# ============================================================

def purge_alert_sent_ttl(conn: sqlite3.Connection) -> None:
    """Delete sent=1 alert rows older than ALERT_SENT_RETENTION_MINUTES (never touches sent=0)."""
    cutoff_ms = now_ms() - (ALERT_SENT_RETENTION_MINUTES * 60 * 1000)
    before = conn.execute(
        "SELECT COUNT(*) FROM alert_queue "
        "WHERE sent=1 AND last_sent_at IS NOT NULL AND last_sent_at < ?",
        (cutoff_ms,),
    ).fetchone()[0]
    if not before:
        return
    conn.execute(
        "DELETE FROM alert_queue "
        "WHERE sent=1 AND last_sent_at IS NOT NULL AND last_sent_at < ?",
        (cutoff_ms,),
    )
    conn.commit()
    debug_log(
        "purge", "removed alert sent rows (ttl)",
        deleted=before,
        retention_minutes=ALERT_SENT_RETENTION_MINUTES,
    )


def purge_queue_if_due(conn: sqlite3.Connection, table: str, kv_key: str) -> None:
    now = int(time.time())
    last = kv_get(conn, kv_key)
    last_ts = int(last) if last and last.isdigit() else 0
    if last_ts and (now - last_ts) < (PURGE_EVERY_DAYS * 86400):
        return

    before = conn.execute(f"SELECT COUNT(*) FROM {table} WHERE sent=1").fetchone()[0]
    conn.execute(f"DELETE FROM {table} WHERE sent=1")
    conn.commit()
    debug_log("purge", "removed sent rows", table=table, deleted=before)
    if VACUUM_AFTER_PURGE:
        conn.execute("VACUUM")
        conn.commit()
    kv_set(conn, kv_key, str(now))


# ============================================================
# Lock
# ============================================================

def acquire_lock():
    ensure_dir(LOCK_PATH)
    f = open(LOCK_PATH, "w")
    try:
        fcntl.flock(f, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        f.close()
        return None
    return f


# ============================================================
# Daemon cycles
# ============================================================

def _run_stream_retry_drain(
    conn: sqlite3.Connection,
    stream: str,
    drain_fn: Callable[[sqlite3.Connection], int],
    table: str,
) -> None:
    """Retry sending queued data only (no API fetch)."""
    pending = queue_pending_count(conn, table)
    if pending == 0:
        if sink_probe(stream):
            sink_on_success(stream)
            debug_log(stream, "sink retry succeeded (probe, queue empty)")
        else:
            sink_on_retry_failed(stream, time.time(), error="TCP probe failed (queue empty)")
        return
    try:
        result = drain_fn(conn)
        sent = result.get("sent", 0) if isinstance(result, dict) else int(result)
        sink_on_success(stream)
        debug_log(stream, "sink retry succeeded", sent_to_syslog=sent, queue_pending=queue_pending_count(conn, table))
    except SinkTransmissionError as e:
        sink_on_retry_failed(stream, time.time(), error=str(e))
        debug_log(stream, "sink retry failed", error=str(e))


def run_alert_cycle(conn: sqlite3.Connection) -> None:
    if not ALERT_ENABLED:
        return
    stream = "alert"
    h = _sink_health[stream]
    now = time.time()
    started = now

    if h["mode"] == "retrying" and now < h["next_wake"]:
        return

    debug_log("alert", "cycle started", sink_mode=h["mode"])
    try:
        if h["mode"] == "paused":
            if not sink_probe(stream):
                ip, port = _sink_target(stream)
                log_operational_event(
                    stream, "syslog_sink", "probe_failed",
                    f"Syslog receiver still unreachable ({ip}:{port})",
                    destination=f"{ip}:{port}", sink_mode="paused",
                )
                debug_log("alert", "sink probe failed", mode="paused")
                return
            sink_on_success(stream)
            debug_log("alert", "sink probe ok after pause; resuming incremental fetch")

        if h["mode"] == "retrying":
            _run_stream_retry_drain(conn, stream, alert_drain_queue, "alert_queue")
            purge_alert_sent_ttl(conn)
            debug_log(
                "alert", "cycle complete",
                elapsed_sec=round(time.time() - started, 2),
                sink_mode=_sink_health[stream]["mode"],
            )
            return

        fetch_stats = alert_fetch_and_enqueue(conn)
        check_shutdown()
        try:
            drain_stats = alert_drain_queue(conn, fetch_stats=fetch_stats)
            sent = drain_stats.get("sent", 0)
        except SinkTransmissionError as e:
            sink_on_failure(stream, time.time(), error=str(e))
            debug_log(
                "alert", "cycle partial",
                elapsed_sec=round(time.time() - started, 2),
                fetch_stats=fetch_stats, sent_to_syslog=0, sink_error=str(e),
            )
            return
        sink_on_success(stream)
        debug_log(
            "alert", "cycle complete",
            elapsed_sec=round(time.time() - started, 2),
            fetch_stats=fetch_stats, sent_to_syslog=sent,
            batch_id=drain_stats.get("batch_id"),
        )
        purge_alert_sent_ttl(conn)
    except ShutdownRequested:
        raise
    except Exception as e:
        print(f"[alert] [stellar_api] fetch failed: {e}", file=sys.stderr)
        log_operational_event(
            "alert", "stellar_api", "fetch_failed",
            f"Failed to fetch alerts from Stellar Cyber ({HOST})",
            error=str(e), host=HOST,
        )
        debug_log("alert", "cycle error", error=str(e))


def run_case_cycle(conn: sqlite3.Connection) -> None:
    if not CASE_ENABLED:
        return
    stream = "case"
    h = _sink_health[stream]
    now = time.time()
    started = now

    if h["mode"] == "retrying" and now < h["next_wake"]:
        return

    debug_log("case", "cycle started", sink_mode=h["mode"])
    try:
        if h["mode"] == "paused":
            if not sink_probe(stream):
                ip, port = _sink_target(stream)
                log_operational_event(
                    stream, "syslog_sink", "probe_failed",
                    f"Syslog receiver still unreachable ({ip}:{port})",
                    destination=f"{ip}:{port}", sink_mode="paused",
                )
                debug_log("case", "sink probe failed", mode="paused")
                return
            sink_on_success(stream)
            debug_log("case", "sink probe ok after pause; resuming incremental fetch")

        if h["mode"] == "retrying":
            _run_stream_retry_drain(conn, stream, case_drain_queue, "case_queue")
            debug_log(
                "case", "cycle complete",
                elapsed_sec=round(time.time() - started, 2),
                sink_mode=_sink_health[stream]["mode"],
            )
            return

        fetched = case_fetch_and_enqueue(conn)
        check_shutdown()
        try:
            sent = case_drain_queue(conn)
        except SinkTransmissionError as e:
            sink_on_failure(stream, time.time(), error=str(e))
            debug_log(
                "case", "cycle partial",
                elapsed_sec=round(time.time() - started, 2),
                new_enqueued=fetched, sent_to_syslog=0, sink_error=str(e),
            )
            return
        sink_on_success(stream)
        debug_log(
            "case", "cycle complete",
            elapsed_sec=round(time.time() - started, 2),
            new_enqueued=fetched, sent_to_syslog=sent,
        )
        if sent > 0:
            print(
                f"[case] sent {sent} case(s) → {CASE_SYSLOG_IP}:{CASE_SYSLOG_PORT}",
                file=sys.stderr,
            )
    except ShutdownRequested:
        raise
    except Exception as e:
        print(f"[case] [stellar_api] fetch failed: {e}", file=sys.stderr)
        log_operational_event(
            "case", "stellar_api", "fetch_failed",
            f"Failed to fetch cases from Stellar Cyber ({HOST})",
            error=str(e), host=HOST,
        )
        debug_log("case", "cycle error", error=str(e))


def _handle_signal(signum, _frame):
    global _shutdown, _signal_count
    _signal_count += 1
    _shutdown = True
    if _signal_count >= 2:
        print("Forced exit.", file=sys.stderr)
        sys.exit(128 + (signum if signum < 128 else 0))
    print(
        f"Shutting down... (signal {signum}; press Ctrl+C again to force quit)",
        file=sys.stderr,
    )


# ============================================================
# CLI
# ============================================================

def parse_args():
    p = argparse.ArgumentParser(
        description="Stellar Cyber Alert + Case syslog daemon",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
        epilog=(
            "Examples:\n"
            "  # alert only\n"
            "  python3 %(prog)s --alert-interval 60 --alert-syslog-ip 10.0.0.1 --alert-syslog-port 5142\n"
            "  # case only\n"
            "  python3 %(prog)s --case-interval 300 --case-syslog-ip 10.0.0.1 --case-syslog-port 5143\n"
            "  # both\n"
            "  python3 %(prog)s --alert-interval 60 --alert-syslog-ip 10.0.0.1 --alert-syslog-port 5142 \\\n"
            "    --case-interval 300 --case-syslog-ip 10.0.0.1 --case-syslog-port 5143"
        ),
    )

    p.add_argument("--host", default=HOST)
    p.add_argument("--userid", default=USERID)
    p.add_argument("--token", default=ALL_ACCESS_TOKEN, help="All-Access API token")

    alert = p.add_argument_group("alert (all three required to enable alert fetch/send)")
    alert.add_argument("--alert-interval", type=int, default=None, metavar="SEC",
                       help="Alert fetch/send interval (seconds)")
    alert.add_argument("--alert-syslog-ip", default=None, metavar="IP",
                       help="Alert syslog destination IP")
    alert.add_argument("--alert-syslog-port", type=int, default=None, metavar="PORT",
                       help="Alert syslog destination port")
    alert.add_argument("--alert-fetch-stability-lag-sec", type=int,
                       default=ALERT_FETCH_STABILITY_LAG_SEC, metavar="SEC",
                       help="Incremental alert fetch: only query write_time up to "
                            "now minus this lag (closed-window watermark upper bound)")

    case = p.add_argument_group("case (all three required to enable case fetch/send)")
    case.add_argument("--case-interval", type=int, default=None, metavar="SEC",
                      help="Case fetch/send interval (seconds)")
    case.add_argument("--case-syslog-ip", default=None, metavar="IP",
                      help="Case syslog destination IP")
    case.add_argument("--case-syslog-port", type=int, default=None, metavar="PORT",
                      help="Case syslog destination port")

    p.add_argument("--initial-lookback-hours", type=int, default=INITIAL_LOOKBACK_HOURS,
                   help="Lookback on first run when checkpoint is absent and --backfill is not set "
                        "(0 = last 1 minute)")
    p.add_argument("--alert-sent-retention-minutes", type=int,
                   default=ALERT_SENT_RETENTION_MINUTES,
                   help="Delete alert queue rows with sent=1 after this many minutes "
                        "(sent=0 rows are never purged)")

    p.add_argument("--backfill", type=int, metavar="DAYS", default=None,
                   help="Always fetch/send the last N days each cycle (ignores checkpoints; "
                        "re-sends data in the window)")

    p.add_argument("--case-min-score", type=int, default=CASE_MIN_SCORE)
    p.add_argument(
        "--case-include-summary",
        action=argparse.BooleanOptionalAction,
        default=CASE_INCLUDE_SUMMARY,
        help="Request case summary from the API (required for Kill Chain parsing; default: on). "
             "Use --no-case-include-summary to fetch base fields only (Kill Chain may be all-zero).",
    )
    p.add_argument(
        "--case-format-summary",
        action=argparse.BooleanOptionalAction,
        default=CASE_FORMAT_SUMMARY,
        help="Request formatted string summary (slower; higher timeout risk). "
             "Default: off (--no-case-format-summary); structured dict summary is used.",
    )
    p.add_argument("--case-fetch-limit", type=int, default=CASE_FETCH_LIMIT)
    p.add_argument(
        "--case-fetch-timeout",
        type=int,
        default=CASE_FETCH_TIMEOUT_SEC,
        metavar="SEC",
        help="Case API fetch timeout in seconds (default: 90).",
    )

    p.add_argument("--db-path", default=DB_PATH)
    p.add_argument("--log-dir", default=LOG_DIR)
    p.add_argument("--send-log-retention-days", type=int, default=SEND_LOG_RETENTION_DAYS,
                   help="Delete send summary log files older than this many days")
    p.add_argument("--lock-path", default=LOCK_PATH)
    p.add_argument("--debug", action="store_true",
                   help="Print alert/case fetch/enqueue/send summary logs to stderr "
                        "(HTTP/HTTP payload noise excluded)")

    return p.parse_args()


def apply_config(args) -> None:
    global HOST, USERID, ALL_ACCESS_TOKEN
    global ALERT_INTERVAL_SEC, CASE_INTERVAL_SEC, INITIAL_LOOKBACK_HOURS, BACKFILL_DAYS
    global ALERT_SYSLOG_IP, ALERT_SYSLOG_PORT, CASE_SYSLOG_IP, CASE_SYSLOG_PORT
    global ALERT_ENABLED, CASE_ENABLED
    global CASE_MIN_SCORE, CASE_INCLUDE_SUMMARY, CASE_FORMAT_SUMMARY, CASE_FETCH_LIMIT
    global CASE_FETCH_TIMEOUT_SEC
    global DB_PATH, LOG_DIR, LOCK_PATH, DEBUG, SEND_LOG_RETENTION_DAYS
    global ALERT_SENT_RETENTION_MINUTES, ALERT_FETCH_STABILITY_LAG_SEC

    HOST = args.host
    USERID = args.userid
    ALL_ACCESS_TOKEN = args.token

    INITIAL_LOOKBACK_HOURS = args.initial_lookback_hours
    BACKFILL_DAYS = args.backfill
    ALERT_SENT_RETENTION_MINUTES = args.alert_sent_retention_minutes
    ALERT_FETCH_STABILITY_LAG_SEC = args.alert_fetch_stability_lag_sec

    ALERT_ENABLED = all(
        v is not None for v in (args.alert_interval, args.alert_syslog_ip, args.alert_syslog_port)
    )
    CASE_ENABLED = all(
        v is not None for v in (args.case_interval, args.case_syslog_ip, args.case_syslog_port)
    )

    ALERT_INTERVAL_SEC = args.alert_interval if ALERT_ENABLED else None
    ALERT_SYSLOG_IP = args.alert_syslog_ip if ALERT_ENABLED else None
    ALERT_SYSLOG_PORT = args.alert_syslog_port if ALERT_ENABLED else None

    CASE_INTERVAL_SEC = args.case_interval if CASE_ENABLED else None
    CASE_SYSLOG_IP = args.case_syslog_ip if CASE_ENABLED else None
    CASE_SYSLOG_PORT = args.case_syslog_port if CASE_ENABLED else None

    CASE_MIN_SCORE = args.case_min_score
    CASE_INCLUDE_SUMMARY = args.case_include_summary
    CASE_FORMAT_SUMMARY = args.case_format_summary
    CASE_FETCH_LIMIT = args.case_fetch_limit
    CASE_FETCH_TIMEOUT_SEC = args.case_fetch_timeout

    DB_PATH = os.path.expanduser(args.db_path)
    LOG_DIR = os.path.expanduser(args.log_dir)
    LOCK_PATH = os.path.expanduser(args.lock_path)
    SEND_LOG_RETENTION_DAYS = args.send_log_retention_days
    DEBUG = args.debug


# ============================================================
# Main
# ============================================================

def main() -> int:
    args = parse_args()
    apply_config(args)

    stream_err = validate_stream_cli(args)
    if stream_err:
        print(f"ERROR: {stream_err}", file=sys.stderr)
        return 1

    if not ALL_ACCESS_TOKEN:
        print("ERROR: --token (All-Access API token) is required.", file=sys.stderr)
        return 1

    if BACKFILL_DAYS is not None and BACKFILL_DAYS < 1:
        print("ERROR: --backfill must be a positive integer (days).", file=sys.stderr)
        return 1

    if SEND_LOG_RETENTION_DAYS < 1:
        print("ERROR: --send-log-retention-days must be a positive integer.", file=sys.stderr)
        return 1

    if ALERT_SENT_RETENTION_MINUTES < 1:
        print("ERROR: --alert-sent-retention-minutes must be a positive integer.", file=sys.stderr)
        return 1

    if ALERT_FETCH_STABILITY_LAG_SEC < 1:
        print("ERROR: --alert-fetch-stability-lag-sec must be a positive integer.", file=sys.stderr)
        return 1

    if CASE_FETCH_TIMEOUT_SEC < 1:
        print("ERROR: --case-fetch-timeout must be a positive integer.", file=sys.stderr)
        return 1

    lock_f = acquire_lock()
    if lock_f is None:
        print("Another instance is already running.", file=sys.stderr)
        return 1

    signal.signal(signal.SIGTERM, _handle_signal)
    signal.signal(signal.SIGINT, _handle_signal)

    db_prepare()

    if BACKFILL_DAYS is not None:
        conn = db_connect()
        try:
            backfill_prepare(conn)
        finally:
            conn.close()
        print(
            f"Backfill mode: every cycle fetches/sends the last {BACKFILL_DAYS} day(s) "
            f"(checkpoints ignored)",
            file=sys.stderr,
        )

    stream_parts = []
    if ALERT_ENABLED:
        stream_parts.append(
            f"alert every {ALERT_INTERVAL_SEC}s → {ALERT_SYSLOG_IP}:{ALERT_SYSLOG_PORT}"
        )
    if CASE_ENABLED:
        stream_parts.append(
            f"case every {CASE_INTERVAL_SEC}s → {CASE_SYSLOG_IP}:{CASE_SYSLOG_PORT}"
        )
    print(
        f"Stellar Alert+Case syslog daemon started "
        f"({', '.join(stream_parts)}, lookback {lookback_label()}"
        f"{', debug logging ON' if DEBUG else ''})",
        file=sys.stderr,
    )
    if (
        ALERT_ENABLED and CASE_ENABLED
        and (ALERT_SYSLOG_IP, ALERT_SYSLOG_PORT) == (CASE_SYSLOG_IP, CASE_SYSLOG_PORT)
    ):
        print(
            "WARNING: alert and case share the same syslog destination; "
            "ensure the receiver accepts both JSON streams on one port.",
            file=sys.stderr,
        )

    next_alert = 0.0
    next_case = 0.0
    last_purge_check = 0.0

    try:
        while not _shutdown:
            try:
                now = time.time()
                conn = db_connect()
                try:
                    if CASE_ENABLED and now >= next_case:
                        run_case_cycle(conn)
                        next_case = stream_next_wake("case", time.time(), CASE_INTERVAL_SEC)

                    if ALERT_ENABLED and now >= next_alert:
                        run_alert_cycle(conn)
                        next_alert = stream_next_wake("alert", time.time(), ALERT_INTERVAL_SEC)

                    if now - last_purge_check >= 3600:
                        if CASE_ENABLED:
                            purge_queue_if_due(conn, "case_queue", "case_last_purge_ts")
                        purge_send_logs_if_due(conn)
                        last_purge_check = now
                finally:
                    conn.close()

                wake_at = []
                if CASE_ENABLED:
                    wake_at.append(next_case)
                if ALERT_ENABLED:
                    wake_at.append(next_alert)
                sleep_until = min(wake_at) - time.time() if wake_at else 1.0
                if sleep_until > 0:
                    interruptible_sleep(min(sleep_until, 1.0))
                elif not _shutdown:
                    interruptible_sleep(0.1)
            except ShutdownRequested:
                break

    finally:
        close_send_logs()
        try:
            lock_f.close()
        except Exception:
            pass
        print("Daemon stopped.", file=sys.stderr)

    return 0


if __name__ == "__main__":
    sys.exit(main())

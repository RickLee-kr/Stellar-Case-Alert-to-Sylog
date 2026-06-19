#!/usr/bin/env python3
"""
Stellar Cyber Alert + Case → Syslog daemon.

- Alert: ES incremental fetch → durable queue → TCP (JSON per line)
- Case:  REST API incremental fetch → durable queue → TCP (JSON per line)
- SQLite DB persists across restarts (queue + checkpoints).
- Checkpoints advance after successful TCP send (alert: search_after, case: created_at).
- With --backfill N: every cycle fetches and sends the last N days (checkpoints ignored).
"""

import argparse
import base64
import fcntl
import json
import os
import random
import signal
import socket
import sqlite3
import ssl
import sys
import time
from datetime import datetime, timezone, timedelta
from typing import Any, Callable, Dict, Optional
from urllib.error import HTTPError
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

INITIAL_LOOKBACK_HOURS = 48
BACKFILL_DAYS = None  # set by --backfill (test mode)

CASE_MIN_SCORE = 10
CASE_INCLUDE_SUMMARY = True
CASE_FORMAT_SUMMARY = True
CASE_FETCH_LIMIT = 200

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

KST = timezone(timedelta(hours=9))

_shutdown = False
_signal_count = 0
DEBUG = False


class ShutdownRequested(Exception):
    """Raised when SIGINT/SIGTERM requests daemon shutdown."""


# Hourly send-log handles (alert / case)
_log_state: Dict[str, Dict[str, Any]] = {
    "alert": {"hour_key": None, "fp": None, "prefix": "stellar_alerts"},
    "case": {"hour_key": None, "fp": None, "prefix": "stellar_cases"},
}

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
    return INITIAL_LOOKBACK_HOURS * 3600 * 1000


def lookback_label() -> str:
    if BACKFILL_DAYS is not None and BACKFILL_DAYS > 0:
        return f"{BACKFILL_DAYS}d (backfill)"
    return f"{INITIAL_LOOKBACK_HOURS}h"


def backfill_mode() -> bool:
    return BACKFILL_DAYS is not None and BACKFILL_DAYS > 0


def stream_enabled(stream: str) -> bool:
    return ALERT_ENABLED if stream == "alert" else CASE_ENABLED


def validate_stream_cli(args) -> Optional[str]:
    """Return an error message if stream CLI options are inconsistent."""
    streams = {
        "alert": (args.alert_interval, args.alert_syslog_ip, args.alert_syslog_port),
        "case": (args.case_interval, args.case_syslog_ip, args.case_syslog_port),
    }
    labels = {
        "alert": ("--alert-interval", "--alert-syslog-ip", "--alert-syslog-port"),
        "case": ("--case-interval", "--case-syslog-ip", "--case-syslog-port"),
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
    """Insert into alert_queue/case_queue. In backfill mode, re-queue for resend."""
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


# Alert fields omitted from --debug output (HTTP/browser/IDS payload noise).
_DEBUG_ALERT_OMIT = frozenset({
    "actual", "ids", "xdr_event", "payload_details", "metadata", "detected_values",
    "detected_fields", "request", "response", "headers", "body", "user_agent",
    "url", "uri", "http", "http_request", "http_response", "raw", "raw_data",
    "raw_msg", "msg", "message", "data", "events", "flow", "file", "files",
    "process", "processes", "registry", "dns", "tls", "ssl", "email",
})

_DEBUG_ALERT_SUMMARY_KEYS = (
    "event_name", "timestamp_utc", "aella_tuples", "anomaly_id", "anomaly_tag",
    "severity", "score", "srcip", "dstip", "srcport", "dstport", "appid_name",
    "direction", "engid", "tenant_name", "cust_id",
)

_DEBUG_CASE_SUMMARY_KEYS = (
    "_id", "name", "created_at", "modified_at", "score", "status", "severity",
    "size", "ticket_id", "tenant_name", "summary", "tags", "assignee_name",
)


def _truncate_debug(value: Any, max_len: int = 240) -> Any:
    if isinstance(value, str) and len(value) > max_len:
        return value[: max_len - 3] + "..."
    return value


def _debug_alert_summary(src: dict) -> dict:
    summary = {k: src.get(k) for k in _DEBUG_ALERT_SUMMARY_KEYS if src.get(k) is not None}
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
    summary = {k: _truncate_debug(case.get(k)) for k in _DEBUG_CASE_SUMMARY_KEYS if case.get(k) is not None}
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

SCHEMA_VERSION = "alert_case_v1"


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


def _create_queue_table(conn: sqlite3.Connection, table: str) -> None:
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


def backfill_prepare(conn: sqlite3.Connection) -> None:
    """Backfill mode: clear checkpoints on start (fetch window is enforced each cycle)."""
    conn.execute(
        "DELETE FROM kv WHERE k IN (?, ?, ?, ?)",
        ("alert_search_after", "case_last_created_at", "alert_last_purge_ts", "case_last_purge_ts"),
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


def log_sent(stream: str, obj: dict, summary_fields: tuple) -> None:
    hour_key = _log_hour_key_now()
    st = _log_state[stream]
    if hour_key != st["hour_key"] or st["fp"] is None:
        _open_log_for_stream(stream, hour_key)

    entry = {"sent_at": datetime.now(KST).isoformat(timespec="milliseconds")}
    for key in summary_fields:
        entry[key] = obj.get(key)
    st["fp"].write(json.dumps(entry, ensure_ascii=False, separators=(",", ":")) + "\n")
    st["fp"].flush()


def flush_sent_log_entries(stream: str, entries: list, summary_fields: tuple) -> None:
    """Write send-log file entries after a drain batch is fully committed."""
    for obj in entries:
        if isinstance(obj, dict):
            log_sent(stream, obj, summary_fields)


def close_send_logs() -> None:
    for st in _log_state.values():
        if st["fp"]:
            st["fp"].close()
        st["fp"] = None
        st["hour_key"] = None


# ============================================================
# Alert fetch / send
# ============================================================

def fetch_alert_page(jwt: str, search_after=None, gte_ts=None):
    url = f"https://{HOST}/connect/api/data/aella-ser-*/_search"
    headers = {
        "Accept": "application/json",
        "Content-Type": "application/json",
        "Authorization": f"Bearer {jwt}",
    }
    payload: Dict[str, Any] = {
        "size": FETCH_SIZE,
        "sort": [{"timestamp": "asc"}, {"_id": "asc"}],
        "query": {"bool": {"filter": []}},
    }
    if gte_ts is not None:
        payload["query"]["bool"]["filter"].append({
            "range": {"timestamp": {"gte": int(gte_ts), "format": "epoch_millis"}},
        })
    if search_after is not None:
        payload["search_after"] = search_after

    code, body = http_get(url, headers, data_bytes=json.dumps(payload).encode("utf-8"), timeout=25)
    if code != 200:
        raise RuntimeError(f"Alert search failed HTTP {code}: {body[:200]!r}")
    return json.loads(body.decode("utf-8"))


def alert_fetch_and_enqueue(conn: sqlite3.Connection) -> int:
    ck = kv_get(conn, "alert_search_after")
    search_after = None
    gte_ts = None

    if backfill_mode():
        gte_ts = backfill_cutoff_ms()
    else:
        if ck:
            try:
                parsed = json.loads(ck)
                if isinstance(parsed, list) and len(parsed) == 2:
                    search_after = parsed
            except Exception:
                search_after = None
        gte_ts = (now_ms() - initial_lookback_ms()) if search_after is None else None

    debug_log(
        "alert", "fetch started",
        backfill=backfill_mode(),
        checkpoint_search_after=None if backfill_mode() else search_after,
        gte_timestamp_ms=gte_ts,
        lookback=lookback_label() if gte_ts else None,
    )
    jwt = with_backoff(get_access_token)
    inserted = 0
    new_count = 0
    dup_count = 0
    pages = 0

    while pages < MAX_FETCH_PAGES_PER_CYCLE:
        check_shutdown()
        res = with_backoff(lambda: fetch_alert_page(jwt, search_after=search_after, gte_ts=gte_ts))
        hits = res.get("hits", {}).get("hits", [])
        if not hits:
            debug_log("alert", "fetch page empty", page=pages + 1)
            break

        pages += 1
        now_inserted_at = now_ms()
        page_new = 0
        page_dup = 0
        for h in hits:
            event_id = h.get("_id")
            src = h.get("_source")
            sortv = h.get("sort")
            if not event_id or not isinstance(src, dict) or not isinstance(sortv, list) or len(sortv) != 2:
                debug_log("alert", "skipped malformed hit", event_id=event_id, sort=sortv)
                continue
            sort_ts, sort_id = sortv[0], sortv[1]
            payload_text = json.dumps(src, ensure_ascii=False, separators=(",", ":"))
            if queue_insert(conn, "alert_queue", event_id, int(sort_ts), str(sort_id), payload_text, now_inserted_at):
                page_new += 1
                debug_log(
                    "alert", "enqueued (new)" if not backfill_mode() else "enqueued (backfill)",
                    event_id=event_id,
                    sort_ts=sort_ts,
                    event_name=src.get("event_name"),
                    timestamp_utc=src.get("timestamp_utc"),
                    aella_tuples=src.get("aella_tuples"),
                    payload=src,
                )
            else:
                page_dup += 1
                debug_log(
                    "alert", "skipped duplicate",
                    event_id=event_id,
                    event_name=src.get("event_name"),
                    timestamp_utc=src.get("timestamp_utc"),
                )

        conn.commit()
        new_count += page_new
        dup_count += page_dup
        debug_log(
            "alert", "fetch page complete",
            page=pages,
            hits=len(hits),
            new=page_new,
            duplicate=page_dup,
        )
        last_sort = hits[-1].get("sort")
        if isinstance(last_sort, list) and len(last_sort) == 2:
            search_after = last_sort
        else:
            break

        gte_ts = None
        inserted += len(hits)
        if len(hits) < FETCH_SIZE:
            break

    debug_log(
        "alert", "fetch finished",
        pages=pages,
        hits_seen=inserted,
        new_enqueued=new_count,
        duplicates_skipped=dup_count,
        queue_pending=queue_pending_count(conn, "alert_queue"),
    )
    return new_count


def _alert_sort_key(sort_ts, sort_id) -> tuple:
    return (int(sort_ts), str(sort_id))


def alert_advance_checkpoint(conn: sqlite3.Connection, sort_ts, sort_id) -> None:
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
    debug_log("alert", "checkpoint advanced", search_after=search_after)


def alert_drain_queue(conn: sqlite3.Connection) -> int:
    pending = queue_pending_count(conn, "alert_queue")
    debug_log(
        "alert", "drain started",
        pending=pending,
        destination=f"{ALERT_SYSLOG_IP}:{ALERT_SYSLOG_PORT}",
    )
    if pending == 0:
        debug_log("alert", "drain finished", sent=0)
        return 0

    sock = with_backoff(lambda: tcp_connect_sink(ALERT_SYSLOG_IP, ALERT_SYSLOG_PORT))
    debug_log("alert", "tcp connected", destination=f"{ALERT_SYSLOG_IP}:{ALERT_SYSLOG_PORT}")
    sent = 0
    last_sent_sort_ts = None
    last_sent_sort_id = None
    sent_log_entries = []
    try:
        rows = conn.execute(
            "SELECT event_id, sort_ts, sort_id, payload FROM alert_queue WHERE sent=0 "
            "ORDER BY sort_ts ASC, sort_id ASC LIMIT ?",
            (MAX_SEND_PER_CYCLE,),
        ).fetchall()

        for event_id, sort_ts, sort_id, payload_text in rows:
            check_shutdown()
            try:
                obj = json.loads(payload_text)
            except Exception:
                obj = {"raw": payload_text}

            def _send_once(o=obj):
                nonlocal sock
                check_shutdown()
                try:
                    json_line_send(sock, o)
                except (BrokenPipeError, ConnectionResetError, OSError):
                    try:
                        sock.close()
                    except Exception:
                        pass
                    sock = tcp_connect_sink(ALERT_SYSLOG_IP, ALERT_SYSLOG_PORT)
                    debug_log("alert", "tcp reconnected", destination=f"{ALERT_SYSLOG_IP}:{ALERT_SYSLOG_PORT}")
                    json_line_send(sock, o)

            with_backoff(_send_once)
            conn.execute("UPDATE alert_queue SET sent=1 WHERE event_id=?", (event_id,))
            last_sent_sort_ts = sort_ts
            last_sent_sort_id = sort_id
            if isinstance(obj, dict):
                sent_log_entries.append(obj)
                debug_log(
                    "alert", "sent json",
                    event_id=event_id,
                    event_name=obj.get("event_name"),
                    timestamp_utc=obj.get("timestamp_utc"),
                    aella_tuples=obj.get("aella_tuples"),
                    payload=obj,
                )
            else:
                debug_log("alert", "sent json", event_id=event_id, payload=obj)
            sent += 1

        conn.commit()
        if last_sent_sort_ts is not None and last_sent_sort_id is not None:
            alert_advance_checkpoint(conn, last_sent_sort_ts, last_sent_sort_id)
        flush_sent_log_entries(
            "alert", sent_log_entries, ("aella_tuples", "event_name", "timestamp_utc"),
        )
        debug_log(
            "alert", "drain finished",
            sent=sent,
            queue_pending=queue_pending_count(conn, "alert_queue"),
        )
        return sent
    finally:
        try:
            sock.close()
        except Exception:
            pass


# ============================================================
# Case fetch / send
# ============================================================

def fetch_cases_page(jwt: str, from_ts: int, skip: int = 0):
    params = {
        "FROM~created_at": str(from_ts),
        "min_score": str(CASE_MIN_SCORE),
        "sort": "created_at",
        "order": "asc",
        "limit": str(CASE_FETCH_LIMIT),
        "include_summary": "true" if CASE_INCLUDE_SUMMARY else "false",
        "format_summary": "true" if CASE_FORMAT_SUMMARY else "false",
    }
    if skip > 0:
        params["skip"] = str(skip)

    qs = urlencode(params)
    url = f"https://{HOST}/connect/api/v1/cases?{qs}"
    headers = {"Authorization": f"Bearer {jwt}", "Accept": "application/json"}
    code, body = http_get(url, headers, timeout=30)
    if code != 200:
        raise RuntimeError(f"Case fetch failed HTTP {code}: {body[:200]!r}")
    return json.loads(body.decode("utf-8"))


def case_fetch_from_ts(conn: sqlite3.Connection) -> int:
    """Lower bound (ms) for case API FROM~created_at."""
    if backfill_mode():
        return backfill_cutoff_ms()
    ck = kv_get(conn, "case_last_created_at")
    if ck and ck.isdigit():
        return int(ck) + 1
    return now_ms() - initial_lookback_ms()


def case_fetch_and_enqueue(conn: sqlite3.Connection) -> int:
    ck = kv_get(conn, "case_last_created_at")
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
        from_created_at_ms=from_ts,
        checkpoint_ms=None if backfill_mode() else (int(ck) if ck and ck.isdigit() else None),
        min_score=CASE_MIN_SCORE,
        include_summary=CASE_INCLUDE_SUMMARY,
        format_summary=CASE_FORMAT_SUMMARY,
        lookback=lookback_label() if backfill_mode() or ck is None else None,
    )

    while pages < MAX_FETCH_PAGES_PER_CYCLE:
        check_shutdown()
        res = with_backoff(lambda s=skip: fetch_cases_page(jwt, from_ts, skip=s))
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
            created_at = case.get("created_at")
            if not case_id or created_at is None:
                debug_log("case", "skipped malformed case", case_id=case_id, created_at=created_at)
                continue
            try:
                sort_ts = int(created_at)
            except (TypeError, ValueError):
                debug_log("case", "skipped invalid created_at", case_id=case_id, created_at=created_at)
                continue

            payload_text = json.dumps(case, ensure_ascii=False, separators=(",", ":"))
            if queue_insert(conn, "case_queue", str(case_id), sort_ts, str(case_id), payload_text, now_inserted_at):
                page_new += 1
                debug_log(
                    "case", "enqueued (new)" if not backfill_mode() else "enqueued (backfill)",
                    case_id=case_id,
                    name=case.get("name"),
                    created_at=created_at,
                    score=case.get("score"),
                    status=case.get("status"),
                    payload=case,
                )
            else:
                page_dup += 1
                debug_log(
                    "case", "skipped duplicate",
                    case_id=case_id,
                    name=case.get("name"),
                    created_at=created_at,
                )

        conn.commit()
        new_count += page_new
        dup_count += page_dup
        inserted += len(cases)
        total = data.get("total", 0)
        debug_log(
            "case", "fetch page complete",
            page=pages,
            skip=skip,
            cases=len(cases),
            total_reported=total,
            new=page_new,
            duplicate=page_dup,
        )
        skip += len(cases)
        if skip >= total or len(cases) < CASE_FETCH_LIMIT:
            break

    debug_log(
        "case", "fetch finished",
        pages=pages,
        cases_seen=inserted,
        new_enqueued=new_count,
        duplicates_skipped=dup_count,
        queue_pending=queue_pending_count(conn, "case_queue"),
    )
    return new_count


def case_advance_checkpoint(conn: sqlite3.Connection, max_created_at: int) -> None:
    if backfill_mode():
        return
    ck = kv_get(conn, "case_last_created_at")
    current = int(ck) if ck and ck.isdigit() else 0
    if max_created_at > current:
        kv_set(conn, "case_last_created_at", str(max_created_at))
        debug_log("case", "checkpoint advanced", case_last_created_at=max_created_at)


def case_drain_queue(conn: sqlite3.Connection) -> int:
    pending = queue_pending_count(conn, "case_queue")
    debug_log(
        "case", "drain started",
        pending=pending,
        destination=f"{CASE_SYSLOG_IP}:{CASE_SYSLOG_PORT}",
    )
    if pending == 0:
        debug_log("case", "drain finished", sent=0)
        return 0

    sock = with_backoff(lambda: tcp_connect_sink(CASE_SYSLOG_IP, CASE_SYSLOG_PORT))
    debug_log("case", "tcp connected", destination=f"{CASE_SYSLOG_IP}:{CASE_SYSLOG_PORT}")
    sent = 0
    max_sent_created_at = 0
    sent_log_entries = []
    try:
        rows = conn.execute(
            "SELECT event_id, sort_ts, payload FROM case_queue WHERE sent=0 "
            "ORDER BY sort_ts ASC, sort_id ASC LIMIT ?",
            (MAX_SEND_PER_CYCLE,),
        ).fetchall()

        for event_id, sort_ts, payload_text in rows:
            check_shutdown()
            try:
                obj = json.loads(payload_text)
            except Exception:
                obj = {"raw": payload_text}

            def _send_once(o=obj):
                nonlocal sock
                check_shutdown()
                try:
                    json_line_send(sock, o)
                except (BrokenPipeError, ConnectionResetError, OSError):
                    try:
                        sock.close()
                    except Exception:
                        pass
                    sock = tcp_connect_sink(CASE_SYSLOG_IP, CASE_SYSLOG_PORT)
                    debug_log("case", "tcp reconnected", destination=f"{CASE_SYSLOG_IP}:{CASE_SYSLOG_PORT}")
                    json_line_send(sock, o)

            with_backoff(_send_once)
            conn.execute("UPDATE case_queue SET sent=1 WHERE event_id=?", (event_id,))
            max_sent_created_at = max(max_sent_created_at, int(sort_ts))
            if isinstance(obj, dict):
                sent_log_entries.append(obj)
                debug_log(
                    "case", "sent json",
                    case_id=event_id,
                    name=obj.get("name"),
                    created_at=obj.get("created_at"),
                    score=obj.get("score"),
                    status=obj.get("status"),
                    payload=obj,
                )
            else:
                debug_log("case", "sent json", case_id=event_id, payload=obj)
            sent += 1

        conn.commit()
        if max_sent_created_at > 0:
            case_advance_checkpoint(conn, max_sent_created_at)
        flush_sent_log_entries(
            "case", sent_log_entries, ("_id", "name", "created_at", "score"),
        )
        debug_log(
            "case", "drain finished",
            sent=sent,
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

def run_alert_cycle(conn: sqlite3.Connection) -> None:
    started = time.time()
    debug_log("alert", "cycle started")
    try:
        fetched = alert_fetch_and_enqueue(conn)
        check_shutdown()
        sent = alert_drain_queue(conn)
        debug_log(
            "alert", "cycle complete",
            elapsed_sec=round(time.time() - started, 2),
            new_enqueued=fetched,
            sent_to_syslog=sent,
        )
    except ShutdownRequested:
        raise
    except Exception as e:
        print(f"[alert] cycle error: {e}", file=sys.stderr)
        debug_log("alert", "cycle error", error=str(e))


def run_case_cycle(conn: sqlite3.Connection) -> None:
    started = time.time()
    debug_log("case", "cycle started")
    try:
        fetched = case_fetch_and_enqueue(conn)
        check_shutdown()
        sent = case_drain_queue(conn)
        debug_log(
            "case", "cycle complete",
            elapsed_sec=round(time.time() - started, 2),
            new_enqueued=fetched,
            sent_to_syslog=sent,
        )
        if sent > 0:
            print(
                f"[case] sent {sent} case(s) → {CASE_SYSLOG_IP}:{CASE_SYSLOG_PORT}",
                file=sys.stderr,
            )
    except ShutdownRequested:
        raise
    except Exception as e:
        print(f"[case] cycle error: {e}", file=sys.stderr)
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

    case = p.add_argument_group("case (all three required to enable case fetch/send)")
    case.add_argument("--case-interval", type=int, default=None, metavar="SEC",
                      help="Case fetch/send interval (seconds)")
    case.add_argument("--case-syslog-ip", default=None, metavar="IP",
                      help="Case syslog destination IP")
    case.add_argument("--case-syslog-port", type=int, default=None, metavar="PORT",
                      help="Case syslog destination port")

    p.add_argument("--initial-lookback-hours", type=int, default=INITIAL_LOOKBACK_HOURS,
                   help="Lookback window on first run when --backfill is not set")

    p.add_argument("--backfill", type=int, metavar="DAYS", default=None,
                   help="Always fetch/send the last N days each cycle (ignores checkpoints; "
                        "re-sends data in the window)")

    p.add_argument("--case-min-score", type=int, default=CASE_MIN_SCORE)
    p.add_argument("--case-include-summary", action=argparse.BooleanOptionalAction, default=CASE_INCLUDE_SUMMARY)
    p.add_argument("--case-format-summary", action=argparse.BooleanOptionalAction, default=CASE_FORMAT_SUMMARY)
    p.add_argument("--case-fetch-limit", type=int, default=CASE_FETCH_LIMIT)

    p.add_argument("--db-path", default=DB_PATH)
    p.add_argument("--log-dir", default=LOG_DIR)
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
    global DB_PATH, LOG_DIR, LOCK_PATH, DEBUG

    HOST = args.host
    USERID = args.userid
    ALL_ACCESS_TOKEN = args.token

    INITIAL_LOOKBACK_HOURS = args.initial_lookback_hours
    BACKFILL_DAYS = args.backfill

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

    DB_PATH = os.path.expanduser(args.db_path)
    LOG_DIR = os.path.expanduser(args.log_dir)
    LOCK_PATH = os.path.expanduser(args.lock_path)
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
                        next_case = now + CASE_INTERVAL_SEC

                    if ALERT_ENABLED and now >= next_alert:
                        run_alert_cycle(conn)
                        next_alert = now + ALERT_INTERVAL_SEC

                    if now - last_purge_check >= 3600:
                        if ALERT_ENABLED:
                            purge_queue_if_due(conn, "alert_queue", "alert_last_purge_ts")
                        if CASE_ENABLED:
                            purge_queue_if_due(conn, "case_queue", "case_last_purge_ts")
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


"""beszel plugin API: PocketBase 反代层 + security events API.

浏览器只认 Hermes dashboard 会话；本模块持有 beszel superuser token，
把 /api/plugins/beszel/pb/* 转发到 127.0.0.1:8090 的 PocketBase。
同时暴露 /api/plugins/beszel/security/* 查询安全事件。
"""
import asyncio
import ipaddress
import json
import os
import re
import sqlite3
import threading
import time
import urllib.request
import urllib.error
from datetime import datetime, timedelta, timezone
from pathlib import Path

from fastapi import APIRouter, Request, HTTPException
from fastapi.responses import JSONResponse, Response

router = APIRouter()

# ---------------------------------------------------------------- config
HUB = "http://127.0.0.1:8090"
# Runtime data lives under the plugin's own directory (~/.hermes/plugins/beszel),
# NOT the maintainer's workspace. Every path is env-overridable.
PLUGIN_DATA_DIR = Path(os.environ.get(
    "BESZEL_PLUGIN_DATA_DIR",
    str(Path.home() / ".hermes/plugins/beszel")))
CRED_FILE = Path(os.environ.get(
    "BESZEL_CRED_FILE", str(PLUGIN_DATA_DIR / "dashboard-credentials.txt")))
# PB superuser identity; override via env — never commit real credentials.
SUPERUSER_EMAIL = os.environ.get("BESZEL_SUPERUSER_EMAIL", "admin@example.com")

_token_cache = {"token": "", "exp": 0.0}


def _warn_bad_config() -> None:
    """Emit a clear startup warning when the superuser identity looks
    misconfigured (the #1 cause of a blank beszel tab). Non-fatal: read-only
    endpoints still work without hub auth."""
    import logging

    log = logging.getLogger(__name__)
    if SUPERUSER_EMAIL == "admin@example.com":
        log.warning(
            "BESZEL_SUPERUSER_EMAIL is not set (default 'admin@example.com'); "
            "beszel auth will likely fail. Set it to the hub superuser identity."
        )
        return
    try:
        text = CRED_FILE.read_text()
    except OSError:
        log.warning(
            "beszel credentials file missing/unreadable: %s — set BESZEL_CRED_FILE.",
            CRED_FILE,
        )
        return
    if re.search(re.escape(SUPERUSER_EMAIL) + r" / \S+", text) is None:
        log.warning(
            "no password line for '%s' in %s — check BESZEL_SUPERUSER_EMAIL "
            "matches the hub's superuser identity.",
            SUPERUSER_EMAIL,
            CRED_FILE,
        )


_warn_bad_config()


def _read_password() -> str:
    try:
        text = CRED_FILE.read_text()
    except OSError as e:
        raise HTTPException(
            500,
            f"beszel credentials file unreadable: {CRED_FILE} ({e}). "
            f"Set BESZEL_CRED_FILE to the correct path.",
        )
    m = re.search(re.escape(SUPERUSER_EMAIL) + r" / (\S+)", text)
    if not m:
        raise HTTPException(
            500,
            f"beszel superuser password not found for '{SUPERUSER_EMAIL}' in "
            f"{CRED_FILE}. Set BESZEL_SUPERUSER_EMAIL to the hub's superuser "
            f"identity (the email shown in beszel hub admin).",
        )
    return m.group(1)


def _get_token() -> str:
    """PocketBase JWT ~1 day; refresh well before expiry."""
    if _token_cache["token"] and time.time() < _token_cache["exp"] - 300:
        return _token_cache["token"]
    body = json.dumps({
        "identity": SUPERUSER_EMAIL,
        "password": _read_password(),
    }).encode()
    req = urllib.request.Request(
        f"{HUB}/api/collections/_superusers/auth-with-password",
        data=body, headers={"Content-Type": "application/json"}, method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            d = json.loads(resp.read())
    except urllib.error.HTTPError as e:
        raise HTTPException(502, f"beszel auth failed: {e.code}")
    tok = d.get("token", "")
    if not tok:
        raise HTTPException(502, "beszel auth returned no token")
    _token_cache["token"] = tok
    _token_cache["exp"] = time.time() + 3600  # conservative 1h cache
    return tok


# ---------------------------------------------------------------- proxy
@router.api_route("/pb/{path:path}", methods=["GET", "POST", "PATCH", "DELETE", "PUT"])
async def pb_proxy(path: str, request: Request):
    """Forward PocketBase API calls with user token attached.

    GET /api/realtime (SSE) is streamed through httpx so PocketBase's
    EventSource keeps its live connection — beszel's realtime subscriptions
    depend on it.
    """
    url = f"{HUB}/{path}"
    if request.url.query:
        url += f"?{request.url.query}"

    headers = {
        "Content-Type": request.headers.get("content-type", "application/json"),
        "Authorization": _get_token(),
    }
    body = await request.body()

    import httpx
    client = httpx.AsyncClient(timeout=httpx.Timeout(600.0, connect=10.0))
    try:
        # streaming request for SSE endpoints
        if "realtime" in path and request.method == "GET":
            req = client.build_request(request.method, url, headers=headers)
            upstream = await client.send(req, stream=True)
            if upstream.status_code != 200:
                payload = await upstream.aread()
                await upstream.aclose()
                await client.aclose()
                return Response(content=payload, status_code=upstream.status_code,
                                media_type="application/json")
            from fastapi.responses import StreamingResponse

            async def stream_sse():
                try:
                    async for chunk in upstream.aiter_bytes():
                        yield chunk
                finally:
                    await upstream.aclose()
                    await client.aclose()

            return StreamingResponse(stream_sse(), media_type="text/event-stream",
                                     headers={"Cache-Control": "no-cache",
                                              "X-Accel-Buffering": "no"})

        # normal JSON request/response
        req = client.build_request(request.method, url, headers=headers,
                                   content=body if body else None)
        resp = await client.send(req)
        await client.aclose()
        return Response(content=resp.content, status_code=resp.status_code,
                        media_type=resp.headers.get("content-type", "application/json"))
    except httpx.HTTPError as e:
        await client.aclose()
        raise HTTPException(502, f"beszel hub unreachable: {e}")


@router.get("/ping")
async def ping():
    """Liveness probe — reports the configured beszel hub URL. No auth."""
    return {"ok": True, "hub": HUB}


@router.get("/auto-auth")
async def auto_auth():
    """Return a (regular) user token+record for the beszel SPA auto-login.

    Regular users collection (not _superusers): the beszel UI is designed
    around regular users — user_settings records, roles, alert filters all
    key on the users table. Superuser tokens caused 400s in user_settings
    and dead buttons.
    Protected by the dashboard session.
    """
    body = json.dumps({
        "identity": SUPERUSER_EMAIL,
        "password": _read_password(),
    }).encode()
    req = urllib.request.Request(
        f"{HUB}/api/collections/users/auth-with-password",
        data=body, headers={"Content-Type": "application/json"}, method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            d = json.loads(resp.read())
    except urllib.error.HTTPError as e:
        raise HTTPException(502, f"beszel auth failed: {e.code}")
    if not d.get("token"):
        raise HTTPException(502, "no token")
    return {"token": d["token"], "record": d.get("record", {})}


# ---------------------------------------------------------------- security
SEC_DB = Path(os.environ.get(
    "BESZEL_SEC_DB", str(PLUGIN_DATA_DIR / "security-events.db")))

# Hard cap on events-endpoint page size. This bounds ONLY the map's "show
# latest N" dropdown — the IP-timeline view uses a fixed small limit and
# never reaches it. Tune upward if attack volume grows; single configurable
# spot rather than scattered literals.
_MAX_EVENTS = 5000

# Authoritative schema — the centre owns this database (agents push over HTTP
# and never touch it). CREATE IF NOT EXISTS so every connect is idempotent and
# a fresh deployment self-initialises. NB: asn column carries the city name
# (legacy naming the UI reads), and event_id is the idempotency key.
_SEC_SCHEMA = """
CREATE TABLE IF NOT EXISTS security_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL,
    machine_id TEXT NOT NULL,
    event_type TEXT NOT NULL,
    src_ip TEXT NOT NULL,
    jail TEXT,
    uri TEXT,
    ua TEXT,
    username TEXT,
    country TEXT,
    city TEXT,
    asn TEXT,
    org TEXT,
    lat REAL,
    lon REAL,
    raw_excerpt TEXT,
    count INTEGER DEFAULT 1,
    burst INTEGER DEFAULT 0,
    created_at TEXT DEFAULT (datetime('now')),
    event_id TEXT
);
CREATE INDEX IF NOT EXISTS idx_events_ts ON security_events(ts);
CREATE INDEX IF NOT EXISTS idx_events_ip ON security_events(src_ip);
CREATE INDEX IF NOT EXISTS idx_events_type_ts ON security_events(event_type, ts);
CREATE UNIQUE INDEX IF NOT EXISTS idx_events_event_id
    ON security_events(event_id);

CREATE TABLE IF NOT EXISTS security_bans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip TEXT NOT NULL,
    jail TEXT NOT NULL,
    machine_id TEXT NOT NULL,
    banned_at TEXT NOT NULL,
    unbanned_at TEXT,
    ban_count INTEGER DEFAULT 1,
    last_event_id INTEGER,
    UNIQUE(ip, jail, machine_id, banned_at)
);
CREATE INDEX IF NOT EXISTS idx_bans_active ON security_bans(unbanned_at IS NULL);
CREATE INDEX IF NOT EXISTS idx_bans_ip ON security_bans(ip);

CREATE TABLE IF NOT EXISTS geo_cache (
    ip TEXT PRIMARY KEY,
    country TEXT,
    city TEXT,
    asn TEXT,
    org TEXT,
    lat REAL,
    lon REAL,
    threat_tags TEXT,
    first_seen TEXT,
    last_seen TEXT,
    query_count INTEGER DEFAULT 1
);
"""


def _sec_db() -> sqlite3.Connection:
    conn = sqlite3.connect(str(SEC_DB))
    conn.row_factory = sqlite3.Row
    conn.executescript(_SEC_SCHEMA)
    try:
        cols_sec = [r[1] for r in conn.execute("PRAGMA table_info(security_events)").fetchall()]
        if "city" not in cols_sec:
            conn.execute("ALTER TABLE security_events ADD COLUMN city TEXT")
        if "org" not in cols_sec:
            conn.execute("ALTER TABLE security_events ADD COLUMN org TEXT")
        cols_geo = [r[1] for r in conn.execute("PRAGMA table_info(geo_cache)").fetchall()]
        if "city" not in cols_geo:
            conn.execute("ALTER TABLE geo_cache ADD COLUMN city TEXT")
        if "org" not in cols_geo:
            conn.execute("ALTER TABLE geo_cache ADD COLUMN org TEXT")
        conn.commit()
    except Exception:
        pass
    return conn


@router.get("/security/events")
async def security_events(
    limit: int = 1000,
    before: str = "",
    jail: str = "",
    ip: str = "",
    type: str = "",
    machine_id: str = "",
    period: str = "all",
):
    """Cursor-paginated security events — map data source and IP timeline.

    Query params:
      limit:      page size (max _MAX_EVENTS)
      before:     ISO timestamp cursor (events older than this)
      jail:       filter by fail2ban jail
      ip:         filter by source IP
      type:       filter by event_type (ban|unban|attack|scan)
      machine_id: filter by machine (empty = all machines)
      period:     all (default) | 30m | 1h | 6h | 12h | 24h | 7d | 30d
    """
    limit = min(max(limit, 1), _MAX_EVENTS)
    sql = """
        SELECT
            e.*,
            COALESCE(e.city, g.city) as city,
            COALESCE(e.asn, g.asn) as asn,
            COALESCE(e.org, g.org) as org
        FROM security_events e
        LEFT JOIN geo_cache g ON e.src_ip = g.ip
        WHERE 1=1
    """
    params: list = []
    if before:
        sql += " AND e.ts < ?"
        params.append(before)
    if jail:
        sql += " AND e.jail = ?"
        params.append(jail)
    if ip:
        sql += " AND e.src_ip = ?"
        params.append(ip)
    if type:
        sql += " AND e.event_type = ?"
        params.append(type)
    if machine_id:
        sql += " AND e.machine_id = ?"
        params.append(machine_id)
    # Time window — ts carries a timezone offset, so compare via julianday
    # (naive string comparison mis-orders mixed +00:00/+08:00 timestamps).
    hours = {"30m": 0.5, "1h": 1, "6h": 6, "12h": 12, "24h": 24, "7d": 168, "30d": 720}.get(period)
    if hours:
        sql += " AND julianday(e.ts) > julianday('now') - ?"
        params.append(hours / 24.0)
    sql += " ORDER BY e.ts DESC LIMIT ?"
    params.append(limit)

    conn = _sec_db()
    try:
        rows = conn.execute(sql, params).fetchall()
        return {
            "items": [dict(r) for r in rows],
            "has_more": len(rows) == limit,
        }
    finally:
        conn.close()


@router.get("/security/bans/current")
async def security_bans_current(
    machine_id: str = "",
    ip: str = "",
    jail: str = "",
    sort: str = "recent",
    limit: int = 30,
    offset: int = 0,
    period: str = "all",
    start: str = "",
    end: str = "",
):
    """Currently active bans (unbanned_at IS NULL), filterable and paginated.

    Query params:
      machine_id: filter by machine (empty = all machines)
      ip:         filter by banned IP (exact)
      jail:       filter by fail2ban jail (exact)
      sort:       recent (last banned) | oldest (first banned) | ip | jail
      limit:      page size (max 500)
      offset:     page offset (0-based)
      period:     all (default) | 24h | 7d | 30d | custom — filters on banned_at
      start/end:  ISO datetime (used when period=custom)
    """
    limit = min(max(limit, 1), 500)
    offset = max(offset, 0)
    conn = _sec_db()
    try:
        conds = ["b.unbanned_at IS NULL"]
        params: list = []
        if machine_id:
            conds.append("b.machine_id = ?")
            params.append(machine_id)
        if ip:
            conds.append("b.ip = ?")
            params.append(ip)
        if jail:
            conds.append("b.jail = ?")
            params.append(jail)

        # Time filter on banned_at (period=custom uses start/end). julianday
        # comparison — banned_at carries a tz offset, so string compare skews.
        if period == "custom":
            if start:
                conds.append("julianday(b.banned_at) >= julianday(?)")
                params.append(start)
            if end:
                conds.append("julianday(b.banned_at) <= julianday(?)")
                params.append(end)
        else:
            days = {"24h": 1, "7d": 7, "30d": 30}.get(period)
            if days:
                conds.append("julianday(b.banned_at) > julianday('now') - ?")
                params.append(days)

        where = " AND ".join(conds)

        sort_map = {
            "recent": "b.banned_at DESC",
            "oldest": "b.banned_at ASC",
            "ip": "b.ip ASC",
            "jail": "b.jail ASC, b.banned_at DESC",
        }
        order = sort_map.get(sort, "b.banned_at DESC")

        total = conn.execute(
            f"SELECT COUNT(*) FROM security_bans b WHERE {where}", params
        ).fetchone()[0]

        rows = conn.execute(
            f"SELECT b.*, g.country, g.city, g.asn, g.org, g.lat, g.lon FROM security_bans b "
            f"LEFT JOIN geo_cache g ON b.ip = g.ip "
            f"WHERE {where} "
            f"ORDER BY {order} LIMIT ? OFFSET ?",
            params + [limit, offset],
        ).fetchall()
        return {"items": [dict(r) for r in rows], "count": len(rows), "total": total}
    finally:
        conn.close()


@router.get("/security/stats/summary")
async def security_stats_summary(period: str = "all", machine_id: str = ""):
    """All-time aggregate stats for the dashboard snapshot cards.

    The three snapshot cards (Active Bans / All-time Unique IPs /
    All-time Event Types) are all-time by design; time-window analysis moved
    to /security/stats/timeseries. `period` is kept for backward compatibility
    but no longer narrows the window.

    machine_id: optional per-machine filter (empty = all machines).
    """
    mcond = " AND machine_id = ?" if machine_id else ""
    mparam = [machine_id] if machine_id else []
    conn = _sec_db()
    try:
        total = conn.execute(
            "SELECT COUNT(*) FROM security_events WHERE 1=1" + mcond, mparam
        ).fetchone()[0]
        bans = conn.execute(
            "SELECT COUNT(*) FROM security_bans WHERE unbanned_at IS NULL" + mcond,
            mparam,
        ).fetchone()[0]
        ips = conn.execute(
            "SELECT COUNT(DISTINCT src_ip) FROM security_events WHERE 1=1" + mcond,
            mparam,
        ).fetchone()[0]
        by_type = {
            r[0]: r[1]
            for r in conn.execute(
                "SELECT event_type, COUNT(*) FROM security_events WHERE 1=1 "
                + mcond + " GROUP BY event_type",
                mparam,
            )
        }
        by_jail = {
            r[0]: r[1]
            for r in conn.execute(
                "SELECT jail, COUNT(*) FROM security_events WHERE jail IS NOT NULL "
                + mcond + " GROUP BY jail",
                mparam,
            )
        }
        return {
            "period": "all",
            "total_events": total,
            "active_bans": bans,
            "unique_ips": ips,
            "by_type": by_type,
            "by_jail": by_jail,
            "geoip": _get_geo_status(),
        }
    finally:
        conn.close()


# Time-bucket aggregation for the Events bar chart. Bucket keys are
# lexicographically ordered strings, so they map 1:1 onto a categorical axis.
_BUCKET_FMT = {"hour": "%Y-%m-%d %H", "day": "%Y-%m-%d", "month": "%Y-%m"}


def _iter_bucket_keys(bucket: str, offset: int, tz_offset_min: int) -> list[str]:
    """Enumerate the bucket keys (local-time, ordered) covering a window.

    bucket:        hour (one day) | day (one month) | month (one year)
    offset:        0 = current window, negative = earlier, positive = later
    tz_offset_min: timezone offset in minutes east of UTC (e.g. +480 for UTC+8)
    """
    import calendar

    now_local = datetime.now(timezone.utc) + timedelta(minutes=tz_offset_min)
    if bucket == "hour":
        base = now_local.replace(hour=0, minute=0, second=0, microsecond=0) + timedelta(days=offset)
        return [f"{(base + timedelta(hours=i)):%Y-%m-%d %H}" for i in range(24)]
    if bucket == "day":
        total = now_local.year * 12 + (now_local.month - 1) + offset
        year, month = divmod(total, 12)
        month += 1
        ndays = calendar.monthrange(year, month)[1]
        return [f"{year:04d}-{month:02d}-{d:02d}" for d in range(1, ndays + 1)]
    # month
    year = now_local.year + offset
    return [f"{year:04d}-{m:02d}" for m in range(1, 13)]


@router.get("/security/stats/timeseries")
async def security_stats_timeseries(
    bucket: str = "hour",
    offset: int = 0,
    tz_offset: int = 0,
    machine_id: str = "",
):
    """Time-bucketed event counts for the Events bar chart.

    bucket:      hour | day | month
    offset:      0 = current window, -1 = previous, +1 = next (caller clamps
                 navigation into the future on the front end)
    tz_offset:   timezone offset in minutes east of UTC (e.g. 480 for UTC+8),
                 supplied by the browser so buckets align with the viewer's
                 local calendar days
    machine_id:  optional per-machine filter (empty = all machines)

    Returns {bucket, offset, tz_offset, buckets:[{key, total, unique_ips,
    by_type:{...}}]} with empty buckets zero-filled, ordered lexicographically.
    """
    if bucket not in _BUCKET_FMT:
        raise HTTPException(400, f"invalid bucket: {bucket}")
    # Clamp to real-world UTC offsets (UTC-14 .. UTC+14) as a sanity guard.
    tz_offset = max(-840, min(840, int(tz_offset)))
    fmt = _BUCKET_FMT[bucket]
    keys = _iter_bucket_keys(bucket, int(offset), tz_offset)
    mod = f"{tz_offset:+d} minutes"
    # e.ts is an ISO string with an explicit offset; strftime normalises it to
    # UTC before applying the viewer's offset. `instr(ts,'T')>0` drops legacy
    # malformed rows that would otherwise bucket under a NULL key.
    mcond = " AND e.machine_id = ?" if machine_id else ""
    mparam = [machine_id] if machine_id else []

    conn = _sec_db()
    try:
        rows = conn.execute(
            f"SELECT strftime(?, e.ts, ?) AS b, COUNT(*) AS total, "
            f"COUNT(DISTINCT e.src_ip) AS uniq "
            f"FROM security_events e "
            f"WHERE instr(e.ts, 'T') > 0 {mcond} "
            f"GROUP BY b",
            (fmt, mod, *mparam),
        ).fetchall()
        totals: dict[str, int] = {}
        uniq: dict[str, int] = {}
        for r in rows:
            if r["b"] is not None:
                totals[r["b"]] = r["total"]
                uniq[r["b"]] = r["uniq"]

        trows = conn.execute(
            f"SELECT strftime(?, e.ts, ?) AS b, e.event_type AS t, COUNT(*) AS c "
            f"FROM security_events e "
            f"WHERE instr(e.ts, 'T') > 0 {mcond} "
            f"GROUP BY b, t",
            (fmt, mod, *mparam),
        ).fetchall()
        by_type: dict[str, dict[str, int]] = {}
        for r in trows:
            if r["b"] is not None:
                by_type.setdefault(r["b"], {})[r["t"]] = r["c"]

        buckets = [
            {
                "key": k,
                "total": totals.get(k, 0),
                "unique_ips": uniq.get(k, 0),
                "by_type": by_type.get(k, {}),
            }
            for k in keys
        ]
        return {
            "bucket": bucket,
            "offset": offset,
            "tz_offset": tz_offset,
            "buckets": buckets,
        }
    finally:
        conn.close()


@router.get("/security/attackers")
async def security_attackers(
    period: str = "7d",
    start: str = "",
    end: str = "",
    type: str = "",
    country: str = "",
    asn: str = "",
    org: str = "",
    ip: str = "",
    sort: str = "recent",
    limit: int = 30,
    offset: int = 0,
    machine_id: str = "",
):
    """Aggregated attacker cards for Level 1 view.

    Query params:
      period:    24h | 7d | 30d | custom (use start/end instead)
      start:     ISO datetime (overrides period)
      end:       ISO datetime (overrides period)
      type:      filter by event_type
      country:   filter by country code
      asn:       filter by ASN (e.g. 14061 or AS14061)
      org:       filter by Organization / ISP name
      ip:        filter by source IP
      sort:      recent (last activity) | count (most events) | newest (first seen)
      limit:     page size (max 500)
      offset:    page offset (0-based)
      machine_id: filter by machine (empty = all machines)
    """
    limit = min(max(limit, 1), 500)
    offset = max(offset, 0)
    conn = _sec_db()
    try:
        # Build time filter (julianday — ts carries a tz offset, string compare skews)
        if start and end:
            time_cond = "julianday(e.ts) >= julianday(?) AND julianday(e.ts) <= julianday(?)"
            params = [start, end]
        else:
            days = {"24h": 1, "7d": 7, "30d": 30}.get(period, 7)
            time_cond = "julianday(e.ts) > julianday('now') - ?"
            params: list = [days]

        # Additional filters
        filters = ""
        if type:
            filters += " AND e.event_type = ?"
            params.append(type)
        if country:
            filters += " AND (e.country = ? OR g.country = ?)"
            params.extend([country, country])
        if asn:
            filters += " AND (e.asn LIKE ? OR g.asn LIKE ?)"
            params.extend([f"%{asn}%", f"%{asn}%"])
        if org:
            filters += " AND (e.org LIKE ? OR g.org LIKE ?)"
            params.extend([f"%{org}%", f"%{org}%"])
        if ip:
            filters += " AND e.src_ip = ?"
            params.append(ip)
        if machine_id:
            filters += " AND e.machine_id = ?"
            params.append(machine_id)

        # Sort mapping (labels on the front-end must mirror these semantics)
        sort_map = {
            "recent": "last_seen DESC",
            "count": "total_events DESC",
            "newest": "first_seen DESC",
        }
        order = sort_map.get(sort, "last_seen DESC")

        # Total matches (for pagination) — same WHERE, aggregated distinct IPs
        total = conn.execute(
            f"SELECT COUNT(DISTINCT e.src_ip) FROM security_events e "
            f"LEFT JOIN geo_cache g ON e.src_ip = g.ip "
            f"WHERE {time_cond} {filters}",
            params,
        ).fetchone()[0]

        sql = f"""
            SELECT
                e.src_ip,
                COALESCE(e.country, g.country) as country,
                COALESCE(e.city, g.city) as city,
                COALESCE(e.asn, g.asn) as asn,
                COALESCE(e.org, g.org) as org,
                COALESCE(e.lat, g.lat) as lat,
                COALESCE(e.lon, g.lon) as lon,
                COUNT(*) as total_events,
                MAX(e.ts) as last_seen,
                MIN(e.ts) as first_seen,
                GROUP_CONCAT(DISTINCT e.event_type) as types
            FROM security_events e
            LEFT JOIN geo_cache g ON e.src_ip = g.ip
            WHERE {time_cond} {filters}
            GROUP BY e.src_ip
            ORDER BY {order}
            LIMIT ? OFFSET ?
        """
        rows = conn.execute(sql, params + [limit, offset]).fetchall()
        return {
            "items": [dict(r) for r in rows],
            "count": len(rows),
            "total": total,
        }
    finally:
        conn.close()


@router.get("/security/export")
async def security_export(
    period: str = "7d",
    start: str = "",
    end: str = "",
    type: str = "",
    country: str = "",
    asn: str = "",
    org: str = "",
    ip: str = "",
    sort: str = "recent",
    format: str = "json",
    machine_id: str = "",
):
    """Export the filtered raw event stream as a JSON/CSV download.

    Exports raw security_events rows (not aggregated) matching the same filter
    params as the Attackers list, so the download mirrors the UI's current
    view. Consumed by the Attackers card's JSON/CSV buttons. Auth: session.
    """
    conn = _sec_db()
    try:
        # julianday comparison — ts carries a tz offset, string compare skews.
        if start and end:
            time_cond = "julianday(ts) >= julianday(?) AND julianday(ts) <= julianday(?)"
            params = [start, end]
        else:
            days = {"24h": 1, "7d": 7, "30d": 30}.get(period, 7)
            time_cond = "julianday(ts) > julianday('now') - ?"
            params: list = [days]

        filters = ""
        if type:
            filters += " AND event_type = ?"
            params.append(type)
        if country:
            filters += " AND country = ?"
            params.append(country)
        if asn:
            filters += " AND asn LIKE ?"
            params.append(f"%{asn}%")
        if org:
            filters += " AND org LIKE ?"
            params.append(f"%{org}%")
        if ip:
            filters += " AND src_ip = ?"
            params.append(ip)
        if machine_id:
            filters += " AND machine_id = ?"
            params.append(machine_id)

        # Export is an event stream (not aggregated), so sort by event time.
        # Mirrors the attackers sort keys so the export follows the same
        # filtering/ordering intent as the UI.
        sort_map = {
            "recent": "ts DESC",
            "count": "count DESC",
            "newest": "ts DESC",
        }
        order = sort_map.get(sort, "ts DESC")

        sql = f"""
            SELECT * FROM security_events
            WHERE {time_cond} {filters}
            ORDER BY {order}
            LIMIT 10000
        """
        rows = conn.execute(sql, params).fetchall()
        items = [dict(r) for r in rows]

        ts = datetime.now().strftime("%Y%m%d-%H%M%S")

        if format == "csv":
            import csv
            import io
            output = io.StringIO()
            if items:
                writer = csv.DictWriter(output, fieldnames=items[0].keys())
                writer.writeheader()
                writer.writerows(items)
            content = output.getvalue()
            return Response(
                content=content,
                media_type="text/csv",
                headers={
                    "Content-Disposition": f"attachment; filename=security-events-{ts}.csv"
                },
            )

        from fastapi.responses import JSONResponse
        return JSONResponse(
            content={"items": items, "count": len(items), "exported_at": datetime.now(timezone.utc).isoformat()},
            headers={
                "Content-Disposition": f"attachment; filename=security-events-{ts}.json"
            },
        )
    finally:
        conn.close()


@router.post("/security/rotate")
async def security_rotate(keep_days: int = 90):
    """Manually trigger event retention pruning.

    Deletes events older than keep_days (default 90). The agent normally runs
    this on a schedule; this lets the centre trigger it manually. Auth: session.
    """
    conn = _sec_db()
    try:
        cur = conn.execute(
            "DELETE FROM security_events WHERE julianday(ts) < julianday('now', ?)",
            (f"-{keep_days} days",),
        )
        conn.commit()
        deleted = cur.rowcount
        return {"ok": True, "deleted": deleted, "keep_days": keep_days}
    finally:
        conn.close()


@router.get("/security/ip/{ip}")
async def security_ip_profile(ip: str):
    """Per-IP drill-down: recent events + ban history + geo profile.

    Backs the Level-2 IP investigation drawer (IpTimeline). Lazily geo-enriches
    the IP on first cache miss. Auth: session.
    """
    conn = _sec_db()
    try:
        events = conn.execute(
            "SELECT * FROM security_events WHERE src_ip = ? "
            "ORDER BY ts DESC LIMIT 100",
            (ip,),
        ).fetchall()
        bans = conn.execute(
            "SELECT * FROM security_bans WHERE ip = ? "
            "ORDER BY banned_at DESC",
            (ip,),
        ).fetchall()
        geo = conn.execute(
            "SELECT * FROM geo_cache WHERE ip = ?",
            (ip,),
        ).fetchone()
        if not geo or not geo["country"] or not geo["asn"]:
            _geoip_lookup(conn, ip)
            geo = conn.execute("SELECT * FROM geo_cache WHERE ip = ?", (ip,)).fetchone()
        return {
            "ip": ip,
            "events": [dict(r) for r in events],
            "bans": [dict(r) for r in bans],
            "geo": dict(geo) if geo else None,
        }
    finally:
        conn.close()


# ================================================================ security ingest (multi-machine push)
#
# Remote agents (USA/HK probes, and the local DE agent) push parsed security
# events here over HTTP bearer-token auth, instead of writing SQLite directly.
# The bearer token is verified by the dashboard's token-auth seam
# (dashboard_auth/token_auth.py) which we plug into below; this endpoint then
# derives machine_id from the verified principal — NEVER trusting the client's
# self-reported machine_id — geo-enriches, and UPSERTs by event_id (idempotent).

GEOIP_CITY_DB = Path(os.environ.get(
    "BESZEL_GEOIP_DB", str(PLUGIN_DATA_DIR / "dbip-city-lite.mmdb")))
GEOIP_ASN_DB = Path(os.environ.get(
    "BESZEL_GEOIP_ASN_DB", str(PLUGIN_DATA_DIR / "dbip-asn-lite.mmdb")))
GEOIP_DB = GEOIP_CITY_DB  # backward compatibility alias

# event types an agent may legitimately report
_VALID_EVENT_TYPES = {"ban", "unban", "attack", "scan", "auth_fail", "auth_success"}
# hard caps — a single ingest batch can never exhaust memory or the DB
_MAX_BATCH = 500
_MAX_COUNT = 100_000
# string field length caps (defence against unbounded payloads)
_LEN = {"jail": 100, "uri": 2048, "ua": 512, "username": 100, "raw_excerpt": 512, "event_id": 200}


# ---------------------------------------------------------------- token auth
# The ingest token is one of two things, both managed in the beszel web UI:
#   * a **per-system token** (UUID, created by "Add System") — lives in the
#     `fingerprints` table, uniquely bound to one system. We resolve the machine
#     name from it via `expand=system`, so the agent cannot spoof another machine.
#   * a **universal token** (created in /settings/tokens) — lives in the
#     `universal_tokens` table, user-scoped and shared by any number of machines.
#     It only proves "is one of us"; the machine_id must be self-reported and
#     checked against the systems table.
#
# Order matters: check universal_tokens FIRST. A universal token that has been
# used to auto-register machines also appears in `fingerprints` (one row per
# machine), so resolving it from fingerprints would be ambiguous. Per-system
# tokens never appear in universal_tokens, so the fallback is unambiguous.

# Cached snapshot of beszel's token/identity tables, refreshed on a TTL.
# verify_token() is synchronous (framework requirement) and runs on every ingest,
# so we never hit the PB API synchronously — the cache is warmed lazily and
# re-read on a short TTL.
_beszel_auth_cache = {
    "universal_tokens": set(),        # universal token values
    "per_system": {},                 # {per-system-token: machine_name}
    "systems": set(),                 # system NAMES (for universal-token self-report)
    "ts": 0.0,
    "lock": threading.Lock(),
}
_AUTH_TTL = 60.0  # seconds


def _refresh_beszel_auth():
    """Refresh the cached token/identity snapshot from beszel PB.

    On any failure the previous cache is kept (fail-closed: an empty cache
    rejects everything, but we only ever replace it on a successful read)."""
    now = time.time()
    cache = _beszel_auth_cache
    if now - cache["ts"] < _AUTH_TTL:
        return
    try:
        tok = _get_token()
    except HTTPException:
        return
    try:
        # universal tokens
        req = urllib.request.Request(
            f"{HUB}/api/collections/universal_tokens/records?perPage=500",
            headers={"Authorization": tok},
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            universal = {r.get("token", "") for r in json.loads(resp.read()).get("items", [])}

        # systems (names, for the universal-token self-report path)
        req = urllib.request.Request(
            f"{HUB}/api/collections/systems/records?perPage=500",
            headers={"Authorization": tok},
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            systems = {r.get("name", "") for r in json.loads(resp.read()).get("items", [])}

        # per-system tokens: {token: system name}, but EXCLUDE any token that is
        # also a universal token (those are ambiguous — one universal token can
        # back several machines). expand=system gives us the name directly.
        req = urllib.request.Request(
            f"{HUB}/api/collections/fingerprints/records?perPage=500&expand=system",
            headers={"Authorization": tok},
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            per_system = {}
            for r in json.loads(resp.read()).get("items", []):
                tk = r.get("token", "")
                name = (r.get("expand", {}).get("system") or {}).get("name", "")
                if tk and name and tk not in universal:
                    per_system[tk] = name
    except Exception:
        return  # keep the previous cache on any error
    with cache["lock"]:
        cache["universal_tokens"] = universal
        cache["per_system"] = per_system
        cache["systems"] = systems
        cache["ts"] = now


def _resolve_token(token: str) -> str | None:
    """Map a bearer token to a machine_id (or None if unknown).

    Returns the machine name for a per-system token, the sentinel
    'authenticated-agent' for a universal token (machine_id resolved later from
    the request body), or None if the token is not recognised."""
    _refresh_beszel_auth()
    with _beszel_auth_cache["lock"]:
        cache = _beszel_auth_cache
        if token in cache["universal_tokens"]:
            return "authenticated-agent"
        return cache["per_system"].get(token)


def _is_known_system(name: str) -> bool:
    _refresh_beszel_auth()
    with _beszel_auth_cache["lock"]:
        return name in _beszel_auth_cache["systems"]


def _make_ingest_provider():
    """Build the beszel-token provider. Imported lazily so the module still
    loads (read-only endpoints keep working) even if hermes_cli moves."""
    from hermes_cli.dashboard_auth.base import (
        DashboardAuthProvider,
        TokenPrincipal,
    )

    class SecurityIngestProvider(DashboardAuthProvider):
        name = "security-ingest"
        display_name = "Security Ingest"
        supports_token = True
        supports_session = False

        def verify_token(self, *, token: str):
            token = (token or "").strip()
            if not token:
                return None
            resolved = _resolve_token(token)
            if resolved is None:
                return None
            # principal is either the resolved machine name (per-system token) or
            # the sentinel "authenticated-agent" (universal token — the real
            # machine_id is taken from the request body + systems table in ingest).
            return TokenPrincipal(
                principal=resolved,
                provider=self.name,
                scopes=("security:ingest",),
            )

        # --- abstract OAuth/session methods: token-only provider, never used ---
        def start_login(self, *, redirect_uri):  # pragma: no cover
            raise NotImplementedError

        def complete_login(self, *, code, state, code_verifier, redirect_uri):  # pragma: no cover
            raise NotImplementedError

        def verify_session(self, *, access_token):  # pragma: no cover
            raise NotImplementedError

        def refresh_session(self, *, refresh_token):  # pragma: no cover
            raise NotImplementedError

        def revoke_session(self, *, refresh_token):  # pragma: no cover
            raise NotImplementedError

    return SecurityIngestProvider()


# Register the ingest route as token-authable + install the provider. Both are
# idempotent / upsert, so repeated plugin imports are safe. Failure here means
# ingest simply stays behind the normal cookie gate (fail-closed, never open).
try:
    from hermes_cli.dashboard_auth.registry import register_global_provider
    from hermes_cli.dashboard_auth.token_auth import register_token_route

    register_token_route("/api/plugins/beszel/security/ingest")
    register_global_provider(_make_ingest_provider())
except Exception as _e:  # pragma: no cover
    import logging
    logging.getLogger(__name__).warning("security ingest token-auth registration failed: %s", _e)


# ---------------------------------------------------------------- geoip & asn (centre-side)
_geo_city_reader = None
_geo_asn_reader = None
_geo_lock = threading.Lock()
_geo_status = {
    "city": {"type": "DBIP-City-Lite", "build_month": None, "build_epoch": None, "status": "idle"},
    "asn": {"type": "DBIP-ASN-Lite", "build_month": None, "build_epoch": None, "status": "idle"},
    "last_checked": None,
    "last_updated": None,
    "status": "ok",
    "error": None,
}


def _get_geo_status() -> dict:
    """Return current GeoIP + ASN metadata and updater state."""
    global _geo_status
    city_reader = _geo_city_reader_get()
    if city_reader is not None and _geo_status["city"]["build_month"] is None:
        try:
            meta = city_reader.metadata()
            _geo_status["city"]["build_epoch"] = meta.build_epoch
            _geo_status["city"]["build_month"] = datetime.fromtimestamp(
                meta.build_epoch, timezone.utc
            ).strftime("%Y-%m")
        except Exception:
            pass
    asn_reader = _geo_asn_reader_get()
    if asn_reader is not None and _geo_status["asn"]["build_month"] is None:
        try:
            meta = asn_reader.metadata()
            _geo_status["asn"]["build_epoch"] = meta.build_epoch
            _geo_status["asn"]["build_month"] = datetime.fromtimestamp(
                meta.build_epoch, timezone.utc
            ).strftime("%Y-%m")
        except Exception:
            pass
    res = dict(_geo_status)
    res["database_type"] = "DBIP City + ASN"
    res["build_month"] = _geo_status["city"].get("build_month") or _geo_status["asn"].get("build_month")
    return res


def _geo_city_reader_get():
    global _geo_city_reader
    if _geo_city_reader is None and GEOIP_CITY_DB.exists():
        with _geo_lock:
            if _geo_city_reader is None:
                try:
                    import maxminddb
                    _geo_city_reader = maxminddb.open_database(str(GEOIP_CITY_DB))
                    meta = _geo_city_reader.metadata()
                    _geo_status["city"]["build_epoch"] = meta.build_epoch
                    _geo_status["city"]["build_month"] = datetime.fromtimestamp(
                        meta.build_epoch, timezone.utc
                    ).strftime("%Y-%m")
                    _geo_status["city"]["status"] = "ok"
                except Exception as e:
                    _geo_status["city"]["status"] = "error"
                    _geo_status["city"]["error"] = str(e)
    return _geo_city_reader


def _geo_asn_reader_get():
    global _geo_asn_reader
    if _geo_asn_reader is None and GEOIP_ASN_DB.exists():
        with _geo_lock:
            if _geo_asn_reader is None:
                try:
                    import maxminddb
                    _geo_asn_reader = maxminddb.open_database(str(GEOIP_ASN_DB))
                    meta = _geo_asn_reader.metadata()
                    _geo_status["asn"]["build_epoch"] = meta.build_epoch
                    _geo_status["asn"]["build_month"] = datetime.fromtimestamp(
                        meta.build_epoch, timezone.utc
                    ).strftime("%Y-%m")
                    _geo_status["asn"]["status"] = "ok"
                except Exception as e:
                    _geo_status["asn"]["status"] = "error"
                    _geo_status["asn"]["error"] = str(e)
    return _geo_asn_reader


def _reload_all_geo_readers():
    """Hot-reload in-memory readers after DB updates."""
    global _geo_city_reader, _geo_asn_reader
    with _geo_lock:
        if _geo_city_reader is not None:
            try:
                _geo_city_reader.close()
            except Exception:
                pass
            _geo_city_reader = None
        if _geo_asn_reader is not None:
            try:
                _geo_asn_reader.close()
            except Exception:
                pass
            _geo_asn_reader = None
    _geo_city_reader_get()
    _geo_asn_reader_get()


def _update_single_mmdb(db_key: str, db_file: Path, url_prefix: str, cur_month: str) -> bool:
    """Safely download, test-open, backup and atomically replace one MMDB file."""
    import gzip
    import shutil
    import urllib.request
    import logging

    logger = logging.getLogger(f"beszel.geoip.{db_key}")
    url = f"https://download.db-ip.com/free/dbip-{url_prefix}-lite-{cur_month}.mmdb.gz"
    gz_path = db_file.with_suffix(".mmdb.gz.tmp")
    tmp_path = db_file.with_suffix(".mmdb.tmp")

    try:
        db_file.parent.mkdir(parents=True, exist_ok=True)
        req = urllib.request.Request(url, headers={"User-Agent": "hermes-beszel-geoip-updater"})
        with urllib.request.urlopen(req, timeout=180) as resp, open(gz_path, "wb") as f:
            shutil.copyfileobj(resp, f)

        with gzip.open(gz_path, "rb") as fi, open(tmp_path, "wb") as fo:
            shutil.copyfileobj(fi, fo)

        # Validate with maxminddb
        import maxminddb
        test_reader = maxminddb.open_database(str(tmp_path))
        meta = test_reader.metadata()
        new_month = datetime.fromtimestamp(meta.build_epoch, timezone.utc).strftime("%Y-%m")
        test_reader.get("8.8.8.8")
        test_reader.close()

        if new_month < cur_month:
            logger.info("Downloaded %s build %s older than %s, skipping", db_key, new_month, cur_month)
            tmp_path.unlink(missing_ok=True)
            return False

        if db_file.exists():
            shutil.copy2(db_file, db_file.with_suffix(".mmdb.bak"))
        os.replace(tmp_path, db_file)
        logger.info("%s DB updated to %s", db_key, new_month)
        return True
    except Exception as e:
        logger.warning("%s DB update failed: %s", db_key, e)
        tmp_path.unlink(missing_ok=True)
        return False
    finally:
        gz_path.unlink(missing_ok=True)


def _update_all_geoip_dbs() -> bool:
    """Update both City and ASN databases if a newer monthly build exists."""
    now = datetime.now(timezone.utc)
    cur_month = now.strftime("%Y-%m")
    _geo_status["last_checked"] = now.isoformat()

    city_updated = False
    asn_updated = False

    city_month = _geo_status["city"].get("build_month")
    if not city_month or city_month < cur_month:
        city_updated = _update_single_mmdb("city", GEOIP_CITY_DB, "city", cur_month)

    asn_month = _geo_status["asn"].get("build_month")
    if not asn_month or asn_month < cur_month:
        asn_updated = _update_single_mmdb("asn", GEOIP_ASN_DB, "asn", cur_month)

    if city_updated or asn_updated:
        _reload_all_geo_readers()
        _geo_status["last_updated"] = datetime.now(timezone.utc).isoformat()
        return True
    return False


def _geoip_updater_loop():
    """Background worker: runs 30s after startup, then every 24 hours."""
    time.sleep(30)
    while True:
        try:
            _update_all_geoip_dbs()
        except Exception:
            pass
        time.sleep(24 * 3600)


# Start background auto-updater thread
_updater_thread = threading.Thread(target=_geoip_updater_loop, name="geoip-updater", daemon=True)
_updater_thread.start()


def _geoip_lookup(conn: sqlite3.Connection, ip: str):
    """Return (country, city, asn, org, lat, lon); cached in geo_cache.
    Enriched on the centre from both DB-IP City and ASN databases."""
    row = conn.execute(
        "SELECT country, city, asn, org, lat, lon FROM geo_cache WHERE ip = ?", (ip,)
    ).fetchone()
    if row and row["country"] and (row["asn"] and str(row["asn"]).startswith("AS")) and (row["city"] is not None or row["lat"] is not None):
        return row[0], row[1], row[2], row[3], row[4], row[5]

    country = row["country"] if row else None
    city = row["city"] if row else None
    asn = row["asn"] if row else None
    org = row["org"] if row else None
    lat = row["lat"] if row else None
    lon = row["lon"] if row else None

    # City reader
    if not country or not city or lat is None or lon is None:
        city_reader = _geo_city_reader_get()
        if city_reader:
            try:
                r = city_reader.get(ip)
                if r:
                    country = country or r.get("country", {}).get("iso_code")
                    city = city or r.get("city", {}).get("names", {}).get("en")
                    loc = r.get("location", {})
                    lat = lat if lat is not None else loc.get("latitude")
                    lon = lon if lon is not None else loc.get("longitude")
            except Exception:
                pass

    # ASN reader
    if not asn or not org:
        asn_reader = _geo_asn_reader_get()
        if asn_reader:
            try:
                r = asn_reader.get(ip)
                if r:
                    asn_num = r.get("autonomous_system_number")
                    asn = asn or (f"AS{asn_num}" if asn_num else None)
                    org = org or r.get("autonomous_system_organization")
            except Exception:
                pass

    now = datetime.now(timezone.utc).isoformat()
    conn.execute(
        "INSERT INTO geo_cache (ip, country, city, asn, org, lat, lon, first_seen, last_seen, query_count) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1) "
        "ON CONFLICT(ip) DO UPDATE SET "
        "country=COALESCE(excluded.country, geo_cache.country), "
        "city=COALESCE(excluded.city, geo_cache.city), "
        "asn=COALESCE(excluded.asn, geo_cache.asn), "
        "org=COALESCE(excluded.org, geo_cache.org), "
        "lat=COALESCE(excluded.lat, geo_cache.lat), "
        "lon=COALESCE(excluded.lon, geo_cache.lon), "
        "last_seen=excluded.last_seen, "
        "query_count=geo_cache.query_count + 1",
        (ip, country, city, asn, org, lat, lon, now, now),
    )
    return country, city, asn, org, lat, lon


# ---------------------------------------------------------------- validation
def _clip(value, field):
    if value is None:
        return None
    return str(value)[: _LEN[field]]


def _validate_event(ev):
    """Validate + normalise one pushed event. Returns a clean dict or None.

    Only structural/semantic checks; machine_id and geo are filled in by the
    centre (never trusted from the wire)."""
    if not isinstance(ev, dict):
        return None

    event_id = ev.get("event_id")
    if not isinstance(event_id, str) or not (1 <= len(event_id) <= _LEN["event_id"]):
        return None

    event_type = ev.get("event_type")
    if event_type not in _VALID_EVENT_TYPES:
        return None

    src_ip = ev.get("src_ip")
    if not isinstance(src_ip, str):
        return None
    try:
        addr = ipaddress.ip_address(src_ip)
    except ValueError:
        return None
    if not addr.is_global:  # reject loopback/private/reserved — never real attackers
        return None

    ts = ev.get("ts")
    if not isinstance(ts, str):
        return None
    try:
        ts_dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        if ts_dt.tzinfo is None:
            ts_dt = ts_dt.replace(tzinfo=timezone.utc)
    except ValueError:
        return None
    now = datetime.now(timezone.utc)
    if ts_dt > now + timedelta(minutes=15):  # clock-skew guard
        return None
    if (now - ts_dt).days > 90:  # older than the rotation window → drop
        return None

    try:
        count = int(ev.get("count", 1))
    except (TypeError, ValueError):
        return None
    if not (1 <= count <= _MAX_COUNT):
        return None

    return {
        "event_id": event_id,
        "ts": ts_dt.isoformat(),
        "event_type": event_type,
        "src_ip": src_ip,
        "jail": _clip(ev.get("jail"), "jail"),
        "uri": _clip(ev.get("uri"), "uri"),
        "ua": _clip(ev.get("ua"), "ua"),
        "username": _clip(ev.get("username"), "username"),
        "raw_excerpt": _clip(ev.get("raw_excerpt"), "raw_excerpt"),
        "count": count,
        "burst": 1 if ev.get("burst") else 0,
    }


def _ingest_one(conn: sqlite3.Connection, machine_id: str, ev: dict) -> bool:
    """Geo-enrich + idempotent UPSERT one validated event. Returns True if stored."""
    clean = _validate_event(ev)
    if clean is None:
        return False

    country, city, asn, org, lat, lon = _geoip_lookup(conn, clean["src_ip"])

    # Idempotent upsert. On event_id conflict keep the larger count (agents push
    # cumulative window snapshots, and a retransmission must never double-count).
    conn.execute(
        "INSERT INTO security_events "
        "(ts, machine_id, event_type, src_ip, jail, uri, ua, username, raw_excerpt, "
        " country, city, asn, org, lat, lon, count, burst, event_id) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) "
        "ON CONFLICT(event_id) DO UPDATE SET count = MAX(security_events.count, excluded.count)",
        (
            clean["ts"], machine_id, clean["event_type"], clean["src_ip"],
            clean["jail"], clean["uri"], clean["ua"], clean["username"],
            clean["raw_excerpt"], country, city, asn, org, lat, lon, clean["count"],
            clean["burst"], clean["event_id"],
        ),
    )

    # fail2ban ban/unban also maintain the bans table (both ops are idempotent).
    if clean["event_type"] == "ban":
        row = conn.execute(
            "SELECT id FROM security_events WHERE event_id = ?", (clean["event_id"],)
        ).fetchone()
        conn.execute(
            "INSERT OR IGNORE INTO security_bans (ip, jail, machine_id, banned_at, last_event_id) "
            "VALUES (?, ?, ?, ?, ?)",
            (clean["src_ip"], clean["jail"] or "", machine_id, clean["ts"],
             row[0] if row else None),
        )
    elif clean["event_type"] == "unban":
        conn.execute(
            "UPDATE security_bans SET unbanned_at = ? "
            "WHERE ip = ? AND jail = ? AND machine_id = ? AND unbanned_at IS NULL",
            (clean["ts"], clean["src_ip"], clean["jail"] or "", machine_id),
        )
    return True


@router.post("/security/ingest")
async def security_ingest(request: Request):
    """Receive a batch of security events from a remote/local agent.

    Auth: bearer token = a beszel universal token (verified by the token-auth
    seam via the beszel PB API). The machine identity is the agent's
    self-reported ``machine_id``, which must equal a system NAME registered in
    beszel (checked against the systems table) — so an agent can't invent an
    arbitrary machine, and machines are managed entirely from the beszel UI.
    """
    principal = getattr(request.state, "token_principal", None)
    if principal is None or "security:ingest" not in getattr(principal, "scopes", ()):
        raise HTTPException(401, "unauthenticated")

    try:
        body = await request.json()
    except Exception:
        raise HTTPException(400, "invalid json")
    events = body.get("events") if isinstance(body, dict) else None
    if not isinstance(events, list):
        raise HTTPException(400, "events must be a list")
    if len(events) > _MAX_BATCH:
        raise HTTPException(400, f"batch too large (max {_MAX_BATCH})")

    # Resolve the machine identity.
    #   * per-system token → principal IS the machine name (locked, no self-report)
    #   * universal token → principal is the sentinel; machine_id must be
    #     self-reported and equal a beszel-registered system name.
    if principal.principal == "authenticated-agent":
        machine_id = body.get("machine_id") if isinstance(body, dict) else None
        if not isinstance(machine_id, str) or not machine_id:
            raise HTTPException(400, "machine_id is required")
        if not _is_known_system(machine_id):
            raise HTTPException(401, "unknown machine_id")
    else:
        machine_id = principal.principal

    conn = _sec_db()
    accepted = rejected = 0
    try:
        for ev in events:
            if _ingest_one(conn, machine_id, ev):
                accepted += 1
            else:
                rejected += 1
        conn.commit()
    finally:
        conn.close()
    return {"ok": True, "machine_id": machine_id, "accepted": accepted, "rejected": rejected}


MACHINE_LOCATIONS_FILE = Path(os.environ.get(
    "BESZEL_MACHINE_LOCATIONS_FILE", str(PLUGIN_DATA_DIR / "machine_locations.json")))


def _load_machine_locations() -> dict:
    """Manual coordinate overrides: {name-or-id: {lat, lon, city, country}}.

    Takes priority over GeoIP — needed when an agent's host is a loopback/NAT
    address (no public IP to geo-locate) or when dbip mis-geolocates (the host
    IP may be registered to a provider whose IP range is announced from a
    different country than where the server actually sits).
    """
    try:
        data = json.loads(MACHINE_LOCATIONS_FILE.read_text())
        return data if isinstance(data, dict) else {}
    except (OSError, json.JSONDecodeError):
        return {}


@router.get("/security/machines")
async def security_machines():
    """Machine list for the front-end selector, reusing beszel's PB systems table.

    Coordinates come from our centre-side GeoIP (systems.host → mmdb); beszel
    itself stores no location. Falls back to the local machine only if PB is down.
    """
    machines = []
    locations = _load_machine_locations()
    try:
        tok = _get_token()
        req = urllib.request.Request(
            f"{HUB}/api/collections/systems/records?perPage=200",
            headers={"Authorization": tok},
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read())
        for s in data.get("items", []):
            host = s.get("host", "")
            ip = host.split(":")[0].strip()
            lat = lon = country = city = None
            # Manual coordinate override (matched by system name or id) wins over
            # GeoIP — covers loopback/NAT hosts and dbip mis-geolocation.
            ov = locations.get(s.get("name")) or locations.get(s.get("id"))
            if isinstance(ov, dict):
                lat, lon = ov.get("lat"), ov.get("lon")
                country, city = ov.get("country"), ov.get("city")
            else:
                try:
                    if ipaddress.ip_address(ip).is_global:
                        conn = _sec_db()
                        try:
                            country, city, asn, org, lat, lon = _geoip_lookup(conn, ip)
                            conn.commit()
                        finally:
                            conn.close()
                except ValueError:
                    pass
            machines.append({
                "id": s.get("id"),
                "name": s.get("name"),
                "host": host,
                "status": s.get("status"),
                "country": country, "city": city, "lat": lat, "lon": lon,
            })
    except Exception as e:
        # PB unreachable → degrade to local machine so the UI still renders
        machines = [{
            "id": "local", "name": "local", "host": "", "status": "up",
            "country": None, "city": None, "lat": None, "lon": None,
            "_error": str(e),
        }]
    return {"items": machines}

"""beszel plugin API: PocketBase 反代层 + security events API.

浏览器只认 Hermes dashboard 会话；本模块持有 beszel superuser token，
把 /api/plugins/beszel/pb/* 转发到 127.0.0.1:8090 的 PocketBase。
同时暴露 /api/plugins/beszel/security/* 查询安全事件。
"""
import asyncio
import hmac
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
CRED_FILE = Path(os.environ.get(
    "BESZEL_CRED_FILE", "/root/hermes-workspace/reports/dashboard-credentials.txt"))
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
SEC_DB = Path("/root/hermes-workspace/reports/security-events.db")

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
    asn TEXT,
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
    return conn


@router.get("/security/events")
async def security_events(
    limit: int = 50,
    before: str = "",
    jail: str = "",
    ip: str = "",
    type: str = "",
    machine_id: str = "",
):
    """Cursor-paginated security events.

    Query params:
      limit:      page size (max 200)
      before:     ISO timestamp cursor (events older than this)
      jail:       filter by fail2ban jail
      ip:         filter by source IP
      type:       filter by event_type (ban|unban|attack|scan)
      machine_id: filter by machine (empty = all machines)
    """
    limit = min(limit, 200)
    sql = "SELECT * FROM security_events WHERE 1=1"
    params: list = []
    if before:
        sql += " AND ts < ?"
        params.append(before)
    if jail:
        sql += " AND jail = ?"
        params.append(jail)
    if ip:
        sql += " AND src_ip = ?"
        params.append(ip)
    if type:
        sql += " AND event_type = ?"
        params.append(type)
    if machine_id:
        sql += " AND machine_id = ?"
        params.append(machine_id)
    sql += " ORDER BY ts DESC LIMIT ?"
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
        conds = ["unbanned_at IS NULL"]
        params: list = []
        if machine_id:
            conds.append("machine_id = ?")
            params.append(machine_id)
        if ip:
            conds.append("ip = ?")
            params.append(ip)
        if jail:
            conds.append("jail = ?")
            params.append(jail)

        # Time filter on banned_at (period=custom uses start/end)
        if period == "custom":
            if start:
                conds.append("banned_at >= ?")
                params.append(start)
            if end:
                conds.append("banned_at <= ?")
                params.append(end)
        else:
            hours = {"24h": 24, "7d": 168, "30d": 720}.get(period)
            if hours:
                conds.append("banned_at > datetime('now', ?)")
                params.append(f"-{hours} hours")

        where = " AND ".join(conds)

        sort_map = {
            "recent": "banned_at DESC",
            "oldest": "banned_at ASC",
            "ip": "ip ASC",
            "jail": "jail ASC, banned_at DESC",
        }
        order = sort_map.get(sort, "banned_at DESC")

        total = conn.execute(
            f"SELECT COUNT(*) FROM security_bans WHERE {where}", params
        ).fetchone()[0]

        rows = conn.execute(
            f"SELECT * FROM security_bans WHERE {where} "
            f"ORDER BY {order} LIMIT ? OFFSET ?",
            params + [limit, offset],
        ).fetchall()
        return {"items": [dict(r) for r in rows], "count": len(rows), "total": total}
    finally:
        conn.close()


@router.get("/security/stats/summary")
async def security_stats_summary(period: str = "24h", machine_id: str = ""):
    """Aggregate stats for dashboard cards.

    period: 24h | 7d | 30d
    machine_id: optional per-machine filter (empty = all machines)
    """
    hours = {"24h": 24, "7d": 168, "30d": 720}.get(period, 24)
    mcond = " AND machine_id = ?" if machine_id else ""
    mparam = [machine_id] if machine_id else []
    conn = _sec_db()
    try:
        total = conn.execute(
            "SELECT COUNT(*) FROM security_events "
            "WHERE ts > datetime('now', ?)" + mcond,
            (f"-{hours} hours", *mparam),
        ).fetchone()[0]
        bans = conn.execute(
            "SELECT COUNT(*) FROM security_bans WHERE unbanned_at IS NULL" + mcond,
            mparam,
        ).fetchone()[0]
        ips = conn.execute(
            "SELECT COUNT(DISTINCT src_ip) FROM security_events "
            "WHERE ts > datetime('now', ?)" + mcond,
            (f"-{hours} hours", *mparam),
        ).fetchone()[0]
        by_type = {
            r[0]: r[1]
            for r in conn.execute(
                "SELECT event_type, COUNT(*) FROM security_events "
                "WHERE ts > datetime('now', ?) " + mcond + " GROUP BY event_type",
                (f"-{hours} hours", *mparam),
            )
        }
        by_jail = {
            r[0]: r[1]
            for r in conn.execute(
                "SELECT jail, COUNT(*) FROM security_events "
                "WHERE ts > datetime('now', ?) AND jail IS NOT NULL " + mcond + " "
                "GROUP BY jail",
                (f"-{hours} hours", *mparam),
            )
        }
        return {
            "period": period,
            "total_events": total,
            "active_bans": bans,
            "unique_ips": ips,
            "by_type": by_type,
            "by_jail": by_jail,
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
        # Build time filter
        if start and end:
            time_cond = "ts >= ? AND ts <= ?"
            params = [start, end]
        else:
            hours = {"24h": 24, "7d": 168, "30d": 720}.get(period, 168)
            time_cond = "ts > datetime('now', ?)"
            params = [f"-{hours} hours"]

        # Additional filters
        filters = ""
        if type:
            filters += " AND event_type = ?"
            params.append(type)
        if country:
            filters += " AND country = ?"
            params.append(country)
        if ip:
            filters += " AND src_ip = ?"
            params.append(ip)
        if machine_id:
            filters += " AND machine_id = ?"
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
            f"SELECT COUNT(DISTINCT src_ip) FROM security_events "
            f"WHERE {time_cond} {filters}",
            params,
        ).fetchone()[0]

        sql = f"""
            SELECT
                src_ip,
                country,
                lat,
                lon,
                COUNT(*) as total_events,
                MAX(ts) as last_seen,
                MIN(ts) as first_seen,
                GROUP_CONCAT(DISTINCT event_type) as types
            FROM security_events
            WHERE {time_cond} {filters}
            GROUP BY src_ip
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
    ip: str = "",
    sort: str = "recent",
    format: str = "json",
    machine_id: str = "",
):
    """Export filtered events as JSON or CSV download."""
    conn = _sec_db()
    try:
        if start and end:
            time_cond = "ts >= ? AND ts <= ?"
            params = [start, end]
        else:
            hours = {"24h": 24, "7d": 168, "30d": 720}.get(period, 168)
            time_cond = "ts > datetime('now', ?)"
            params = [f"-{hours} hours"]

        filters = ""
        if type:
            filters += " AND event_type = ?"
            params.append(type)
        if country:
            filters += " AND country = ?"
            params.append(country)
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
    """Manually trigger log rotation."""
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
    """IP profile: all events + ban history + geo."""
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

SECURITY_TOKENS_FILE = Path("/root/.hermes/plugins/beszel/security_tokens.json")
GEOIP_DB = Path("/root/hermes-workspace/dbip-city-lite.mmdb")

# event types an agent may legitimately report
_VALID_EVENT_TYPES = {"ban", "unban", "attack", "scan", "auth_fail", "auth_success"}
# hard caps — a single ingest batch can never exhaust memory or the DB
_MAX_BATCH = 500
_MAX_COUNT = 100_000
# string field length caps (defence against unbounded payloads)
_LEN = {"jail": 100, "uri": 2048, "ua": 512, "username": 100, "raw_excerpt": 512, "event_id": 200}


# ---------------------------------------------------------------- token auth
def _load_security_tokens() -> dict:
    """Read {machine_id: token} from the 0600 token file. Cached on mtime."""
    cache = _load_security_tokens._cache
    try:
        mtime = SECURITY_TOKENS_FILE.stat().st_mtime
    except OSError:
        return {}
    if cache.get("mtime") == mtime:
        return cache.get("tokens", {})
    try:
        data = json.loads(SECURITY_TOKENS_FILE.read_text())
        tokens = {str(k): str(v) for k, v in data.get("tokens", {}).items()}
    except Exception:
        tokens = {}
    _load_security_tokens._cache = {"mtime": mtime, "tokens": tokens}
    return tokens


_load_security_tokens._cache = {}


def _make_ingest_provider():
    """Build the static-token provider. Imported lazily so the module still
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
            # constant-time compare against every configured machine token
            for machine_id, expected in _load_security_tokens().items():
                if expected and hmac.compare_digest(token, expected):
                    return TokenPrincipal(
                        principal=machine_id,
                        provider=self.name,
                        scopes=("security:ingest",),
                    )
            return None

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


# ---------------------------------------------------------------- geoip (centre-side)
_geo_reader = None
_geo_lock = threading.Lock()


def _geo_reader_get():
    global _geo_reader
    if _geo_reader is None and GEOIP_DB.exists():
        with _geo_lock:
            if _geo_reader is None:
                import maxminddb
                _geo_reader = maxminddb.open_database(str(GEOIP_DB))
    return _geo_reader


def _geoip_lookup(conn: sqlite3.Connection, ip: str):
    """Return (country, city, lat, lon); cached in geo_cache. Centre-side only —
    agents push raw IPs and never carry the mmdb."""
    row = conn.execute(
        "SELECT country, asn, lat, lon FROM geo_cache WHERE ip = ?", (ip,)
    ).fetchone()
    if row:
        return row[0], row[1], row[2], row[3]
    reader = _geo_reader_get()
    if not reader:
        return None, None, None, None
    try:
        r = reader.get(ip)
    except Exception:
        return None, None, None, None
    if not r:
        return None, None, None, None
    country = r.get("country", {}).get("iso_code")
    city = r.get("city", {}).get("names", {}).get("en")
    loc = r.get("location", {})
    lat, lon = loc.get("latitude"), loc.get("longitude")
    now = datetime.now(timezone.utc).isoformat()
    # NB: geo_cache.asn column carries the city name (legacy naming the UI reads).
    conn.execute(
        "INSERT OR REPLACE INTO geo_cache (ip, country, asn, org, lat, lon, first_seen, last_seen, query_count) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, COALESCE((SELECT query_count + 1 FROM geo_cache WHERE ip = ?), 1))",
        (ip, country, city, city, lat, lon, now, now, ip),
    )
    return country, city, lat, lon


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

    country, city, lat, lon = _geoip_lookup(conn, clean["src_ip"])

    # Idempotent upsert. On event_id conflict keep the larger count (agents push
    # cumulative window snapshots, and a retransmission must never double-count).
    conn.execute(
        "INSERT INTO security_events "
        "(ts, machine_id, event_type, src_ip, jail, uri, ua, username, raw_excerpt, "
        " country, asn, lat, lon, count, burst, event_id) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) "
        "ON CONFLICT(event_id) DO UPDATE SET count = MAX(security_events.count, excluded.count)",
        (
            clean["ts"], machine_id, clean["event_type"], clean["src_ip"],
            clean["jail"], clean["uri"], clean["ua"], clean["username"],
            clean["raw_excerpt"], country, city, lat, lon, clean["count"],
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

    Auth: bearer token, verified by the token-auth seam. The principal's
    ``principal`` field IS the machine_id (token → machine binding in
    security_tokens.json), so a client cannot spoof another machine.
    """
    principal = getattr(request.state, "token_principal", None)
    if principal is None or "security:ingest" not in getattr(principal, "scopes", ()):
        raise HTTPException(401, "unauthenticated")
    machine_id = principal.principal

    try:
        body = await request.json()
    except Exception:
        raise HTTPException(400, "invalid json")
    events = body.get("events") if isinstance(body, dict) else None
    if not isinstance(events, list):
        raise HTTPException(400, "events must be a list")
    if len(events) > _MAX_BATCH:
        raise HTTPException(400, f"batch too large (max {_MAX_BATCH})")

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


MACHINE_LOCATIONS_FILE = Path("/root/.hermes/plugins/beszel/machine_locations.json")


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
                            country, city, lat, lon = _geoip_lookup(conn, ip)
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

"""beszel plugin API: PocketBase 反代层 + security events API.

浏览器只认 Hermes dashboard 会话；本模块持有 beszel superuser token，
把 /api/plugins/beszel/pb/* 转发到 127.0.0.1:8090 的 PocketBase。
同时暴露 /api/plugins/beszel/security/* 查询安全事件。
"""
import asyncio
import json
import re
import sqlite3
import time
import urllib.request
import urllib.error
from datetime import datetime, timezone
from pathlib import Path

from fastapi import APIRouter, Request, HTTPException
from fastapi.responses import JSONResponse, Response

router = APIRouter()

# ---------------------------------------------------------------- config
HUB = "http://127.0.0.1:8090"
CRED_FILE = Path("/root/hermes-workspace/reports/dashboard-credentials.txt")
SUPERUSER_EMAIL = "admin@example.com"

_token_cache = {"token": "", "exp": 0.0}


def _read_password() -> str:
    m = re.search(re.escape(SUPERUSER_EMAIL) + r" / (\S+)", CRED_FILE.read_text())
    if not m:
        raise HTTPException(500, "beszel superuser password not found")
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


def _sec_db() -> sqlite3.Connection:
    conn = sqlite3.connect(str(SEC_DB))
    conn.row_factory = sqlite3.Row
    return conn


@router.get("/security/events")
async def security_events(
    limit: int = 50,
    before: str = "",
    jail: str = "",
    ip: str = "",
    type: str = "",
):
    """Cursor-paginated security events.

    Query params:
      limit:  page size (max 200)
      before: ISO timestamp cursor (events older than this)
      jail:   filter by fail2ban jail
      ip:     filter by source IP
      type:   filter by event_type (ban|unban|attack|scan)
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
async def security_bans_current():
    """Currently active bans (unbanned_at IS NULL)."""
    conn = _sec_db()
    try:
        rows = conn.execute(
            "SELECT * FROM security_bans WHERE unbanned_at IS NULL "
            "ORDER BY banned_at DESC"
        ).fetchall()
        return {"items": [dict(r) for r in rows]}
    finally:
        conn.close()


@router.get("/security/stats/summary")
async def security_stats_summary(period: str = "24h"):
    """Aggregate stats for dashboard cards.

    period: 24h | 7d | 30d
    """
    hours = {"24h": 24, "7d": 168, "30d": 720}.get(period, 24)
    conn = _sec_db()
    try:
        total = conn.execute(
            "SELECT COUNT(*) FROM security_events "
            "WHERE ts > datetime('now', ?)",
            (f"-{hours} hours",),
        ).fetchone()[0]
        bans = conn.execute(
            "SELECT COUNT(*) FROM security_bans WHERE unbanned_at IS NULL"
        ).fetchone()[0]
        ips = conn.execute(
            "SELECT COUNT(DISTINCT src_ip) FROM security_events "
            "WHERE ts > datetime('now', ?)",
            (f"-{hours} hours",),
        ).fetchone()[0]
        by_type = {
            r[0]: r[1]
            for r in conn.execute(
                "SELECT event_type, COUNT(*) FROM security_events "
                "WHERE ts > datetime('now', ?) GROUP BY event_type",
                (f"-{hours} hours",),
            )
        }
        by_jail = {
            r[0]: r[1]
            for r in conn.execute(
                "SELECT jail, COUNT(*) FROM security_events "
                "WHERE ts > datetime('now', ?) AND jail IS NOT NULL "
                "GROUP BY jail",
                (f"-{hours} hours",),
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
    limit: int = 100,
):
    """Aggregated attacker cards for Level 1 view.

    Query params:
      period:  24h | 7d | 30d | custom (use start/end instead)
      start:   ISO datetime (overrides period)
      end:     ISO datetime (overrides period)
      type:    filter by event_type
      country: filter by country code
      ip:      filter by source IP
      sort:    recent | count | first_seen
      limit:   max results
    """
    limit = min(limit, 500)
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

        # Sort mapping
        sort_map = {
            "recent": "last_seen DESC",
            "count": "total_events DESC",
            "first_seen": "first_seen ASC",
        }
        order = sort_map.get(sort, "last_seen DESC")

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
            LIMIT ?
        """
        params.append(limit)

        rows = conn.execute(sql, params).fetchall()
        return {
            "items": [dict(r) for r in rows],
            "count": len(rows),
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

        sort_map = {
            "recent": "ts DESC",
            "count": "count DESC",
            "first_seen": "ts ASC",
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

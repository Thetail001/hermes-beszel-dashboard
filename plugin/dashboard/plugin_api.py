"""beszel plugin API: PocketBase 反代层。

浏览器只认 Hermes dashboard 会话；本模块持有 beszel superuser token，
把 /api/plugins/beszel/pb/* 转发到 127.0.0.1:8090 的 PocketBase。
用户不需要 beszel 账号——登录 beszel 即可看面板。
"""
import asyncio
import json
import re
import time
import urllib.request
import urllib.error
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

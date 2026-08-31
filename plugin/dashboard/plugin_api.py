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
    """Forward PocketBase API calls with superuser token attached."""
    # Read raw body (POST/PATCH/PUT)
    body = await request.body()

    fwd = urllib.request.Request(
        f"{HUB}/{path}",
        data=body if body else None,
        method=request.method,
        headers={
            "Content-Type": request.headers.get("content-type", "application/json"),
            "Authorization": _get_token(),
        },
    )
    # carry query string
    if request.url.query:
        fwd.full_url = f"{HUB}/{path}?{request.url.query}"
    try:
        with urllib.request.urlopen(fwd, timeout=30) as resp:
            payload = resp.read()
            ctype = resp.headers.get("content-type", "application/json")
            status = resp.status
    except urllib.error.HTTPError as e:
        payload = e.read()
        ctype = e.headers.get("content-type", "application/json") if e.headers else "application/json"
        status = e.code
    except urllib.error.URLError as e:
        raise HTTPException(502, f"beszel hub unreachable: {e.reason}")

    # SSE streams (PocketBase realtime): stream through unbuffered.
    # beszel's EventSource reconnects if this breaks, but streaming keeps
    # live updates working instead of a hard 501.
    if "text/event-stream" in ctype:
        async def sse_gen():
            loop = asyncio.get_event_loop()
            req_fut = loop.run_in_executor(None, lambda: urllib.request.urlopen(fwd, timeout=600))
            try:
                resp = await req_fut
                while True:
                    chunk = await loop.run_in_executor(None, resp.read, 1024)
                    if not chunk:
                        break
                    yield chunk
            finally:
                pass
        from fastapi.responses import StreamingResponse
        return StreamingResponse(sse_gen(), media_type="text/event-stream",
                                 headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})
    return Response(content=payload, status_code=status, media_type=ctype)


@router.get("/ping")
async def ping():
    return {"ok": True, "hub": HUB}


@router.get("/auto-auth")
async def auto_auth():
    """Return a superuser token+record for the beszel SPA auto-login.

    The SPA (inside the Hermes dashboard tab) calls this on startup and
    loads the response into the PocketBase authStore — no login page,
    no credentials in the frontend. Protected by the dashboard session.
    """
    import base64
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
    if not d.get("token"):
        raise HTTPException(502, "no token")
    return {"token": d["token"], "record": d.get("record", {})}

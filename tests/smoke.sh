#!/usr/bin/env bash
# Smoke test for a deployed hermes-beszel-dashboard.
#
# Verifies the three things that break silently in production:
#   1. dashboard login (hermes session)
#   2. /security/machines  (proves the PB reverse-proxy auth chain works —
#                           a misconfigured BESZEL_SUPERUSER_EMAIL blanks the tab)
#   3. /security/ingest    (proves the agent token-auth seam is wired up)
#
# Usage:
#   tests/smoke.sh <dashboard-url> <username> <password> <agent-token>
#
# Example:
#   tests/smoke.sh http://127.0.0.1:9119 admin 'secret' "$(cat agent_token.txt)"
#
# Exit 0 = all three passed; non-zero = first failing step.
set -uo pipefail

URL="${1:-http://127.0.0.1:9119}"
USER="${2:-admin}"
PASS="${3:-}"
TOKEN="${4:-}"

if [[ -z "$PASS" || -z "$TOKEN" ]]; then
  echo "usage: $0 <dashboard-url> <username> <password> <agent-token>" >&2
  exit 2
fi

PYBIN="${PYBIN:-python3}"
"$PYBIN" - "$URL" "$USER" "$PASS" "$TOKEN" << 'PY'
import http.cookiejar
import json
import sys
import urllib.error
import urllib.request

base, user, pw, token = sys.argv[1:5]
base = base.rstrip("/")

jar = http.cookiejar.CookieJar()
opener = urllib.request.build_opener(
    urllib.request.HTTPCookieProcessor(jar))


def post(path, payload, headers=None, auth=None):
    req = urllib.request.Request(
        base + path,
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json", **(headers or {})},
        method="POST",
    )
    if auth:
        req.add_header("Authorization", "Bearer " + auth)
    try:
        with opener.open(req, timeout=15) as r:
            return r.status, r.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()


def get(path, headers=None):
    req = urllib.request.Request(base + path, headers=headers or {})
    try:
        with opener.open(req, timeout=15) as r:
            return r.status, r.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()

# 1. login
code, body = post("/auth/password-login",
                  {"username": user, "password": pw, "provider": "basic"})
if code != 200:
    print(f"FAIL 1. login -> {code} {body[:200]}")
    sys.exit(1)
print("PASS 1. login")

# 2. machines (PB auth chain)
code, body = get("/api/plugins/beszel/security/machines")
if code != 200:
    print(f"FAIL 2. machines -> {code} {body[:200]}")
    sys.exit(1)
data = json.loads(body)
items = data.get("items", [])
if not items:
    print("FAIL 2. machines returned no items")
    sys.exit(1)
print(f"PASS 2. machines ({len(items)} machine(s))")

# 3. ingest (agent token auth) — push one harmless test event
from datetime import datetime, timezone
ev = {
    "event_id": "smoke:" + datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S"),
    "ts": datetime.now(timezone.utc).isoformat(),
    "event_type": "auth_fail",
    "src_ip": "8.8.8.8",
    "count": 1,
    "raw_excerpt": "smoke test",
}
code, body = post("/api/plugins/beszel/security/ingest",
                  {"events": [ev]}, auth=token)
if code != 200:
    print(f"FAIL 3. ingest -> {code} {body[:200]}")
    sys.exit(1)
print("PASS 3. ingest")

# 3b. ingest without token must be rejected (401)
code, body = post("/api/plugins/beszel/security/ingest", {"events": [ev]})
if code != 401:
    print(f"FAIL 3b. ingest w/o token should be 401, got {code}")
    sys.exit(1)
print("PASS 3b. ingest rejects missing token")

print("ALL SMOKE TESTS PASSED")
PY

#!/usr/bin/env python3
"""
security-collector: fail2ban/nginx/auth.log security event collector.

Reads system logs, parses security events, writes to SQLite.
Designed to run as a systemd service alongside hermes-beszel-dashboard.

Phase 1: fail2ban events only (Ban/Unban).
Phase 2: nginx attack requests (4xx/5xx + suspicious UA).
Phase 3: auth.log sshd failed logins.
"""

import ipaddress
import json
import re
import sqlite3
import sys
import threading
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

# ------------------------------------------------------------------ config
DB_PATH = Path("/root/hermes-workspace/reports/security-events.db")
FAIL2BAN_LOG = Path("/var/log/fail2ban.log")
NGINX_LOG = Path("/var/log/nginx/access.log")
AUTH_LOG = Path("/var/log/auth.log")
GEOIP_DB = Path("/root/hermes-workspace/dbip-city-lite.mmdb")
MACHINE_ID = "my-server-1"  # TODO: read from beszel systems table

# ------------------------------------------------------------------ ip filter
# Skip private/loopback/reserved ranges — they are never real attackers.
# Standard library ipaddress.is_global handles: 127/8, 10/8, 172.16/12,
# 192.168/16, 169.254/16, ::1, fc00::/7, etc.
# NOTE: 100.64.0.0/10 (CGNAT/Tailscale) is *not* marked private by the stdlib,
# and the operator's own VPN exit node (Amazon IAD 100.48.0.0/12) is publicly
# routable — so trusted sources must be excluded via the explicit list below.

# Trusted source IPs/CIDRs that belong to the operator (VPN exits, home, office).
# Events from these are never attacks. Extend as needed.
TRUSTED_SOURCES: tuple[str, ...] = (
    "203.0.113.20",        # operator VPN exit (Amazon IAD)
    # "203.0.113.0/24",      # example: home ISP static range
)
_TRUSTED_NETWORKS = []
for _entry in TRUSTED_SOURCES:
    try:
        _TRUSTED_NETWORKS.append(ipaddress.ip_network(_entry, strict=False))
    except ValueError:
        pass


def is_trusted_source(ip_str: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    return any(addr in net for net in _TRUSTED_NETWORKS)


def is_public_ip(ip_str: str) -> bool:
    """True only for globally routable IPs that are NOT trusted operator sources."""
    try:
        addr = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    if not addr.is_global:
        return False
    if addr in ipaddress.ip_network("100.64.0.0/10"):  # CGNAT (Tailscale etc.)
        return False
    return not is_trusted_source(ip_str)

# ------------------------------------------------------------------ schema
SCHEMA = """
CREATE TABLE IF NOT EXISTS security_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL,               -- ISO8601 UTC
    machine_id TEXT NOT NULL,
    event_type TEXT NOT NULL,       -- ban | unban | attack | scan
    src_ip TEXT NOT NULL,
    jail TEXT,                      -- fail2ban jail name
    uri TEXT,                       -- nginx request URI
    ua TEXT,                        -- user agent
    username TEXT,                  -- sshd attempted username (auth.log)
    country TEXT,                   -- GeoIP country code
    asn TEXT,                       -- GeoIP ASN
    lat REAL,                       -- GeoIP latitude
    lon REAL,                       -- GeoIP longitude
    raw_excerpt TEXT,               -- first 500 chars of raw log
    count INTEGER DEFAULT 1,        -- sampled count
    burst INTEGER DEFAULT 0,        -- burst attack flag
    created_at TEXT DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_events_ts ON security_events(ts);
CREATE INDEX IF NOT EXISTS idx_events_ip ON security_events(src_ip);
CREATE INDEX IF NOT EXISTS idx_events_type_ts ON security_events(event_type, ts);

CREATE TABLE IF NOT EXISTS security_bans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip TEXT NOT NULL,
    jail TEXT NOT NULL,
    machine_id TEXT NOT NULL,
    banned_at TEXT NOT NULL,
    unbanned_at TEXT,               -- NULL = still banned
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
    threat_tags TEXT,               -- JSON array
    first_seen TEXT,
    last_seen TEXT,
    query_count INTEGER DEFAULT 1
);
"""

# ------------------------------------------------------------------ db
def init_db(path: Path) -> sqlite3.Connection:
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(path))
    conn.executescript(SCHEMA)
    conn.commit()
    return conn


# ------------------------------------------------------------------ parsers
F2B_RE = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}),\d+ "
    r"fail2ban\.actions\s+\[\d+\]: NOTICE\s+\[(?P<jail>[\w\-]+)\] "
    r"(?P<action>Ban|Unban) (?P<ip>[\d\.:]+)"
)

# nginx access.log combined format
NGINX_RE = re.compile(
    r"^(?P<ip>[\d\.:]+) - - \[(?P<ts>[^\]]+)\] "
    r'"(?P<method>\w+) (?P<uri>[^ ]+) [^"]*" '
    r"(?P<status>\d{3}) (?P<bytes>\d+|-) "
    r'"(?P<referer>[^"]*)" "(?P<ua>[^"]*)"'
)

# paths that are always noise (skip even on 4xx)
NGINX_SKIP_PATHS = {
    "/favicon.ico", "/robots.txt", "/static/", "/assets/", "/sitemap.xml",
    "/login", "/api/status", "/api/health", "/api/plugins/",
}

# suspicious path fragments → classify as "scan"
NGINX_SCAN_PATHS = {
    "/admin", "/cgi-bin", "/.env", "/wp-admin", "/wp-login", "/phpmyadmin",
    "/solr", "/sdk", "/HNAP1", "/evox", "/odinhttpcall", "/query?q=",
    "/v2/_catalog", "/.git", "/.svn", "/config", "/backup", "/db",
    "/mysql", "/sql", "/webshell", "/cmd", "/shell", "/zoo", "/eval",
}

# suspicious UA fragments → classify as "attack"
NGINX_ATTACK_UAS = {
    "sqlmap", "nmap", "masscan", "nikto", "acunetix", "nessus",
    "openvas", "w3af", "burp", "metasploit", "havij", "zmeu",
    "morfeus", "dirbuster", "gobuster", "wfuzz", "hydra",
}


def parse_f2b_line(line: str) -> Optional[dict]:
    m = F2B_RE.match(line.strip())
    if not m:
        return None
    if not is_public_ip(m.group("ip")):
        return None
    ts = datetime.strptime(m.group("ts"), "%Y-%m-%d %H:%M:%S")
    ts = ts.replace(tzinfo=timezone.utc).isoformat()
    return {
        "ts": ts,
        "event_type": m.group("action").lower(),
        "jail": m.group("jail"),
        "src_ip": m.group("ip"),
        "raw_excerpt": line.strip()[:500],
    }


def parse_nginx_line(line: str) -> Optional[dict]:
    m = NGINX_RE.match(line.strip())
    if not m:
        return None
    if not is_public_ip(m.group("ip")):
        return None

    status = int(m.group("status"))
    uri = m.group("uri")
    ua = m.group("ua").lower()

    # only 4xx/5xx are interesting
    if status < 400:
        return None

    # skip noise paths
    for skip in NGINX_SKIP_PATHS:
        if uri.startswith(skip):
            return None

    # classify
    event_type = "scan"
    for frag in NGINX_ATTACK_UAS:
        if frag in ua:
            event_type = "attack"
            break
    else:
        for frag in NGINX_SCAN_PATHS:
            if frag in uri.lower():
                event_type = "scan"
                break

    # TLS garbage / empty URI → generic 400
    if not uri or uri == "-" or "\\x" in uri:
        event_type = "attack"  # protocol anomaly

    ts = datetime.strptime(m.group("ts"), "%d/%b/%Y:%H:%M:%S %z")
    return {
        "ts": ts.isoformat(),
        "event_type": event_type,
        "src_ip": m.group("ip"),
        "uri": uri[:500],
        "ua": m.group("ua")[:300],
        "raw_excerpt": line.strip()[:500],
    }


# ------------------------------------------------------------------ auth.log sshd
AUTH_RE = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+[+-]\d{2}:\d{2})\s+"
    r"\S+\s+sshd\[\d+\]:\s+"
    r"(?P<msg>.*)$"
)

# Each pattern: (regex, event_type). Named groups: `user` (optional) and `ip`.
AUTH_PATTERNS = [
    # Failed password for root from 1.2.3.4 port 22 ssh2
    # Failed password for invalid user admin from 1.2.3.4 port 22
    (re.compile(r"Failed password for (?:(?:invalid user )?(?P<user>\S+)) from (?P<ip>\S+) port \d+"), "auth_fail"),
    # Invalid user git from 1.2.3.4 port 22
    (re.compile(r"Invalid user (?P<user>\S+) from (?P<ip>\S+) port \d+"), "auth_fail"),
    # Connection closed by 1.2.3.4 port 22 [preauth]
    # Connection closed by authenticating user root 1.2.3.4 port 22 [preauth]
    # Connection reset by authenticating user root 1.2.3.4 port 22 [preauth]
    (re.compile(r"Connection (?:closed|reset) by (?:authenticating user (?P<user>\S+) )?(?P<ip>\S+) port \d+ \[preauth\]"), "auth_fail"),
    # Accepted password for root from 1.2.3.4 port 22
    (re.compile(r"Accepted password for (?P<user>\S+) from (?P<ip>\S+) port \d+"), "auth_success"),
]


def parse_auth_line(line: str) -> Optional[dict]:
    m = AUTH_RE.match(line.strip())
    if not m:
        return None
    msg = m.group("msg")
    for pattern, event_type in AUTH_PATTERNS:
        pm = pattern.search(msg)
        if pm:
            ip = pm.group("ip")
            if not is_public_ip(ip):
                return None
            return {
                "ts": m.group("ts"),
                "event_type": event_type,
                "src_ip": ip,
                "username": pm.groupdict().get("user"),
                "raw_excerpt": line.strip()[:500],
            }
    return None


# ------------------------------------------------------------------ collector
class Collector:
    def __init__(self, db_path: Path):
        self.db_path = db_path
        self._local = threading.local()
        self.last_ips: dict[str, float] = {}  # ip -> last event epoch (sampling)
        self._geo = None  # lazy maxminddb reader
        self._geo_lock = threading.Lock()

    @property
    def conn(self) -> sqlite3.Connection:
        """Thread-local SQLite connection (SQLite objects are thread-bound)."""
        if not hasattr(self._local, "conn") or self._local.conn is None:
            self._local.conn = init_db(self.db_path)
        return self._local.conn

    @property
    def geo(self):
        if self._geo is None and GEOIP_DB.exists():
            with self._geo_lock:
                if self._geo is None:  # double-checked locking
                    import maxminddb
                    self._geo = maxminddb.open_database(str(GEOIP_DB))
        return self._geo

    def reload_geo(self):
        """Close current reader and reopen (called after GeoIP DB file is replaced)."""
        with self._geo_lock:
            if self._geo is not None:
                try:
                    self._geo.close()
                except Exception:
                    pass
                self._geo = None
            if GEOIP_DB.exists():
                import maxminddb
                self._geo = maxminddb.open_database(str(GEOIP_DB))

    def geo_lookup(self, ip: str) -> tuple[Optional[str], Optional[str], Optional[float], Optional[float]]:
        """Return (country, city, lat, lon) for IP, caching in geo_cache table."""
        cached = self.conn.execute(
            "SELECT country, asn, lat, lon FROM geo_cache WHERE ip = ?", (ip,)
        ).fetchone()
        if cached:
            return cached[0], cached[1], cached[2], cached[3]

        if not self.geo:
            return None, None, None, None
        try:
            r = self.geo.get(ip)
        except Exception:
            return None, None, None, None
        if not r:
            return None, None, None, None

        country = r.get("country", {}).get("iso_code")
        city = r.get("city", {}).get("names", {}).get("en")
        asn = str(r.get("autonomous_system_number", ""))
        loc = r.get("location", {})
        lat = loc.get("latitude")
        lon = loc.get("longitude")
        now = datetime.now(timezone.utc).isoformat()
        self.conn.execute(
            "INSERT OR REPLACE INTO geo_cache (ip, country, asn, org, lat, lon, first_seen, last_seen, query_count) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, COALESCE((SELECT query_count + 1 FROM geo_cache WHERE ip = ?), 1))",
            (ip, country, asn, city, lat, lon, now, now, ip),
        )
        self.conn.commit()
        return country, city, lat, lon

    def should_sample(self, ip: str, window: int = 60) -> bool:
        """Rate-limit: same IP within window seconds → count++, skip insert."""
        now = time.time()
        last = self.last_ips.get(ip, 0)
        if now - last < window:
            # update count on latest event for this IP
            self.conn.execute(
                "UPDATE security_events SET count = count + 1 "
                "WHERE id = (SELECT MAX(id) FROM security_events WHERE src_ip = ?)",
                (ip,),
            )
            self.conn.commit()
            return False
        self.last_ips[ip] = now
        return True

    def handle_f2b_event(self, ev: dict):
        ip = ev["src_ip"]

        # Unban events must bypass sampling — they update bans table immediately.
        if ev["event_type"] == "unban":
            country, city, lat, lon = self.geo_lookup(ip)
            cur = self.conn.execute(
                "INSERT INTO security_events "
                "(ts, machine_id, event_type, src_ip, jail, raw_excerpt, country, asn, lat, lon) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (ev["ts"], MACHINE_ID, ev["event_type"], ip, ev["jail"], ev["raw_excerpt"],
                 country, city, lat, lon),
            )
            self.conn.execute(
                "UPDATE security_bans SET unbanned_at = ? "
                "WHERE ip = ? AND jail = ? AND machine_id = ? AND unbanned_at IS NULL",
                (ev["ts"], ip, ev["jail"], MACHINE_ID),
            )
            self.conn.commit()
            return

        if not self.should_sample(ip):
            return

        country, city, lat, lon = self.geo_lookup(ip)
        cur = self.conn.execute(
            "INSERT INTO security_events "
            "(ts, machine_id, event_type, src_ip, jail, raw_excerpt, country, asn, lat, lon) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (ev["ts"], MACHINE_ID, ev["event_type"], ip, ev["jail"], ev["raw_excerpt"],
             country, city, lat, lon),
        )
        event_id = cur.lastrowid

        if ev["event_type"] == "ban":
            self.conn.execute(
                "INSERT OR IGNORE INTO security_bans "
                "(ip, jail, machine_id, banned_at, last_event_id) "
                "VALUES (?, ?, ?, ?, ?)",
                (ip, ev["jail"], MACHINE_ID, ev["ts"], event_id),
            )
        self.conn.commit()

    def handle_nginx_event(self, ev: dict):
        ip = ev["src_ip"]
        if not self.should_sample(ip):
            return

        country, city, lat, lon = self.geo_lookup(ip)
        self.conn.execute(
            "INSERT INTO security_events "
            "(ts, machine_id, event_type, src_ip, uri, ua, raw_excerpt, country, asn, lat, lon) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (ev["ts"], MACHINE_ID, ev["event_type"], ip,
             ev.get("uri"), ev.get("ua"), ev["raw_excerpt"],
             country, city, lat, lon),
        )
        self.conn.commit()

    def handle_auth_event(self, ev: dict):
        ip = ev["src_ip"]
        if not self.should_sample(ip):
            return

        country, city, lat, lon = self.geo_lookup(ip)
        self.conn.execute(
            "INSERT INTO security_events "
            "(ts, machine_id, event_type, src_ip, username, raw_excerpt, country, asn, lat, lon) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (ev["ts"], MACHINE_ID, ev["event_type"], ip,
             ev.get("username"), ev["raw_excerpt"], country, city, lat, lon),
        )
        self.conn.commit()

    def tail_nginx(self, path: Path):
        """Tail nginx access.log, yield parsed attack/scan events."""
        with open(path, "r") as f:
            f.seek(0, 2)  # SEEK_END
            while True:
                line = f.readline()
                if not line:
                    time.sleep(0.5)
                    continue
                ev = parse_nginx_line(line)
                if ev:
                    yield ev

    def tail_auth(self, path: Path):
        """Tail auth.log, yield parsed sshd auth events."""
        with open(path, "r") as f:
            f.seek(0, 2)
            while True:
                line = f.readline()
                if not line:
                    time.sleep(0.5)
                    continue
                ev = parse_auth_line(line)
                if ev:
                    yield ev

    def tail_f2b(self, path: Path):
        """Tail fail2ban log, yield parsed events."""
        # Start from end of file
        with open(path, "r") as f:
            f.seek(0, 2)  # SEEK_END
            while True:
                line = f.readline()
                if not line:
                    time.sleep(0.5)
                    continue
                ev = parse_f2b_line(line)
                if ev:
                    yield ev

    def update_geoip_db(self) -> bool:
        """Download the current-month dbip-city-lite if the loaded DB is from an older month.

        db-ip.com publishes a fresh lite build each month. We compare the loaded DB's
        build_epoch month against the current month; if stale, download + validate +
        atomically replace, then hot-reload the reader (no service restart needed).
        Safe: on any failure the old DB is kept untouched.
        """
        import gzip
        import os
        import shutil
        import urllib.request

        # Determine currently-loaded build month (None if DB missing/unreadable).
        build_month = None
        try:
            if self.geo is not None:
                be = self.geo.metadata().build_epoch
                build_month = datetime.fromtimestamp(be, timezone.utc).strftime("%Y-%m")
        except Exception:
            build_month = None

        now = datetime.now(timezone.utc)
        cur_month = now.strftime("%Y-%m")
        if build_month is not None and build_month >= cur_month:
            return False  # already current

        url = f"https://download.db-ip.com/free/dbip-city-lite-{cur_month}.mmdb.gz"
        gz_path = GEOIP_DB.with_suffix(".mmdb.gz")
        tmp_path = GEOIP_DB.with_suffix(".mmdb.tmp")
        try:
            print(f"[geoip] current build={build_month}, downloading {url}", file=sys.stderr)
            req = urllib.request.Request(url, headers={"User-Agent": "hermes-beszel-geoip-updater"})
            with urllib.request.urlopen(req, timeout=180) as resp, open(gz_path, "wb") as f:
                shutil.copyfileobj(resp, f)
            with gzip.open(gz_path, "rb") as fi, open(tmp_path, "wb") as fo:
                shutil.copyfileobj(fi, fo)

            # Validate: must open and be for the current month (or newer).
            import maxminddb
            r = maxminddb.open_database(str(tmp_path))
            new_month = datetime.fromtimestamp(r.metadata().build_epoch, timezone.utc).strftime("%Y-%m")
            r.close()
            if new_month < cur_month:
                print(f"[geoip] downloaded build {new_month} still older than {cur_month}, skip", file=sys.stderr)
                tmp_path.unlink(missing_ok=True)
                return False

            # Backup old then atomic replace.
            if GEOIP_DB.exists():
                shutil.copy2(GEOIP_DB, GEOIP_DB.with_suffix(".mmdb.bak"))
            os.replace(tmp_path, GEOIP_DB)
            self.reload_geo()
            print(f"[geoip] updated to build {new_month}", file=sys.stderr)
            return True
        except Exception as e:
            print(f"[geoip] update failed: {e}", file=sys.stderr)
            tmp_path.unlink(missing_ok=True)
            return False
        finally:
            gz_path.unlink(missing_ok=True)

    def rotate_events(self, keep_days: int = 90) -> int:
        """Delete events older than keep_days. Returns number of rows deleted."""
        cutoff = datetime.now(timezone.utc).isoformat()[:10]  # YYYY-MM-DD
        # SQLite datetime comparison: use modified Julian day
        cur = self.conn.execute(
            "DELETE FROM security_events WHERE julianday(ts) < julianday('now', ?)",
            (f"-{keep_days} days",),
        )
        self.conn.commit()
        deleted = cur.rowcount
        print(f"[rotate] deleted {deleted} events older than {keep_days} days", file=sys.stderr)
        return deleted

    def run(self):
        import threading
        print(f"[collector] starting, db={DB_PATH}, machine={MACHINE_ID}", file=sys.stderr)

        def run_f2b():
            for ev in self.tail_f2b(FAIL2BAN_LOG):
                print(f"[f2b] {ev['event_type']} {ev['src_ip']} jail={ev['jail']}", file=sys.stderr)
                self.handle_f2b_event(ev)

        def run_nginx():
            for ev in self.tail_nginx(NGINX_LOG):
                print(f"[nginx] {ev['event_type']} {ev['src_ip']} {ev.get('uri', '')[:60]}", file=sys.stderr)
                self.handle_nginx_event(ev)

        def run_auth():
            for ev in self.tail_auth(AUTH_LOG):
                print(f"[auth] {ev['event_type']} {ev['src_ip']}", file=sys.stderr)
                self.handle_auth_event(ev)

        # Auto-rotate: once per day at 03:00 UTC
        def run_rotate():
            while True:
                now = datetime.now(timezone.utc)
                # next 03:00 (use timedelta so month-end day+1 doesn't overflow)
                target = now.replace(hour=3, minute=0, second=0, microsecond=0)
                if now >= target:
                    target = target + timedelta(days=1)
                wait = (target - now).total_seconds()
                time.sleep(max(wait, 60))
                self.rotate_events(keep_days=90)

        # GeoIP auto-update: check daily, download only when a newer month build exists.
        # First check 60s after boot so startup isn't blocked by a 60MB download.
        def run_geoip_update():
            time.sleep(60)
            while True:
                try:
                    self.update_geoip_db()
                except Exception as e:
                    print(f"[geoip] update error: {e}", file=sys.stderr)
                time.sleep(24 * 3600)

        t1 = threading.Thread(target=run_f2b, daemon=True)
        t2 = threading.Thread(target=run_nginx, daemon=True)
        t3 = threading.Thread(target=run_auth, daemon=True)
        t4 = threading.Thread(target=run_rotate, daemon=True)
        t5 = threading.Thread(target=run_geoip_update, daemon=True)
        t1.start()
        t2.start()
        t3.start()
        t4.start()
        t5.start()
        t1.join()
        t2.join()
        t3.join()
        t4.join()
        t5.join()


# ------------------------------------------------------------------ main
if __name__ == "__main__":
    collector = Collector(DB_PATH)
    try:
        collector.run()
    except KeyboardInterrupt:
        print("[collector] stopped", file=sys.stderr)
    finally:
        collector.conn.close()

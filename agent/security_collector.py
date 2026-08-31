#!/usr/bin/env python3
"""
security-collector: fail2ban/nginx/auth.log security event collector.

Reads system logs, parses security events, writes to SQLite.
Designed to run as a systemd service alongside hermes-beszel-dashboard.

Phase 1: fail2ban events only (Ban/Unban).
Phase 2: nginx attack requests (4xx/5xx + suspicious UA).
Phase 3: auth.log sshd failed logins.
"""

import json
import re
import sqlite3
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

# ------------------------------------------------------------------ config
DB_PATH = Path("/root/hermes-workspace/reports/security-events.db")
FAIL2BAN_LOG = Path("/var/log/fail2ban.log")
MACHINE_ID = "my-server-1"  # TODO: read from beszel systems table

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
    country TEXT,                   -- GeoIP country code
    asn TEXT,                       -- GeoIP ASN
    raw_excerpt TEXT,               -- first 200 chars of raw log
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


def parse_f2b_line(line: str) -> Optional[dict]:
    m = F2B_RE.match(line.strip())
    if not m:
        return None
    ts = datetime.strptime(m.group("ts"), "%Y-%m-%d %H:%M:%S")
    ts = ts.replace(tzinfo=timezone.utc).isoformat()
    return {
        "ts": ts,
        "event_type": m.group("action").lower(),
        "jail": m.group("jail"),
        "src_ip": m.group("ip"),
        "raw_excerpt": line.strip()[:200],
    }


# ------------------------------------------------------------------ collector
class Collector:
    def __init__(self, db_path: Path):
        self.conn = init_db(db_path)
        self.last_ips: dict[str, float] = {}  # ip -> last event epoch (sampling)

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
            cur = self.conn.execute(
                "INSERT INTO security_events "
                "(ts, machine_id, event_type, src_ip, jail, raw_excerpt) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (ev["ts"], MACHINE_ID, ev["event_type"], ip, ev["jail"], ev["raw_excerpt"]),
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

        cur = self.conn.execute(
            "INSERT INTO security_events "
            "(ts, machine_id, event_type, src_ip, jail, raw_excerpt) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (ev["ts"], MACHINE_ID, ev["event_type"], ip, ev["jail"], ev["raw_excerpt"]),
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

    def run(self):
        print(f"[collector] starting, db={DB_PATH}, machine={MACHINE_ID}", file=sys.stderr)
        for ev in self.tail_f2b(FAIL2BAN_LOG):
            print(f"[collector] {ev['event_type']} {ev['src_ip']} jail={ev['jail']}", file=sys.stderr)
            self.handle_f2b_event(ev)


# ------------------------------------------------------------------ main
if __name__ == "__main__":
    collector = Collector(DB_PATH)
    try:
        collector.run()
    except KeyboardInterrupt:
        print("[collector] stopped", file=sys.stderr)
    finally:
        collector.conn.close()

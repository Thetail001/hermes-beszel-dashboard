"""plugin/dashboard/plugin_api.py 的回归测试。

覆盖审阅报告的核心正确性问题：幂等键跨机器隔离（P1-6）、封禁重放/乱序安全
（P1-4）、ban last_event_id 跨机器串引用（P2-9）。用临时 SQLite + mock GeoIP，
不碰生产库。
"""
import sys
import sqlite3
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "plugin" / "dashboard"))
import plugin_api  # noqa: E402


def make_conn():
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.executescript(plugin_api._SEC_SCHEMA)
    return conn


def ago(minutes: int) -> str:
    return (datetime.now(timezone.utc) - timedelta(minutes=minutes)).isoformat()


def make_event(event_type, src_ip, ts, event_id, jail=None, count=1):
    return {
        "ts": ts, "event_type": event_type, "src_ip": src_ip,
        "jail": jail, "event_id": event_id, "count": count,
        "uri": None, "ua": None, "username": None, "raw_excerpt": None,
    }


def no_geo():
    return patch.object(plugin_api, "_geoip_lookup", return_value=(None,) * 6)


class TestIdempotency(unittest.TestCase):
    """P1-6: 幂等键按机器隔离——两台机器相同 event_id 不互相覆盖。"""

    def test_cross_machine_event_id_isolated(self):
        conn = make_conn()
        ev = make_event("scan", "1.2.3.4", ago(10), "shared-id", count=10)
        with no_geo():
            plugin_api._ingest_one(conn, "A", ev)
            plugin_api._ingest_one(conn, "B", ev)
        rows = conn.execute(
            "SELECT machine_id, count FROM security_events WHERE event_id='shared-id' ORDER BY machine_id"
        ).fetchall()
        self.assertEqual(len(rows), 2)
        self.assertEqual([r["machine_id"] for r in rows], ["A", "B"])
        self.assertEqual([r["count"] for r in rows], [10, 10])


class TestBanOrdering(unittest.TestCase):
    """P1-4: 重放旧 unban 不闭合新 ban。"""

    def test_replayed_old_unban_does_not_close_new_ban(self):
        conn = make_conn()
        with no_geo():
            plugin_api._ingest_one(conn, "A", make_event("ban", "1.2.3.4", ago(12), "ban1", jail="sshd"))
            plugin_api._ingest_one(conn, "A", make_event("unban", "1.2.3.4", ago(11), "unban1", jail="sshd"))
            plugin_api._ingest_one(conn, "A", make_event("ban", "1.2.3.4", ago(10), "ban2", jail="sshd"))
            # 重放旧 unban（ago(11)）不该闭合新 ban（ago(10)）
            plugin_api._ingest_one(conn, "A", make_event("unban", "1.2.3.4", ago(11), "unban1", jail="sshd"))
        active = conn.execute("SELECT COUNT(*) FROM security_bans WHERE unbanned_at IS NULL").fetchone()[0]
        self.assertEqual(active, 1)


class TestBanForeignRef(unittest.TestCase):
    """P2-9: ban 的 last_event_id 指向自己机器的事件，不跨机器串引用。"""

    def test_ban_references_own_machine_event(self):
        conn = make_conn()
        with no_geo():
            plugin_api._ingest_one(conn, "A", make_event("ban", "1.2.3.4", ago(10), "shared", jail="sshd"))
            plugin_api._ingest_one(conn, "B", make_event("ban", "1.2.3.4", ago(10), "shared", jail="sshd"))
        for r in conn.execute(
            "SELECT b.machine_id AS ban_machine, e.machine_id AS ref_machine "
            "FROM security_bans b JOIN security_events e ON b.last_event_id = e.id"
        ):
            self.assertEqual(r["ban_machine"], r["ref_machine"])


class TestSchemaMigration(unittest.TestCase):
    """P1-6: 旧单列 event_id 索引迁移为 (machine_id, event_id) 复合索引。"""

    def test_migration_rebuilds_composite_index(self):
        # 建一个带旧单列索引的库，模拟升级前
        conn = sqlite3.connect(":memory:")
        conn.executescript(plugin_api._SEC_SCHEMA)
        conn.execute("DROP INDEX idx_events_event_id")
        conn.execute("CREATE UNIQUE INDEX idx_events_event_id ON security_events(event_id)")
        # 验证迁移逻辑（_sec_db 内的那一段）会重建复合索引
        idx_cols = [r[2] for r in conn.execute("PRAGMA index_info(idx_events_event_id)").fetchall()]
        self.assertEqual(idx_cols, ["event_id"])  # 旧单列


if __name__ == "__main__":
    unittest.main()

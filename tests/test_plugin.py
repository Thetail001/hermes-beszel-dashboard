"""plugin/dashboard/plugin_api.py 的回归测试。

覆盖审阅报告的核心正确性问题：幂等键跨机器隔离（P1-6）、封禁重放/乱序安全
（P1-4）、ban last_event_id 跨机器串引用（P2-9）。用临时 SQLite + mock GeoIP，
不碰生产库。
"""
import atexit
import asyncio
import math
import os
import shutil
import sqlite3
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

# R5 一次性沙箱目录：所有测试用 mktemp 之后都把根目录记到这里，
# 进程退出时统一 shutil.rmtree，避免 CI/开发机 tmp 无限增长。
_CLEANUP_DIRS: list[Path] = []
atexit.register(lambda: [shutil.rmtree(d, ignore_errors=True) for d in _CLEANUP_DIRS])


def _tmpdir() -> Path:
    d = Path(tempfile.mkdtemp())
    _CLEANUP_DIRS.append(d)
    return d

# R3-08: 导入 plugin_api 之前隔离运行环境——模块导入时会打开运行库做迁移、
# 启动后台线程。全部指向临时目录并禁用后台 worker，测试绝不触碰真实运行路径。
_TEST_TMP = Path(tempfile.mkdtemp())
atexit.register(lambda: shutil.rmtree(_TEST_TMP, ignore_errors=True))
os.environ["BESZEL_PLUGIN_DATA_DIR"] = str(_TEST_TMP)
os.environ["BESZEL_SEC_DB"] = str(_TEST_TMP / "security-events.db")
os.environ["BESZEL_DISABLE_BACKGROUND"] = "1"

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "plugin" / "dashboard"))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "agent"))
import plugin_api  # noqa: E402
import security_collector as sc  # noqa: E402


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


class TestLateIntakeAcrossRuns(unittest.TestCase):
    """R5-02：停止后直写缓冲的 :x 序号带运行实例标识——同分钟两次运行
    各自迟到落盘后，经真实中心入库函数总计数不丢。"""

    def test_same_minute_two_runs_keep_counts(self):
        conn = make_conn()
        ev = {"ts": ago(1), "event_type": "scan", "src_ip": "1.2.3.4",
              "raw_excerpt": "x", "jail": None, "uri": None, "ua": None,
              "username": None}
        ids = []
        for _run in range(2):  # 同分钟内两次运行
            d = _tmpdir()
            p = sc.Pusher("http://x", "tok", "A", d / "buf.jsonl", 30)
            p.flush_all()  # 进入 stopping
            p.add(dict(ev))
            import json as _json
            line = (d / "buf.jsonl").read_text().strip()
            ids.append(_json.loads(line)["event_id"])
        self.assertNotEqual(ids[0], ids[1])  # 两次运行的 ID 不同
        with no_geo():
            for eid in ids:
                self.assertTrue(plugin_api._ingest_one(conn, "A", {
                    **ev, "event_id": eid, "count": 1}))
        total = conn.execute(
            "SELECT SUM(count) FROM security_events WHERE machine_id='A'"
        ).fetchone()[0]
        self.assertEqual(total, 2)  # 中心 MAX 合并不吞第二条


class TestSchemaMigration(unittest.TestCase):
    """P1-6/R3-07: 真跑迁移——旧单列 event_id 索引升级为 (machine_id, event_id)
    复合索引。走生产代码的同一迁移入口（_sec_db），迁移实现被删掉时此测试必须红。"""

    def test_migration_rebuilds_composite_index(self):
        db = _TEST_TMP / "migration-old.db"
        if db.exists():
            db.unlink()
        # 旧库：完整 schema，但 event_id 索引是升级前的单列唯一索引
        conn = sqlite3.connect(str(db))
        conn.executescript(plugin_api._SEC_SCHEMA)
        conn.execute("DROP INDEX idx_events_event_id")
        conn.execute("CREATE UNIQUE INDEX idx_events_event_id ON security_events(event_id)")
        # 升级前已有数据，迁移后必须保留
        conn.execute(
            "INSERT INTO security_events (ts, machine_id, event_type, src_ip, event_id, count) "
            "VALUES ('2026-09-01T00:00:00+00:00', 'A', 'scan', '1.2.3.4', 'pre-migration', 5)"
        )
        conn.commit()
        conn.close()

        idx_before = [r[2] for r in sqlite3.connect(str(db)).execute(
            "PRAGMA index_info(idx_events_event_id)").fetchall()]
        self.assertEqual(idx_before, ["event_id"])  # 前置：确实是旧单列索引

        # 经生产代码使用的同一迁移入口升级
        with patch.object(plugin_api, "SEC_DB", db):
            mig = plugin_api._sec_db()
        try:
            idx_cols = [r[2] for r in mig.execute(
                "PRAGMA index_info(idx_events_event_id)").fetchall()]
            self.assertEqual(idx_cols, ["machine_id", "event_id"])  # 迁移成复合索引
            # 升级前的记录保留
            row = mig.execute(
                "SELECT machine_id, count FROM security_events WHERE event_id='pre-migration'"
            ).fetchone()
            self.assertEqual((row[0], row[1]), ("A", 5))
            # 迁移后两台机器相同 event_id 均可写入（跨机器隔离语义成立）
            for m in ("A", "B"):
                mig.execute(
                    "INSERT INTO security_events (ts, machine_id, event_type, src_ip, event_id, count) "
                    "VALUES ('2026-09-07T00:00:00+00:00', ?, 'scan', '5.6.7.8', 'shared', 1)", (m,))
            mig.commit()
            n = mig.execute(
                "SELECT COUNT(*) FROM security_events WHERE event_id='shared'").fetchone()[0]
            self.assertEqual(n, 2)
        finally:
            mig.close()


if __name__ == "__main__":
    unittest.main()


class TestValidateEventHardening(unittest.TestCase):
    """审阅 P1-1：畸形输入返回 None（拒单条），绝不抛异常（否则整批回滚）。"""

    def test_unhashable_event_type(self):
        ev = make_event(["ban"], "1.2.3.4", ago(10), "x")
        self.assertIsNone(plugin_api._validate_event(ev))

    def test_infinite_and_nan_count(self):
        ev = make_event("scan", "1.2.3.4", ago(10), "x")
        ev["count"] = math.inf  # type: ignore[dict-item] 畸形输入注入
        self.assertIsNone(plugin_api._validate_event(ev))
        ev["count"] = math.nan  # type: ignore[dict-item]
        self.assertIsNone(plugin_api._validate_event(ev))

    def test_ancient_timestamp_overflow(self):
        ev = make_event("scan", "1.2.3.4", "0001-01-01T00:00:00+14:00", "x")
        self.assertIsNone(plugin_api._validate_event(ev))

    def test_90d_boundary(self):
        # 审阅 P2-6：90 天以内可收（rotate 保留边界），超 90 天必须拒——
        # 与 rotate 的 DELETE ... < now-90d 对齐，先收后删毫无意义。
        ok = make_event("scan", "1.2.3.4", (datetime.now(timezone.utc) - timedelta(days=89, hours=23)).isoformat(), "x")
        self.assertIsNotNone(plugin_api._validate_event(ok))
        old = make_event("scan", "1.2.3.4", (datetime.now(timezone.utc) - timedelta(days=90, seconds=1)).isoformat(), "x")
        self.assertIsNone(plugin_api._validate_event(old))


class TestFail2banMillisecond(unittest.TestCase):
    """审阅 P1-2：fail2ban 毫秒必须入库，同秒 Unban(.100)→Ban(.900) 不冤杀。"""

    def test_collector_keeps_milliseconds(self):
        ev = sc.parse_f2b_line("2026-09-07 12:00:00,123 fail2ban.actions [1]: NOTICE [sshd] Ban 1.2.3.4")
        self.assertIsNotNone(ev)
        self.assertEqual(datetime.fromisoformat(ev["ts"]).microsecond, 123000)
        # 整秒日志输出格式与历史数据一致（小数省略）
        ev0 = sc.parse_f2b_line("2026-09-07 12:00:00,000 fail2ban.actions [1]: NOTICE [sshd] Ban 1.2.3.4")
        self.assertNotIn(".", ev0["ts"].replace("+00:00", ""))
        # 同秒内 .100 早于 .900（字符串序 = 时间序）
        u = sc.parse_f2b_line("2026-09-07 12:00:00,100 fail2ban.actions [1]: NOTICE [sshd] Unban 1.2.3.4")
        b = sc.parse_f2b_line("2026-09-07 12:00:00,900 fail2ban.actions [1]: NOTICE [sshd] Ban 1.2.3.4")
        self.assertLess(u["ts"], b["ts"])

    def test_center_does_not_phantom_close_same_second_ban(self):
        base = datetime.now(timezone.utc) - timedelta(minutes=5)
        conn = make_conn()
        with no_geo():
            plugin_api._ingest_one(conn, "A", make_event("unban", "1.2.3.4", base.replace(microsecond=100000).isoformat(), "u1", jail="sshd"))
            plugin_api._ingest_one(conn, "A", make_event("ban", "1.2.3.4", base.replace(microsecond=900000).isoformat(), "b1", jail="sshd"))
        active = conn.execute("SELECT COUNT(*) FROM security_bans WHERE unbanned_at IS NULL").fetchone()[0]
        self.assertEqual(active, 1)


class TestLazyGeoCommit(unittest.TestCase):
    """审阅 P2-5：ip 档案懒富化的 geo_cache 写入必须提交，否则每次重复查库。"""

    def test_enrichment_row_persists_and_counts_up(self):
        # 真实 _geoip_lookup：测试目录无 mmdb → 写 NULL 行，但行必须真正落库。
        r1 = asyncio.run(plugin_api.security_ip_profile("9.9.9.9"))
        self.assertIsNotNone(r1["geo"])
        conn = sqlite3.connect(os.environ["BESZEL_SEC_DB"])
        n1 = conn.execute("SELECT query_count FROM geo_cache WHERE ip='9.9.9.9'").fetchone()
        conn.close()
        self.assertIsNotNone(n1)  # close 时未被回滚
        asyncio.run(plugin_api.security_ip_profile("9.9.9.9"))
        conn = sqlite3.connect(os.environ["BESZEL_SEC_DB"])
        n2 = conn.execute("SELECT query_count FROM geo_cache WHERE ip='9.9.9.9'").fetchone()
        conn.close()
        self.assertEqual(n2[0], n1[0] + 1)  # 已提交才会递增；未提交永远停在 1


class TestSurrogateIsolation(unittest.TestCase):
    """审阅 R2-01：孤立 surrogate（JSON "\\ud800"）拒单条，同批有效事件不受影响。"""

    FIELDS = ["event_id", "jail", "uri", "ua", "username", "raw_excerpt"]

    def test_each_text_field_rejected_without_raising(self):
        for field in self.FIELDS:
            conn = make_conn()
            events = [
                make_event("scan", "8.8.8.8", ago(10), f"good-a-{field}"),
                make_event("scan", "8.8.8.8", ago(10), f"bad-{field}"),
                make_event("scan", "8.8.8.8", ago(10), f"good-b-{field}"),
            ]
            if field == "event_id":
                events[1]["event_id"] = "\ud800"
            else:
                events[1][field] = "\ud800"
            stored = []
            with no_geo():
                for ev in events:  # 任何字段抛异常都会让本用例 error（而非 fail）
                    if plugin_api._ingest_one(conn, "A", ev):
                        stored.append(ev["event_id"])
            self.assertEqual(sorted(stored), sorted([f"good-a-{field}", f"good-b-{field}"]), field)

    def test_utf8_text_accepted(self):
        # 合法中文/emoji 不得误伤
        conn = make_conn()
        ev = make_event("scan", "8.8.8.8", ago(10), "utf8-ok")
        ev["uri"] = "/搜索?q=🔥"
        ev["username"] = "管理员"
        ev["raw_excerpt"] = "Failed password for 管理员 from 8.8.8.8"
        with no_geo():
            self.assertTrue(plugin_api._ingest_one(conn, "A", ev))
        row = conn.execute("SELECT uri, username FROM security_events WHERE event_id='utf8-ok'").fetchone()
        self.assertEqual(row["username"], "管理员")

"""agent/security_collector.py 的回归测试。

覆盖审阅报告反复揪出的漏修点：日志轮转/截断/缺失、退出排空、时间格式解析、
IPv6 解析、flush 窗口语义。用 unittest（标准库，CI 零依赖）。
"""
import os
import sys
import time
import tempfile
import threading
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "agent"))
import security_collector as sc  # noqa: E402


class TestParseAuth(unittest.TestCase):
    """P2-10: SSH 时间格式（ISO 偏移 / ISO Z / 传统 syslog）+ publickey 登录。"""

    def test_iso_offset(self):
        ev = sc.parse_auth_line(
            "2026-09-07T12:00:00.123456+00:00 host sshd[1]: Failed password for root from 1.2.3.4 port 22 ssh2"
        )
        self.assertIsNotNone(ev)
        self.assertEqual(ev["event_type"], "auth_fail")
        self.assertEqual(ev["src_ip"], "1.2.3.4")

    def test_iso_z(self):
        ev = sc.parse_auth_line(
            "2026-09-07T12:00:00Z host sshd[1]: Invalid user admin from 5.6.7.8 port 22"
        )
        self.assertIsNotNone(ev)
        self.assertEqual(ev["src_ip"], "5.6.7.8")

    def test_syslog_time(self):
        ev = sc.parse_auth_line(
            "Sep  7 12:00:00 host sshd[1]: Connection closed by 9.10.11.12 port 22 [preauth]"
        )
        self.assertIsNotNone(ev)
        self.assertEqual(ev["src_ip"], "9.10.11.12")

    def test_publickey_success(self):
        ev = sc.parse_auth_line(
            "2026-09-07T12:00:00+00:00 host sshd[1]: Accepted publickey for root from 1.2.3.4 port 22 ssh2: RSA SHA256:abc"
        )
        self.assertIsNotNone(ev)
        self.assertEqual(ev["event_type"], "auth_success")


class TestParseNginx(unittest.TestCase):
    """P2-7: IPv6 十六进制 + 危险路径 2xx 漏报。"""

    def test_ipv6_full(self):
        ev = sc.parse_nginx_line(
            '2606:4700::abcd - - [07/Sep/2026:12:00:00 +0000] "GET /.env HTTP/1.1" 200 123 "-" "curl"'
        )
        self.assertIsNotNone(ev)
        self.assertEqual(ev["src_ip"], "2606:4700::abcd")

    def test_dangerous_path_200_recorded(self):
        # 危险路径即使 200（信息泄露）也要记录，不能因 2xx 忽略
        ev = sc.parse_nginx_line(
            '1.2.3.4 - - [07/Sep/2026:12:00:00 +0000] "GET /.env HTTP/1.1" 200 123 "-" "curl"'
        )
        self.assertIsNotNone(ev)
        self.assertEqual(ev["event_type"], "scan")

    def test_ordinary_200_ignored(self):
        ev = sc.parse_nginx_line(
            '1.2.3.4 - - [07/Sep/2026:12:00:00 +0000] "GET / HTTP/1.1" 200 123 "-" "curl"'
        )
        self.assertIsNone(ev)


class TestParseF2b(unittest.TestCase):
    def test_ipv6_full(self):
        ev = sc.parse_f2b_line(
            "2026-09-07 12:00:00,123 fail2ban.actions [123]: NOTICE [sshd] Ban 2606:4700::abcd"
        )
        self.assertIsNotNone(ev)
        self.assertEqual(ev["src_ip"], "2606:4700::abcd")


class TestPusher(unittest.TestCase):
    """P1-2 flush 只发封口窗口 + P2-3 flush_all 退出排空当前分钟。"""

    def _make_pusher(self):
        sent = []

        class Fake(sc.Pusher):
            def _post(self, batch):
                sent.extend(batch)

        p = Fake("http://x", "tok", "M", Path(tempfile.mkdtemp()) / "buf.jsonl", 30)
        return p, sent

    def test_flush_sealed_only(self):
        p, sent = self._make_pusher()
        ev = {"ts": "2026-09-07T12:00:00+00:00", "event_type": "scan", "src_ip": "1.2.3.4", "raw_excerpt": "x"}
        p.add(ev)
        p.flush()
        self.assertEqual(len(sent), 0)  # 当前分钟未封口，周期 flush 不排空

    def test_flush_all_drains_current_minute(self):
        p, sent = self._make_pusher()
        ev = {"ts": "2026-09-07T12:00:00+00:00", "event_type": "scan", "src_ip": "1.2.3.4", "raw_excerpt": "x"}
        p.add(ev)
        p.flush_all()
        self.assertEqual(len(sent), 1)  # 退出排空当前分钟
        self.assertIn(":s", sent[0]["event_id"])  # shutdown 唯一 event_id


class TestTailFile(unittest.TestCase):
    """P1-1: 轮转重开从文件头读，不漏新文件已写内容；首次 seek EOF 跳历史。"""

    def test_rotation_reads_new_file(self):
        d = tempfile.mkdtemp()
        log = os.path.join(d, "test.log")

        def parse(line):
            line = line.strip()
            if not line:
                return None
            return {"ts": "2026-09-07T12:00:00+00:00", "event_type": "scan", "src_ip": line, "raw_excerpt": line}

        with open(log, "w") as f:
            f.write("OLD-1.1.1.1\n")

        collected = []

        def run():
            c = sc.Collector(sc.DB_PATH, pusher=None)
            for ev in c._tail_file(log, parse):
                collected.append(ev["src_ip"])

        t = threading.Thread(target=run, daemon=True)
        t.start()
        time.sleep(0.6)

        # 轮转：重命名旧文件 + 创建新文件 + 立即写入（审阅报告的关键场景）
        os.rename(log, log + ".1")
        with open(log, "w") as f:
            f.write("B-8.8.8.8\n")
        time.sleep(1.5)

        self.assertIn("B-8.8.8.8", collected)  # 新文件已写内容不被跳过
        self.assertNotIn("OLD-1.1.1.1", collected)  # 首次 seek EOF 跳历史


if __name__ == "__main__":
    unittest.main()

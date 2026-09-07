"""agent/security_collector.py 的回归测试。

覆盖审阅报告反复揪出的漏修点：日志轮转/截断/缺失、退出排空、时间格式解析、
IPv6 解析、flush 窗口语义。用 unittest（标准库，CI 零依赖）。
"""
import os
import signal
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


class TestFlushAllIds(unittest.TestCase):
    """R3-02: flush_all 的 event_id 规则——跨分钟窗口绝不碰撞。"""

    def _make_pusher(self):
        sent = []

        class Fake(sc.Pusher):
            def _post(self, batch):
                sent.extend(batch)

        p = Fake("http://x", "tok", "M", Path(tempfile.mkdtemp()) / "buf.jsonl", 30)
        return p, sent

    def _current_minute_start(self):
        return int(time.time() // 60 * 60)

    def test_sealed_window_keeps_minute_id(self):
        """已封口窗口保留原分钟边界 ID，不和当前分钟尾段撞。"""
        p, sent = self._make_pusher()
        w_prev = self._current_minute_start() - 60
        ev_prev = {
            "ts": "2026-09-07T11:59:00+00:00", "event_type": "scan",
            "src_ip": "1.2.3.4", "raw_excerpt": "x",
            "event_id": f"M:scan:1.2.3.4:{w_prev}", "count": 100,
        }
        p._windows[("scan", "1.2.3.4", w_prev)] = ev_prev  # 已封口，待发
        p.add({"ts": "2026-09-07T12:00:10+00:00", "event_type": "scan",
               "src_ip": "1.2.3.4", "raw_excerpt": "y"})  # 当前分钟 count=1
        p.flush_all()
        self.assertEqual(len(sent), 2)
        ids = {e["event_id"] for e in sent}
        self.assertEqual(len(ids), 2)  # 两个分钟窗口绝不共享 ID
        sealed = [e for e in sent if e.get("count") == 100]
        self.assertEqual(sealed[0]["event_id"], f"M:scan:1.2.3.4:{w_prev}")

    def test_unsealed_rekey_keeps_wstart(self):
        """当前分钟尾段 ID 含原窗口起点 + :s 尾段，重放不重新生成。"""
        p, sent = self._make_pusher()
        w_cur = self._current_minute_start()
        p.add({"ts": "2026-09-07T12:00:10+00:00", "event_type": "scan",
               "src_ip": "1.2.3.4", "raw_excerpt": "x"})
        p.flush_all()
        self.assertEqual(len(sent), 1)
        eid = sent[0]["event_id"]
        self.assertIn(f":{w_cur}:s", eid)  # 窗口起点保留在 ID 里
        # 同分钟重启后的新窗口用纯分钟 ID，与关机批次的 ID 不撞
        self.assertNotEqual(eid, f"M:scan:1.2.3.4:{w_cur}")

    def test_buffer_replay_keeps_id(self):
        """发送失败落盘的批次保留已生成 ID，重放幂等。"""
        import json as _json
        buf = Path(tempfile.mkdtemp()) / "buf.jsonl"

        class Fail(sc.Pusher):
            def _post(self, batch):
                raise OSError("centre down")

        p = Fail("http://x", "tok", "M", buf, 30)
        p.add({"ts": "2026-09-07T12:00:10+00:00", "event_type": "scan",
               "src_ip": "1.2.3.4", "raw_excerpt": "x"})
        p.flush_all()
        lines = buf.read_text().strip().splitlines()
        self.assertEqual(len(lines), 1)
        buffered_id = _json.loads(lines[0])["event_id"]  # JSONL：每行一个事件
        self.assertIn(":s", buffered_id)


class TestSyslogYear(unittest.TestCase):
    """R3-05: syslog 无年份时间的年份推断——小幅超前是时钟偏差，不回退。"""

    _MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun",
               "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]

    def _syslog_line(self, dt):
        # 手工拼 syslog 时间戳（"Sep  7 12:00:00"），不用 strftime %b——
        # %b 依赖 locale（zh_CN 下输出"9月"），测试必须 locale 无关。
        ts = f"{self._MONTHS[dt.month - 1]} {dt.day:2d} {dt:%H:%M:%S}"
        return ts + " host sshd[1]: Connection closed by 9.10.11.12 port 22 [preauth]"

    def test_small_future_skew_stays_this_year(self):
        from datetime import datetime, timedelta
        future = datetime.now() + timedelta(seconds=2)
        ev = sc.parse_auth_line(self._syslog_line(future))
        self.assertIsNotNone(ev)
        ts = datetime.fromisoformat(ev["ts"])
        self.assertEqual(ts.year, datetime.now().astimezone().year)  # 不变去年

    def test_year_crossing_rolls_back(self):
        from datetime import datetime, timedelta
        now = datetime.now()
        future = now + timedelta(minutes=20)  # 远超 15min 容差
        if future.date() != now.date():
            self.skipTest("跨日边界窗口，跳过（每年约 20 分钟）")
        ev = sc.parse_auth_line(self._syslog_line(future))
        self.assertIsNotNone(ev)
        ts = datetime.fromisoformat(ev["ts"])
        self.assertEqual(ts.year, now.astimezone().year - 1)  # 跨年日志回退


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


class TestSigtermDrain(unittest.TestCase):
    """R3-01: SIGTERM 必须走排空路径——真实子进程跑 __main__，注入合成事件，
    发 SIGTERM，验证事件送达中心（或断网时落盘）。"""

    def _run_child(self, center_url, tmp, extra_env=None):
        """起真实 agent 子进程：tail 临时日志，flush 间隔拉长防周期 flush 干扰。"""
        import subprocess
        f2b_log = os.path.join(tmp, "fail2ban.log")
        open(f2b_log, "w").close()
        for name in ("nginx.log", "auth.log"):
            open(os.path.join(tmp, name), "w").close()
        env = os.environ.copy()
        env.update({
            "SEC_F2B_LOG": f2b_log,
            "SEC_NGINX_LOG": os.path.join(tmp, "nginx.log"),
            "SEC_AUTH_LOG": os.path.join(tmp, "auth.log"),
            "SEC_BUFFER_FILE": os.path.join(tmp, "buf.jsonl"),
            "SEC_MACHINE_ID": "TEST-M",
        })
        if extra_env:
            env.update(extra_env)
        script = str(Path(sc.__file__ or "").resolve())
        proc = subprocess.Popen(
            [sys.executable, script, "--push", "--center-url", center_url,
             "--token", "t", "--flush-interval", "999"],
            env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        time.sleep(1.2)  # 等 tail 完成首次 seek EOF
        return proc, f2b_log

    def _stop_and_wait(self, proc, sig):
        proc.send_signal(sig)
        try:
            rc = proc.wait(timeout=20)
        except Exception:
            proc.kill()
            raise AssertionError("子进程未在 20s 内退出")
        return rc

    def test_sigterm_drains_pending_events(self):
        """SIGTERM → finally flush_all：ban（离散队列）必须送达中心。"""
        import http.server
        received = []

        class Sink(http.server.BaseHTTPRequestHandler):
            def do_POST(self):
                n = int(self.headers.get("Content-Length", 0))
                import json as _json
                body = _json.loads(self.rfile.read(n) or b"{}")
                received.extend(body.get("events", []))
                self.send_response(200)
                self.end_headers()

            def log_message(self, format, *args):
                pass

        srv = http.server.HTTPServer(("127.0.0.1", 0), Sink)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        tmp = tempfile.mkdtemp()
        proc, f2b_log = self._run_child(f"http://127.0.0.1:{srv.server_port}/ingest", tmp)
        try:
            with open(f2b_log, "a") as f:
                f.write("2026-09-07 12:00:00,123 fail2ban.actions [1]: "
                        "NOTICE [sshd] Ban 9.9.9.9\n")
            time.sleep(1.5)  # 等 tail 读到（事件留在内存队列，flush-interval=999 不发）
            self.assertEqual(len(received), 0)  # 周期 flush 未触发，事件在内存里
            rc = self._stop_and_wait(proc, signal.SIGTERM)
        finally:
            srv.shutdown()
            if proc.poll() is None:
                proc.kill()
        self.assertEqual(rc, 0)  # KeyboardInterrupt 被捕获，正常退出
        types = [e.get("event_type") for e in received]
        self.assertIn("ban", types)  # SIGTERM 排空把内存事件送达中心

    def test_sigterm_offline_buffers_to_disk(self):
        """SIGTERM + 中心不可达 → 落盘缓冲，不丢数据。"""
        tmp = tempfile.mkdtemp()
        proc, f2b_log = self._run_child("http://127.0.0.1:1/ingest", tmp)  # 端口 1 不可达
        try:
            with open(f2b_log, "a") as f:
                f.write("2026-09-07 12:00:00,123 fail2ban.actions [1]: "
                        "NOTICE [sshd] Ban 8.8.8.8\n")
            time.sleep(1.5)
            rc = self._stop_and_wait(proc, signal.SIGTERM)
        finally:
            if proc.poll() is None:
                proc.kill()
        self.assertEqual(rc, 0)
        buf = os.path.join(tmp, "buf.jsonl")
        self.assertTrue(os.path.exists(buf), "断网退出必须落盘缓冲")
        content = open(buf).read()
        self.assertIn("8.8.8.8", content)


if __name__ == "__main__":
    unittest.main()

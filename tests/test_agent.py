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

    def _run_child(self, center_url, tmp, extra_env=None, flush_interval=999):
        """起真实 agent 子进程：tail 临时日志，flush 间隔默认拉长防周期 flush 干扰。"""
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
             "--token", "t", "--flush-interval", str(flush_interval)],
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

    def test_sigterm_during_inflight_send(self):
        """R4-01 场景 A 端到端：周期 flush 已取走批次、中心 hang 住时 SIGTERM——
        进程有界等待在途批次，中心返回 503 后批次落盘，不随 daemon 线程消失。"""
        import http.server
        received_req = threading.Event()
        release = threading.Event()

        class Hang(http.server.BaseHTTPRequestHandler):
            def do_POST(self):
                n = int(self.headers.get("Content-Length", 0))
                self.rfile.read(n)
                received_req.set()
                release.wait(30)  # 中心 hang，由测试放行
                self.send_response(503)
                self.end_headers()

            def log_message(self, format, *args):
                pass

        srv = http.server.HTTPServer(("127.0.0.1", 0), Hang)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        tmp = tempfile.mkdtemp()
        # flush-interval=1：周期 flush 真取走批次；shutdown_wait 缩短到 3s
        proc, f2b_log = self._run_child(
            f"http://127.0.0.1:{srv.server_port}/ingest", tmp,
            extra_env={"SEC_SHUTDOWN_WAIT": "3"}, flush_interval=1)
        try:
            with open(f2b_log, "a") as f:
                f.write("2026-09-07 12:00:00,123 fail2ban.actions [1]: "
                        "NOTICE [sshd] Ban 9.9.9.9\n")
            self.assertTrue(received_req.wait(8),
                            "周期 flush 应取走批次并发到中心（中心 hang 住）")
            proc.send_signal(signal.SIGTERM)
            time.sleep(0.5)
            self.assertIsNone(proc.poll(), "在途批次未确认前进程不应退出")
            release.set()  # 中心返回 503 → flush 线程失败落盘 → inflight 清空
            try:
                rc = proc.wait(timeout=15)
            except Exception:
                proc.kill()
                raise AssertionError("子进程未在 15s 内退出")
        finally:
            release.set()
            srv.shutdown()
            if proc.poll() is None:
                proc.kill()
        self.assertEqual(rc, 0)
        buf = Path(tmp) / "buf.jsonl"
        self.assertTrue(buf.exists(), "中心 503 → 在途批次必须落盘")
        self.assertIn("ban", buf.read_text())

    def test_repeated_sigterm_does_not_abort_drain(self):
        """R4-01：排空期间的重复 SIGTERM 必须被忽略（stopping 幂等）——
        KeyboardInterrupt 是 BaseException，会穿透 except Exception 打断排空。"""
        import http.server
        received = []

        class SlowSink(http.server.BaseHTTPRequestHandler):
            def do_POST(self):
                n = int(self.headers.get("Content-Length", 0))
                import json as _json
                body = _json.loads(self.rfile.read(n) or b"{}")
                received.extend(body.get("events", []))
                time.sleep(0.8)  # 慢中心：制造排空窗口期
                self.send_response(200)
                self.end_headers()

            def log_message(self, format, *args):
                pass

        srv = http.server.HTTPServer(("127.0.0.1", 0), SlowSink)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        tmp = tempfile.mkdtemp()
        proc, f2b_log = self._run_child(f"http://127.0.0.1:{srv.server_port}/ingest", tmp)
        try:
            with open(f2b_log, "a") as f:
                f.write("2026-09-07 12:00:00,123 fail2ban.actions [1]: "
                        "NOTICE [sshd] Ban 9.9.9.9\n")
            time.sleep(1.5)
            proc.send_signal(signal.SIGTERM)  # 第一次：进入排空（慢中心，发送中）
            time.sleep(0.2)
            proc.send_signal(signal.SIGTERM)  # 第二次：stopping=True，必须被忽略
            try:
                rc = proc.wait(timeout=20)
            except Exception:
                proc.kill()
                raise AssertionError("子进程未在 20s 内退出（排空可能被打断）")
        finally:
            srv.shutdown()
            if proc.poll() is None:
                proc.kill()
        self.assertEqual(rc, 0)
        types = [e.get("event_type") for e in received]
        self.assertIn("ban", types)


class TestInflightShutdown(unittest.TestCase):
    """R4-01 场景 A（线程内精确时序）：flush 线程已取走批次时停止，
    批次必须有归属——等待它完成，或超时接管落盘。"""

    def _ban_ev(self):
        return {"ts": "2026-09-07T12:00:10+00:00", "event_type": "ban",
                "src_ip": "9.9.9.9", "raw_excerpt": "ban-x"}

    def test_inflight_send_settles_before_exit(self):
        """在途发送完成后 flush_all 才返回；批次送达而非落盘。"""
        post_called = threading.Event()
        release = threading.Event()
        sent = []

        class Blocking(sc.Pusher):
            def _post(self, batch):
                post_called.set()
                release.wait(10)
                sent.extend(batch)

        buf = Path(tempfile.mkdtemp()) / "buf.jsonl"
        p = Blocking("http://x", "tok", "M", buf, 30, shutdown_wait=5)
        p.add(self._ban_ev())
        t = threading.Thread(target=p.flush, daemon=True)
        t.start()
        self.assertTrue(post_called.wait(2), "flush 线程应取走批次进入在途发送")

        drained = threading.Event()
        def shutdown():
            p.flush_all()
            drained.set()
        st = threading.Thread(target=shutdown, daemon=True)
        st.start()
        time.sleep(0.5)
        self.assertFalse(drained.is_set(), "在途批次未确认前 flush_all 不应返回")
        release.set()  # 中心响应 200
        st.join(5)
        t.join(5)
        self.assertTrue(drained.is_set())
        self.assertEqual(len(sent), 1)  # 批次送达中心
        self.assertFalse(buf.exists())  # 无落盘

    def test_inflight_timeout_taken_over_to_disk(self):
        """在途发送超出 shutdown_wait → 主线程接管落盘；发送线程随后的失败
        落盘产生同 ID 双份（幂等，中心计数不变）。"""
        import json as _json
        post_called = threading.Event()
        release = threading.Event()

        class Hanging(sc.Pusher):
            def _post(self, batch):
                post_called.set()
                release.wait(10)
                raise OSError("centre 503")

        buf = Path(tempfile.mkdtemp()) / "buf.jsonl"
        p = Hanging("http://x", "tok", "M", buf, 30, shutdown_wait=0.5)
        p.add(self._ban_ev())
        t = threading.Thread(target=p.flush, daemon=True)
        t.start()
        self.assertTrue(post_called.wait(2))
        p.flush_all()  # 0.5s 超时 → 接管落盘
        self.assertTrue(buf.exists(), "超时后批次必须落盘")
        release.set()  # flush 线程失败 → 再落一份（同 ID 幂等）
        t.join(5)
        lines = buf.read_text().strip().splitlines()
        self.assertEqual(len(lines), 2)  # 接管 1 + 发送线程失败 1
        self.assertEqual(_json.loads(lines[0])["event_id"],
                         _json.loads(lines[1])["event_id"])  # 同 ID 幂等


class TestReplayOwnership(unittest.TestCase):
    """R4-01 场景 B：缓冲重放原子 rename 切换归属——并发追加写新文件，
    重放只删自己 rename 走的那份；失败留下 replay 文件等下轮/重启捡起。"""

    def _ev(self, tag):
        return {"event_id": f"M:scan:1.2.3.4:{tag}", "event_type": "scan",
                "src_ip": "1.2.3.4", "count": 1, "ts": "2026-09-07T12:00:00+00:00"}

    def test_replay_never_deletes_concurrent_appends(self):
        """报告的精确时序：重放读到 old 后暂停 → 并发追加 new → 重放成功
        只删 replay 文件 → new 必须仍在主缓冲。"""
        import json as _json
        d = Path(tempfile.mkdtemp())
        buf = d / "buf.jsonl"
        old, new = self._ev("old"), self._ev("new")
        buf.write_text(_json.dumps(old) + "\n")

        post_called = threading.Event()
        release = threading.Event()
        sent = []

        class Blocking(sc.Pusher):
            def _post(self, batch):
                sent.extend(batch)
                post_called.set()
                release.wait(10)

        p = Blocking("http://x", "tok", "M", buf, 30)
        t = threading.Thread(target=p.retry_buffer, daemon=True)
        t.start()
        self.assertTrue(post_called.wait(2), "重放应已 rename 并读到 old")
        p._buffer([new])  # 并发追加（模拟 flush_all 失败落盘）
        release.set()
        t.join(5)
        # new 仍在主缓冲，没被误删
        remaining = buf.read_text().strip().splitlines()
        self.assertEqual(len(remaining), 1)
        self.assertEqual(_json.loads(remaining[0])["event_id"], new["event_id"])
        # old 已发送，replay 文件已删
        self.assertEqual([e["event_id"] for e in sent], [old["event_id"]])
        self.assertFalse(p._replay_path().exists())

    def test_failed_replay_keeps_file_and_next_round_picks_up(self):
        """重放失败留下 replay 文件（不归还、不删除）；下轮重放直接捡起它，
        崩溃重启后也不会孤儿化。"""
        import json as _json
        d = Path(tempfile.mkdtemp())
        buf = d / "buf.jsonl"
        old = self._ev("old")
        buf.write_text(_json.dumps(old) + "\n")
        sent = []

        class FailOnce(sc.Pusher):
            def _post(self, batch):
                if not getattr(self, "_failed", False):
                    self._failed = True
                    raise OSError("centre down")
                sent.extend(batch)

        p = FailOnce("http://x", "tok", "M", buf, 30)
        p.retry_buffer()  # 失败
        self.assertTrue(p._replay_path().exists())  # replay 文件留着
        self.assertFalse(buf.exists())  # 主缓冲已被 rename 走
        p.retry_buffer()  # 第二轮：捡起 replay → 成功 → 删除
        self.assertEqual([e["event_id"] for e in sent], [old["event_id"]])
        self.assertFalse(p._replay_path().exists())


class TestStoppingIntake(unittest.TestCase):
    """R4-01：stopping 后 add 直接落盘（flush_all 已排空队列，进程将退出），
    窗口单条带唯一 :x<seq> 后缀，防中心 MAX 合并丢计数。"""

    def test_add_after_stopping_goes_to_disk(self):
        import json as _json
        buf = Path(tempfile.mkdtemp()) / "buf.jsonl"
        sent = []

        class Sink(sc.Pusher):
            def _post(self, batch):
                sent.extend(batch)

        p = Sink("http://x", "tok", "M", buf, 30)
        p.flush_all()  # 队列空，仅翻转 stopping
        p.add({"ts": "t", "event_type": "scan", "src_ip": "1.2.3.4", "raw_excerpt": "a"})
        p.add({"ts": "t", "event_type": "scan", "src_ip": "1.2.3.4", "raw_excerpt": "b"})
        p.add({"ts": "t", "event_type": "ban", "src_ip": "9.9.9.9", "raw_excerpt": "c"})
        self.assertEqual(len(sent), 0)  # stopping 后不再进内存队列
        lines = buf.read_text().strip().splitlines()
        self.assertEqual(len(lines), 3)
        ids = [_json.loads(l)["event_id"] for l in lines]
        self.assertEqual(len(set(ids)), 3)  # 三条 ID 互不相同
        scan_ids = [i for i in ids if ":scan:" in i]
        self.assertTrue(all(":x" in i for i in scan_ids))  # 唯一后缀


if __name__ == "__main__":
    unittest.main()

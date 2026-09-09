"""agent/install-agent.sh 变更检测/重启决策的行为测试（R5-05）。

把脚本的 security-collector 段原样抽取出来，在沙箱里真跑：
- 路径全部重定向到临时目录（AGENT_DIR、unit 文件）
- curl/systemctl 用 PATH 里的假实现记录调用、模拟服务状态

验收（对齐复审报告的关闭条件）：
- 仅 token 变化 → 恰好一次 restart
- 内容完全不变 → 不 restart
- 仅代码变化 → restart
- 首次安装（服务未运行）→ enable --now
不碰真实 systemd、不下载、不用真实 token。
"""
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
SCRIPT = REPO / "agent" / "install-agent.sh"
COLLECTOR_SRC = REPO / "agent" / "security_collector.py"


def extract_section() -> str:
    """截取「2. security-collector」到「3. 自检」之间的真实脚本内容。"""
    text = SCRIPT.read_text()
    start = text.index("# ---------------------------------------------------------------- 2. security-collector")
    end = text.index("# ---------------------------------------------------------------- 3. 自检")
    body = text[start:end]
    # 路径重定向到测试环境：unit 文件 + AGENT_DIR 硬赋值改为可被环境覆盖
    body = body.replace("/etc/systemd/system/security-collector.service",
                        '"$UNIT_PATH"')
    body = body.replace('AGENT_DIR="/opt/beszel-sec-agent"',
                        'AGENT_DIR="${AGENT_DIR:-/opt/beszel-sec-agent}"')
    return body


class InstallerSandbox(unittest.TestCase):
    def setUp(self):
        self.d = Path(tempfile.mkdtemp())
        bin_dir = self.d / "bin"
        bin_dir.mkdir()
        self.agent_dir = self.d / "opt"
        self.unit_path = self.d / "unit.service"
        self.fake_log = self.d / "calls.log"
        self.state = self.d / "service-active"  # 存在 = 服务运行中
        src_copy = self.d / "collector.py"
        shutil.copyfile(COLLECTOR_SRC, src_copy)

        fake_curl = bin_dir / "curl"
        fake_curl.write_text(
            "#!/usr/bin/env bash\n"
            'out=""\nprev=""\nfor a in "$@"; do\n'
            '  if [ "$prev" = "-o" ]; then out="$a"; fi\n  prev="$a"\ndone\n'
            f'[ -n "$out" ] && cp "{src_copy}" "$out"\nexit 0\n')
        fake_systemctl = bin_dir / "systemctl"
        fake_systemctl.write_text(
            "#!/usr/bin/env bash\n"
            'echo "$*" >> "$FAKE_LOG"\n'
            'case "$1" in\n'
            '  is-active) if [ -f "$STATE_FILE" ]; then exit 0; else exit 3; fi;;\n'
            '  enable)  touch "$STATE_FILE"; exit 0;;\n'   # enable --now
            '  restart) touch "$STATE_FILE"; exit 0;;\n'
            '  *) exit 0;;\n'
            'esac\n')
        for f in (fake_curl, fake_systemctl):
            f.chmod(f.stat().st_mode | stat.S_IEXEC)

        self.harness = self.d / "run.sh"
        header = (
            "set -u\n"
            f'AGENT_DIR="{self.agent_dir}"\n'
            f'UNIT_PATH="{self.unit_path}"\n'
            'mkdir -p "$AGENT_DIR"\n'
            'TOKEN="${TOKEN:-tok-v1}"\n'
            'CENTER_URL="http://center/ingest"\n'
            'OUR_REPO="local/test"\nOUR_BRANCH="master"\n'
            'info()  { :; }\nwarn()  { :; }\nfail()  { echo "FAIL: $*" >&2; exit 1; }\n'
        )
        self.harness.write_text(header + extract_section())

    def _run(self, token: str) -> list[str]:
        env = dict(os.environ)
        env.update({
            "PATH": f"{self.d}/bin:{env['PATH']}",
            "FAKE_LOG": str(self.fake_log),
            "STATE_FILE": str(self.state),
            "TOKEN": token,
        })
        r = subprocess.run(["bash", str(self.harness)], env=env,
                           capture_output=True, text=True, timeout=60)
        self.assertEqual(r.returncode, 0, f"installer section failed: {r.stderr}")
        return self.fake_log.read_text().splitlines() if self.fake_log.exists() else []

    def _restart_count(self, calls: list[str]) -> int:
        return sum(1 for c in calls if c.startswith("restart "))

    def test_first_install_enables_service(self):
        calls = self._run("tok-v1")
        self.assertTrue(any(c.startswith("enable") for c in calls),
                        "首次安装应 enable --now")
        self.assertEqual(self._restart_count(calls), 0)

    def test_token_only_change_triggers_exactly_one_restart(self):
        self._run("tok-v1")            # 首次安装
        calls = self._run("tok-v2")    # 只有 token 变了
        self.assertEqual(self._restart_count(calls), 1,
                         "R5-05: 仅 token 变化必须恰好重启一次")
        self.assertIn("tok-v2", (self.agent_dir / "agent_token.txt").read_text())

    def test_nothing_changed_does_not_restart(self):
        self._run("tok-v1")
        self.fake_log.unlink()
        calls = self._run("tok-v1")    # 什么都没变
        self.assertEqual(self._restart_count(calls), 0,
                         "幂等重跑不得白重启服务")
        self.assertTrue(any("daemon-reload" in c for c in calls))

    def test_code_change_triggers_restart(self):
        self._run("tok-v1")
        # 改一下仓库里的源文件副本（fake curl 会把它“下载”过去）
        copy = sorted(self.d.glob("collector.py"))[0]
        copy.write_text(copy.read_text() + "\n# touched\n")
        self.fake_log.unlink()
        calls = self._run("tok-v1")
        self.assertEqual(self._restart_count(calls), 1)

    def test_token_never_logged(self):
        self._run("tok-secret-9f3")
        calls = self.fake_log.read_text()
        self.assertNotIn("tok-secret-9f3", calls, "systemctl 调用记录不得含 token")


if __name__ == "__main__":
    unittest.main()

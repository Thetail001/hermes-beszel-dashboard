#!/usr/bin/env bash
# hermes-beszel-dashboard — agent 侧安装脚本
#
# 在一台被监控的 VPS 上完成两件事：
#   1. 安装 beszel agent（资源监控）—— 复用 beszel 官方脚本，不重写
#   2. 安装 security-collector（安全事件采集）—— 本项目独有，推送到中心
#
# 用法（去中心机的 beszel webui → 添加系统 → 复制公钥和 token）：
#   curl -fsSL https://raw.githubusercontent.com/<owner>/<repo>/master/agent/install-agent.sh \
#     | bash -s -- -k "<公钥>" -t "<token>" -url "https://<中心域名>" -center "https://<中心域名>/api/plugins/beszel/security/ingest"
#
# 参数（全部可选，缺省会交互式询问）：
#   -k <公钥>        beszel 公钥（webui 添加系统时显示，ssh-ed25519 开头）
#   -t <token>       beszel token（universal token 或 per-system token 均可，
#                    中心两种都认；webui 添加系统时复制）
#   -url <hub地址>   beszel hub 地址，如 https://example.com
#   -center <url>    中心 security ingest 地址，如 https://example.com/api/plugins/beszel/security/ingest
#   -p <端口>        agent 端口（默认 45876）
#   --china-mirrors  使用国内镜像下载 beszel 二进制
#   -h               帮助
#
# 示例（universal token 一键装，含国内镜像）：
#   curl -fsSL .../install-agent.sh | bash -s -- \
#     -k "ssh-ed25519 AAAA..." \
#     -t "zKrqwQwM1..." \
#     -url "https://example.com" \
#     -center "https://example.com/api/plugins/beszel/security/ingest" \
#     --china-mirrors
set -euo pipefail

BESZEL_REPO="henrygd/beszel"
OUR_REPO="${OUR_REPO:-Thetail001/hermes-beszel-dashboard}"
OUR_BRANCH="${OUR_BRANCH:-master}"

KEY=""
TOKEN=""
HUB_URL=""
CENTER_URL=""
PORT="45876"
CHINA_MIRRORS=""

info()  { printf '\033[32m[+] %s\033[0m\n' "$*"; }
warn()  { printf '\033[33m[!] %s\033[0m\n' "$*"; }
fail()  { printf '\033[31m[x] %s\033[0m\n' "$*" >&2; exit 1; }

usage() {
  sed -n '2,20p' "$0" | sed 's/^# \{0,1\}//'
  exit 0
}

# 参数解析
while [ $# -gt 0 ]; do
  case "$1" in
    -k) shift; KEY="$1" ;;
    -t) shift; TOKEN="$1" ;;
    -url) shift; HUB_URL="$1" ;;
    -center) shift; CENTER_URL="$1" ;;
    -p) shift; PORT="$1" ;;
    --china-mirrors) CHINA_MIRRORS="--china-mirrors" ;;
    -h|--help) usage ;;
    *) fail "未知参数: $1（-h 看用法）" ;;
  esac
  shift
done

# 交互式补齐缺失参数
[ -z "$HUB_URL" ] && { printf 'beszel hub 地址（如 https://example.com）: '; read -r HUB_URL; }
[ -z "$KEY" ] && { printf 'beszel 公钥（ssh-ed25519 开头）: '; read -r KEY; }
[ -z "$TOKEN" ] && { printf 'beszel token: '; read -r TOKEN; }
# center-url 默认从 hub-url 推导（同源，路径固定）
[ -z "$CENTER_URL" ] && CENTER_URL="${HUB_URL%/}/api/plugins/beszel/security/ingest"

[ -z "$HUB_URL" ] || [ -z "$KEY" ] || [ -z "$TOKEN" ] && fail "缺少必要参数（-url/-k/-t）"
[ "$(id -u)" = "0" ] || fail "需要 root 权限（sudo 运行）"

# ---------------------------------------------------------------- 1. beszel agent
info "安装 beszel agent（复用官方脚本）..."
OFFICIAL_SCRIPT=""
if curl -fsSL --max-time 30 "https://get.beszel.dev/agent" -o /tmp/beszel-install-agent.sh 2>/dev/null \
   && head -c 20 /tmp/beszel-install-agent.sh | grep -q "sh"; then
  OFFICIAL_SCRIPT="/tmp/beszel-install-agent.sh"
  info "  官方脚本来源: get.beszel.dev/agent"
else
  # Cloudflare 挡了 get.beszel.dev，fallback 到 GitHub raw
  curl -fsSL --max-time 30 \
    "https://raw.githubusercontent.com/$BESZEL_REPO/main/supplemental/scripts/install-agent.sh" \
    -o /tmp/beszel-install-agent.sh || fail "下载官方 agent 脚本失败"
  OFFICIAL_SCRIPT="/tmp/beszel-install-agent.sh"
  warn "  get.beszel.dev 被 Cloudflare 挡，改用 GitHub raw"
fi
chmod +x "$OFFICIAL_SCRIPT"
"$OFFICIAL_SCRIPT" -p "$PORT" -k "$KEY" -t "$TOKEN" -url "$HUB_URL" --auto-update=false $CHINA_MIRRORS \
  || fail "beszel agent 安装失败"

# ---------------------------------------------------------------- 2. security-collector
info "安装 security-collector（安全事件采集）..."
AGENT_DIR="/opt/beszel-sec-agent"
mkdir -p "$AGENT_DIR"

curl -fsSL --max-time 30 \
  "https://raw.githubusercontent.com/$OUR_REPO/$OUR_BRANCH/agent/security_collector.py" \
  -o "$AGENT_DIR/security_collector.py" || fail "下载 security_collector.py 失败"

# token 复用 beszel 的（universal 或 per-system 均可，中心两种都认）
printf '%s' "$TOKEN" > "$AGENT_DIR/agent_token.txt"
chmod 600 "$AGENT_DIR/agent_token.txt"

# 写 systemd unit
cat > /etc/systemd/system/security-collector.service <<EOF
[Unit]
Description=Beszel Security Event Collector
After=network-online.target beszel-agent.service
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 $AGENT_DIR/security_collector.py \\
  --push \\
  --center-url $CENTER_URL \\
  --token-file $AGENT_DIR/agent_token.txt \\
  --flush-interval 30
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal
SyslogIdentifier=beszel-security-collector

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now security-collector.service || fail "security-collector 启动失败"

# ---------------------------------------------------------------- 3. 自检
sleep 3
info "自检："
if systemctl is-active --quiet beszel-agent.service; then
  info "  beszel-agent: 运行中"
else
  warn "  beszel-agent: 未运行（systemctl status beszel-agent 排查）"
fi
if systemctl is-active --quiet security-collector.service; then
  info "  security-collector: 运行中"
else
  warn "  security-collector: 未运行（journalctl -u security-collector 排查）"
fi

info "完成。agent 侧安装就绪。"
info "去中心面板的 beszel tab 确认这台机器出现在机器列表里，并能看到安全事件。"
rm -f /tmp/beszel-install-agent.sh

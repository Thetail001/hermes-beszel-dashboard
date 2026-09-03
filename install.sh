#!/usr/bin/env bash
# hermes-beszel-dashboard — 中心侧（宿主机）安装脚本
#
# 在运行 hermes 的控制机上完成：
#   1. 安装 beszel hub（复用官方脚本，PocketBase 内核，监听 127.0.0.1:8090）
#   2. 非交互创建 beszel superuser（beszel superuser upsert，无需浏览器注册）
#   3. 下载本项目的 GitHub Release 产物（预构建的插件 dist），部署插件到 ~/.hermes/plugins/
#   4. 白名单 + GeoIP 库 + 配置 + 重启 dashboard + 冒烟测试
#
# 用法（一条命令）：
#   curl -fsSL https://raw.githubusercontent.com/<owner>/<repo>/master/install.sh | bash
#
# 前置：hermes 已安装（hermes 命令可用）。未安装则本脚本只提示不代装。
#
# 环境变量（可选，不设则交互式询问）：
#   BESZEL_SUPERUSER_EMAIL   beszel superuser 邮箱（脚本会自动建号）
#   BESZEL_SUPERUSER_PASS    beszel superuser 密码
#   BESZEL_RELEASE_TAG       GitHub Release tag（默认 v0.2.1）
set -euo pipefail

OUR_REPO="${OUR_REPO:-Thetail001/hermes-beszel-dashboard}"
OUR_BRANCH="${OUR_BRANCH:-master}"
RELEASE_TAG="${BESZEL_RELEASE_TAG:-v0.2.1}"
BESZEL_HUB_PORT="${BESZEL_HUB_PORT:-8090}"

info() { printf '\033[32m[+] %s\033[0m\n' "$*"; }
warn() { printf '\033[33m[!] %s\033[0m\n' "$*"; }
fail() { printf '\033[31m[x] %s\033[0m\n' "$*" >&2; exit 1; }

# ---------------------------------------------------------------- 前置检查
info "检查前置依赖..."
command -v hermes >/dev/null 2>&1 || fail "未检测到 hermes 命令。请先安装 Hermes Agent：curl -fsSL https://hermes-agent.nousresearch.com/install.sh | bash"
command -v curl >/dev/null 2>&1 || fail "需要 curl"
[ "$(id -u)" = "0" ] || fail "需要 root 权限"

# ---------------------------------------------------------------- 1. beszel hub
if command -v beszel >/dev/null 2>&1 || [ -f /usr/local/bin/beszel ]; then
  info "检测到 beszel 已安装，跳过 hub 安装"
else
  info "安装 beszel hub（复用官方脚本）..."
  if curl -fsSL --max-time 30 "https://get.beszel.dev/hub" -o /tmp/beszel-install-hub.sh 2>/dev/null \
     && head -c 20 /tmp/beszel-install-hub.sh | grep -q "sh"; then
    chmod +x /tmp/beszel-install-hub.sh
    /tmp/beszel-install-hub.sh -p "$BESZEL_HUB_PORT" || fail "beszel hub 安装失败"
  else
    # GitHub raw fallback
    curl -fsSL --max-time 30 \
      "https://raw.githubusercontent.com/henrygd/beszel/main/supplemental/scripts/install-hub.sh" \
      -o /tmp/beszel-install-hub.sh || fail "下载官方 hub 脚本失败"
    chmod +x /tmp/beszel-install-hub.sh
    /tmp/beszel-install-hub.sh -p "$BESZEL_HUB_PORT" || fail "beszel hub 安装失败"
  fi
  rm -f /tmp/beszel-install-hub.sh
fi

# 确认 hub 在跑
sleep 2
if ! curl -s --max-time 5 "http://127.0.0.1:$BESZEL_HUB_PORT/api/health" >/dev/null 2>&1; then
  warn "hub 健康检查未通过（可能刚启动，稍后可用），继续..."
fi

# ---------------------------------------------------------------- 2. superuser
info "创建 beszel superuser（非交互）..."
BESZEL_DATA_DIR="${BESZEL_DATA_DIR:-/opt/beszel}"
[ -z "${BESZEL_SUPERUSER_EMAIL:-}" ] && { printf 'beszel superuser 邮箱（如 admin@example.com）: '; read -r BESZEL_SUPERUSER_EMAIL; }
[ -z "${BESZEL_SUPERUSER_PASS:-}" ] && { printf 'beszel superuser 密码: '; read -r BESZEL_SUPERUSER_PASS; }
[ -z "$BESZEL_SUPERUSER_EMAIL" ] || [ -z "$BESZEL_SUPERUSER_PASS" ] && fail "superuser 邮箱/密码不能为空"

# beszel superuser upsert <email> <password>（--dir 指向数据目录）
if [ -f /usr/local/bin/beszel ]; then
  BESZEL_BIN="/usr/local/bin/beszel"
else
  BESZEL_BIN="$(command -v beszel)"
fi
"$BESZEL_BIN" superuser upsert "$BESZEL_SUPERUSER_EMAIL" "$BESZEL_SUPERUSER_PASS" --dir "$BESZEL_DATA_DIR" \
  || fail "beszel superuser upsert 失败"
info "  superuser 就绪: $BESZEL_SUPERUSER_EMAIL"

# ---------------------------------------------------------------- 3. 插件部署
info "下载本项目 Release 产物并部署插件..."
PLUGIN_DIR="$HOME/.hermes/plugins/beszel"
mkdir -p "$PLUGIN_DIR"

# 从 GitHub Release 下载预构建的插件包（dist 含前端构建产物，不在 git 里）
RELEASE_URL="https://github.com/$OUR_REPO/releases/download/$RELEASE_TAG/beszel-dashboard-plugin.tar.gz"
curl -fsSL --max-time 120 "$RELEASE_URL" -o /tmp/beszel-dashboard-plugin.tar.gz \
  || fail "下载 release 产物失败：$RELEASE_URL（确认 release $RELEASE_TAG 已发布且仓库公开）"
tar -xzf /tmp/beszel-dashboard-plugin.tar.gz -C "$PLUGIN_DIR" \
  || fail "解压插件失败"
rm -f /tmp/beszel-dashboard-plugin.tar.gz
info "  插件已部署到 $PLUGIN_DIR"

# ---------------------------------------------------------------- 4. 白名单
info "白名单插件..."
python3 - "beszel" << 'PY'
import os
import sys
import yaml

plugin_name = sys.argv[1]
p = os.path.expanduser("~/.hermes/config.yaml")
with open(p) as f:
    c = yaml.safe_load(f) or {}
en = c.setdefault("plugins", {}).setdefault("enabled", [])
if plugin_name not in en:
    en.append(plugin_name)
    with open(p, "w") as f:
        yaml.dump(c, f, allow_unicode=True, sort_keys=False)
    print("config: plugins.enabled += " + plugin_name)
else:
    print("config: plugins.enabled already contains " + plugin_name)
PY

# ---------------------------------------------------------------- 5. 凭据文件
info "写入 beszel 凭据文件（plugin_api.py 读取）..."
CRED_FILE="${BESZEL_CRED_FILE:-$PLUGIN_DIR/dashboard-credentials.txt}"
mkdir -p "$(dirname "$CRED_FILE")"
# 格式：<email> / <password>（plugin_api.py 的正则 <email> / (\S+) 匹配）
printf '%s / %s\n' "$BESZEL_SUPERUSER_EMAIL" "$BESZEL_SUPERUSER_PASS" > "$CRED_FILE"
chmod 600 "$CRED_FILE"
info "  凭据文件: $CRED_FILE"

# ---------------------------------------------------------------- 6. GeoIP 库
info "下载 GeoIP 库（dbip-city-lite，中心侧 GeoIP 富化用）..."
GEOIP_DB="${GEOIP_DB:-$PLUGIN_DIR/dbip-city-lite.mmdb}"
if [ -f "$GEOIP_DB" ]; then
  info "  GeoIP 库已存在，跳过"
else
  mkdir -p "$(dirname "$GEOIP_DB")"
  GEOIP_MONTH="$(date +%Y-%m)"
  curl -fL --max-time 180 "https://download.db-ip.com/free/dbip-city-lite-$GEOIP_MONTH.mmdb.gz" \
    -o /tmp/dbip.mmdb.gz || warn "GeoIP 下载失败（可稍后手动下载）"
  if [ -f /tmp/dbip.mmdb.gz ]; then
    gunzip -c /tmp/dbip.mmdb.gz > "$GEOIP_DB" 2>/dev/null || warn "GeoIP 解压失败"
    rm -f /tmp/dbip.mmdb.gz
    [ -f "$GEOIP_DB" ] && info "  GeoIP 库就绪" || warn "  GeoIP 库未就绪"
  fi
fi

# ---------------------------------------------------------------- 7. 配置环境变量
info "配置 dashboard 环境变量（BESZEL_SUPERUSER_EMAIL）..."
# 提示：plugin_api.py 通过 BESZEL_SUPERUSER_EMAIL 环境变量读取 superuser 身份
# dashboard 是 systemd user unit，环境变量要写进 unit 的 [Service] 段
cat <<EOF

⚠  手动一步：把下面这行加进 hermes-dashboard 的 systemd user unit 的 [Service] 段：

  Environment="BESZEL_SUPERUSER_EMAIL=$BESZEL_SUPERUSER_EMAIL"
  Environment="BESZEL_CRED_FILE=$CRED_FILE"

然后重载：
  systemctl --user daemon-reload && systemctl --user restart hermes-dashboard

（unit 文件通常在 ~/.config/systemd/user/hermes-dashboard.service）
EOF

# ---------------------------------------------------------------- 8. 重启 + 冒烟
info "重启 dashboard..."
if systemctl --user list-unit-files 2>/dev/null | grep -q "^hermes-dashboard"; then
  systemctl --user daemon-reload
  systemctl --user restart hermes-dashboard
else
  pkill -f "hermes_cli.main dashboard" || true
  sleep 2
  setsid python -m hermes_cli.main dashboard --no-open >> /var/log/hermes-dashboard.log 2>&1 < /dev/null &
  sleep 5
fi

info "中心侧安装完成。"
info "下一步："
info "  1. 打开 beszel webui（http://127.0.0.1:8090）用 $BESZEL_SUPERUSER_EMAIL 登录"
info "  2. 去 /settings/tokens 生成 universal token（或添加系统复制公钥+token）"
info "  3. 在被监控机器上跑 agent 侧脚本：agent/install-agent.sh"

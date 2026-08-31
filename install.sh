#!/usr/bin/env bash
# hermes-beszel-dashboard 一键安装：同步插件到 ~/.hermes/plugins/ + 白名单 + 重启
set -euo pipefail
PLUGIN_NAME=beszel
DEST="$HOME/.hermes/plugins/$PLUGIN_NAME/dashboard"

mkdir -p "$DEST"
cp -r plugin/dashboard/dist "$DEST/"
cp plugin/dashboard/manifest.json "$DEST/"
cp plugin/dashboard/plugin_api.py "$DEST/"

# 白名单
python3 - << 'PY'
import yaml, os
p = os.path.expanduser("~/.hermes/config.yaml")
c = yaml.safe_load(open(p))
en = c.setdefault("plugins", {}).setdefault("enabled", [])
if "beszel" not in en:
    en.append("beszel")
    yaml.dump(c, open(p, "w"), allow_unicode=True, sort_keys=False)
    print("config: plugins.enabled + beszel")
PY

# 重启 dashboard
pkill -f "hermes_cli.main dashboard" || true
sleep 2
setsid python -m hermes_cli.main dashboard --no-open >> /var/log/hermes-dashboard.log 2>&1 < /dev/null &
sleep 5
echo "✓ 安装完成，dashboard 已重启"

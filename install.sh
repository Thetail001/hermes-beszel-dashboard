#!/usr/bin/env bash
# hermes-beszel-dashboard one-shot install:
#   sync the plugin into ~/.hermes/plugins/, whitelist it, restart the dashboard.
set -euo pipefail
PLUGIN_NAME=beszel
DEST="$HOME/.hermes/plugins/$PLUGIN_NAME/dashboard"

mkdir -p "$DEST"
cp -r plugin/dashboard/dist "$DEST/"
cp plugin/dashboard/manifest.json "$DEST/"
cp plugin/dashboard/plugin_api.py "$DEST/"

# Whitelist the plugin in hermes config.yaml
python3 - << 'PY'
import yaml, os
p = os.path.expanduser("~/.hermes/config.yaml")
c = yaml.safe_load(open(p))
en = c.setdefault("plugins", {}).setdefault("enabled", [])
if PLUGIN_NAME not in en:
    en.append(PLUGIN_NAME)
    yaml.dump(c, open(p, "w"), allow_unicode=True, sort_keys=False)
    print("config: plugins.enabled +" + PLUGIN_NAME)
PY

# Restart the dashboard so it picks up the plugin.
# Prefer the systemd user unit; fall back to killing the process and letting
# whatever supervises it (systemd/Restart=on-failure) bring it back up.
if systemctl --user list-unit-files 2>/dev/null | grep -q "^hermes-dashboard"; then
  systemctl --user restart hermes-dashboard
else
  pkill -f "hermes_cli.main dashboard" || true
  sleep 2
  setsid python -m hermes_cli.main dashboard --no-open >> /var/log/hermes-dashboard.log 2>&1 < /dev/null &
  sleep 5
fi
echo "✓ installed; dashboard restarted"

#!/usr/bin/env bash
# hermes-beszel-dashboard one-shot install:
#   sync the plugin into ~/.hermes/plugins/, whitelist it, restart the dashboard.
set -euo pipefail
PLUGIN_NAME=beszel
DEST="$HOME/.hermes/plugins/$PLUGIN_NAME/dashboard"

# --- fail-fast: the beszel iframe renders BLANK if the plugin can't resolve
#     the hub superuser credentials. Surface that here instead of in the browser.
if [[ -z "${BESZEL_SUPERUSER_EMAIL:-}" ]]; then
  echo "⚠  BESZEL_SUPERUSER_EMAIL is not set." >&2
  echo "   The plugin authenticates to the beszel hub with this identity; without it" >&2
  echo "   the dashboard tab will be blank. Set it on the dashboard process, e.g. in" >&2
  echo "   the systemd user unit:" >&2
  echo "     Environment=\"BESZEL_SUPERUSER_EMAIL=you@example.com\"" >&2
  echo "   (and BESZEL_CRED_FILE if the credentials file lives elsewhere)." >&2
fi
if [[ -z "${BESZEL_CRED_FILE:-}" ]] && [[ ! -f /root/hermes-workspace/reports/dashboard-credentials.txt ]]; then
  echo "⚠  default credential file not found — set BESZEL_CRED_FILE." >&2
fi

mkdir -p "$DEST"
cp -r plugin/dashboard/dist "$DEST/"
cp plugin/dashboard/manifest.json "$DEST/"
cp plugin/dashboard/plugin_api.py "$DEST/"

# Whitelist the plugin in hermes config.yaml.
# Pass PLUGIN_NAME as argv so the single-quoted heredoc stays literal (no shell
# interpolation mangles the YAML), yet the name still reaches Python.
python3 - "$PLUGIN_NAME" << 'PY'
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

# Restart the dashboard so it picks up the plugin.
if systemctl --user list-unit-files 2>/dev/null | grep -q "^hermes-dashboard"; then
  systemctl --user restart hermes-dashboard
else
  pkill -f "hermes_cli.main dashboard" || true
  sleep 2
  setsid python -m hermes_cli.main dashboard --no-open >> /var/log/hermes-dashboard.log 2>&1 < /dev/null &
  sleep 5
fi
echo "✓ installed; dashboard restarted"
echo "  next: run tests/smoke.sh <dashboard-url> <username> <password> <agent-token>"

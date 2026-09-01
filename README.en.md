# hermes-beszel-dashboard

> **A [Hermes Agent](https://github.com/NousResearch/hermes-agent) dashboard plugin** that drops the whole [beszel](https://github.com/henrygd/beszel) panel (lightweight server monitoring) into Hermes' dashboard, and layers a multi-machine **Security Operations Room** on top: collection, aggregation, geolocation and an attack map for SSH brute-force / fail2ban / nginx scan events. 中文文档：[README.md](README.md)

**This is not a standalone app** — it exists as a plugin and runs alongside hermes:

- Front-end: beszel's full web panel, mounted as an iframe under the beszel tab of the hermes dashboard
- Back-end: `plugin_api.py` (FastAPI router) under `/api/plugins/beszel/`, doing PocketBase reverse-proxying + the security-events API
- Install: one command on the centre side into `~/.hermes/plugins/beszel/`, one command on each agent

No fork of beszel — the front-end tracks upstream via a "patch replay" model; the back-end mounts as a plugin API, so beszel's own features (system metrics, agent channel, machine management) are kept untouched.

```
VPSes ():  beszel-agent (metrics)  + security-collector (security events)
                          │ ws                │ https POST /security/ingest
                          ▼                   ▼
Control host:      beszel hub (PocketBase)   token auth + idempotent UPSERT + GeoIP
                          │                    │
                          ▼                    ▼
              plugin_api.py aggregation ──► single UI in the hermes dashboard
```

## Features

**beszel core (unmodified)**
- Multi-machine CPU / memory / disk / network / temperature monitoring with live SSE
- Full beszel hub + agent management

**Security Operations Room (this project)**
- Three log sources: `auth.log` (SSH brute force, with username extraction), `fail2ban.log` (ban/unban), nginx access log (scans/attack paths)
- Multi-machine architecture: agents are stateless pushers (60s window merging to survive floods); the centre is the single writer. `event_id` idempotent UPSERT; a jsonl disk buffer with automatic retry covers outages
- Centre-side GeoIP enrichment (dbip-city-lite, monthly auto-update + hot reload); the attack map renders real coordinates
- Attacker cards (aggregated per IP), per-IP timeline, live event stream, global filters (`ip:` `type:` `country:` syntax), CSV/JSON export, 90-day auto rotation
- Security: bearer token reuses beszel's universal token (managed in the web UI at `/settings/tokens`), machine_id checked against beszel's systems table, strict input validation (type whitelist / public IP / time window / count cap / batch cap), fully parameterized SQL

## Repository layout

```
├── install.sh                  # centre-side install script (one command)
├── agent/
│   ├── install-agent.sh        # agent-side install script (one command)
│   ├── security_collector.py   # security probe: tails 3 logs, push or local-write mode
│   └── security-collector.service  # example systemd unit
├── scripts/
│   └── release.sh              # build front-end dist → package → create GitHub Release
├── patches/                    # front-end patches against beszel (versioned, replayable)
│   ├── 001..007-*.patch        #   reverse-proxy baseURL, strip beszel login, tab wiring…
│   ├── 007-security-ui-enhancements.tsx   # full front-end snapshot after patch 007
│   ├── 008-attack-map.patch    #   attack map + machine list via security/machines
│   ├── 008-attack-map.tsx      #   full front-end snapshot after 008 (base for the next patch)
│   ├── 009-install-command.patch  # copy-install-command now exports this project's installer (Linux/brew/freebsd)
│   ├── 010-machine-selector.patch # machine selector moved from the Attackers card to the top header (global)
│   └── 010-machine-selector.tsx    # full front-end snapshot after 010 (current base)
├── plugin/
│   ├── manifest.json           # hermes plugin manifest
│   └── dashboard/
│       ├── dist/               # beszel vite build output (assets partially gitignored, shipped via release)
│       └── plugin_api.py       # PocketBase reverse proxy + /security/* API (ingest/machines/events/…)
├── hub/                        # control-host deployment refs (beszel hub/agent units + nginx example)
└── tests/
    └── smoke.sh                # post-deploy smoke test (login→machines→ingest→no-token rejection)
```

## Usage

Installation is two steps: the centre host first, then each monitored machine.

### Centre side (the host running hermes + the beszel hub)

**Prerequisite**: hermes installed (`hermes` on PATH). If not, install Hermes Agent first:

```bash
curl -fsSL https://hermes-agent.nousresearch.com/install.sh | bash
```

**One-command install**:

```bash
curl -fsSL https://raw.githubusercontent.com/<owner>/<repo>/master/install.sh | bash
```

The script handles:

1. beszel hub install (reuses the official script; listens on `127.0.0.1:8090`, no public exposure — panel traffic goes through the plugin's reverse proxy)
2. Non-interactive beszel superuser creation (`beszel superuser upsert`, **no browser registration**; prompts for email/password)
3. Downloads the prebuilt plugin dist from GitHub Release (`dist/assets`/`index.html` are gitignored build artifacts shipped via release)
4. Plugin whitelist + beszel credentials file + GeoIP DB (dbip-city-lite)
5. Dashboard restart

The script ends with **one manual step**: add `BESZEL_SUPERUSER_EMAIL` to the hermes-dashboard systemd user unit (`~/.config/systemd/user/hermes-dashboard.service`, `[Service]` section). plugin_api.py needs it to log into the beszel hub — missing it blanks the tab.

**Another critical manual step: nginx reverse proxy** (install.sh does not handle it; without it remote agents can't reach the centre). See [`hub/nginx-beszel.conf.example`](hub/nginx-beszel.conf.example):

- Session cookie gate: requests without a `hermes_session` cookie get 302 → `/login`
- **Allow `/api/beszel/agent-connect`** → proxy to beszel hub `127.0.0.1:8090` (WebSocket Upgrade; agent authenticates with X-Token)
- **Allow `/api/plugins/beszel/security/ingest`** → proxy to hermes `127.0.0.1:9119` (collector authenticates with Bearer token)
- Both allowances fail closed: invalid token → 401, never an open pass-through

Then log into the beszel web UI (`http://127.0.0.1:8090`), generate a **universal token** at `/settings/tokens` (or add a system and copy its public key + token) for the agent side.

### Agent side (every monitored VPS)

First add the machine in the centre's beszel web UI to get its public key + token:

1. "Add system" → fill in the **name** (display name) + **Host/IP** (the machine's public IP; port defaults to 45876, usually leave it)
2. Copy the install command (the public key + token are included automatically)
3. **Click the bottom "Add" button to save** — this step is mandatory: the system record and token are only effective once written into the hub database

> ⚠️ **"Copy command" ≠ "save"**: the copy button and the "Add" button are two separate actions in the dialog. Copying the command without clicking "Add" leaves the token unregistered, and the agent will keep failing with 401. Make sure the machine shows up in the list before you run the install on the target.

**One-command install** (using the public key + token copied above):

```bash
curl -fsSL https://raw.githubusercontent.com/<owner>/<repo>/master/agent/install-agent.sh \
  | bash -s -- -k "<public key>" -t "<token>" -url "https://<centre-host>" \
      -center "https://<centre-host>/api/plugins/beszel/security/ingest"
```

The script handles:

1. beszel agent install (reuses the official script, with a GitHub-raw fallback when Cloudflare blocks `get.beszel.dev`; `--china-mirrors` uses a domestic mirror)
2. security-collector install (security-event collection), token reuses beszel's (universal or per-system — the centre accepts both)
3. Writes the systemd unit + enables both services + self-check

**Three log sources** (default paths; a missing log simply disables that source):

| Log | Default path | Provides |
|---|---|---|
| fail2ban | `/var/log/fail2ban.log` | ban/unban events |
| nginx | `/var/log/nginx/access.log` | scan/attack paths (needs fail2ban nginx jails) |
| sshd | `/var/log/auth.log` | brute-force attempts (with username extraction) |

**Verify**:

```bash
systemctl status security-collector
journalctl -u security-collector -f   # expect: [collector] starting, mode=push
```

When the centre is unreachable, events land in `security-push-buffer.jsonl` and are re-sent automatically every `--flush-interval` until they stick — no manual intervention after an outage.

### Auth & tokens

Ingest auth reuses beszel's token system — **no separate security-event token to mint**:

- **per-system token** (UUID, generated by "Add System", stored in the `fingerprints` table): bound to one machine; the centre resolves the machine name from the token (strongest spoof protection)
- **universal token** (generated at `/settings/tokens`, stored in `universal_tokens`): shared by many machines; identity is self-reported + checked against the `systems` table

Both are accepted. To add a machine: "Add System" and copy key+token, or just reuse the universal token (auto-registers).

### Using the panel

- hermes dashboard → beszel tab: system monitoring (beszel core) + the Security Operations Room
- Filter syntax: `ip:1.2.3.4`, `type:auth_fail`, `country:NL` — combinable; Attackers / Active Bans support search, filter, sort, pagination, and click-through IP details
- Event types: `ban` / `unban` / `scan` / `attack` / `auth_fail` / `auth_success`

## Development: build + release

Normal installs do **not** need a front-end build (prebuilt artifacts are on GitHub Release). Only when developing/changing the front-end:

```bash
# Prepare beszel front-end source + replay patches
git clone https://github.com/henrygd/beszel /tmp/beszel
cd /tmp/beszel/internal/site
for p in 001 002 003 004 005 006 007 008; do
  git apply /path/to/hermes-beszel-dashboard/patches/$p-*.patch
done
npm install && npm run build

# Release a new version (build dist → package → create GitHub Release)
scripts/release.sh v0.1.0-beta "release notes"
```

> Patches target beszel master as of 2026-08. Major upstream releases may need patch adaptations — the `patches/NNN-*.tsx` snapshots are the diff bases.

## License

- This project: MIT (see [LICENSE](LICENSE))
- [beszel](https://github.com/henrygd/beszel): MIT (© henrygd) — see [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)
- Inter typeface bundled with the front-end: SIL Open Font License

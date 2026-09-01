# hermes-beszel-dashboard

> Drops the whole [beszel](https://github.com/henrygd/beszel) panel (lightweight server monitoring) into a [Hermes Agent](https://github.com/NousResearch/hermes-agent) dashboard plugin, and layers a multi-machine **Security Operations Room** on top: collection, aggregation, geolocation and an attack map for SSH brute-force / fail2ban / nginx scan events. 中文文档：[README.md](README.md)

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
- Security: bearer tokens (hmac constant-time compare; machine_id derived from the token, not client input), strict input validation (type whitelist / public IP / time window / count cap / batch cap), fully parameterized SQL

## Repository layout

```
├── install.sh                  # deploy plugin to ~/.hermes/plugins/ + whitelist + restart
├── patches/                    # front-end patches against beszel (versioned, replayable)
│   ├── 001..007-*.patch        #   reverse-proxy baseURL, strip beszel login, tab wiring…
│   ├── 007-security-ui-enhancements.tsx   # full front-end snapshot after patch 007
│   ├── 008-attack-map.patch    #   attack map + machine list via security/machines
│   └── 008-attack-map.tsx      #   current full front-end snapshot (base for the next patch)
├── plugin/
│   ├── manifest.json           # hermes plugin manifest
│   └── dashboard/
│       ├── dist/               # beszel vite build output (assets partially gitignored)
│       └── plugin_api.py       # PocketBase reverse proxy + /security/* API (ingest/machines/events/…)
├── agent/
│   ├── security_collector.py   # security probe: tails 3 logs, push or local-write mode
│   └── security-collector.service  # example systemd unit
├── hub/                        # control-host deployment refs (beszel hub/agent units + nginx example)
```

## Usage

### Centre side (the host running hermes + the beszel hub)

#### 1. Install the beszel hub

Install the hub per the [official beszel docs](https://beszel.dev) (PocketBase core; listening on `127.0.0.1:8090` is enough — panel traffic goes through the plugin's reverse proxy). See `hub/` for reference systemd units.

#### 2. Build the front-end

Requires node/npm:

```bash
git clone https://github.com/henrygd/beszel /tmp/beszel
cd /tmp/beszel/internal/site
# Apply patches in order: 001 → 008 (order matters)
for p in 001 002 003 004 005 006 007 008; do
  git apply /path/to/hermes-beszel-dashboard/patches/$p-*.patch
done
# Patch 008's base is the security.tsx from after 007: after applying 007,
# copy patches/007-security-ui-enhancements.tsx to src/components/routes/security.tsx,
# then apply 008, then also copy 008-attack-map.tsx (keeps workdir == snapshot)
npm install && npm run build
cp -r dist/* /path/to/hermes-beszel-dashboard/plugin/dashboard/dist/
```

> Patches target beszel master as of 2026-08 (v0.14.x). Major upstream releases may need patch adaptations — the snapshot files are the diff bases.

#### 3. Deploy the plugin + configure

```bash
cd hermes-beszel-dashboard
./install.sh          # copies the plugin into ~/.hermes/plugins/beszel/ + whitelist + dashboard restart
```

Centre-side config files (all under `~/.hermes/plugins/beszel/`, chmod 0600, **never committed**):

| File | Format | Purpose |
|---|---|---|
| `security_tokens.json` | `{"tokens": {"<machine_id>": "<random token>"}}` | Per-agent ingest credentials. Generate tokens with `openssl rand -hex 32`; **machine_id must equal the agent's `SEC_MACHINE_ID` (hostname by default)** |
| `machine_locations.json` | `{"<machine_id or name>": {"lat": .., "lon": .., "city": .., "country": ..}}` | Manual coordinate overrides (fallback when GeoIP misjudges an IP range), optional |

Environment variables (systemd user unit or `.env`):

| Variable | Default | Purpose |
|---|---|---|
| `BESZEL_SUPERUSER_EMAIL` | `admin@example.com` | PB superuser identity (`_read_password()` reads the password from the cred file) |
| `BESZEL_CRED_FILE` | `/root/hermes-workspace/reports/dashboard-credentials.txt` | Credentials file path (line format: `<email> / <password>`) |

#### 4. Download the GeoIP database

The centre translates IPs to coordinates; agents never need the mmdb:

```bash
mkdir -p /root/hermes-workspace/reports
curl -Lo /root/hermes-workspace/dbip-city-lite.mmdb.gz \
  https://download.db-ip.com/free/dbip-city-lite-$(date +%Y-%m).mmdb.gz
gunzip /root/hermes-workspace/dbip-city-lite.mmdb.gz
# A thread inside the centre process checks for a newer build monthly — no cron needed
```

#### 5. Verify

```bash
# Push one test event from the centre (replace <token> with a value from security_tokens.json)
curl -s -X POST http://127.0.0.1:9119/api/plugins/beszel/security/ingest \
  -H "Content-Type: application/json" -H "Authorization: Bearer <token>" \
  -d '{"events":[{"event_id":"smoke:1","event_type":"auth_fail","src_ip":"8.8.8.8",
       "ts":"'"$(date -u +%Y-%m-%dT%H:%M:%S+00:00)"'","count":1,"raw_excerpt":"smoke test"}]}'
# Expect: {"ok":true,"accepted":1,...}; open the beszel tab in the dashboard to see the room
```

### Agent side (every monitored VPS)

#### 1. Prerequisites

Three log sources (default paths below; a missing log simply disables that source):

| Log | Default path | Provides |
|---|---|---|
| fail2ban | `/var/log/fail2ban.log` | ban/unban events |
| nginx | `/var/log/nginx/access.log` | scan/attack paths (needs your fail2ban nginx jails) |
| sshd | `/var/log/auth.log` | brute-force attempts (with username extraction) |

#### 2. Deploy

```bash
mkdir -p /opt/beszel-sec-agent
cp agent/security_collector.py /opt/beszel-sec-agent/
echo "<this machine's token from the centre's security_tokens.json>" > /opt/beszel-sec-agent/agent_token.txt
chmod 600 /opt/beszel-sec-agent/agent_token.txt

# Optional: operator-owned IPs/ranges (events from these are never recorded as attacks)
cat > /opt/beszel-sec-agent/trusted-sources.json << 'EOF'
{"trusted_sources": ["203.0.113.7"]}
EOF

cp agent/security-collector.service /etc/systemd/system/
# Edit the unit: point --center-url at your centre (
#   https://your-centre-host/api/plugins/beszel/security/ingest
# ) and set SEC_MACHINE_ID / SEC_TRUSTED_SOURCES_FILE as needed
systemctl daemon-reload && systemctl enable --now security-collector
```

Key options:

| Option / env | Default | Purpose |
|---|---|---|
| `--push` | off | Without it the collector writes a local SQLite DB (single-host mode) |
| `--center-url` | — | The centre's ingest URL |
| `--token-file` | — | Bearer token file (0600); preferred over `--token` |
| `--flush-interval` | 30 | Push interval (seconds) |
| `SEC_MACHINE_ID` | hostname | Machine identity; must match a key in the centre's token file |
| `SEC_TRUSTED_SOURCES_FILE` | `<repo>../security-trusted-sources.json` | Trusted-sources list path |

#### 3. Verify

```bash
systemctl status security-collector
journalctl -u security-collector -f     # expect: [collector] starting, mode=push
```

When the centre is unreachable, events land in `security-push-buffer.jsonl` and are re-sent automatically every `--flush-interval` until they stick — no manual intervention after an outage.

### Using the panel

- hermes dashboard → beszel tab: system monitoring (beszel core) + the Security Operations Room
- Filter syntax: `ip:1.2.3.4`, `type:auth_fail`, `country:NL` — combinable
- Event types: `ban` / `unban` / `scan` / `attack` / `auth_fail` / `auth_success`

## Upstream upgrades

When beszel releases a new version: re-pull upstream → replay `patches/` in order (each `patches/NNN-*.tsx` snapshot is the diff base) → build → refresh `plugin/dashboard/dist/`.

## License

- This project: MIT (see [LICENSE](LICENSE))
- [beszel](https://github.com/henrygd/beszel): MIT (© henrygd) — see [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)
- Inter typeface bundled with the front-end: SIL Open Font License

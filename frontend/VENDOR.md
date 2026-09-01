# Vendored: beszel frontend

## Upstream

- **Repository:** https://github.com/henrygd/beszel
- **Vendored commit:** `b38fb7d`
- **Upstream path:** `internal/site/`
- **Vendored as:** `frontend/` (the site root)

## Why vendored, not forked

This repository is a **Hermes dashboard plugin**, not a beszel fork. The beszel
frontend is one vendored component of the plugin — our real value (the Security
panel, the agent probe, the plugin backend, the deploy scripts) is independent
of beszel. Forking would invert that: it would make this repo a beszel fork with
some plugin files bolted on.

## Updating upstream

1. Fetch upstream and check out the target commit.
2. Diff upstream `internal/site/` against `frontend/` to review what changed.
3. Merge upstream changes into `frontend/`, preserving our modifications.
   Our changes are the commits sitting on top of the "vendor beszel frontend"
   baseline commit, so `git log frontend/` shows exactly what is ours.

## Our modifications

Everything after the baseline vendor commit is ours. Key touchpoints:

- `src/components/routes/security.tsx` — the Security panel (attack map,
  attackers list, IP timeline, active bans)
- `public/countries-50m.json` — world map TopoJSON for the attack map
- `index.html`, `src/main.tsx`, `src/lib/api.ts` — PocketBase reverse-proxy
  base URL, auto-login, history trap, token renewal
- `src/components/install-dropdowns.tsx`, `add-system.tsx`,
  `routes/settings/tokens-fingerprints.tsx` — install-command export
- `package.json` / `package-lock.json` — added `d3-geo`, `topojson-client`
  (and their `@types`) for the attack map
- `src/locales/**/*.po` — lingui-extracted strings for the new UI

Build: `cd frontend && npm install && npm run build`
(`lingui extract && lingui compile && vite build`; the `src/locales/*/*.ts`
compile output is gitignored.)

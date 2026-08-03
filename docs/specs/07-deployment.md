# Spec 07 — One-Click Deployment

**Status:** 📋 · **Depends on:** 02 (exec), 05 (SFTP for .env/nginx), 01 · **Spec owner:** core

## 1. Overview

Paste a GitHub repo, fill one form, and Oars deploys it to the server the
way a human would: clone → install → build → PM2 → nginx → certbot — six
steps, each with live output, each failing loudly with its own error.

## 2. Goals / non-goals

**Goals**
- App model: repo, branch, stack (Node/React/Next/static), commands, env vars, domains, SSL.
- One-click deploy with a visible step pipeline; re-deploy (pull + rebuild + restart).
- Node version installation on demand; bulk `.env` paste; per-app deploy history.
- Private repos via SSH deploy key (generated in-app, spec 08).

**Non-goals**
- No Docker builds, no Python/PHP/Go (v1), no rollbacks (v1: re-deploy previous commit), no preview environments, no CI triggers.

## 3. User stories

- I paste `github.com/you/storefront.git`, pick Next.js, paste my `.env`, add a domain, toggle SSL, hit Create — and watch six steps go green.
- A build fails; the failing step's output is right there and I hand it to the AI terminal.
- Two weeks later I hit "Update" and it pulls main, rebuilds, restarts PM2.

## 4. UI/UX

### 4.1 Add Application form
- **Basic:** app name · environment (Development/Staging/Production) · folder (default `/home/<user>/<name>`) · repo transport (HTTPS/SSH) · repo URL · branch (default main).
- **Runtime:** Node.js version select (18/20/22; "not installed — Oars installs it" badge) · app type (Node.js / React / Next.js / Static build folder) · install/build/start commands (auto-filled from type, editable) · build folder (Next.js output).
- **Environment:** individual key/value rows **or** bulk `.env` paste (comments ignored, quotes preserved).
- **Domains:** one or more; SSL toggle (certbot; auto-covers `www.`); note: A record must point at the server first; inline DNS hint.
- Create → transitions to the deploy view.

### 4.3 Deploy view
- Step rail: Clone repository / Install dependencies / Build application / Start with PM2 / Configure Nginx / Issue SSL certificate.
- Each step: pending (gray) → running (spinner + live output) → success (green check, collapsed output) → failed (red, output expanded).
- Final state: "https://storefront.dev · Live" card + Update (re-deploy) and View Logs buttons.
- Cancellation: per-step cancel (kills the current command's channel); deploy marked cancelled.

### 4.4 App list
- Per server: "Applications" section in the File Manager toolbar → list of apps (name, status: live/degraded/never, url, last deploy) → open → deploy view with history (last 10 runs).

## 5. Bridge API

### `oars.deploy.apps.list` `{server_id}` → `{ok, apps}`
### `oars.deploy.apps.save` `{app}` → `{ok, app}` · `oars.deploy.apps.delete` `{server_id, app_id}` → `{ok}`
App model:
```json
{"id":"a1…","server_id":"s1…","name":"storefront","environment":"production",
 "folder":"/home/ubuntu/storefront",
 "repo":{"url":"git@github.com:you/storefront.git","transport":"ssh","branch":"main"},
 "runtime":{"node_version":"22.3.0","type":"next","install":"npm install",
            "build":"npm run build","start":"npm start","build_folder":".next"},
 "env_vars":{"DATABASE_URL":"postgres://…"},"domains":["storefront.dev"],"ssl":true,
 "app_port":3000,"created_at":…,"updated_at":…}
```
- `env_vars` values that match `*secret*|*password*|*key*` are stored in the Keychain (account `deploy:<app_id>:<var>`), not in the JSON.

### `oars.deploy.run` `{server_id, app_id}` → `{ok, run_id}`
### `oars.deploy.poll` `{run_id}` → steps + output deltas
```json
{"ok":true,"status":"running","steps":[
  {"id":"clone","label":"Clone repository","state":"success"},
  {"id":"install","label":"Install dependencies","state":"running","channel":7}]}
```
### `oars.deploy.cancel` `{run_id}` · `oars.deploy.history` `{server_id, app_id, limit}` → `{ok, runs}`

## 6. Zig core design

- `src/deploy.zig` — App model/store (`<data>/apps.json`), step planner, step command builder, run state machine (per-run: step index, per-step channel + stream, status; poll-driven from frontend, no extra threads — steps execute sequentially through the session worker's exec path).
- Step command builders (argv-safe; paths/domains validated):
  1. clone: `git clone <repo> <folder>` or `git -C <folder> pull --ff-only` when folder exists
  2. install: `<install>` in folder (default `npm ci || npm install`)
  3. build: `<build>` in folder (`NODE_OPTIONS=--max-old-space-size=4096` prefix for node builds)
  4. pm2: `pm2 start <start> --name <app>` or `pm2 restart <app>` when it exists
  5. nginx: write site config via SFTP (temp + rename), `nginx -t`, symlink to `sites-enabled`, `systemctl reload nginx`
  6. certbot: `certbot --nginx -d <d1> -d <d2> --non-interactive --agree-tos -m <user>@<host>` (v1 requires root/appropriate user; failure surfaced with guidance)
- Node install helper (step 1.5, implicit): detect missing version (`node -v`), then the **current documented NodeSource flow** (not the legacy pipe-to-bash form): `curl -fsSL https://deb.nodesource.com/setup_<major>.x -o nodesource_setup.sh` → `sudo -E bash nodesource_setup.sh` (or `bash nodesource_setup.sh` as root) → `sudo apt install -y nodejs` — approval-gated within the deploy flow (deploy already confirmed; the install is part of it — documented in the confirm text). See §13 for the citation and supported distro/version matrix.
- Secrets: env vars are written to `<folder>/.env` via SFTP before install/build (never echoed in step output; masked in logs).

## 7. Data model

- `<data>/apps.json`: apps (env_vars without secret values; secret values in Keychain).
- `<data>/deploy_runs.json`: run history (status, step results, timestamps, output trimmed to 200 KB/run, raw kept 30 days).

## 8. Security

- Deploying is inherently mutating → the Create/Update click is the approval; audit entry per run (command list).
- Private repos: generated deploy key (spec 08) shown once; never persisted as a secret (it's the user's to add to GitHub).
- Secrets never appear in step output or run history (masking pass on captured output: replace known secret values with `***`).

## 9. Performance

- Step output streams ride the poll budget; long builds stream for hours without buffering issues (channel stream capped, dropped-warning applies).
- History capped: 10 runs listed, 30 days retained.

## 10. Edge cases

- Repo already cloned → pull path (fast-forward only; non-FF → step fails with message + suggestion to reset).
- Build OOM → step fails showing the OOM line (NODE_OPTIONS hint applied by default).
- Domain without A record → certbot step fails with validation error; UI pre-checks DNS (A record lookup via `dig +short <domain>` on the server) before starting.
- nginx config collision (site already exists) → fail with existing-config diff shown.
- Server disconnected mid-deploy → run marked `interrupted`, steps resume from failure point on next run (idempotent commands).

## 11. Testing

- Unit: step planner (app type → command templates), path/domain validation, env masking.
- Integration (container with node+pm2+nginx): deploy a fixture Next.js app → verify site responds (curl), re-deploy after change, SSL skip path (no domain), failure injection (broken build) → verify step red + resume.
- Manual: bulk .env paste, node install path.

## 12. Acceptance criteria

- [ ] End-to-end deploy of a fixture app: clone→install→build→pm2→nginx (SSL skipped in test) with green steps.
- [ ] Re-deploy pulls and restarts correctly.
- [ ] Secret env vars never appear in output, history, or JSON.
- [ ] DNS pre-check prevents certbot failure for missing records.
- [ ] Interrupted deploys resume cleanly.

## 13. Research & References

- **PM2** — verified against PM2's official docs
  (`https://pm2.keymetrics.io/docs/usage/process-management/`):
  `pm2 start api.js` and `pm2 start "npm run start"` (starting shell
  commands is supported), `pm2 restart <name>`, `pm2 stop <name>`,
  `pm2 delete <name>`, `pm2 list`. "Start with PM2" = `pm2 start
  <start> --name <app>` is the documented form; re-deploy uses
  `pm2 restart <app>`.
- **nginx** — verified against nginx's official Beginner's Guide
  (`https://nginx.org/en/docs/beginners_guide.html`):
  - `nginx -s reload` — "checks the syntax validity of the new
    configuration file and tries to apply the configuration…
    Otherwise, the master process rolls back the changes and continues
    to work with the old configuration" — so a reload is safe after
    `nginx -t` (the documented config test, `nginx -t`, is also what
    the certbot nginx plugin uses for `configtest`).
  - The `sites-available` → `sites-enabled` symlink convention is the
    Debian/Ubuntu packaging layout (Debian wiki: Nginx page,
    `https://wiki.debian.org/Nginx`); nginx itself documents
    `include`-ing config directories and `server` blocks with
    `proxy_pass` to a local app port (Beginner's Guide "Setting Up a
    Simple Proxy Server") — which is how our site config serves the
    PM2 app (`proxy_pass http://127.0.0.1:<app_port>`).
  - Write-then-rename (temp + rename) for site configs is our standard
    atomic-write pattern (same as spec 08/05).
- **certbot** — verified against the official Certbot docs
  (`https://certbot.eff.org/docs/using.html`):
  - The nginx plugin is both an authenticator **and** installer
    (table "Plugins"): `certbot --nginx` automates obtaining and
    installing a certificate with Nginx, using the http-01 challenge
    on port 80 — this is why the spec requires port 80 reachable and
    the domain's A record pointing at the server.
  - Non-interactive automation flags: `-n/--non-interactive`,
    `--agree-tos`, `-m EMAIL` (documented under "Certbot
    command-line options"); multiple domains via repeated `-d`.
  - Certificates land in `/etc/letsencrypt/live/<cert-name>/`
    (`fullchain.pem`, `privkey.pem` 0600); automatic renewal runs
    `certbot renew` (safe to run on a schedule; only renews
    near-expiry certs, exit 0 when nothing to do).
  - **Correction:** as of Certbot 2.0.0 the default key type for new
    certificates is ECDSA (P-256), not RSA — irrelevant to our flow
    (we never touch key types) but noted so tests don't assume RSA.
- **NodeSource install** — verified against the official
  nodesource/distributions docs (DEV_README.md,
  `https://github.com/nodesource/distributions`): **correction** — the
  current documented flow is NOT `curl … | bash -`; it is:
  ```
  curl -fsSL https://deb.nodesource.com/setup_22.x -o nodesource_setup.sh
  sudo -E bash nodesource_setup.sh
  sudo apt install -y nodejs
  ```
  (`-E` preserves the environment; the script adds the apt source).
  The spec's pipe form is the legacy pattern and is deprecated in the
  docs — update the step builder to download-then-execute (argv-based
  with a fixed URL per major version; supported: Ubuntu Focal/Jammy/
  Noble and Debian 10/11/12 for Node 18/20/22 — verified in the
  supported-versions tables).
- **`git clone`/`pull --ff-only`** — standard git semantics (git
  docs: `git clone`, `git pull --ff-only` refuses non-fast-forward
  merges, which the spec surfaces as a step failure); no external
  dependency beyond git being installed.
- **DNS pre-check** — `dig +short <domain>` is the documented dig
  short-output mode (BIND 9 man page). Fail-early before certbot is
  cheaper than a failed http-01.

Sources: pm2.keymetrics.io docs, nginx.org beginner's guide, Debian wiki
Nginx, certbot.eff.org using.html, nodesource/distributions DEV_README,
git(1), dig(1).

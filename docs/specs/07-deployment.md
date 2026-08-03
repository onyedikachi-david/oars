# Spec 07 — One-Click Deployment

**Status:** 📋 · **Depends on:** 02 (exec), 05 (SFTP for .env/nginx), 08 (deploy keys), 01 · **Spec owner:** core

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
- **Runtime:** Node.js version select (supported production lines only: 22 or
  24 as of 2026-08-03; refresh from the official release table) · app type
  (Node.js / React / Next.js / Static build folder) · package manager ·
  install/build/start commands (auto-filled from detected lockfile and type,
  editable) · build folder.
- **Environment:** individual key/value rows **or** bulk `.env` paste (comments ignored, quotes preserved).
- **Domains:** one or more explicit names; SSL toggle; certificate email.
  `www` is never added unless the user selects it and DNS for that name passes
  the preflight. Check both A and AAAA records and explain that public port 80
  must reach this server for the HTTP-01 challenge.
- Create → transitions to the deploy view.

### 4.2 Deploy view
- Step rail: Clone repository / Install dependencies / Build application / Start with PM2 / Configure Nginx / Issue SSL certificate.
- Each step: pending (gray) → running (spinner + live output) → success (green check, collapsed output) → failed (red, output expanded).
- Final state: "https://storefront.dev · Live" card + Update (re-deploy) and View Logs buttons.
- Cancellation: generated wrappers start each step in a tracked remote process
  group. Cancel sends a termination signal, waits for exit, and then closes the
  channel. If Oars cannot verify termination, the run is `cancel requested`,
  not `cancelled`.

### 4.3 App list
- Per server: "Applications" section in the File Manager toolbar → list of apps (name, status: live/degraded/never, url, last deploy) → open → deploy view with history (last 10 runs).

## 5. Bridge API

### `oars.deploy.apps.list` `{server_id}` → `{ok, apps}`
### `oars.deploy.apps.save` `{app}` → `{ok, app}` · `oars.deploy.apps.delete` `{server_id, app_id}` → `{ok}`
App model:
```json
{"id":"a1…","server_id":"s1…","name":"storefront","environment":"production",
 "folder":"/home/ubuntu/storefront",
 "repo":{"url":"git@github.com:you/storefront.git","transport":"ssh","branch":"main"},
 "runtime":{"node_version":"22","type":"next","install":"npm ci",
            "build":"npm run build","start":"npm start","build_folder":".next"},
 "env_vars":[{"name":"NODE_ENV","secret":false,"value":"production"},
             {"name":"DATABASE_URL","secret":true,"has_value":true}],
 "domains":["storefront.dev"],"ssl":true,
 "app_port":3000,"created_at":…,"updated_at":…}
```
- Each environment row has an explicit `secret` flag, which defaults to true.
  Secret detection can suggest that flag, but name matching is not a security
  boundary. Secret values use Keychain account
  `deploy:<app_id>:<var>` and never enter the JSON store.

### `oars.deploy.run` `{server_id, app_id, secret_values?}` → `{ok, run_id}`
- The frontend reads only the required Keychain accounts and sends their values
  in this transient, origin-gated request. The core validates that every name
  matches a declared secret field, keeps values only in the run's protected
  memory, and clears them after the remote `.env` write and redaction setup.
### `oars.deploy.poll` `{run_id, cursors?}` → steps + output deltas
```json
{"ok":true,"status":"running","steps":[
  {"id":"clone","label":"Clone repository","state":"success"},
  {"id":"install","label":"Install dependencies","state":"running","channel":7}]}
```
- Each caller supplies an absolute cursor for every step channel. The response
  reports per-caller gaps without advancing another deployment view.
### `oars.deploy.cancel` `{run_id}` · `oars.deploy.history` `{server_id, app_id, limit}` → `{ok, runs}`

## 6. Zig core design

- `src/deploy.zig` — App model/store (`<data>/apps.json`), step planner, step command builder, run state machine (per-run: step index, per-step channel + stream, status; poll-driven from frontend, no extra threads — steps execute sequentially through the session worker's exec path).
- A read-only preflight detects the OS, architecture, libc, DNS, listening
  ports, repository state, and required tools. Missing `git`, PM2, nginx, or
  certbot never triggers a guessed install command. Oars shows a separate,
  distro-specific install plan only for a tested OS adapter, with the exact
  packages, repositories, and privileges, and waits for approval.
- Step command builders use fixed templates plus the shared shell-quoting
  function for every dynamic value. SSH exec does not provide argv transport:
  1. clone: `git clone <repo> <folder>` or `git -C <folder> pull --ff-only` when folder exists
  2. install: use the lockfile-specific frozen command (`npm ci`,
     `pnpm install --frozen-lockfile`, or `yarn install --immutable`). Use the
     non-frozen install command only when no lockfile exists; do not hide a
     failed frozen install behind `|| npm install`.
  3. build: `<build>` in folder (`NODE_OPTIONS=--max-old-space-size=4096` prefix for node builds)
  4. pm2: write an ecosystem file with explicit `cwd`, script, args,
     environment, and app name; run `pm2 startOrReload <file> --only <app>`.
  5. nginx: write site config via SFTP (temp + rename), `nginx -t`, symlink to `sites-enabled`, `systemctl reload nginx`
  6. certbot: `certbot --nginx` with one `-d` per validated name,
     `--non-interactive --agree-tos`, and the user-supplied email. Oars never
     invents an email address.
- For an SSH repository, create a per-app `known_hosts` file and use a scoped
  `GIT_SSH_COMMAND` with that file, the app's deploy key, and
  `IdentitiesOnly=yes`. Show the Git host key fingerprint before the first
  clone. For `github.com`, compare it with GitHub's current official
  fingerprints or published known-host entries. For another Git host, require
  independent user verification. `ssh-keyscan` can collect a key but cannot
  establish its authenticity by itself. Never disable strict host-key checking
  or modify the server user's global `known_hosts` silently.
- Node install helper (step 1.5, implicit): resolve the latest patched release
  in the selected supported LTS line from Node.js release metadata. Show the
  exact version, platform archive, install directory, and checksum before
  approval. Download the official prebuilt archive and `SHASUMS256.txt`, verify
  SHA-256, and unpack under `~/.local/share/oars/node/<version>` so Oars does not
  replace the system Node installation. The PM2 ecosystem file uses that exact
  Node path. Unsupported architecture or libc stops with a documented manual
  path; it never falls through to an unreviewed package repository script.
- Secrets: env vars are written to `<folder>/.env` via SFTP before install/build (never echoed in step output; masked in logs).

## 7. Data model

- `<data>/apps.json`: apps (env_vars without secret values; secret values in Keychain).
- `<data>/deploy_runs.json`: run history (status, step results, timestamps, output trimmed to 200 KB/run, raw kept 30 days).

## 8. Security

- Deploying is inherently mutating → the Create/Update click is the approval; audit entry per run (command list).
- Private repos: the public deploy key is shown for GitHub. The private half
  must persist on the remote server so future pulls work; store it with mode
  0600 and never copy it into Oars config or logs.
- Secrets never appear in step output or run history (masking pass on captured output: replace known secret values with `***`).

## 9. Performance

- Step output streams ride the poll budget; long builds stream for hours without buffering issues (channel stream capped, dropped-warning applies).
- History capped: 10 runs listed, 30 days retained.

## 10. Edge cases

- Existing folder → verify that it is the expected Git repository and remote
  before fetch. A mismatched or dirty folder stops with a diff summary. Oars
  never suggests an automatic reset that could discard server changes.
- Build OOM → step fails showing the OOM line (NODE_OPTIONS hint applied by default).
- DNS preflight resolves A and AAAA, compares the result with the server's
  known public addresses where possible, and warns when NAT prevents proof.
  It cannot prove that inbound port 80 is reachable, so certbot remains the
  final authority.
- nginx config collision (site already exists) → fail with existing-config diff shown.
- Server disconnected mid-deploy → run marked `interrupted`. The next run
  rechecks repository, dependencies, process state, Nginx config, and
  certificate state before planning work. It does not blindly resume at a
  stored step number.

## 11. Testing

- Unit: step planner (app type → command templates), path/domain validation, env masking.
- Integration (container with node+pm2+nginx): deploy a fixture Next.js app → verify site responds (curl), re-deploy after change, SSL skip path (no domain), failure injection (broken build) → verify step red + resume.
- Manual: bulk .env paste, node install path.

## 12. Acceptance criteria

- [ ] End-to-end deploy of a fixture app: clone→install→build→pm2→nginx (SSL skipped in test) with green steps.
- [ ] Re-deploy pulls and restarts correctly.
- [ ] Secret env values never appear in JSON. Known secret values are redacted
      from captured output, history, and audit fixtures.
- [ ] DNS pre-check prevents certbot failure for missing records.
- [ ] A new run after an interruption rechecks remote state and replans safely;
      it never skips work solely because an old step was marked successful.

## 13. Research & References

- **PM2** — verified against PM2's official docs
  (`https://pm2.io/docs/runtime/reference/ecosystem-file/` and
  `https://pm2.io/docs/runtime/reference/pm2-cli/`): ecosystem files support
  `name`, `script`, `cwd`, `args`, `interpreter`, and `env`; the CLI documents
  `startOrReload <json>`. This is the idempotent first-deploy/redeploy command
  used in §6, with `--only <app>` scoped to the selected process.
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
- **Node.js installation and support** — the official Node.js release page
  says production applications should use Active LTS or Maintenance LTS and
  defines official installation methods as downloading unmodified official
  binaries. The release table on
  2026-08-03 marks 18 and 20 EOL, 22 and 24 LTS, and 26 Current. Production
  choices are therefore 22 and 24 at this review date. The deployment flow
  resolves this list again rather than freezing those majors forever
  (`https://nodejs.org/en/about/previous-releases`). Official release
  directories publish the platform archives and `SHASUMS256.txt`, which is the
  checksum boundary used in §6 (`https://nodejs.org/download/release/`). The earlier NodeSource
  bootstrap plan was removed because it would add a third-party system package
  repository and change the server-wide Node installation.
- **Lockfile installs** — npm documents `npm ci` as a deployment-oriented clean
  install that fails when `package-lock.json` disagrees with the manifest and
  never rewrites the lockfile (`https://docs.npmjs.com/cli/v11/commands/npm-ci`).
  pnpm documents `--frozen-lockfile` with the same no-update/fail-on-drift
  contract (`https://pnpm.io/cli/install`). Yarn documents `--immutable` as an
  error when installation would modify the lockfile
  (`https://yarnpkg.com/cli/install`). These contracts support step 2 without
  the earlier silent fallback to a mutable install.
- **`git clone`/`pull --ff-only`** — standard git semantics (git
  docs: `git clone`, `git pull --ff-only` refuses non-fast-forward
  merges, which the spec surfaces as a step failure); no external
  dependency beyond git being installed.
- **Git host identity** — GitHub publishes its current SSH host-key
  fingerprints and `known_hosts` entries at
  `https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/githubs-ssh-key-fingerprints`.
  Those values support the `github.com` verification path. A key returned by
  `ssh-keyscan` over the same untrusted network is discovery data, not
  independent verification.
- **DNS pre-check** — `dig +short <domain>` is the documented dig
  short-output mode (BIND 9 man page). Fail-early before certbot is
  cheaper than a failed http-01.

Sources: pm2.keymetrics.io docs, nginx.org beginner's guide, Debian wiki
Nginx, certbot.eff.org using.html, Node.js release and download documentation,
git(1), dig(1).

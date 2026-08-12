# Spec 07 Deployment Research and Current-State Audit

**Reviewed:** 2026-08-11

**Checkout:** commit `41b237d`

> This is the pre-implementation baseline audit for Spec 07. It describes the
> gaps at the reviewed commit. It is not a description of the current checkout;
> the completion record is in `docs/HANDOVER.md` §36.

**Scope:** `docs/specs/07-deployment.md`, the current deploy core and bridge, the
frontend deploy workspace, installed Native SDK credential use, and the
external tools that the product contract invokes.

This file records evidence for the next implementation guide. The feature spec
remains the product contract. Current code gaps do not narrow that contract.

## Method

The audit used four evidence classes:

1. The current product and design contracts in `docs/specs/README.md`,
   `docs/specs/07-deployment.md`, and `docs/DESIGN.md`.
2. Direct source inspection of `src/deploy.zig`, the deploy handlers in
   `src/bridge.zig`, `frontend/src/DeployTab.tsx`, `frontend/src/bridge.ts`, and
   `frontend/src/types.ts`.
3. Existing unit, dispatcher, frontend, and container integration tests.
4. Current official documentation from Node.js, npm, pnpm, Yarn, Git, GitHub,
   PM2, nginx, Certbot, and util-linux. The links in this file are primary
   sources. They were checked on 2026-08-11.

## Verified Product Boundary

Spec 07 is a one-click deployment workflow for Node.js, Next.js, React SPA, and
static sites. It must support a read-only preflight, an exact reviewed mutation
plan, live per-step output, safe re-deploy, private Git repositories through a
deploy key, local Keychain storage for app secrets, nginx configuration, and
optional Certbot issuance. Docker and non-JavaScript runtimes remain outside
v1.

The shared spec rules add three hard constraints:

- SSH execution carries one shell string, so every dynamic value must use the
  shared POSIX-shell quote function (`docs/specs/README.md:73-77`).
- Closing an SSH channel does not prove that its remote process stopped. Hard
  cancellation must signal and verify a tracked remote process group
  (`docs/specs/README.md:78-81`).
- The bridge main thread must not block on network work
  (`docs/specs/README.md:90-91`).

## What Exists Now

### Core and persistence

`src/deploy.zig` contains an app model, JSON app store, six-step planner, config
generators, run registry, secret masking, and JSON history store. The bridge
registers list, save, delete, run, poll, cancel, and history commands at
`src/bridge.zig:104-110`.

The existing model has environment, folder, repository, Node major, app type,
user-authored install/build/start strings, build folder, environment rows,
domains, SSL email, and app port (`src/deploy.zig:53-137`). Secret values are
removed from the app JSON, but the client supplies `has_value` and the store
trusts it (`src/deploy.zig:411-529`). The store and history writer truncate and
rewrite their final paths directly rather than write a temporary file and
rename it (`src/deploy.zig:387-400`, `src/deploy.zig:1291-1301`).

The run owns a cloned app and command plan, which is a useful exact-run
property (`src/deploy.zig:960-983`). It retains secret values until run
eviction, frees them without `secureZero`, and has an output cursor that the
capture path does not use (`src/deploy.zig:985-1018`). Completed live records
are bounded to 32, but there is no stated active-run admission cap
(`src/deploy.zig:1058-1065`).

### Planner and remote mutations

The planner quotes repository and folder values. It rejects a dirty tracked
worktree, verifies the origin URL, and uses `git pull --ff-only` for an existing
checkout (`src/deploy.zig:635-670`). It does not freeze or verify the checked-out
branch and commit before approval.

Lockfile branches all execute the same user-supplied install command, so the
planner does not actually select the package manager or its frozen command
(`src/deploy.zig:673-692`). Node 22 and 24 are hard-coded and no Node download,
checksum, installation, or exact interpreter path exists
(`src/deploy.zig:14`, `src/deploy.zig:223-227`).

The planner starts PM2 whenever a start command exists. It always writes a
reverse-proxy nginx server, including for React and static apps
(`src/deploy.zig:707-740`, `src/deploy.zig:790-817`). This does not implement
the required static-file plans. The PM2 file splits a shell command at the
first space into `script` and `args`, which changes shell semantics, and it has
no exact Node interpreter (`src/deploy.zig:837-870`).

The nginx path is under `/etc`, but the handler uses the connected user without
an explicit `sudo -n` or root contract. It writes the site before the command
runs, then tests nginx before it enables the new site. A first-deploy candidate
is therefore not part of the configuration that `nginx -t` checks
(`src/deploy.zig:722-739`, `src/bridge.zig:3478-3495`). There is no ownership
marker, collision hash, config diff, backup, or restore transaction.

The `.env` and PM2 files contain deployment secrets on the server. They are
written with a generic SFTP save and no verified mode-0600 step
(`src/deploy.zig:819-870`, `src/bridge.zig:3428-3476`). A missing secret is
silently omitted from both generated files. The ecosystem writer also uses the
source row index for commas; if an earlier missing secret is skipped, a later
row can produce invalid JSON (`src/deploy.zig:859-868`).

Certbot is preceded only by a check that each domain has some A or AAAA record.
It does not compare the records with known server addresses, inspect port 80,
or provide a full preflight (`src/deploy.zig:742-759`). No tested OS adapter or
approved dependency-install plan exists.

### Run, poll, and cancellation

Run validates supplied secret names, but it does not reject duplicate names or
require a value for every declared secret (`src/bridge.zig:3381-3395`). It
builds and audits the plan immediately. There is no read-only prepare request,
review token, expiry, or commit of an immutable plan
(`src/bridge.zig:3397-3411`).

Config writes wait synchronously for SFTP completion in a bridge handler
(`src/bridge.zig:3428-3453`). The step engine polls its active channel from
cursor zero on every pass, so it can append the same retained bytes to history
more than once. It does not close a completed channel after EOF
(`src/bridge.zig:3504-3578`). The separate view poll correctly accepts caller
cursors and returns cursor, gap, EOF, and data fields
(`src/bridge.zig:3619-3680`).

Cancel sets a flag and closes the SSH channel, then records "run canceled by
the user" (`src/bridge.zig:3685-3706`). The next poll changes the run to
`canceled` without proving that the remote process group exited
(`src/bridge.zig:3505-3511`). The status model has no `cancel_requested` state
(`src/deploy.zig:917-928`).

The bridge takes a run pointer under the run-registry lock, releases the lock,
then continues to mutate and serialize that pointer
(`src/bridge.zig:3592-3616`). The implementation must establish stable
ownership or hold a safe lock across each state transition before it supports
multiple deploy views.

Timestamps are epoch nanoseconds serialized as JSON integers. JavaScript
numbers cannot preserve current epoch nanoseconds exactly. The wire contract
must use integer milliseconds or decimal strings.

### Frontend

`DeployTab` declares partial local interfaces and uses `any` for bridge
responses and history (`frontend/src/DeployTab.tsx:5-44`). The shared bridge
also types deploy payloads and poll/history results as `any`
(`frontend/src/bridge.ts:244-251`). There are no shared deployment models in
`frontend/src/types.ts`.

The run flow requests secrets through `window.prompt`; delete uses
`window.confirm` (`frontend/src/DeployTab.tsx:94-105`,
`frontend/src/DeployTab.tsx:175-178`). The poll does not send cursors, replaces
all steps with each response, checks the nonexistent `pending` run status,
does not retain or clear its timer, swallows errors, and loads history for the
first app instead of the active app (`frontend/src/DeployTab.tsx:115-140`). The
component expects step `output`, while the backend sends `data`, so live output
is not displayed (`frontend/src/DeployTab.tsx:20-27`,
`frontend/src/DeployTab.tsx:185-203`).

The editor exposes the integration-only `file` transport, hard-codes
`/home/ubuntu`, and omits complete controls for package manager, environment,
build folder, port, SSL, and email. Its bulk environment parser trims input and
cannot preserve the defined value bytes (`frontend/src/DeployTab.tsx:219-268`).
The modal has no dialog semantics, focus trap, Escape handling, or focus
restore. The UI uses raw buttons, inline styles, color-only status dots, and
many nested boxes instead of the surface and status system in
`docs/DESIGN.md:167-203`.

`frontend/preview.html` has no deployment fixtures. No frontend test covers
`DeployTab`.

The frontend already wraps the permission-gated Native SDK credential commands
as `vault.set`, `vault.get`, and `vault.delete`
(`frontend/src/bridge.ts:70-103`). `ServerModal` provides a useful
metadata-plus-Keychain rollback pattern (`frontend/src/ServerModal.tsx:200-253`).
The current wrapper also keeps every value read or written in a process-lifetime
JavaScript map. Deployment secrets need a transient read path or an explicit
cache-forget operation so a deploy does not retain all app secrets for the
rest of the desktop process.

## Primary-Source Findings

### Node.js support and installation

The [official Node.js release table](https://nodejs.org/en/about/previous-releases)
says production applications should use Active LTS or Maintenance LTS. On
2026-08-11, Node 24 and 22 are LTS, Node 26 is Current, and Node 20 is EOL.
The selectable production majors are therefore 24 and 22 today. Oars must
resolve this list again from official release data instead of freezing it in
source.

Node publishes platform archives and a `SHASUMS256.txt` file in each official
release directory. For example, the current
[Node 24 checksum file](https://nodejs.org/download/release/latest-v24.x/SHASUMS256.txt)
lists separate Linux x64 and arm64 archives with their SHA-256 values. The
approved plan can freeze one exact patched version, archive name, URL, and
checksum, then install it under the connected user's Oars directory without
replacing system Node.

### Reproducible package installation

The official [npm `ci` documentation](https://docs.npmjs.com/cli/v11/commands/npm-ci/)
says `npm ci` requires a lockfile, fails when it disagrees with `package.json`,
removes an existing `node_modules`, and does not write the manifest or lockfile.
The current [pnpm install documentation](https://pnpm.io/cli/install) says
`--frozen-lockfile` prevents lockfile generation or updates and fails when the
lockfile and manifest are out of sync. The current
[Yarn install documentation](https://yarnpkg.com/cli/install) says
`--immutable` aborts when the install would change the lockfile.

The implementation must select exactly one manager from the app setting and
detected lockfile. It must stop on conflicting lockfiles. It must not hide a
frozen-install failure behind a mutable fallback.

### Git checkout safety and repository identity

The official [Git pull documentation](https://git-scm.com/docs/git-pull)
confirms that `--ff-only` fails when local and remote histories have diverged.
The official [Git status documentation](https://git-scm.com/docs/git-status.html)
defines porcelain output as stable for scripts. The preflight must use these
machine-readable checks, freeze the target remote branch commit, and show dirty
or divergent state as a blocker. It must never reset user changes.

GitHub documents that a deploy key grants access to one repository and
[cannot be reused for another repository](https://docs.github.com/en/authentication/connecting-to-github-with-ssh/managing-deploy-keys).
GitHub also publishes its current
[SSH host fingerprints and known-host entries](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/githubs-ssh-key-fingerprints).
The SSH repository path must use a per-app private key and a per-app
`known_hosts` file with strict checking. A key collected with `ssh-keyscan` is
discovery data; it is not independent identity proof.

### PM2 and nginx

The [PM2 ecosystem-file documentation](https://pm2.keymetrics.io/docs/usage/application-declaration/)
defines `name`, `script`, `cwd`, `args`, `interpreter`, and environment fields.
PM2 documents `startOrReload` as the first-deploy/redeploy command in its
[official FAQ](https://pm2.keymetrics.io/docs/faq/). Oars must create a valid
ecosystem object from explicit fields and use the frozen Node interpreter. It
must not reinterpret an arbitrary shell command by splitting on whitespace.

The [nginx command-line documentation](https://nginx.org/en/docs/switches.html)
says `-t` checks syntax and tries to open referenced files. It says reload
starts workers with the new configuration and gracefully shuts down old
workers. The candidate site must be enabled before the full test, and Oars
must restore the prior link and file if validation or reload fails.

### Certbot

The official [Certbot user guide](https://eff-certbot.readthedocs.io/en/stable/using.html)
says the nginx plugin can authenticate and install, HTTP-01 uses port 80, and
`--non-interactive` prevents an automation run from waiting for input. It also
recommends backing up nginx configurations before plugin use. The
[installation guide](https://eff-certbot.readthedocs.io/en/stable/install.html)
says root access is recommended for automatic nginx configuration.

Oars must check DNS facts and the local listener before approval, state that
it cannot prove public ingress through NAT or a firewall, and let Certbot be
the final domain-control authority. It must show the exact email and domain
arguments and must restore the Oars-owned nginx state on failure.

### Remote process groups

The upstream util-linux [`setsid` manual](https://man7.org/linux/man-pages/man1/setsid.1.html)
says `setsid` runs a program in a new session, and `--wait` returns the child
program's exit status. This gives Oars a portable Linux building block for a
tracked wrapper. The product status can become `canceled` only after a separate
control command signals the recorded group and a later check confirms that no
process in the group remains.

## Corrections Required Before Spec 07 Can Be Complete

1. Add a read-only preflight and a bounded, expiring, immutable approval token.
   Run must execute that frozen plan, not reload the app and replan.
2. Resolve current production Node lines from official release metadata, then
   freeze one patched version, platform archive, and checksum in the preflight.
3. Add an explicit package-manager field and correct frozen install selection.
4. Separate Node/Next process plans from React/static file-serving plans.
5. Add a tested Debian/Ubuntu dependency adapter. Show exact privileged
   commands and require separate approval. Unsupported systems stop with
   manual instructions.
6. Make repository identity, branch, commit, deploy key, and host key part of
   the preflight and frozen plan.
7. Make nginx changes transactional and ownership-aware. Test the enabled
   candidate before reload and restore the prior state on failure.
8. Require all declared secrets, reject duplicates, use Keychain transactions,
   avoid the process-lifetime frontend secret cache, write server secret files
   with mode 0600, and clear in-memory values.
9. Give internal history capture its own cursor, close completed channels, and
   retain only bounded masked deltas.
10. Implement tracked process-group cancellation and the honest
    `cancel_requested` state.
11. Move SFTP waits and all other network waits off the bridge main thread.
12. Replace the untyped frontend with a tested deploy state module, accessible
    dialogs, complete form controls, stable cursor polling, deployment preview
    fixtures, and the Oars surface/status system.

## Existing Test Evidence and Its Limit

Before commit `41b237d`, the full container integration suite passed 205 of
205 tests, the frontend suite passed 59 of 59 tests, TypeScript passed, and the
focused Scripts checks passed. The deployment integration test exercises a
local `file://` fixture, clone/install/build, PM2, nginx, re-deploy, history,
failure, masking, and channel-close cancellation.

That fixture runs with privileges and uses a local repository. It does not
prove non-root `/etc` changes, HTTPS or SSH repository identity, current Node
download and checksum verification, package-manager conflict handling, public
DNS/port behavior, Certbot, Keychain rollback, or verified remote termination.
The new implementation guide requires production-shaped fixtures for those
boundaries.

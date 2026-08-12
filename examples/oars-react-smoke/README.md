# Oars React smoke app

This fixture tests a real React static deployment on a server that is already
connected in Oars.

## Put it in a Git repository

Copy this directory into an empty GitHub, GitLab, or other Git repository. Commit
`package-lock.json` with the other files and push the `main` branch.

## Oars application settings

- Application type: `React SPA`
- Node LTS major: `24`
- Package manager: `Detect from lockfile`
- Install override: leave empty (`npm ci` is derived from the lockfile)
- Build command: `npm run build`
- Build folder: `dist`
- Environment row: `VITE_DEPLOYMENT_LABEL=contabo-smoke-1`, marked non-secret
- SSL: off for the first IP-based test
- Domain: leave empty for the first test, or add a name whose DNS already
  resolves to the server

Run preflight. Confirm that port 80 is `free` or `nginx`. A `foreign` listener
must be resolved before deployment. Deploy the reviewed plan, then open the
server IP in a browser. The page must show `oars-smoke-ok` and the selected build
label.

For the update test, change the environment value to
`VITE_DEPLOYMENT_LABEL=contabo-smoke-2`, save, run a new preflight, and deploy
again. The live page must show the new label.

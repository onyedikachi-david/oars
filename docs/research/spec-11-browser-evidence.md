# Spec 11 browser fixture evidence

Date: 2026-08-31

Browser: Codex In-app Browser

Viewports: 1440 x 1000 desktop and 768 x 900 narrow

Themes: light and dark

The runtime review covered every frozen `?ai=` mode: `no-server`,
`no-provider`, `credential-missing`, `context-disclosure`,
`provider-test-running`, `provider-auth-failed`, `streaming`, `question`,
`refusal`, `proposal-safe`, `proposal-destructive`, `proposal-edited`,
`execution-running`, `cancel-requested`, `recovery-required`,
`summary-disclosure`, and `long-command`.

All 68 mode, viewport, and theme combinations rendered their expected state.
No fixture reported a runtime console error or document-level horizontal
overflow. The narrow AI layout collapsed to one column. The 65,520-character
command rendered in a bounded scrolling command region without document
overflow. The destructive proposal showed its exact command, warning,
revision-specific acknowledgement, disabled Run action, and exact server.

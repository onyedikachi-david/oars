# Oars product context

This file records the product facts that guide interface work. It extends
`docs/DESIGN.md`; that document remains the visual authority.

## Product

Oars is a native desktop operations workspace for people who manage Linux
servers over SSH. It keeps monitoring, logs, files, scripts, deployments,
access, backups, remote desktop, and reviewed AI-assisted operations in one
local application.

The primary user is a technical operator who needs to understand and change a
server without losing track of the exact target, command, output, or approval.
This audience and job are inferred from the checked-in specifications and the
implemented navigation.

## Positioning

Oars should feel like a calm control room, not a browser dashboard placed in a
desktop window. The useful distinction is local authority: native code owns
credentials, provider requests, durable operation state, and SSH execution,
while the React interface explains and controls those operations.

## AI operations surface

The AI surface is a conversation about one exact server. Normal assistant text,
questions, reviewed command calls, approval, live output, and follow-up analysis
belong to the same chronological transcript. Provider and disclosure settings
are supporting controls and must not compete with the conversation.

The model never receives authority to run a command. Oars freezes the server,
provider revision, reviewed context, command, and destructive classification in
native state before it offers an approval control. Secrets stay in the native
secure store and never enter React state, bridge results, logs, journals, or
persisted JSON.

## Interaction principles

- Make the next valid action visible and explain a blocked action beside it.
- Use progressive disclosure for provider metadata and shared-context controls.
- Keep messages and tool activity in one transcript so cause and result remain
  adjacent.
- Use technical typography only for commands, output, identifiers, and measured
  values.
- Preserve useful work across refresh and restart through native durable state.

## Constraints

- `docs/DESIGN.md` defines the established visual world.
- The Zig process is the authority for secrets, network requests, approval,
  persistence, and remote execution.
- The React surface may project native events into chat parts but must not infer
  a successful provider request or remote command.
- Server and log content is untrusted data. A user approves the exact context
  selection before it is sent.
- Commands require explicit approval; locally or model-classified destructive
  commands require an additional acknowledgement.

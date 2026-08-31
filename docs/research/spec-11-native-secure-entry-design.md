# Spec 11 native secure-entry design review

Status: accepted for the Oars-owned adapter used by Spec 11.

## Decision

Oars will own a small platform prompt adapter and will keep credential storage
in the Native SDK runtime service. The WebView asks Oars to configure a named
provider, but the request contains no secret. A modal operating-system control
collects the secret into one fixed 4,096-byte native buffer. The runtime thread
then calls `Runtime.setCredential` with service `dev.oars.ai` and account
`ai:<provider_id>`. React receives only a status.

The pinned Native SDK 0.7.1 cannot own this input because it exposes credential
set/get/delete methods but no native secret-entry field. Its built-in
credential bridge is excluded because the secret would originate in WebView
JSON. An untracked SDK edit is also excluded because CI and packaged builds
install the published 0.7.1 package.

## Platform controls

- macOS uses an AppKit `NSAlert` with `NSSecureTextField`.
- Linux uses a GTK 4 modal dialog with an invisible `GtkEntry`. If GTK cannot
  create the control, configuration reports `unavailable`.
- Windows uses Credential UI with a password-masked field and disables its own
  persistence. The resulting bytes are passed to the Native SDK credential
  service, which remains the only persistent owner.
- The null platform injects a fake prompt and fake credential service. It never
  falls back to WebView input.

Every platform adapter returns `configured`, `canceled`, `denied`,
`unavailable`, or `too_large`. It writes only into a caller-owned fixed buffer
and clears all platform-local buffers before return.

## Thread and lifetime rules

`App.start_fn` installs a narrow facade that records the runtime thread. All
prompt and credential-service calls reject another thread. `App.stop_fn` closes
admission and clears the facade before the runtime is destroyed. Provider
workers never receive the runtime pointer. A future admitted provider job gets
one copied `SecretBuffer`; its `deinit` uses `std.crypto.secureZero` on the full
capacity, including error and cancel paths.

## Security properties and limits

The bridge configure payload contains only `operation_id` and `provider_id`.
The key is absent from React state, browser storage, bridge JSON, audit,
history, provider metadata, and journals. Prompt labels contain the provider
name and normalized origin, never server context. Secret length is 1 to 4,096
UTF-8 bytes with no NUL byte. No prompt implementation accepts a default value
or returns the existing value.

The API key necessarily exists in native memory while Oars calls the provider.
Oars does not claim that it remains inside the operating-system credential
store during a request.

## Failure behavior

Cancel makes no credential change. An unavailable or denied prompt or
credential service returns the matching status without a fallback input. A
successful replacement makes the provider test stale. Provider metadata
deletion does not delete the credential, and credential deletion does not
delete provider metadata.

## Required proof

Unit tests use injected services to cover configure, replace, cancel, denied,
unavailable, missing, wrong-thread use, the 4,096-byte boundary, and full-buffer
overwrite. Platform package builds compile each adapter. A final scan uses a
known canary key and must not find it in frontend state, bridge traffic, app
files, audit, history, journals, or errors.

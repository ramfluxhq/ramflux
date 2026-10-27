# Home migration: client custody and job contract

Home migration uses born-v3 authority. Unlocking account data does not approve a
move or reconstruct a primary key. A confirmation is bound to the stored
authorization proposal: its destination key fingerprint, predecessor hash, next
home epoch and complete authorization body. The client must show that preview
immediately before requesting OS presence. The OS dialog is generic; the SDK does
not claim that Keychain itself displays migration fields.

## macOS primary credentials

New native primary credentials use a versioned `presence:v1:` Keychain reference,
with `AccessibleWhenUnlockedThisDeviceOnly`, synchronization disabled and
`kSecAccessControlUserPresence`. Branch credentials retain their existing
noninteractive flags-0 policy. Provider availability/existence queries request
attributes only with authentication UI disabled; branch reads also forbid UI.

An older flags-0 primary is copied into the versioned item without overwriting an
existing item. A small, non-secret `upgrade:v1:` Keychain journal records each
step. The SDK reads back the new item under OS presence, checks its certified
public key, removes the old item, verifies its absence and marks the upgrade ready
before allowing a signature. A failed/cancelled upgrade never authorizes a move.
Every later signature still reads the protected item under fresh OS presence;
ready metadata is not an authentication token. Branch items are not upgraded.

The provider supplies no reusable authentication context. As documented by
[Apple](https://developer.apple.com/documentation/security/ksecuseauthenticationcontext),
Security creates a context for that request, uses it once and discards it. The
loaded primary signs one request and is dropped; it is never stored in the job,
event stream or data vault. Application-owned buffers zeroize. CoreFoundation,
Keychain IPC and OS-internal copies are not claimed to be synchronously scrubbed.
A seed copied before upgrade remains a management-compromise residual.

The safe password setter can replace duplicate items. The private native provider
therefore uses insert-only Security FFI inside one narrowly allowed unsafe module;
the rest of the SDK retains its unsafe-code denial. Other providers remain behind
the `PrimaryVault` interface, whose migration-signing default refuses. Other OSes
return `custody_user_presence_unavailable`; there is no file or data-unlock fallback.

`rfd` must run in the user's GUI/login session with the required protected-Keychain
entitlements. A headless/SSH/LaunchDaemon context or rejected interaction fails
closed. Presence work must run off the socket/UI and account DB writer threads.

## Test providers and the real-device acceptance boundary

The default-off `itest-memory-vault` fixture needs explicit one-use migration
approval. It does not enforce OS presence and must never enter a production/demo
build. Automated memory-item tests cover every upgrade I/O boundary, denied
presence, repeat approval, mismatching items and preservation of branch items.
Compiling the macOS provider is not evidence that a provisioned Keychain prompt
has run.

Before the two-Mac demo, perform this manual check using provisioned GUI-session
builds and two admitted migration-capable homes:

1. Keep the same v3 account on its primary Mac and a secondary Mac. Confirm that
   account-data unlock alone does not produce a migration authorization. A
   secondary without the separate primary credential must fail closed.
2. Prepare a move with an independently supplied destination fingerprint. Verify
   the preview's fingerprint, predecessor and next epoch. Cancel the OS dialog:
   no seal/commit may follow, the job must remain safely retryable and unrelated
   source messaging must continue.
3. Retry with Touch ID or the OS login credential. Verify that one exact pending
   proposal is signed, no recovery phrase is requested, and a changed proposal
   digest is refused. On a pre-upgrade account, verify that the old flags-0 item
   is removed after successful protected readback; never export credential data.
4. Use the controlled lost-seal-response acceptance scenario to cancel at A using
   the Authorization alone. After the signed noncommit result, prepare another
   eligible move and require a new OS prompt even immediately after the first
   successful authentication. No cached context may silently approve it.
5. Complete the move and observe the secondary resolving the signed refusal at
   its old home. Reconnect ordinary branch sessions repeatedly; those reads must
   not cause management prompts. Neither a node ACK nor a local timeout proves
   E2EE delivery or a successful move.

Record both macOS/build versions and the observed prompt/cancel/retry results.
This manual boundary is required before the demo and is not run by unit tests.

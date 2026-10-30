# Home migration: client custody and job contract

Home migration uses born-v3 authority. Unlocking account data does not approve a
move or reconstruct a primary key. A confirmation is bound to the stored
authorization proposal: its destination key fingerprint, predecessor hash, next
home epoch and complete authorization body. The client must show that preview
immediately before requesting OS presence. The OS dialog is generic; the SDK does
not claim that Keychain itself displays migration fields.

## macOS primary credentials

Native primary credentials for ordinary signing use a noninteractive flags-0
Keychain item with `AccessibleWhenUnlockedThisDeviceOnly` and synchronization
disabled. Account creation, recovery, contact-card sharing, consent signing and
branch-session credentials do not request OS presence. Ordinary reads explicitly
disable authentication UI and report `CustodyVaultUnavailable` for a locked,
missing, corrupt or unavailable credential. Availability/existence queries read
attributes only with UI disabled.

Only `sign_home_authorization` requests OS presence. It uses a separate versioned
`presence:v1:` item protected by `kSecAccessControlUserPresence`, copied from the
ordinary primary without overwriting an existing protected item. A small,
non-secret `upgrade:v1:` journal records the transition. The SDK reads the
protected item under fresh OS presence and checks its certified public key
before signing. The ordinary item remains available for card/consent signing;
it is never used as a fallback for migration approval. A failed/cancelled
presence check never authorizes a move. Every later migration signature still
reads the protected item under fresh OS presence; ready metadata is not an
authentication token. Branch items are not upgraded.

Accounts created by the earlier protected-only provider have no ordinary item.
Ordinary reads refuse without prompting. A successful, explicitly requested
migration presence check restores the ordinary item before signing, so later
card/consent signing is noninteractive. The old `delete_legacy` journal stage
remains readable, but this provider never deletes the ordinary signing item as
part of migration. Generic Keychain errors remain `CustodyVaultUnavailable`;
only migration preflight/signing maps them to
`HomeMigrationRefused(CustodyUserPresenceUnavailable)`.

The provider supplies no reusable authentication context. As documented by
[Apple](https://developer.apple.com/documentation/security/ksecuseauthenticationcontext),
Security creates a context for that request, uses it once and discards it. The
loaded primary signs one request and is dropped; it is never stored in the job,
event stream or data vault. Application-owned buffers zeroize. CoreFoundation,
Keychain IPC and OS-internal copies are not claimed to be synchronously scrubbed.
The ordinary and protected items contain the same software signing seed. This
separates operation/prompt policy, not cryptographic authority: compromise of the
ordinary credential remains a management-compromise residual.

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
build. Start a fixture daemon with `rf daemon start --itest-memory-vault`, then
send this local bus request with the frame account set to `human`:

```json
{
  "method": "itest.migration.approve_once",
  "body": {"account": "human", "request_id": "<canonical base64url 32-byte migration ID>"}
}
```

The successful body is `{account, request_id, approved_once: true}`. The account
must match the frame account, and the request ID is the journal's migration ID,
not the bus frame ID. The method requires the `itest-memory-vault` feature,
`RAMFLUX_ITEST_BUILD=1` provenance, and daemon opt-in. It is absent in production
or release-profile builds; enabling the feature in either build fails compilation.
The daemon's process-local memory vault tracks consumed account/request pairs
until it exits, including when signing fails after consumption. A mismatched
account/request cannot consume the pending approval. Saved journal requests are
resumed without another approval or signature.

| Typed bus error | Meaning |
| --- | --- |
| `MigrationApprovalUnavailable` | Daemon did not opt into the memory vault, or the configured provider has no fixture approval operation. |
| `MigrationApprovalAlreadyArmed` | Another approval is still pending, including another call for the pending pair. |
| `MigrationApprovalConsumed` | This account/request pair has already consumed its approval; it cannot be re-armed in this daemon, even while another pair is pending. |
| `CustodySetupInvalid` | Account/frame mismatch or invalid account/request identifier. |

Automated memory-item tests cover every upgrade I/O boundary, denied presence,
repeat approval, mismatching items, noninteractive card/consent access and
preservation of branch items.
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
   digest is refused. On a pre-upgrade account, verify that ordinary card/consent
   signing remains noninteractive after protected readback; never export
   credential data.
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

## Durable client journal

`HomeMigrationJournal` binds an existing encrypted account DB to its indexed
account anchor and verified born-v3 human custody record. `migrate_home_node`
now starts that durable intent rather than changing the in-memory federation
simulation. It requires a previously verified source home; it does not bootstrap
trust from a URL response. The target fingerprint uses
`hash_hex(CLIENT_DISCOVERY_DOMAIN, node_public_key.as_bytes())`, independently
supplied by the user, and the target client discovery signature is checked.

The migration job and an immutable progress transition commit in the same
account-writer transaction. A migration write refuses an enclosing transaction,
so returning a send plan cannot mean only an uncommitted savepoint. Each
transition writes the K0 outbox. Projection reads
that immutable transition, so later phase changes cannot collapse earlier
progress. The job carries bounded public signing/admission evidence, never primary
seeds, recovery phrases, branch seeds, account passwords or provider credentials.
There is one live operation per account; total jobs and unpublished transitions
are bounded. A changed operation intent is an idempotency conflict. Retry time
uses a nondecreasing persisted clock floor and bounded exponential backoff.

The stored unsigned proposal precedes OS presence. An opaque, non-clonable
approval plan can cross to a blocking worker without holding a writer transaction.
The returned result is installed only if its revision, digest, authorization body,
authority and pending phase still match. Cancelling during presence invalidates
that result. `seal_sent` and the recovery guard commit before the signed
Authorization is returned for transport. If the seal reply is lost, cancel retains
the Authorization without requiring a seal receipt. A timeout retains the guard
and reports `needs_attention`; it cannot select a home, activate B or resume A.

Backups strip the private job tables and migration progress outbox/journal rows
from the copied snapshot, without changing the live source DB. Imported replacement
generations also strip this work. Merge skips incoming migration tables and keeps
the live local journal. The public home-chain replay floor is a separate concern
and must survive restore; exporting a timer is not a way to resume an old move.

## Desktop bus contract

These are the required bus methods and event shape. They describe the integration
contract; the journal/provider implementation alone does not install a running
network driver or these daemon dispatch methods.

| Method | Request body |
| --- | --- |
| `account.home_node.migrate` | `{operation_id, target_discovery_url, expected_node_fingerprint}` |
| `account.home_node.migration.status` | `{operation_id}` |
| `account.home_node.migration.abort` | `{operation_id}` |
| `account.home_node.migration.confirm` | `{operation_id, proposal_digest}` |

An `operation_id` is the canonical unpadded base64url encoding of 32 random bytes
and is the wire `migration_id`. It is immutable across restart and business
retries. Confirmation uses the stored proposal digest, never an arbitrary digest
supplied for generic primary signing. Desktop must show destination fingerprint,
previous home hash and next home epoch before invoking confirmation.

`home_migration.progress` has this complete metadata body:

```json
{
  "operation_id": "<canonical base64url identifier>",
  "seq": 1,
  "phase": "intent",
  "source": "source.example",
  "target": null,
  "home_epoch": 0,
  "home_hash": "<verified home hash>",
  "commit_deadline": null,
  "forward_until": null,
  "backlog": {
    "scheduled": 0,
    "forwarded": 0,
    "receiver_acked": 0,
    "expired": 0,
    "rejected": 0,
    "evidence_required": 0,
    "remaining": 0
  }
}
```

`reason` is an optional typed refusal code. Unknown target/deadlines remain null.
The body `seq` is the operation's durable revision; the K1 event frame `seq` is the
global account-journal replay cursor. They must not be interchanged. Backlog
forwarded, receiver_acked, expired, rejected and remaining are disjoint and sum to
scheduled; evidence_required is a subset of remaining.

The full phase vocabulary is `intent`, `prepare_sent`, `awaiting_custody_unlock`,
`seal_sent`, `sealed`, `commit_pending`, `activate_sent`, `backlog_transferring`,
`reconnecting`, `manifest_switch_pending`, `forwarding`, `complete`, `expired`,
`abort_pending`, `aborted`, `refused` and `needs_attention`. A local error is not evidence for a
terminal phase. Completion requires authenticated terminal evidence and an
ordinary v3 reconnect, followed by an atomic, fsynced manifest switch. In
particular, a provisional native DM channel does not establish that reconnect.

The intended CLI spelling is `rf account migrate` with `migrate-home` as an
alias, plus status/cancel operations. Every base64url identifier positional must
accept a leading `-`. CLI/desktop must consume the same daemon operation; they
must not create a separate migration engine or a new trust anchor.

## Recovering outbound plans and outcomes

`resume(operation, vault, now)` returns the journaled Prepare at `prepare_sent`,
or the exact Authorization and actor-signed Seal Control at `seal_sent`. Neither
path reads the vault, re-signs a message, generates a nonce or requests OS presence.
The caller must obtain fresh channel-bound possession for each transmission; the
business signature and control nonce remain unchanged. Resuming after a server's
control/admission expiry requires authenticated status/cancel handling, never
silently extending the signed lifetime.

`sealed()` verifies B's fresh reply against B's pinned key, the saved Seal
Control hash and nonce, the Authorization hash, phase and time bounds. It stores
both that reply and the reply's `seal_hash`. B keeps the original durable seal;
the fresh receipt is not that seal and is not sent as `Evidence.seal_receipt`.
`commit_payload()` uses the saved `seal_hash`, and `committed()` compares A's
proof with it. A different seal hash is `home_fork`; a changed proof with the
same seal is `idempotency_conflict`. An identical accepted commit is a no-op,
including after activation has begun. A late commit after a cancellation or
noncommit fence is refused with `idempotency_conflict`. Cancellation keeps the
uncertainty guard until A supplies the authorization-bound noncommit fence.

Before any Seal, cancellation enters `abort_pending` if a Prepare was persisted.
`resume()` creates an actor-signed Abort addressed to B, with the operation
payload and no Authorization. This Abort is persisted before sending and replayed
unchanged after restart while its Control is valid. After Control expiry, the
same Abort payload gets a fresh branch-only Control persisted before transmission;
this does not require management approval. `reservation_aborted()` accepts only B's pinned,
control-bound signed release; then the local job becomes `aborted`, allowing a
new operation. Cancelling an unsent intent can terminate locally. An unsealed
Offer past `accept_until` becomes `expired`; `resume()`, `authorize()` and a new
`begin()` reap this expiry and release the local active-job lock. A seal attempt
never expires locally. An A-signed noncommit fence maps an uncancelled job to
`expired` and a cancelled job to `aborted`.

## Control transport integration requirement

Migration uses the existing custody connection and node-owned endpoint. It must
obtain a fresh challenge for each control request, bind the branch proof to that
control hash and TLS exporter (or the current admitted proxy receipt), and pin
the node CA, signed server name and node identity. `NoChannelBinding` is refused
for migration even if an ordinary debug connection permits it. There is no new
listener, WebPKI/TOFU replacement or ordinary-session fallback.

A former home must still answer bounded migration status, cancellation and resolve
operations after it refuses an ordinary session. The client driver must
therefore acquire an operation-scoped custody grant before sending the typed
business request. The server contract carries current publication and read/manage
purpose in the proof action, binds the grant to one Control hash, returns it via
`SessionEstablished`, and consumes it for one request. A control hash by itself
does not carry the payload. The journal does not yet implement that transport;
an empty ordinary session identifier or an undocumented token is not a substitute.

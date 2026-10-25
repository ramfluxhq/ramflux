# Root key custody

Design proposal, phase 1, 2026-10-26. This document changes no executable behavior.
The current implementation still requires the root seed on every local device.
The proposed guarantees apply only after the protocol, storage, backup and client
migration stages below ship together. Cryptographic and protocol review precedes
implementation rollout.

## Current implementation and authority boundary

The inspected baseline is product commit
`615845998ba61ada13058d130e5f7f17e2c8eb8a`. Relevant source paths are:

- [Account manifest](../crates/ramflux-sdk/src/bus/protocol.rs):
  `LocalBusPersistedAccount` serializes `root_seed`, `device_seed` and
  `account_secret`; file permissions are the present protection boundary.
- [Daemon startup](../crates/ramflux-sdk/src/bus/daemon.rs) reconstructs the root
  signer from that manifest. Removing the field alone would prevent startup.
- [Owned authority](../crates/ramflux-sdk/src/client/identity_authority/owned.rs)
  signs device-set changes and fresh root-bound branch proofs.
  [Registration](../crates/ramflux-sdk/src/client/identity_authority/registration.rs)
  refreshes those proofs during ordinary operation; their default lifetime is
  one hour. A secondary currently needs the root even without changing devices.
- [Revocation](../crates/ramflux-sdk/src/client/identity_authority/publication.rs)
  publishes a complete root-signed set, checks the exact acknowledgement and
  preserves monotonic observations and tombstones.
- [Identity types](../crates/ramflux-protocol/src/identity_keys.rs) bind principal
  kind, root-qualified device keys and device epochs. The existing signed-set
  format has no primary/custody fields and rejects unknown fields.
- [Recovery KDF](../crates/ramflux-crypto/src/kdf.rs) uses Argon2id v19,
  262144 KiB, three passes, one lane and a 32-byte output.
  [Key backup](../crates/ramflux-sdk/src/bus/dispatch/account.rs) encrypts the
  entire manifest, including the root seed, with the backup passphrase.

The separately reviewed creator-root group snapshot design signs genesis,
full snapshots, request results and ownership transfers with the root master
key; transport also has a branch signature. That design must evolve before a
keyless creator secondary can publish. Delegation described here is proposed
protocol work, not an existing verifier capability.

## Threat model and invariants

Protect against theft of a secondary's files or running process, a compromised
agent host, malicious directories/relays, intercepted pairing, stolen backups,
replayed custody records and an attacker guessing an encrypted recovery secret
offline. A compromised secondary can still read its available history, impersonate
that device until revocation, and exercise any explicit group delegation. It must
not enroll devices, revoke siblings, transfer primary custody or recover the root.

The primary OS, its trusted approval UI and its unlocked signer are trusted.
Malware controlling an unlocked primary can obtain root authority. Disk encryption,
vault access control and memory hygiene reduce exposure; they do not stop that
attacker. Root compromise requires a new identity and contact re-verification.
This proposal does not introduce root rotation under the same public identity.

Invariants after migration:

1. One designated primary per human account holds the usable root secret;
   service identities use the explicit external-custodian variant below. Its ordinary
   account manifest contains a vault reference and root public key, never the seed.
2. Secondaries contain their own branch signing/agreement secrets, public root
   certificates and data keys. Neither root seed nor a locally decryptable root
   wrapper travels through pairing, sibling sync, exports or agent provisioning.
3. A single logical recovery capsule contains an encrypted copy of the root seed;
   offline replicas of that same ciphertext are allowed. The recovery key is kept
   separately and is never sent to servers or synchronized to secondaries.
4. Root-qualified device identities, signed revocation tombstones and highest
   accepted epochs remain authorization inputs on every send, receive and resume.
5. Storage, transport and UI claims about primary status cannot grant authority.
   Only verified root-signed custody records and scoped certificates can do so.

A signed erase command cannot make a malicious device forget a seed it already
copied. Revoking a branch also cannot revoke knowledge of its root seed. Migration
can establish cooperative erasure, not retroactive isolation from compromised
legacy devices. Secure deletion from SSD snapshots and external backups cannot be
proven. Users who cannot trust a former root holder must create a new identity.

## Primary storage and signer API

Keep Ed25519 and the existing root commitment. Use an OS credential vault with
non-synchronizing, device-local access control and explicit user presence for
root-authority changes. On platforms with a suitable hardware provider, protect a
local wrapping key with that provider. The Ed25519 seed may still exist briefly in
protected process memory during signing: do not claim nonexportable hardware
Ed25519 support. Apple's documented Secure Enclave interface supports P-256 and
cannot import existing keys; a hardware wrapping design requires its own provider
review. See [Apple's key protection documentation](https://developer.apple.com/documentation/security/protecting-keys-with-the-secure-enclave).

Use a narrow signer interface with typed enrollment, revocation, custody and
delegation requests, not a generic sign-arbitrary-bytes bus API. The signer
reconstructs domain-separated canonical bodies and checks current policy after
approval. Zeroize temporary seed/KDF/plaintext buffers, avoid secret clones,
exclude secrets from logs, crash reports, swap where supported and clipboard
history, and expire unlocked signer handles promptly. Same-user local process
compromise remains within the trusted-primary threat boundary.

Desktop prefers a supported platform vault. A TUI can be primary using a supported
vault or an explicitly selected encrypted local vault with an interactive unlock
prompt; never a plaintext-file fallback. Refuse unattended root operations when
no approved storage/unlock provider exists. A recovery capsule is not the runtime
vault and its recovery key is not cached to enable unattended operation.

## Recovery capsule and parameters

Default recovery credential: a freshly generated 256-bit random key, encoded as
a versioned, checksummed printable string. Decode to the original 32 bytes before
KDF input; separators and checksum are presentation only. Confirm possession by
asking the user to re-enter selected portions before completing setup. Keep the
capsule in a different location from the key. No security question or server-side
password reset can replace it.

An optional user passphrase must be a separate, password-manager-generated secret
with at least 128 bits of generated entropy. A minimum character count alone does
not establish that entropy; the existing KDF's byte-length check is insufficient
as a UI policy. Recommend shipping generated keys first and deferring arbitrary
user-chosen passphrases. A later passphrase profile must specify UTF-8 encoding,
input limits and exact normalization; it must never silently truncate or alter
an existing secret.

| Capsule v1 parameter | Proposal |
| --- | --- |
| KDF | Argon2id, version 0x13 |
| Memory | 262144 KiB (256 MiB) |
| Passes / lanes | 3 / 1 |
| Salt / output | 32 fresh random bytes / 32 bytes |
| Payload encryption | AES-256-GCM, fresh random 12-byte nonce, full 16-byte tag |
| Input envelope budget | 64 KiB before parsing or KDF allocation |
| KDF concurrency | One recovery derivation per process; cancellable job admission |

This preserves the existing recovery KDF cost and crypto implementation rather
than silently weakening it for custody. Recovery is rare and can tolerate a
larger memory budget than message operations; one lane avoids assuming a parallel
runtime. The random key supplies the main guessing resistance. Argon2id adds a
memory cost if a future passphrase profile is supported.
[RFC 9106 section 4](https://www.rfc-editor.org/rfc/rfc9106.html#section-4)
gives 2 GiB/one pass/four lanes and a memory-constrained 64 MiB/three passes/four
lanes as reference choices. Our 256 MiB/three passes/one lane profile is a project
choice, not either reference profile or a claim of equivalent attack cost.
Benchmark peak memory and latency on supported desktop/TUI recovery machines
before freezing v1; target an interactive recovery flow, with no latency claimed
from measurements in this design phase. Failure to allocate must yield a typed
error, never downgrade parameters. Any alternative profile needs separate review,
explicit versioning and cross-client test vectors.

The capsule plaintext contains only the seed, root public key/commitment, account
binding and custody/recovery epochs. Authenticate a canonical header containing
format/domain, KDF parameters, salt, nonce, account binding and epochs as AEAD AAD.
After decryption derive the public root again and compare every binding. Require
exact supported parameter profiles and lengths before invoking Argon2, reject
unknown versions, duplicate keys and invalid I-JSON, and return a generic unlock
failure for wrong credentials or authentication failure. Root seed, capsule
plaintext and derived key are zeroized on success, cancellation and error.

Creating a new capsule uses a new random key, salt, nonce and recovery epoch. The
primary verifies the durable capsule by decrypting it before acknowledging setup.
The user must confirm storage before older recoverability is retired. Rotating
the key protects the new capsule; it does not revoke an old copied capsule plus
its old key, because they recover the same root. Suspected disclosure of that
pair is a root compromise and requires a new identity.

## Custody records and branch authority

Extend the existing complete signed-device-set model with a newly versioned,
domain-separated custody record. Proposed additional signed fields are
`custody_epoch`, `primary_device` (root-qualified reference), `recovery_epoch`,
minimum custody protocol version and per-device role/erasure acknowledgement
state. Primary must be active and unique. Preserve all device tombstones and
key commitments. Use an explicit `legacy` versus `primary_custody` mode; no
implicit upgrade based on a client-supplied role label.

Publish against the last accepted device-set hash/epoch with an exact
acknowledgement; persist intent and observation durably across crashes. Verifiers
retain the highest custody and device epochs and refuse rollback or same-epoch
conflicts. Clients without the new verifier cannot participate in a migrated
account; capability negotiation must fail closed, not strip unknown fields.
A holder of the root can still forge a higher record, so the primary label is a
custody policy, not cryptographic protection from a stolen root.

Separate durable root authorization of a branch from short-lived session
possession. The primary certifies its signing/agreement keys, root, device epoch,
kind and capabilities with a maximum 30-day authorization lease; current
signed-set membership supplies revocation. Renewing that certificate requires
the primary, but does not change device keys or advance the device-set epoch
merely to renew a lease. A secondary can operate with the primary offline until
its lease expires. After expiry, history remains readable and new authenticated
network operations wait for primary renewal. This preserves a finite first-observer
exposure to withheld revocations instead of making old root endorsements eternal.
An enrolled secondary signs each bounded-lifetime session proof/challenge with
its branch key, binding server audience, session/channel, fresh nonce and
certificate hash. Servers verify both layers and current device authority.
A branch cannot certify another branch, extend capabilities, change keys or
mint a root-signed set. This requires a new registration version across router,
gateway and SDK; current one-hour root-signed proof refresh cannot simply be
reused or allowed to expire. Replay guards remain session-bound and root-qualified.

| Operation | Required authority after implementation |
| --- | --- |
| Initial identity creation, custody setup and recovery capsule issuance | Primary root signer with human confirmation |
| Add device; rotate any branch key; revoke device; publish device set | Primary root signer |
| Transfer primary, change recovery policy/key, renew branch authorization, issue/revoke delegation | Primary root signer |
| Register/refresh/resume an enrolled device session | Branch signature + root-issued certificate + current set |
| Prekeys, DM/group message encryption, receipts, calls and transport envelopes | Branch keys and current device authority |
| Sibling history/contact sync and ordinary data backup | Branch authentication and authorized data keys; no root secret |
| Creator genesis and ownership transfer | Primary root signer; secondary can queue a request |
| Creator full snapshot and signed request result | Creator branch with the scoped delegation below, or primary root |
| Non-creator group change request | Requester's branch and certified group actor; current role checked |
| Recovery to a replacement primary | Recovery key + capsule, explicit recovery ceremony, then root signing |

Group actor certificates and other long-lived root authorizations must be issued
at enrollment or explicitly by the primary, retained as public objects, and
usable without the root signer. X3DH agreement identity in the inspected proof
path derives from branch material or a stored prekey bundle; do not regenerate
existing agreement keys during custody migration. Audit every root accessor:
public-root lookup, signing and recovery must be separate capabilities.

## Pairing, approval and primary replacement

1. A new secondary generates its branch signing/agreement keys locally. It sends
   a provisional enrollment proposal, never a root seed request. Nothing becomes
   routable or trusted until approval completes.
2. The unlocked primary creates a one-use, five-minute invitation. QR contains
   a fresh 256-bit secret and invitation identifier. For manual pairing use a
   short random code with a reviewed PAKE, explicit key confirmation and at most
   three failed attempts per invitation; then invalidate it. Rate limits are
   enforced by the primary, not only the relay. A short code is never a raw AEAD
   password or a substitute for authenticating the channel.
3. Recommend a vetted [SPAKE2 implementation using RFC 9382](https://www.rfc-editor.org/rfc/rfc9382.html)
   with fixed primary/secondary roles and its specified key-confirmation flow,
   for both QR and manual invitations. Bind the application context and the
   authenticated enrollment payload to root fingerprint, both endpoint keys,
   invitation id, custody epoch, intended role and principal kind. A later crypto
   review must freeze the exact supported suite and implementation; do not create
   a custom PAKE. The relay may forward opaque bytes but cannot approve enrollment.
4. Both screens show the matching account fingerprint and new device fingerprint;
   primary displays device name, requested capabilities and expiry. User presence
   and explicit approve are mandatory. Sign the exact displayed proposal and
   current device set; reject changes, stale epochs and replayed approvals.
5. Publish the new signed set and obtain its exact durable acknowledgement before
   releasing branch authorization and starting account sync. Retry by proposal
   id without duplicating enrollment. If acknowledgement is uncertain, reconcile
   the signed record; never copy a root seed as a fallback.
6. Secondary verifies the root fingerprint, certificate, set inclusion, key
   commitments and transcript. Close and erase invitation/session secrets. A
   cancelled or expired invitation leaves no active device or usable authority.

Entering the recovery key is a different operation: explicitly recover/promote
this device as the new primary, then pair additional secondaries. Do not accept
a recovery key into a device that will remain secondary. This prevents a hidden
root-seed path disguised as normal pairing.

For planned primary transfer, the old primary approves a trusted new human
primary and sends the root over the authenticated one-use channel, wrapped for
the recipient's local vault. Stage, verify and commit the higher custody record,
then erase the old primary's signer and demote or revoke it. Use a durable journal
and retryable acknowledgement; a temporary overlap during transfer cannot be
eliminated atomically across offline devices. Report transfer incomplete until
the old primary acknowledges deletion. Prefer revoke when retiring the machine.

After primary loss, unlock the capsule only in the replacement primary's vault
flow, generate fresh branch keys, refresh the signed set, revoke the lost primary,
advance custody/recovery epochs and rotate the recovery key. Activate with fresh
outbound sessions and group sender chains. A surviving secondary may provide a
higher signed-set checkpoint without providing root material. Check local and
surviving-device epoch pins before publication. If all trusted checkpoints are
lost, a malicious server can withhold newer signed state; signatures alone cannot
prove global freshness. Surface that uncertainty and require explicit recovery
confirmation, rather than claiming an online lookup resolves it. A stolen unlocked
old primary is already a possible root compromise, not repaired by branch revocation.

## Legacy migration and erasure

Upgrade verifiers and backup paths before activating custody. The chosen existing
human device stores the root in its vault and verifies a recovery capsule. Freeze
legacy enrollment writers, fetch the highest known signed device set, and publish
a new custody record designating that primary and listing erasure requirements.
Each upgraded secondary verifies it, preserves its own branch/data keys, removes
root material from manifests, database values, staging and cached signer objects,
then restarts keyless and emits a branch-signed erasure acknowledgement bound to
record hash and device epoch. A narrowly scoped migration-control endpoint accepts
that acknowledgement without granting an ordinary application session. Only admit it to normal sessions after that ack;
record the acknowledgement in the next root-signed set. A crash before completion
resumes erasure, not the old root-enabled runtime.

Unreachable or incompatible devices remain visibly pending and cannot use the
new protocol until they erase and acknowledge; the primary can revoke them.
Do not label migration complete while pending devices remain. Revocation blocks
their branch but cannot neutralize root knowledge. An erasure acknowledgement is
an authenticated statement by an honest client, not remote attestation. Inventory
old backups and filesystem snapshots and explain their retained authority. If
any former secondary is untrusted, recommend a new identity instead of asserting
that migration restored a lost trust boundary.

The root commitment and contact safety material stay unchanged for cooperative
migration. Branch key rotation and revoked identities keep their normal epochs;
never reconstruct membership by signing a server's unauthenticated directory.

## Full backup and restore interaction

Both full streamed backup and legacy key backup must adopt custody together.
The current manifest backup includes the root seed; merely encrypting a full
archive with its ordinary backup password does not meet this design.

- Primary export includes an optional unchanged recovery capsule, encrypted
  independently with the recovery key. The outer archive password never unlocks
  that capsule. Never include the plaintext root, runtime root vault, hardware
  wrapping credentials or an exportable unwrap key.
- Secondary export includes no root capsule by default and no root secret. An
  explicitly copied recovery capsule may be transported only as opaque ciphertext
  with no recovery key. The capsule's account binding must match the archive.
- Export a logical, sanitized snapshot. Audit manifests, database rows, WAL,
  attachments, diagnostics and staging; copying an encrypted database plus its
  ordinary unlock key can still leak embedded root material. Preserve all user
  history and files, with existing explicit missing-attachment policy unchanged.
- Full restore remains streamed, authenticated and verify-then-commit; merge
  preserves live identity, monotonic authority and tombstones. Never restore a
  saved primary role or activate a root signer from ordinary backup credentials.
- An empty-root data restore generates a fresh secondary branch and needs primary
  approval before sending. Recovery promotion additionally needs the separate
  recovery key and capsule. Saved outbound ratchets remain archived/inactive;
  restore establishes fresh outbound DM and group chains before sending.
- Legacy archives that contain a root require explicit legacy recovery into a
  primary or a sanitizer that decrypts them inside an already trusted primary.
  They cannot be imported directly onto a secondary. Preserve importability
  through that controlled migration flow, and warn that retained old archives
  keep their former root authority. Headless restore cannot use that exception.

Do not silently omit history or attachments to achieve sanitization. Verification
counts/hashes, cancellation cleanup, encrypted staging, newer-wins data merge
and backup portability remain required. These are coordination requirements for
the full-backup implementation, not changes made by this note.

## Creator secondary group signing

Recommend delegated creator-device signatures, rather than requiring the primary
online for every snapshot. A secondary of the creator must be able to publish
full snapshots and process admin requests while the primary is offline. Other
account roots still request changes; delegation does not restore cross-root
multi-writer authority.

The primary issues a domain-separated root-signed certificate scoped to one
group genesis hash/id and current creator root. Bind the root-qualified device,
branch key commitment/device epoch, custody epoch, certificate id, allowed
operations, validity interval and delegation generation. Initial proposal:
30-day validity, no subdelegation, renewable only on the primary. Allow only
snapshot mutation and request-result signing under the existing role rules.
Do not allow identity enrollment/revocation, primary transfer, group ownership
transfer or group genesis creation. Those operations can queue for the primary.
A per-group certificate can be requested by a paired secondary without sharing
root material; a newly created group is not editable there until issued.

A new group wire version carries either the existing master signature or the
branch signature plus delegation chain. Verify the certificate against the
creator root established by genesis/ownership transfers; require current active
device membership, exact keys/epochs, non-revocation, time validity, delegation
generation and all normal content/role/size checks. Bind result signatures to
the original request hash, snapshot signatures to the complete content/hash,
and retain the independent authenticated transport-source check. An unendorsed
ordinary member or admin branch signature can never replace creator authority.

Use the same verified creator account and existing deterministic same-epoch
snapshot conflict rule across its delegated devices. Ownership transfer invalidates
old-creator delegations. Revocation/key rotation or a root-signed delegation
generation advance fences old certificates for future mutations. Persist highest
known generations and retain immutable historical authorization evidence, so
revocation does not erase already accepted group history or authorize new writes
from that history. Reject expiry as a typed approval-required condition; do not
fall back to raw root access. Before erasing a creator secondary's seed, provision
its actor certificate and required per-group delegations.

Offline receivers cannot know that a newer revocation exists. Fresh online
mutations require refreshed signed authority; when that is unavailable, wait
rather than accept a stale certificate as proof of current membership. Expiry
bounds some stale-certificate exposure but provides no immediate offline
revocation guarantee. Implementation must define and test the authority freshness
window and trusted clock behavior with the existing device-manifest policy. Proposed cache limit for new online
mutations is five minutes since a successful verified manifest refresh, with
no older cached fallback after refresh fails. This limits honest cache staleness,
not a malicious directory withholding newer signed records. The 30-day root-issued
branch lease and delegation expiry bound acceptance by a first observer; local
highest-epoch pins always take precedence. The primary may be offline while
directory services remain available.

## Headless identities and UX

`headless_ai` is never a primary, recovery destination or root-secret consumer.
Enforce this in signed policy and daemon APIs as well as UI. A human-operated
custody vault holds the root of a separate service identity and approves its
headless branch; the custodian is outside the headless deployment, not a hidden
primary service process. For that identity use an explicit external-human-custodian
record variant instead of marking an AI device primary. Provision only branch
credentials, public certificates and necessary scoped group delegations. If the
custodian is unavailable, existing authorized operations continue; enrollment,
recovery, root changes and expired-delegation renewal wait. This service-custodian
variant needs owner approval before implementation; it must not become a runtime
flag that lets a headless device promote itself or change signed principal kind.

Desktop account security shows primary/secondary/custodian role, root fingerprint,
verified devices, pending erasures, recovery setup and delegation expiry. Pairing
shows the exact new device and permissions, with approve/deny on the primary.
Recovery distinguishes restoring data from taking primary authority and warns
about the lost device and old recovery copies. Show an explicit blocked state
when primary approval is required; no silent account creation or seed copying.

TUI offers the same ceremonies with a QR payload or manual PAKE code, fingerprint
comparison and interactive secret prompts. Recovery secrets never appear in argv,
environment variables, logs, normal JSON responses or shell history. Primary
transfer and recovery need explicit confirmation, not an unattended yes flag.
Both clients display unknown recovery freshness and incomplete legacy erasure;
both retain read access to restored history while activation awaits approval.

## Staged delivery and tests

1. Freeze versioned custody, durable branch authorization/session proof and group
   delegation formats, domain separation and cross-client vectors. Review the
   threat model, PAKE library/suite and platform vault providers. Decide service
   custody semantics and freshness limits before code rollout.
2. Implement typed signer/public-identity separation and vault providers. Prove
   keyless SDK startup, registration beyond one hour, restart, prekeys and normal
   messaging. Add router/gateway verifiers before any account enables custody;
   reject downgrade/unknown critical versions and preserve exact ACK behavior.
3. Add primary enrollment, revocation, pairing, promotion and crash journals.
   Implement recovery capsule and both backup sanitizers before enabling setup.
4. Add creator delegation for actor certificates, full snapshots and results;
   retain root-only genesis/transfer and existing single-creator convergence.
5. Ship desktop/TUI ceremonies, headless provisioning and legacy migration;
   migrate opt-in accounts only after complete end-to-end compatibility checks.
   Release notes must identify legacy backups and untrusted-secondary limits.

Required test matrix for implementation:

- Deterministic KDF/capsule vectors; random salt/nonce uniqueness; tamper every
  header/payload field; wrong key, foreign root, truncation and unknown profile;
  KDF memory/length/concurrency bounds and cancellation/zeroization paths.
- Platform vault permission/unlock/cancel/restart behavior, missing hardware,
  provider failure without plaintext fallback, root-secret leak scans of account
  files, DB/WAL, exports, staging, logs and public API responses.
- Pairing MITM/key substitution, wrong account/role, replay, reflection, expired
  invitation, PAKE confirmation failure, retry budget, modified approved proposal,
  concurrent enrollment and uncertain publish ACK; secondary cannot add/revoke.
- Keyless secondary registration and proof renewal after one hour, session resume,
  revoked/rotated branch rejection, replay across roots/sessions/audiences, sibling
  history sync and messaging/calls with primary offline.
- Planned transfer/recovery crashes at every durable boundary, old-primary overlap
  visibility, branch revocation, rollback pins and withheld-state uncertainty;
  old capsule plus old key still recovers the same root (document the limitation).
- Mixed-version migration, unreachable device, forged erasure ACK, crash during
  erasure, rollback to old files, old backup import and retained root compromise;
  no false claim that revoking an old root holder removes its master authority.
- Primary/secondary full and key backups: archive password alone cannot unlock
  root; independent capsule recovery; no root import on secondary/headless;
  complete attachments/history, merge tombstones and inactive outbound state.
- Creator secondary snapshots/results with primary offline; foreign group/root,
  altered certificate, expired/revoked/rotated device, stale generation, ownership
  transfer, no subdelegation and forbidden genesis/transfer; same-epoch honest
  concurrency, arbitrary snapshot gaps and authenticated admin request results.
- Desktop/TUI approval parity and actionable waiting states; headless cannot
  become primary or recover through kind/mode spoofing, restored state or API.

Native regressions precede controller-run container/real-network tests. Include
existing identity, proof-renewal, sibling restore, group convergence, agent and
full-backup suites; add explicit primary-offline and stolen-secondary scenarios.
Phase 1 contains only this design and its decision report, with no new code,
wire format, migration or operational custody guarantee.

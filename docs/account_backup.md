# Full account backup and restore

The daemon job API backs up the complete unlocked SQLCipher account database,
including messages and local plaintext, receipts, contacts and restrictions,
conversation state, groups, member pins and roles, surfaces, tasks, settings,
attachment ciphertext, content keys, transfer metadata and inbound ratchets.
There are no message, contact, group or attachment count limits. SQLite snapshot
copy and archive I/O use bounded page/chunk buffers; attachment verification reads
BLOBs incrementally. Each attachment must pass its AEAD tag, ciphertext manifest
hash and plaintext hash. Create first attempts to fetch missing deferred attachments. Unavailable files fail by default with `attachments_unavailable`; an explicit retry with `allow_missing_attachments:true` records the missing selectors and expected hashes in the authenticated omission manifest. Corrupt stored files always fail. Missing or corrupt files are never silently skipped.

See [account writer ownership](account_writer_ownership.md) for process locking,
lease expiry, backup isolation and the checkpoint-overlap residual.

## Daemon workflow

An attended human frontend starts a job; agents cannot start backup/restore jobs.

| Method | Body | Immediate answer |
|---|---|---|
| `account.backup.create` | account scope, `output_path`, secret `passphrase`, optional `allow_missing_attachments:false` | `{job}` preparing |
| `account.restore.verify` | `input_path`, secret `passphrase` | `{job}` verifying |
| `account.restore.install` | `job_id` | `{job}` installing |
| `account.backup.cancel` | `job_id` | `{job}` cancelled after worker cleanup |
| `account.backup.jobs` | `{}` | `{jobs}` newest first; capability probe |

Restore and job listing work without any bound account, including from the entry
page. Subscribe with no account to `account.backup.job.changed` and
`attended_frontend:true`. This minimal daemon stream accepts only that topic.
Its frame `seq` is the daemon job stream cursor; each row has a separate rising
per-job `seq`. Reconnect using the frame cursor as `since_seq`; a cursor outside
retention produces `resync_required`. Slow subscribers receive `lagged` and must
reload jobs and reopen the stream. Polling `account.backup.jobs` is also supported.
One job is active at a time; recent rows are kept in daemon memory.

The whole secret-free row includes `job_id`, `kind`, `state`, `seq`, `path`,
`created_at`, `finished_at`, `progress`, and, when known, `counts`, `archive_bytes`,
`archive`, `restored`, `kept_newer`, `attachments`, `error`. Both `restored` and
`kept_newer` are per-category objects: contacts, conversations, messages, groups,
surfaces, tasks, attachments, attachment_bytes. Totals describe the exact snapshot,
not the currently advancing live account. Restore totals are trusted only after
header authentication. Attachment checks distinguish verified, mismatched, missing, explicitly `unavailable_at_source` (included in missing), and `local_missing_kept` (pre-existing undownloaded local references retained by merge, not archive omissions). Progress updates are coalesced at 250 ms or one percent; phase and terminal updates are immediate.

States are Preparing → Writing → Done for backup and Verifying → Verified →
Installing → Done for restore. Cancel is available until Installing. Verified
staging expires after 30 minutes. Cancel, expiry, failure and daemon restart discard
staging; the passphrase and staging key are never persisted. Unavailable-file failure diagnostics retain only their encrypted snapshot under a RAM-only key for at most 30 minutes. Restart clears the
in-memory job history; poll again to discover the current daemon's jobs.

## Native data-only archives

Native backups carry public signed account evidence and historical data. They
contain no legacy recovery manifest, root/device signing seed, account passphrase,
primary credential, vault reference or authority-key wrapper. The snapshot removes
local runtime work, pending recovery controls and local network selection before
archive encryption. Public evidence from the archive is never installed as live
authority. Authenticated native metadata and legacy manifest metadata are distinct;
ambiguous metadata is refused after archive authentication.

For an existing independently approved native installation, `account.restore.install`
keeps the `{job_id}` request and requires that account to be unlocked first through
ordinary `account.unlock`. The archive passphrase used by `account.restore.verify`
cannot unlock the local installation. The authenticated account anchor selects a
unique independently installed native identity; the archive's local account ID is
an origin label. A colliding or changed origin ID cannot select another identity.
Ambiguous installed matches fail closed. A private actor snapshot supplies the live
data key through a transient RAM-only wrapper. Installation rechecks immutable
pins before selecting a new generation. It retains the installation's data key and
wrapped key, authority file, branch selection, network selection, pins, denial
fences and replay floors. Native verification does not unlock the local database;
local pin conflicts are checked again during installation. Imported history is
merged; imported outbound sessions remain inactive. Existing live outbound sessions
are retained. After the installation worker runs the account remains locked;
explicitly unlock it with its local data passphrase. No secret is recovered from
archive metadata.

For a fresh installation, send `account.restore.install` with `job_id` and a new
local `passphrase`. This independently seals the restored data key; it is separate
from the archive password and never comes from archive metadata. The preview names
a fresh local account ID. Installation generates fresh branch keys in the local
credential provider, imports history, and leaves that branch uncertified with
`networking_pending`. No primary credential is loaded or treated as consent. Omitting
the local passphrase refuses with typed `networking_pending` without creating an
account. Existing-installation merge keeps its `{job_id}` request and ordinary
unlock precondition.

Complete the separate user-started [phrase recovery ceremony](local_bus_account_recovery.md)
to certify the fresh branch and publish the replacement authority. A matching durable
publication ACK is required before networking becomes live; an uncertain ACK leaves
the same signed intent pending for reconciliation. Until SAS pairing is implemented,
adding another native installation uses this recovery/promotion path and revokes the
former branches. Restore alone never approves a branch.

## Verification and atomic installation

Verification authenticates the entire archive into a private staging directory,
checks SQLCipher integrity, public identity and every attachment. Legacy previews
also check epochs and immutable contact/member pins against the local database;
native local pin checks occur at installation using the already-unlocked data key. Staging is encrypted with a fresh random master key held only
in RAM; independently derived keys protect its database and sealed identity
metadata. Passphrases are erased after header authentication. No plaintext history
or private identity metadata is written to staging.

Install quiesces only the affected account and prepares a complete new encrypted
generation. All files and directories are synchronized before one FULL/WAL account
index transaction selects the generation, its wrapped database key and recovery
manifest. An error before that commit keeps the previous generation selected.
An interrupted pre-commit install cannot expose partial live state. On restart,
secret-free ownership markers remove abandoned output prefixes and unselected
prepared generations. The committed generation pointer always wins, including a
crash immediately after commit. A durable post-commit marker reclaims exactly the previously selected database/generation; unrelated unmarked data is preserved. Failed cleanup logs a warning and never blocks daemon startup. Periodic retry handles job folders only. Generation cleanup runs at startup and after committed installs, under per-account leases that skip active installs. Other accounts and daemon requests continue.
Normal contact/conversation/message invalidations are queued through the durable
outbox, followed by `account.restored`; clients reload after completion.

Output is written to a private partial file and published exclusively after final
AEAD and fsync completion. Hard-link publication falls back to an exclusive no-replace rename, then to exclusive `create_new` plus a bounded streamed copy and fsync on filesystems such as NFS/FUSE that lack both operations. The copy fallback makes the final path visible while writing; clients must wait for Done. Failure/cancellation removes its partial final, and copy I/O never holds the job-state lock. Existing output files are never overwritten. Space is
estimated before writing and checked between bounded copy/write batches. Partial
output and encrypted staging are removed on cancellation or failure.

Typed failures: `account_busy` (retryable, message `account in use by another
process`), `wrong_passphrase`, `tampered`, `truncated`, `unsupported_version`,
`schema_reset_required` (`SchemaResetRequired`, C ABI code 23),
`insufficient_space` (needed_bytes, available_bytes), `unreadable`, `not_writable`,
`staging_expired`, `interrupted`, `attachment_mismatch`, `attachments_unavailable`, `identity_rollback`,
`root_conflict`. A wrong passphrase fails immediately after header authentication,
before staging or account installation. Any unapproved missing or mismatched attachment refuses verification and installation. Root replacement is always refused; merge accepts older epochs and keeps the live manifest. Legacy fresh-install identity adoption still uses checked epoch advancement.

## Merge and outbound activation

For an existing account, merge occurs in a private copy of the live generation.
Rows with version/epoch/time ordering use the newer value. Ties keep the live
value, except a tied contact restriction wins over an acceptance. Message and attachment deletions are monotonic and never revive plaintext or a deleted file. Restrictions and tombstones use their
stored version/time; read/delivery receipts use their own timestamps. Immutable
contact roots and group member pins cannot change. Unordered conflicts keep the
live value; nonconflicting history is added. The live recovery manifest and live
outbound crypto always win. Imported outbound state is archived, never resumed. Archive `backup/*` controls never enter the live merge.
The report distinguishes restored and retained values per category. Verify and install strictly authenticate the archive's supplied payloads and references. Merge does not demand downloads of unchanged local references: those stay fetchable and are reported as `attachments.local_missing_kept`, outside source-omission counts. Local corruption outside the archive contribution does not grant any archive omission approval.

Released/deleted held contact messages have per-message erasure fences retained through their seven-day request validity window; expired fences are pruned. Merge replacement is not a user erasure and does not create a fence. Direct-message projections and deletion tombstones also prevent older held copies from returning. Block/decline decisions and explicit lifts (unblock/accept) carry durable ordered decision times. Newer consent wins in either merge direction, including same-tick changes; an older backup cannot restore a lifted denial. Requester authority floors keep the maximum epoch and retention time. Unseen held history remains private; merging never executes its controls.

For legacy archives on an empty data root, restore preserves all history, attachment keys and inbound
or archived sessions needed for late messages. Saved outbound DM sessions are
inactive; saved outbound group chains stay archived. Before the first send, the
device performs fresh root-authorized activation at an increased device epoch.
The first post-restore send establishes fresh outbound DM sessions; each group's
first send rotates its sender seed/chain ID before distributing it to members. All newly created distributions use
`ramflux.sdk.group_sender_key.distribution.v3`, which binds the fresh seed into the
chain ID; participating receivers need v3 support. Existing v1/v2 receive chains
remain readable. The UI must show **re-establishing secure
sessions** while `account.status` / `sync.status.get` has
`secure_sessions:reestablishing`; `account.secure_sessions.changed` announces ready.
If activation is refused, history remains readable and sending fails closed.
Merge preserves existing live outbound sessions. The first group send without a live sending checkpoint gets a fresh seed-bound chain; a known chain ID with different secret material is refused loudly. Inactive receive-only DM chains remain subject to the ordinary eight-chain retirement limit and a 24-hour late-delivery deadline measured from restore/migration, never from last use. Retirement erases private archived copies as well as live session records.

Transient network work is intentionally not resumed: queued gateway sends,
own-device sends and runtime command idempotency/outbox receipts are not replayed
from the imported snapshot. Their historical records remain available. CA bytes
are included; network endpoint reachability and external helper processes are
re-established separately. The account database is the backup boundary: temporary
upload spool files outside that database are not historical attachments. Incomplete referenced attachments require the explicit omission workflow described below.

Before opening the backup snapshot, an independent account reader worker builds a hash set of stored attachment metadata and scans reference metadata once. It computes the missing total once and drops that read transaction before the actor attempts fetches. Payload bytes are never loaded by this scan. Preparing-phase progress reports attempted items and an estimated total; the final attempted count is emitted before snapshot capture. No reader snapshot is held across network waits. The one coherent backup reader opens only after this phase.

## Explicit unavailable-file workflow

`attachments_unavailable` reports `unavailable_count`, a first page of up to 64
`unavailable_attachments` selectors, and `unavailable_next_cursor`. Request all
remaining pages with `account.backup.jobs {job_id, missing_after}`; its answer is
`{job, unavailable_attachments, unavailable_count, unavailable_next_cursor}`.
Continue until the cursor is null. Encrypted diagnostics expire after 30 minutes,
when their recent job is evicted, or immediately when their account erasure
generation changes; after daemon restart retry create. No grant,
content key or attachment reference enters the error details. An explicit retry
with `allow_missing_attachments:true` still tries fetching first. It records every
remaining valid selector and its expected hashes in the encrypted archive's
`backup_missing_attachment` manifest, whose count is also in the authenticated
header (`missing_attachments`). Restore validates that approval against the exact
references; unrelated approvals cannot excuse a missing or corrupt file. Verify
and install report the explicit unavailable count separately. No item-count limit
or silent prefix is introduced by diagnostic paging or the omission manifest.

The local bus checks the same-user peer UID; daemon attendance is self-asserted.
Account-scoped headless restrictions do not authenticate another same-user process.

## Compatibility and own-device history

`account.backup.export` / `account.backup.import` remain the legacy key recovery
API. Manifest-only and manifest-plus-contact files stay importable with that API;
they never acquire full-history semantics. The full job API uses the authenticated
stream format documented in [backup_stream_format.md](backup_stream_format.md).

Own-device synchronization retains the existing per-page authority admission
budgets. Larger contact/member-authority sets use an authenticated encrypted
continuation chain. The importer follows every page and persists continuation
receipts for retries. Authority pages are installed before ordinary group/message
history. Small snapshots retain v1 compatibility; paged snapshots use v2 bundles,
which older importers explicitly refuse. A single authority record exceeding a
page's byte budget fails explicitly rather than truncating the account.

## Dedicated large-data acceptance

The ignored SDK test
`bus::backup_jobs::tests::large_backup_restores_ten_thousand_messages_one_thousand_contacts_two_hundred_groups_and_gibibyte_files`
creates 10,000 messages, 1,100 contacts, 200 groups, two 512 MiB attachments and a
small attachment. It runs the production create/verify/install job workflow,
checks exact counts, and authenticates every file on verify and install. Run it
on a suitably provisioned QA Linux host only; it explicitly refuses macOS:

```sh
cargo test --release -p ramflux-sdk bus::backup_jobs::tests::large_backup_restores_ten_thousand_messages_one_thousand_contacts_two_hundred_groups_and_gibibyte_files -- --ignored --exact --nocapture --test-threads=1
```

The large fixture generator uses ordinary object creation and needs at least
4 GiB RAM and 12 GiB free disk. Export/verify/install use bounded buffers; fixture
generation is outside that memory guarantee. Crypto review and large-data QA are
separate acceptance evidence from local unit tests.

## Copy recovery and reclamation limits

When both hard-link and exclusive-rename publication are unavailable, the final
file is created exclusively and its device/inode ownership marker is fsynced
before any copy bytes are written. Restart removes an owned incomplete final
file, and never claims a pre-existing destination or a replacement inode. The
marker is removed only after the complete copy and its parent directory are
synced. Active jobs remain excluded from periodic job-folder cleanup.

If old-generation reclamation fails and another install replaces that generation
before a restart, an earlier encrypted database can remain orphaned after its
reclamation marker is removed with the replaced directory. Its key is discarded;
this accepted limitation can waste disk space but does not select or resume the
orphaned state.

## Reference CLI

`rf account backup export --account ACCOUNT --out ARCHIVE` creates a full-data
archive and waits for its job to finish. `rf account backup import --in ARCHIVE`
verifies, installs and waits for the restore job. Both read the archive password
from `RAMFLUX_ACCOUNT_BACKUP_PASSPHRASE` or the named `--passphrase-env` variable.
For a new installation, explicitly provide `--new-passphrase-env VARIABLE` with
an independent local data passphrase. Existing installations must be unlocked
before import. The commands use the attended daemon job workflow above; they no
longer call the old manifest/key-only backup endpoints. A completed new-install
restore still requires explicit recovery before networking is authorized.

Writer-lock and index-read I/O failures during restore checks or installation use
`unreadable`. Failure to unwrap or verify the local wrapped DB key (including a
stale local passphrase) and a failed `PRAGMA integrity_check` also use `unreadable`.
`tampered` is reserved for backup archive MAC, hash or signature verification
failures. These failures follow the
[account writer error mapping](account_writer_ownership.md#error-codes).

## Attachment erasure and restore boundaries

An attachment received by several messages keeps its payload and content key until
its last message owner is deleted. Separate references retain their own private
key slots. Explicit standalone object puts/imports keep their independent retention
claim; deleting a message does not delete such an object. Unconverted send holds
expire within ten minutes, with cancellation cleanup on the normal send path.
Internal history containers expire after one hour and are also retired when a
message whose bytes they carry is deleted.

Last-owner deletion removes the payload, content key, cached chunks, private
references and progress in the message deletion transaction. Cached keys are wiped
and runtime-owned download spools are closed and unlinked before successful
completion. Later get, fetch, share, decrypt and export requests report
`ObjectErased`; `rf` reports that code and exits unsuccessfully without terminating
the daemon. The C ABI uses `RAMFLUX_ERR_OBJECT_ERASED` (19), while account
writer contention remains `RAMFLUX_ERR_ACCOUNT_BUSY` (18). Object identity
conflicts and unverifiable ownership use codes 20 and 21 respectively. Cached
operation responses become compact erased receipts.

Portable fences contain only a domain-separated BLAKE3 commitment to the account
root, wire object id and verified ciphertext manifest, plus opaque lookup indexes.
Both native and full restore merge fences before payloads or private archive
copies, regardless of payload timestamps. A post-delete backup preserves these
fences across rekey and fresh restore. Reusing a wire id with different verified
ciphertext requires an explicit checked replacement; ordinary put/import and
conflicting restore refuse it with `ObjectIdentityConflict`. SDK
`replace_encrypted_object` and `replace_shared_object` require the expected prior
manifest, or explicit expected absence. Active owners of a different identity
prevent replacement. A replacement never removes an existing fence.

A backup worker captures the erasure generation and asks the account's ordered
writer for publication authorization after staging and encryption. The generation
also advances when one shared message reference is removed while another owner
keeps the payload. If deletion
wins first, the job fails with `object_erased` and discards its staged snapshot,
key and partial archive; create a new backup after deletion. If authorization
wins first, the archive is a pre-delete external copy.

Account schema version 12 installs a versioned checksum sentinel on migration 1.
Older binaries fail closed with `MigrationChecksumMismatch`, naming that migration
and its writer-floor version. Operator recovery is to upgrade the binary and
reopen the same account; no data change is required. Keep the sentinel and
migration checksums intact. Newer unsupported schema versions also fail closed.

Existing accounts discover ownership with a durable phase/cursor. Each account
open scans at most 256 metadata rows and decodes at most 1 MiB. Reclamation starts
only after discovery completes, handles at most one proven imported orphan per
maintenance transaction, and measures ciphertext and legacy body sizes before
reclaiming either BLOB (each is bounded by the supported 16 MiB ciphertext size
plus its authentication tag). Oversized legacy BLOBs await a separate policy.
Ambiguous legacy zero-reference objects remain readable and listed as before;
missing references alone never prove that an object may be erased. This is a
residual limitation for previously orphaned ciphertext and keys. Legacy archives
whose private attachment references cannot be reconstructed safely are refused
with `object_ownership_unverified`, rather than installed. Reopen and upgrade the
original account to complete discovery, then create a verifiable archive; retain
an intact source if ownership remains ambiguous.

A fresh restore using only a pre-delete archive has no newer erasure fence.
Deletion does not revoke another device's data, relay copies, user-owned exports
or bytes already returned to callers. Those copies are outside local erasure.


Upgrade ownership discovery promotes a legacy payload to imported in the same
transaction that proves a live message owner. A newly authenticated message owner
also promotes an existing legacy payload. Explicit standalone retention remains
standalone. Only rows that remain ambiguous without a proven owner retain the
legacy preservation policy; a proven pre-upgrade attachment is erased after its
last message owner is deleted, including its ciphertext and content key.

Two remaining crash/upgrade limitations are tracked separately: task fallback
metadata written before message-footprint enrollment can remain after deletion;
and a sender process dying after successful delivery but before recording the
sender-side attachment owner can lose its own copy when the send hold expires.
Receiver ownership is durable before import, so an interrupted receive can retry
without orphan reclamation fencing its attachment.

Pre-import attachment revocations are exported as payload-free placeholders with
no chunks or content key. A placeholder lives exactly while a live reference to
its private selector survives and no payload fence covers it. Removing the last
reference to that selector removes its placeholder and revocation provenance,
even when another selector keeps the shared payload alive. Later exports omit the
erased selector and its private copies. `ObjectErased` remains distinct from
`attachment deleted`.

New revocations require a nonzero manifest from an authenticated reference or a
valid legacy actor with an agreeing owner and an exact owning message. Display
metadata alone cannot authorize one. Valid legacy revocations remain honored and
are retired with their owning message, including before ownership discovery has
finished. Sender revocations without matching authenticated ownership are refused.

During restore, a legacy payload-free placeholder with a zero manifest can inherit
the verified manifest of an admitted live reference. When it overlaps a live wire
object, ordinary timestamp arbitration still applies; a newer live object can win.
A surviving same-selector reference preserves the revocation veto. Erased selectors,
fenced payloads and rejected owners do not restore their placeholder or provenance.
Unowned legacy placeholders and their selector-only copies are omitted while other
valid data can restore; ambiguous or conflicting authenticated ownership fails with
an ownership or authorization error. Restore never invents a payload identity from
zeros or rewrites the input archive. Existing untouched live-store orphan rows are
not scrubbed by startup.

> Restoring historical data can keep a message while omitting its attachment,
> even if you never deleted that message. If this device previously erased the
> attachment's selector and has no surviving reference for it, the historical
> attachment is refused as `ObjectErased`. A newly authenticated message using
> the same selector can be accepted when its payload is not fenced; historical
> restore does not receive that fresh-message exception.

# Full account backup and restore

The daemon job API backs up the complete unlocked SQLCipher account database,
including messages and local plaintext, receipts, contacts and restrictions,
conversation state, groups, member pins and roles, surfaces, tasks, settings,
attachment ciphertext, content keys, transfer metadata and inbound ratchets.
There are no message, contact, group or attachment count limits. SQLite snapshot
copy and archive I/O use bounded page/chunk buffers; attachment verification reads
BLOBs incrementally. Each attachment must pass its AEAD tag, ciphertext manifest
hash and plaintext hash. A missing deferred attachment makes a full backup fail;
fetch it first and retry. Missing or corrupt files are never silently skipped.

## Daemon workflow

An attended human frontend starts a job; agents cannot start backup/restore jobs.

| Method | Body | Immediate answer |
|---|---|---|
| `account.backup.create` | account scope, `output_path`, secret `passphrase` | `{job}` preparing |
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
header authentication. Attachment checks distinguish verified, mismatched, missing.

States are Preparing → Writing → Done for backup and Verifying → Verified →
Installing → Done for restore. Cancel is available until Installing. Verified
staging expires after 30 minutes. Cancel, expiry, failure and daemon restart discard
staging; the passphrase and staging key are never persisted. Restart clears the
in-memory job history; poll again to discover the current daemon's jobs.

## Verification and atomic installation

Verification authenticates the entire archive into a private staging directory,
checks SQLCipher integrity, identity, epochs, immutable contact/member pins and
every attachment. Staging is encrypted with a fresh random master key held only
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
crash immediately after commit; unmarked older data is preserved. Other accounts and daemon requests continue.
Normal contact/conversation/message invalidations are queued through the durable
outbox, followed by `account.restored`; clients reload after completion.

Output is written to a private partial file and published exclusively after final
AEAD and fsync completion. Existing output files are never overwritten. Space is
estimated before writing and checked between bounded copy/write batches. Partial
output and encrypted staging are removed on cancellation or failure.

Typed failures: `wrong_passphrase`, `tampered`, `truncated`, `unsupported_version`,
`insufficient_space` (needed_bytes, available_bytes), `unreadable`, `not_writable`,
`staging_expired`, `interrupted`, `attachment_mismatch`, `identity_rollback`,
`root_conflict`. A wrong passphrase fails immediately after header authentication,
before staging or account installation. Any missing/mismatched attachment refuses
verification and installation. Root replacement and epoch rollback are refused.

## Merge and outbound activation

For an existing account, merge occurs in a private copy of the live generation.
Rows with version/epoch/time ordering use the newer value. Ties keep the live
value, except a tied contact restriction wins over an acceptance. Message deletions
are monotonic and never revive plaintext. Restrictions and tombstones use their
stored version/time; read/delivery receipts use their own timestamps. Immutable
contact roots and group member pins cannot change. Unordered conflicts keep the
live value; nonconflicting history is added. The live recovery manifest and live
outbound crypto always win. Imported outbound state is archived, never resumed.
The report distinguishes restored and retained values per category.

On an empty data root, restore preserves all history, attachment keys and inbound
or archived sessions needed for late messages. Saved outbound DM sessions are
inactive; saved outbound group chains stay archived. Before the first send, the
device performs fresh root-authorized activation at an increased device epoch,
starts fresh outbound DM sessions, and rotates each group's sender seed/chain ID
before distributing it to members. Rotated distributions use
`ramflux.sdk.group_sender_key.distribution.v3`, which binds the fresh seed into the
chain ID; participating receivers need v3 support. Existing v1/v2 receive chains
remain readable. The UI must show **re-establishing secure
sessions** while `account.status` / `sync.status.get` has
`secure_sessions:reestablishing`; `account.secure_sessions.changed` announces ready.
If activation is refused, history remains readable and sending fails closed.
Merge preserves the existing live outbound sessions and does not require rotation.

Transient network work is intentionally not resumed: queued gateway sends,
own-device sends and runtime command idempotency/outbox receipts are not replayed
from the imported snapshot. Their historical records remain available. CA bytes
are included; network endpoint reachability and external helper processes are
re-established separately. The account database is the backup boundary: temporary
upload spool files outside that database are not historical attachments. Incomplete
referenced attachments cause a strict missing-file failure rather than omission.

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

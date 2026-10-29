# Account writer ownership and transaction boundaries

Opening a writable `AccountDb` acquires a nonblocking advisory file lock at
`<account-index-root>/accounts/<local-account-id>/.writer.lock` before opening
SQLite, applying migrations or changing runtime settings. A second process gets
`StorageError::AccountWriterBusy(account_id)` and must close its attempted account
session and retry after the owner stops. The account directory is canonicalized,
so directory aliases share ownership. The lock is stable across restored database
generations; it is not placed beside a generation-specific database file.

Connections in the owning process share the file descriptor lease. Their actual
write transactions still serialize through SQLite `BEGIN IMMEDIATE` and the
five-second busy timeout. The ownership lock does not replace SQLite locking.
One process registry serializes sharing and final descriptor teardown, so a new
acquire cannot open a second descriptor while the previous registry entry exists.
Query-only readers, pinned backup readers and private snapshot/staging databases
do not acquire or prolong account writer ownership. Opening the account index
alone does not acquire ownership. Account creation/replacement and generation
selection take the account lease before changing their index pointer. Quiesced
restore holds it across identity checks, copying the selected generation and
installation; generation cleanup takes it before reclaiming files and skips
accounts owned by another process. Each live writer worker retains ownership
until all its clones close and its SQLite thread has finished closing the database.

## Expiry, lost holders and backup

This is a kernel descriptor lease, with event-based expiry rather than a clock
TTL: the final owner explicitly unlocks before closing its descriptor; process
exit, including abnormal termination, also releases ownership. A live but hung owner retains ownership; stop or
terminate that process (`kill -TERM <owner-pid>` on Unix, or the service
supervisor's stop command), wait for it to exit, then retry opening the account.
Elapsed time, a PID file and a file's modification time never authorize takeover.
There is no heartbeat or stored expiry to restore. Startup never deletes or
recreates an existing lock file to recover ownership. Deleting the inode while an
owner is alive could admit two owners and is unsupported.

The empty owner-only sidecar remains after release. Its existence grants no
ownership. SQLite backup exports database pages, not account-directory sidecars;
restore creates/acquires the destination account's local descriptor lease.
Neither archives, generation manifests nor account database state contain a live
writer lease. The two-process regression covers refusal while an owner is alive,
last-worker release, readers not retaining ownership and recovery after a killed
holder. A snapshot/restore regression checks destination ownership independently.

Advisory locking requires a local filesystem with working advisory locks and
cooperating product processes. External SQLite tools that bypass this API are
outside this ownership contract. Use `BackupDatabase` on a selected generation
only while holding `AccountIndex::acquire_account_writer` for restore checks;
quiesce it before copying or replacing it. Ordinary live writes use `AccountDb`.
Do not copy/remove an active account directory.

If advisory locking is unsupported or otherwise fails, account opening fails
closed and reports both the writer-lock path and the filesystem error. Move the
data root to a local filesystem with advisory-lock support before retrying.

## Error codes

Writer contention is retryable; local filesystem failures are not evidence of
archive tampering. The storage and SDK boundaries use these classifications:

| Cause | Storage | Backup job | Local bus | C ABI |
| --- | --- | --- | --- | --- |
| Another process holds the lock | `AccountWriterBusy` | `account_busy`, retryable | `account_busy`, retry after 1000 ms | `RAMFLUX_ERR_ACCOUNT_BUSY` (18), retryable |
| Lock open/locking or index I/O fails | `Io` (or `Sqlite` for index queries) | `unreadable` | `storage_unavailable` | `StorageFailed` (8) |
| Local wrapped DB key authentication fails | `Integrity` | `unreadable` | `ValidationFailed` (existing) | `StorageFailed` (8, existing) |

Unsupported locking, permission failures, a full filesystem and a directory at
the lock-file path are local I/O failures. The lock error retains the path and
underlying filesystem cause. `tampered` is reserved for backup archive integrity
failures (archive MAC, hash or signature). Local wrapped-key authentication failures
and I/O errors use `unreadable` at backup surfaces. SQLite page-budget exhaustion
during archive work continues to use the backup job's `insufficient_space` code.
Bus contention
includes `reason_code: "account_busy"`, the message "account in use by another
process" and `retry_after_ms: 1000`. Wait for ownership to be released before
retrying; the retry hint does not expire or evict an owner.

The C header is generated from the SDK's C ABI declarations. Code 18 and its
`RAMFLUX_ERR_ACCOUNT_BUSY` constant are additive; existing numeric codes retain
their meanings. A wrong secret and a damaged wrapped-key MAC cannot be
distinguished cryptographically; both report "wrong passphrase or damaged local
key" and keep their existing bus and C ABI codes.

## Managed transactions and source guard

Live account writes use `immediate_transaction` (or `write_transaction` /
`surface_transaction`). Read snapshots use `deferred_transaction`. Nested writes
are allowed only inside a known immediate outer transaction. An untracked raw
`BEGIN` may host nested read savepoints but cannot be promoted to a writer.
Pinned backup readers start through the managed deferred boundary and retain the
outer snapshot until the reader closes.

SQLite can automatically roll a transaction back, for example after an I/O/full
error or a `ROLLBACK` conflict action. A subsequent wrapper acquisition detects
that its old tracked transaction is gone, invalidates it and returns an error for
that phase. A later phase may acquire a new transaction. Transaction IDs prevent
a stale guard from committing, rolling back or clearing the mode of that new
transaction. Errors still propagate; this mechanism does not silently retry a
partially completed operation.

Run `python3 -B scripts/check-account-transactions.py` and
`python3 -B scripts/test_account_transactions.py`. The CI **Rust checks** job runs
both. The source guard scans all production Rust in the storage crate, where the
managed connection type is crate-private. It rejects raw savepoint/transaction
APIs, including associated-function and UFCS forms inside `connection.call`, and
raw SQL transaction starts/terminators, including `concat!`-built statements.
It also follows simple `const`, `static` and `let` string bindings used as the
SQL argument, and covers `query_row_and_then` and associated `Connection` calls.
Exceptions name exact functions: managed entrypoints/acquisition, commit and
rollback-on-drop in `database.rs`,
`BackupDatabase::enqueue_restore_events` and
`BackupDatabase::merge_backup_with_group_actor` on private staging databases.
Read-only backup snapshots need no raw-SQL exception. Transaction keywords
supplied through `format!` substitutions and calls through aliased rusqlite types
remain explicit review items; the source guard cannot resolve Rust values or types.
Other functions in those files remain checked. Test-only code is excluded; the
checker is a source guard, not a substitute for Rust types or SQL review.

## Checkpoint overlap residual

`checkpoint_retired_secrets` still uses `PRAGMA wal_checkpoint(TRUNCATE)`.
Concurrent readers (including pinned backup snapshots) or another connection's
immediate writer can prevent truncation. SQLite may wait up to the configured
busy timeout and report a busy checkpoint result without a SQL error. Account
process ownership prevents a second cooperating writer process, but does not
remove reader overlap or contention among connections in the owning process.
This can delay the calling operation and leave WAL pages until a later successful
checkpoint. Checkpoint policy, result handling and scheduling are unchanged here;
callers must not treat an attempted checkpoint as proof that the WAL was truncated.

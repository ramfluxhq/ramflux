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
TTL: ownership expires on the final writer descriptor closing or process exit,
including abnormal termination. A live but hung owner retains ownership; stop or
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
APIs, including inside `connection.call`, and raw SQL `BEGIN` / `SAVEPOINT`.
Exceptions name exact functions: managed entrypoints/acquisition in `database.rs`,
`BackupDatabase::enqueue_restore_events` and `BackupDatabase::merge_backup` on
private staging databases. Read-only backup snapshots need no raw-SQL exception.
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

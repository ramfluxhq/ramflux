# Dormant receive ledger storage

The schema installer is explicit and has no receive caller. Opening an ordinary
account does not install or activate the ledger. Installation creates the five
metadata/work tables and schema writer floor 15 in one immediate transaction.
Writer 14 refuses the new floor before migrating. Installation never changes
receive coverage, creates an epoch or advertises a capability. Restore sanitization
and runtime activation belong to subsequent implementation steps.

Sequence and range keys are eight-byte unsigned big-endian BLOBs. Composite
primary keys start with target and incarnation; receipts support indexed range
reconciliation and intents have an indexed due queue. The sole coverage authority
remains `projection_checkpoint` at `gateway_receive_cursor:<target>`; the epoch
stores activation/legacy uncertainty boundaries, not a second mutable cursor.

`receive_transaction` acquires the account's immediate writer phase, checks actor
generation, durable incarnation/expected coverage and private-erasure generation,
and hands its callback a scoped authority. The callback must do no network I/O.
Runtime receipt-state checks and receive writers are added with their owning
stages. Generic checkpoint writers are not yet restricted by this dormant step.

## Physical commit inventory

At base `c7bc48bdb9101970f254111c50d4edc4608dc5b2`:

- `AccountDb::write_transaction` in `account_db/runtime/config.rs` enters
  `Connection::immediate_transaction` and commits its returned guard.
- `database.rs::transaction` emits BEGIN IMMEDIATE or a nested SAVEPOINT.
- `database.rs::Transaction::commit` emits RELEASE for a child and COMMIT for
  the outer writer. RELEASE is explicitly not a durable boundary.
- `Connection::execute_batch` and `Connection::execute` notify before and after
  successful SQL on the actual SQLite worker. Callbacks see SQL, completion and
  SQLite's autocommit state. Direct raw operations inside `Connection::call`
  require their own instrumentation when introduced by later receive stages;
  a multi-statement batch has a batch boundary, not per-statement boundaries.

Hooks are path-scoped and available only in tests or with the explicit
`durability-test-hooks` feature. Production builds reject that feature and the
production graph checker rejects normal/build dependency activation. No hook
registration or SQL payload observer exists in the normal production build.
The P01 child aborts immediately before/after actual migration COMMIT and reopens
the real encrypted SQLite file. These are local SQLite crash claims, not router
WAL/redb or actor/transport crash acceptance.

Dependency gate: S6a P1 `194259e3`, P2 `a400593f`, P3 `84d9ccfd`, P13
`7838348a` are ancestors of the base. P14's final patch `9616732f` is identical
by stable patch-id to merged `1567b84a`; the preceding gateway adapters and
compatibility fixes are also in the base. P16 is not required by this step.

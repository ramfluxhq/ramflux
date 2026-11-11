# Receive ledger storage

First activation is default-on. Managed session connect, standalone receive and
gateway-session connect advertise `gateway.session_push.v1` so a fresh handshake
can supply the verified node incarnation, then bind schema, import and the
discriminator to that incarnation before ledger phases. Reverting the
first-activation switch leaves already-activated accounts on the shared ledger;
it does not reverse-migrate. Restore sanitization still strips the discriminator
so a restored account first-activates afresh.

Installation creates the five metadata/work tables and schema writer floor 15 in
one immediate transaction. Writer 14 refuses the new floor before migrating.

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

## Dormant W0 admission

`ReceiveTransaction::stage` accepts caller-authenticated normalized entry bytes,
checks the entry's outer sequence/target and envelope target against the transaction
identity, and preserves the supplied bytes exactly. The entry cap is 1 MiB; router
P12 independently enforces complete downstream frame sizing. The opaque admission
key is required. The actor must commit W0 before invoking any W1 processing.
No runtime path invokes this API yet.

Each receipt reserves one potential terminal intent. Quota admission counts the
union of receipt/intent keys across every incarnation for the target (1,024),
plus staged work count (1,024) and serialized bytes (64 MiB). Duplicate work uses
no second slot and preserves the first bytes, key, deadline and first-seen time.
Capacity refusal writes nothing and grants no new processing authority; existing
local recovery work remains available. Sequence keys are point operations, including
u64::MAX; range reconciliation and actor scheduling belong to later steps.

A mismatch preserves original work and returns Conflict, never permission to process
the replacement or retire the connection. Metadata-only checkpoint keys under
`gateway_receive_conflict:<quoted-target>:` suppress repeated diagnostics for the
64 most recent conflicting keys. They contain only target/incarnation/sequence and
a fixed enum, never content, message identity or hashes. Callers emit diagnostics
only when diagnostic_created is true. Ordinary entry normalization remains the
caller's authenticated protocol boundary; storage does not reserialize input.

Erased receipts refuse restaging. P01's transaction checks private-erasure generation
before admission and again before commit. P03 owns wire/logical footprint registration,
replay aliases, erasure transitions and backup/import sanitization, including clearing
receive diagnostic checkpoints. Until those owners and the remaining ledger stages
land, the schema and admission remain dormant. S6a P2 a400593f and P12 a353d30d
are ancestors of the fetched main c7bc48bd; P02 is stacked on P01 f21690fe.

Admission uses a nested savepoint under its scoped outer writer. A failed work
insert rolls back the receipt reservation even when the caller handles the error;
only the outer receive transaction commits W0 durably. Exact-error tests exercise
that SQLite failure and pre-/post-write private-erasure generation refusal.

The runtime installer excludes all five ledger tables from generic rowid-based
outbox triggers and removes any earlier installations on reopen. Their composite
keys and transition-specific publication remain owned by the ledger W paths.

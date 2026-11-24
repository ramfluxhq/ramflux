# Shared-root session handoff

Native Rust hosts opt in with
`LocalBusConfig::with_session_lease(SessionLeasePriority, Duration)` before calling
`serve_local_bus` or `serve_local_bus_until`. Configure both the app and extension.
The processes must use the same protected data root, platform custody provider and
device identity. A shared read-only snapshot does not request a session.

The waiting process advertises a kernel-owned request lock. The current daemon
closes command admission, drains lifecycle work, stops account actors and closes
their transports before releasing `daemon.lock`. Detached custody workers retain
that lock until they finish. The incoming daemon cannot open account writers or
connect a network session before acquiring it. The node's existing per-target
session registration fence retires a superseded registration, including after a
process crash. Receive transactions and durable ACK ordering are unchanged.

Any pending request asks a cooperative holder to yield. Among waiters, `Foreground`
precedes `Notification`, which precedes `Background`; priority does not interrupt
a writer or take its lease. There is at most one advertised waiter per priority.
A second waiter at the same priority receives busy immediately. Requests wait for
the requested duration, capped at five seconds. On exhaustion the SDK returns
`SdkError::LocalBusRefused` with code `SessionLeaseBusy` and a `retry_after_ms` hint
of 250. Busy does not grant ownership and does not promise that the holder will
finish draining in that interval. The host may retry within its own deadline.

Successful handoff completes the old daemon future. To regain the session the
old host must start a fresh daemon, reacquire the lease and silently reopen the
account through ordinary custody. A returned busy request can already have
initiated the old holder's drain; hosts must observe daemon completion separately.
No existing unlocked account object may be reused across ownership generations.

Request files and `daemon.lock` are never unlinked or replaced. Process death or
request cancellation releases kernel locks automatically; leftover filenames do
not represent ownership. Ordinary daemons without this option retain their
existing `DataRootInUse` exclusion and never yield to a request. The existing
shared reader and single account writer rules still apply. This Rust host option
does not add a C ABI entrypoint or change the bus method set.

Both v2 C ABI open functions accept the optional configuration
`"session_lease": {"priority": "notification", "wait_ms": 5000}`. Priorities use
lowercase names; `wait_ms` defaults to 5000 and must be an integer from 0 to 5000.
Contention returns `AccountBusy` (18). Once the old supervisor has yielded, close
its retained client handle and open a fresh one before issuing further operations.
Without this option the existing exclusive-open behavior remains in force.

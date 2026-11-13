# Gateway admission before device authentication

Admission is disabled by default. Enabling it requires an operator decision and a
separate mounted random cookie key. The proposed deployment policy is 60 admissions
per observed source in 60 seconds, with cookie TTL 60 seconds; this change does
not activate that policy.

```toml
[gateway.pre_auth]
enabled = false
per_source_ip_handshake_rate = 60
window_seconds = 60
cookie_ttl_seconds = 60
auth_deadline_ms = 5000
```

When enabled, `RAMFLUX_GATEWAY_PRE_AUTH_COOKIE_KEY_FILE` names a regular private
file containing base64url without padding of 32 random bytes. Allowed Unix modes
are 0600, 0400, 0640 and 0440. Use a separate key from the persistent node privacy
key and resume signing secret. The admission key stays in memory and is redacted
in diagnostics. Rotation invalidates admission cookies while preserving resume
tokens. The policy's `cookie_secret` is used only for resume tokens in service builds.

Validated runtime configuration applies before persisted admission validation.
An absent section preserves a valid stored policy; an explicit section overrides
storage. Policy updates trim debt to the configured rate and commit atomically.
Enabled rates are 0..60, windows and TTLs 0..3600 seconds, and Auth deadlines
0..10000 milliseconds (zero clamps to 1 ms). A zero rate always challenges; a zero
window or TTL includes only the current second. Source buckets are capped at 4096,
with at most 60 events each. Empty restored buckets are reclaimed, including at
rate zero. Each Open reclaims at most 16 expired buckets; capacity refusal can be
conservative while an expired backlog drains. Live debt is never evicted.

TCP uses the accepted peer throughout TLS and authentication. Quinn and compio
freeze the peer observed when accepting each application stream through Open/Auth
and custody handoff. Sources retain IPv4 /32, IPv6 /64, IPv4-mapped aliases and
well-known NAT64 normalization, excluding ports. Later QUIC streams observe their
then-current peer. Signed source/time hints have no admission authority.

## Clock reservation and checkpoint outage

Server time is sampled under the state lock. Pre-epoch clocks and rollback fail
closed with `pre_auth_rejected:clock_invalid` or `pre_auth_rejected:clock_rollback`.
Before listening and every 10 seconds, a transaction checkpoints policy, bounded
admission debt, counters and a 30-second clock reservation. Copying admission
metadata happens under the state lock; serialization and commit happen outside it.
The payload contains no sessions, tokens, frames or replay snapshot, so its copy
and serialization do not grow with the session count. Retention visits at most 64
entries per metadata family per pass and prunes bounded indexed session/token rows.
No whole-state snapshot runs on the timer.

The committed reservation endpoint fences admission in both enabled and disabled
modes. Graceful shutdown commits the exact observed floor and releases the future
reservation; a clean restart starts immediately. After a crash, startup waits
through the committed endpoint before listening, for at most 30 seconds, logging
one aggregate wait message. A host clock below the committed floor itself is a
true rollback and fails with the typed clock error. Equal seconds are accepted.
Enabled mode separately preserves unknown-source debt cooldown through a crash
reservation plus the larger saved/configured window, including any longer prior
cooldown. No admission is evaluated before the committed endpoint.

Opens perform no disk write. An Open beyond the committed reservation fails with
`checkpoint_unavailable` in either mode until another checkpoint succeeds. Failed
commits leave the previous reservation in force. A stalled writer never owns the
global state mutex: established sessions can continue heartbeat/read activity.
Network writes acquire one of eight bounded asynchronous offload permits before
waiting for the writer gate or fsync. Excess requests receive retryable
`gateway_writer_busy`; cancellation keeps the permit until the actual blocking
work finishes. No uncommitted signed operation is acknowledged. Recovery is
automatic after a successful checkpoint. `checkpoint_failures` counts failed
checkpoints; `checkpoint_outages` counts observed outage episodes. A separate
observer emits at most one aggregate warning each 10-second interval and a
recovery message. No per-Open outage logging is emitted. Logs contain no peers,
source pseudonyms, cookies or client frame fields.

Persisted admission metadata uses `pre_auth_admission_v1`, version 1 and source
scheme `transport-peer-v2`, bounded to 8 MiB and 4096 canonical source pseudonyms.
Clock reservation metadata uses `pre_auth_reservation_v2`. Malformed metadata or
unknown versions refuse startup. Cookie BLAKE3 v1 and canonical signed Open grammar
are unchanged. Cookies are reusable within TTL for the observed source, including
port rebinding, and are not a hard handshake quota. Admission follows transport
handshake establishment and cannot prevent transport handshake floods.

## Gateway format 3 and controller reset

Gateway stores now require the `gateway_state_format` marker `3`. Every existing
file without that marker is refused at startup with `GatewayStateResetRequired`,
before publishing state or adding tables/markers. There is no old replay snapshot
reader, ownerless accounting, legacy clock import or session snapshot migration.
Downgrade is unsupported.

At the next deployment the controller resets demo gateway state: stop every
gateway using the configured gateway redb file, back up that file and its own
sidecars, then remove only that gateway database and its sidecars. Restart to
create a fresh format 3 store. This deliberately retires gateway sessions, resume
tokens, replay evidence and admission debt. Preserve account, router and other
service stores. Rotate the admission cookie key if the reset also discards a clock
fence. Never reset a running database or edit redb bytes. The implementation does
not perform this deployment/reset itself.

## Authentication replay storage

Gateway signed-request validity remains at most seven days (604800 seconds),
with 120 seconds allowed future clock skew. Quotas apply to signed gateway
requests only, never router envelope admission. Each admitted account ROOT owns a configured share S (default32768)
across all devices. Configured root budget R defaults to256; maximum live
identities are R×S=8388608. Exhaustion returns typed `GatewayReplayCapacity`.
Live evidence is never evicted and accepted validity is never shortened.

Reservations are allocated only with the first committed identity, and released
when no identity remains live (expiry equal to fenced server time is still live).
All root membership, counts, generation and expiry indexes are transactional disk
authority. Failed writes install nothing. The writer gate serializes pending
commits with reclamation. An expired generation's remaining rows cannot charge or
resurrect a subsequent reservation. Cleanup examines at most64 expiry candidates
per transaction, deletes bodies only at matching expiry, and reconciles expired
root metadata before admission on reopen. An active root's own expiry index takes
priority over unrelated expired-body backlog so others cannot occupy its share.

No evidence is materialized at startup or cached in application maps. redb's page
cache is limited to8MiB, leaving headroom within the64MiB replay-cache budget for
allocation overhead; eviction never removes disk evidence. Cleanup holds at most64
small candidates. Full checkpoints never serialize the replay ledger.

These **OPEN-VALUE** allocations retain the declared full-validity traffic profile:
two combined signed operations/minute for604800+120 seconds require20164 live
identities, below32768. Higher profiles require corresponding share/storage
increases. Default planning uses512 logical bytes/identity and256/root:
4GiB+64KiB, with8GiB initial backing storage. These are planning allowances,
not measured physical bounds. Startup rejects zero/overflowed/unfunded budgets,
checks available filesystem capacity plus the existing store against the declared
storage budget, and refuses a share reduction while roots remain live. Storage is
not preallocated; operators must retain the configured backing capacity. Omitting `[gateway.replay]` selects the small-node profile. Its complete configuration is:

```toml
[gateway.replay]
root_budget = 256
per_root_share = 32768
storage_budget_bytes = 8589934592
```

The larger profile is explicit opt-in (64GiB+1MiB logical,128GiB backing):

```toml
[gateway.replay]
root_budget = 4096
per_root_share = 32768
storage_budget_bytes = 137438953472
```

`disk_replay_storage_measurement_and_bounded_restore` records actual file growth
and all-index bytes for32768 committed identities with maximum-width generation
and expiry counters. Deployment sizing must include every index, page overhead
and database working space. Measured on the QA fixture:632 bytes/identity file
growth,350 stored bytes plus205
bytes of index metadata/fragmentation; maximum encoded replay body118 bytes
(decoder bound256). The fixture exceeds the8MiB cache and checks replay after
cache eviction/reopen. Its isolated Linux process checks peak resident allocation
growth including overhead against64MiB. These measurements are evidence for that
fixture, not a physical upper bound for arbitrary workloads.
Authentication and each signed operation commit one root-owned identity and its
indexes outside the global state mutex. Establishment commits a session/token pair.

The shared router replay guard retains its pre-existing v2 key isolation/lookup
until the separate legacy-removal work removes the router store upgrader. Gateway
format 3 never imports those rows and does not charge ownerless rows to roots.

Test HTTP policy routes exist only with the non-default `itest-http` feature.
The listener binds only to a literal loopback address (default `127.0.0.1:18081`);
non-loopback addresses fail startup with `ItestListenerNonLoopback`. Loopback is
the test authority boundary; local processes can use these test routes. Release
and production builds refuse the feature, and CI checks release/deploy build
commands and the normal production feature graph.

The pre-auth and forwarded registration policy routes share one management-write
slot. Overlap receives HTTP 503 with retryable `gateway_writer_busy`. A policy
snapshot is captured under the state mutex, then serialized and committed after
releasing it while retaining the writer gate. Only the committed policy is merged
back into live state, preserving concurrent admission, metrics and session work.
A failed commit leaves live policy unchanged.

Network writes admit at most eight authenticated roots concurrently, with one
queued/running write per root across all devices and sessions. Unverified AUTH
uses a separate two-operation budget. No waiting request queue is allocated;
exhaustion returns typed retryable `GatewayWriterBusy` before spawning work.
A busy root cannot take other roots' slots; disk failure can still prevent commits.

Fresh databases are initialized, committed and synced under a temporary name in
the destination directory, then published without replacing an existing store.
A crash before publication leaves no public partial file; existing unmarked or
older stores still require explicit reset. SIGTERM during a crash-reservation
wait drains startup without opening listeners or releasing the crash barrier.

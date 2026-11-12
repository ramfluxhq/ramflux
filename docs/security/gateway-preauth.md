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

The committed reservation endpoint is a strict restart clock barrier in both
enabled and disabled modes. Startup below it is refused, even if the previous
process served an Open after its checkpoint. Correct the clock and wait for the
endpoint before restarting. Equal seconds are accepted. Enabled mode separately
retains a restart debt cooldown through the reservation plus the larger saved or
configured rate window, preserving any longer prior cooldown. Restart cannot
reset unknown sources' uncheckpointed rate debt.

Opens perform no disk write. An Open beyond the committed reservation fails with
`checkpoint_unavailable` in either mode until another checkpoint succeeds. Failed
commits leave the previous reservation in force. A stalled writer never owns the
global state mutex: established sessions can continue heartbeat/read activity.
Operations requiring persistence wait on the separate writer gate. Recovery is
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

## Gateway format 2 and controller reset

Gateway stores now require the `gateway_state_format` marker `2`. Every existing
file without that marker is refused at startup with `GatewayStateResetRequired`,
before publishing state or adding tables/markers. There is no old replay snapshot
reader, ownerless accounting, legacy clock import or session snapshot migration.
Downgrade is unsupported.

At the next deployment the controller resets demo gateway state: stop every
gateway using the configured gateway redb file, back up that file and its own
sidecars, then remove only that gateway database and its sidecars. Restart to
create a fresh format 2 store. This deliberately retires gateway sessions, resume
tokens, replay evidence and admission debt. Preserve account, router and other
service stores. Rotate the admission cookie key if the reset also discards a clock
fence. Never reset a running database or edit redb bytes. The implementation does
not perform this deployment/reset itself.

## Authentication replay storage

Gateway signed-request validity remains at most seven days (604800 seconds),
with 120 seconds allowed future clock skew. Quotas apply to signed gateway
requests only, never router envelope admission. Each admitted account ROOT owns
32768 replay entries shared by all its devices. At most 64 roots are admitted,
for total capacity 64 × 32768 = 2097152. Root reservations persist until an explicit
store reset, even after their entries expire, so another root cannot steal an
existing root's allocation. A new root beyond the budget, or an exhausted root,
receives the typed `GatewayReplayCapacity` error. Live evidence is never evicted
and validity is never shortened retroactively.

These are **OPEN-VALUE** sizing choices for security review: a share supports two
combined signed operations per minute throughout the full validity plus skew,
2 × (604800 + 120) / 60 = 20164 entries, leaving headroom below 32768. Higher
sustained workloads and the 64-root deployment budget require explicit resizing.

Authentication persists one root-owned replay row and expiry-index row before
acknowledgment, outside the global state mutex. Replacement removes the prior
expiry index in the same transaction. Each prune processes at most 64 expired
index rows and deletes a replay body only when its current expiry equals that
index expiry; obsolete index rows are always removed. The inclusive expiry second
remains protected. Session establishment writes its session/token pair; expiry
cleanup uses current per-row tables rather than snapshots or compatibility overlays.

The test-feature HTTP policy POST remains a CARRY: its existing unauthenticated
administrative full-state save can hold the global lock during commit. It acquires
the writer gate before that lock to preserve ordering. Production Open/Auth and
timer paths do not use that administrative save path.

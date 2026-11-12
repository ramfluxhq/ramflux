# Gateway admission before device authentication

Admission is disabled by default. Enabling it requires an operator decision and a
separate mounted random cookie key. A proposed deployment policy is 60 admissions
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

When enabled, `RAMFLUX_GATEWAY_PRE_AUTH_COOKIE_KEY_FILE` must name a regular
private file containing base64url without padding of 32 random bytes. The
NodeSecret mount modes are 0600, 0400, 0640 and 0440 on Unix. Use a separate key
from the persistent node privacy key and resume signing secret. This key exists
only in memory and is redacted in diagnostics. Restart reloads the mount; rotating
it invalidates admission cookies while preserving existing resume tokens. The
persisted legacy `cookie_secret` is used only for resume tokens in service builds.

Validated runtime configuration is applied before persisted admission validation.
An absent admission section preserves a valid stored policy; a fresh store stays
disabled. An explicit section, including `enabled = false`, overrides storage.
An out-of-bounds stored policy does not block startup. Restored debt is trimmed
to the new rate; policy, debt, counters and floor are then committed in one redb
transaction. HTTP policy updates use that same atomic transaction and retain the
previous live policy and debt if commit fails. Enabled rates are 0..60, windows and TTLs 0..3600 seconds, and Auth deadlines
0..10000 milliseconds (zero clamps to 1 ms). A zero rate always challenges; a zero
window or TTL includes only the current second. Source buckets are capped at
4096. Expired buckets are reclaimed before insertion; a new source is refused at
capacity while live source debt is retained.

TCP uses the accepted peer throughout TLS and authentication. Quinn and compio
snapshot the peer after accepting each application stream and freeze it through
Open/Auth and native custody handoff. Source buckets retain IPv4 /32, IPv6 /64,
IPv4-mapped aliases and the well-known NAT64 prefix normalization. They exclude
ports. Later QUIC streams observe the then-current peer. Legacy source/time hints
remain typed, signed wire fields but have no admission authority.

Server time is sampled under the state lock before expiry. Pre-epoch clocks and
rollback fail closed with `pre_auth_rejected:clock_invalid` or
`pre_auth_rejected:clock_rollback`. The fence remains active while admission is
disabled, including legacy stores. Startup and retention return `clock_invalid`
or `clock_rollback` errors too. Equal seconds are accepted. Debt, counters and the time floor are committed in one
redb transaction before an admission or cookie challenge is sent. Storage failure
refuses the attempt and retains conservative in-memory debt.

The `pre_auth_admission_v1` JSON envelope uses version 1 and source scheme
`transport-peer-v2`. Restore bounds are 8 MiB, 4096 canonical 43-character source
pseudonyms, ordered event arrays of at most 60 timestamps (trimmed to the configured rate),
and timestamps at or below the persisted high-water mark. Malformed or unknown
snapshots refuse startup. Nonempty unversioned admission state requires an
explicit migration before enabling admission; sessions and resume tokens remain
separate. Changing the source scheme or cookie algorithm needs its own migration
and security review.

A cookie is reusable within its TTL for its observed source, including port
rebinding, and is not a hard handshake quota. The existing domain-separated
BLAKE3 v1 cookie format and canonical signed Open grammar are unchanged. Clients
must explicitly rebuild and sign a fresh Open/Auth exchange when retrying with a
cookie. Admission runs after TLS/QUIC establishment and therefore does not protect
against transport handshake floods. Ingress failures, unbound custody requests and legacy migration warnings increment
fixed-cardinality counters. At most one aggregate warning is emitted per 30
seconds; it contains counts only. Neither peers, source pseudonyms, cookies nor
client frame fields belong in logs or labels.


## Clock recovery

First correct the host clock and wait until it reaches the persisted high-water
second. This preserves replay protection and debt. A pre-epoch clock must be
corrected before restarting. No gateway clock-reset CLI exists.

If waiting is impossible, stop every gateway using this database and back up the
redb file. With an offline redb maintenance tool using the same redb format,
open the `gateway_state_v1` table and commit one write transaction:

- For a trusted store, delete `pre_auth_admission_v1`. This also clears admission
  debt and aggregate counters. Rotate the mounted admission cookie key before
  restarting to prevent old cookies becoming valid again after rollback.
- For a legacy store, delete only `pre_auth_legacy_clock_v1`. Keep
  `pre_auth_rate_state` and `pre_auth_metrics`; migration remains required.

Preserve `pre_auth_policy`, session, challenge, replay and resume-token entries.
Restart at corrected time. This explicit reset discards the admission clock
fence; it does not relax the independent timestamp checks on resume tokens or
custody proofs. Never edit redb bytes directly or reset a running database.

## Legacy admission migration

Nonempty legacy debt is never interpreted as transport-observed debt. While
admission is disabled the gateway can run, emits an aggregate migration warning,
and persists its trusted floor and new counters in `pre_auth_legacy_clock_v1`.
This marker retains `migration_required: true` across restarts. Enabling admission
fails with `PreAuthMigrationRequired` until an operator performs the migration.

Stop the gateway and back up the database. An offline redb maintenance tool must
perform one transaction in `gateway_state_v1`: remove `pre_auth_rate_state`,
`pre_auth_metrics` and `pre_auth_legacy_clock_v1`, and insert
`pre_auth_admission_v1` with this JSON shape:

```json
{"version":1,"source_scheme":"transport-peer-v2","high_water_unix_seconds":0,"buckets":{},"metrics":{"pre_auth_cookie_required":0,"pre_auth_cookie_failed":0,"deviceproof_rate_limited":0,"slowloris_auth_timeout":0}}
```

Replace the example zero floor with the trusted floor from
`pre_auth_legacy_clock_v1`, or the checked current Unix second when no trusted
legacy floor exists. Preserve the new counters from that marker when present;
do not import the untrusted legacy counters or debt. Keep the persisted policy
(including its resume-only `cookie_secret`) and all session/resume data. The empty
buckets intentionally reset legacy debt; schedule migration as an operator
security decision. Configure a separate mounted cookie key, restart with the
validated runtime policy, and enable admission only after migration succeeds.

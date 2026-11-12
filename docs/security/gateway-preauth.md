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

Configuration overrides the persisted admission policy without clearing source
debt. Enabled rates are 0..60, windows and TTLs 0..3600 seconds, and Auth deadlines
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
rollback fail closed with `pre_auth_rejected:clock_invalid` or `clock_rollback`.
Equal seconds are accepted. Debt, counters and the time floor are committed in one
redb transaction before an admission or cookie challenge is sent. Storage failure
refuses the attempt and retains conservative in-memory debt.

The `pre_auth_admission_v1` JSON envelope uses version 1 and source scheme
`transport-peer-v2`. Restore bounds are 8 MiB, 4096 canonical 43-character source
pseudonyms, ordered event arrays no longer than the configured rate (maximum 60),
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
against transport handshake floods. Only aggregate counters belong in logs or
labels; source pseudonyms remain linkable and must not be logged.

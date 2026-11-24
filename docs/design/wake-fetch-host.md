# Notification-extension wake-fetch host

`ramflux_v2_wake_fetch(config, config_len, custody, out)` runs one account's
authenticated inbox fetch without opening the full SDK client. Call it on a
worker thread with the app's existing shared-root and ABI-v1 custody provider.
The root must already exist and be private to its owner (0700 on Unix).

```json
{"data_root":"/absolute/shared/root","account_id":"local-account","deadline_ms":"1795500000000","lease_wait_ms":50}
```

`deadline_ms` is an absolute Unix-millisecond decimal string, converted once to
a monotonic deadline on entry. The total operation budget is capped at 20 seconds.
`lease_wait_ms` defaults to 50 milliseconds and accepts 0 through 5000; the
remaining operation deadline also bounds lease admission. Expired calls do not
open the account or start networking. Custody callbacks must return promptly;
blocking host callbacks and synchronous OS storage calls cannot be interrupted.
The host joins custody blocking jobs before releasing its session lease.

On C status 0, the SDK-owned output buffer contains one of:

```json
{"outcome":"busy"}
{"outcome":"locked"}
{"outcome":"deadline"}
{"outcome":"fetched","items":[{"envelope_id":"opaque-id","inbox_seq":"42"}]}
```

Free the output with `ramflux_v2_buffer_free`. Invalid inputs, wrong custody,
unavailable node configuration and network/authentication failures retain ordinary
nonzero SDK statuses with null output. `locked` covers unavailable device-unlock
custody and an explicitly removed device wrap; no account code is requested or
checked. This entry point never creates an account or a device-unlock secret.

The host takes the S14 notification-priority session lease and existing account
writer fencing. An app that retains its ordinary session produces `busy`; an
app that suspends/releases ownership permits the extension to fetch. Cooperative
S14 holders may drain in response to the notification request. A timed-out
request never steals ownership or leaves a waiter behind.

The account is silently opened using the existing device wrap. Node selection
comes from its stored account node and the root's pinned node profiles. The
existing channel-bound native authentication and authoritative inbox-page reader
run over one TCP/TLS gateway session. No supervisor, actor, courier, subscriber,
media engine, card runtime, download or automatic reconnect loop is started.
Transport and runtime are closed before ownership is released.

One page contains at most 32 encrypted envelopes. The output identifies those
envelopes without exposing plaintext. Empty `items` means an empty fetched page.
`fetched` establishes transport receipt only: this S1A host does not decrypt or
apply the page, advance receive/ACK cursors, acknowledge messages, or construct a
notification. Durable apply/ACK (S1B), notification policy/results and populated
account RSS acceptance (S1C) remain separate work.

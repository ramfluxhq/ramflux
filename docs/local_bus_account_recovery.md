# Explicit local phrase recovery and primary promotion

Recovery starts only through a user action on this installation. No network event,
ordinary unlock, reminder, support request or received message requests the phrase.
Use `LocalBusRecoveryClient` on an exclusive same-user protected connection. The
typed client serializes phrase/passphrase inputs from `Zeroizing<String>` buffers;
do not put the phrase in a generic `LocalBusFrame`, logs, events or retry journals.
`rf account recover --account ACCOUNT` drives this ceremony on the controlling
terminal. It confirms the displayed fingerprint and reads phrase/data-passphrase
input with terminal echo disabled. There are no phrase command-line or environment
options, and the public result alone is printed as JSON on standard output.

1. Send `account.recover.begin {"account_id":"…"}`. The daemon checks the primary
   provider, refreshes available independently configured public checkpoints, and
   returns `ceremony_id`, `account_anchor`, `expires_in_ms` and `warning`. Display
   the anchor/fingerprint and warning before requesting phrase entry. A directory
   can withhold newer authority; this does not prove global freshness.
2. On that same connection, send `account.recover.confirm` with exactly `phrase`,
   `passphrase` and `confirmed_anchor`. The latter must equal the displayed anchor;
   the passphrase unlocks local data and does not derive identity. A wrong phrase
   returns `CustodyConfirmationFailed` without changing authority or vault entries.
   Every confirmation attempt consumes the ceremony. It expires after five minutes;
   expiry returns `CustodyExpired`. Cancel with `account.recover.cancel {}` or drop
   the connection. Cancellation is idempotent after consumption.
3. Recovery derives the master temporarily, verifies the immutable anchor, creates
   a fresh random self-signing key, and certifies a fresh local branch. A branch
   allocated by fresh data restore is certified in place. Every old active branch
   is revoked. The new range exceeds every retained authenticated or fenced range;
   current denial/checkpoint and identity floors survive. No master seed or phrase
   is written to a vault, database, manifest, backup or journal.
4. A synchronized public journal records the exact replacement before selecting
   it. The old actor stops; outbound sessions become inactive while receive history
   and replay floors remain. The journal dominates a stale authority file after an
   interrupted selection. It stores public signed intent and opaque credential
   references, with no credential bytes. Connection loss before the commit gate
   cancels and removes fresh credentials. After commit, an interrupted operation
   leaves the certified replacement pending and never reopens the old authority.
5. Ordinary activation publishes that exact intent over the existing authenticated
   custody transport. Only a matching durable publication ACK, branch registration
   and session establishment can mark networking live. A missing/mismatched ACK
   keeps the intent pending. Retry ordinary unlock with the local data passphrase
   to reconcile the same intent; do not derive another master automatically.
   Successful ordinary activation removes obsolete local credential references.

Confirmation returns the ordinary typed account response with `account_id`,
`display_name`, `state: unlocked`, and `networking: live|networking_pending`.
Data can remain unlocked while a node, credential provider or transport is
unavailable. Public state and local history never authorize a legacy fallback.
Recovery request identifiers and envelope strings have the same 128-byte cap as
creation; secret requests use an 8192-byte erasing buffer and reject retry operation
IDs. Generic `LocalBusClient` rejects these secret-capable methods.

Recovery replaces authority, whereas [data restore](account_backup.md) imports
history. Until SAS pairing is available, adding a second native installation uses
phrase recovery there, promoting it and revoking the former branches. This flow
does not retain multiple concurrently approved devices, transfer the old primary
secret, or change the master/account anchor. Phrase compromise requires a new
identity and contact re-verification.

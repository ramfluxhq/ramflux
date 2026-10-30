# Account creation over the ordinary local bus

Creation uses the `ramflux.local_bus.v1` request/response/error envelope and a
dedicated same-user protected connection. `LocalBusCreationClient` owns that
connection exclusively; use `LocalBusClient` for the resulting account's ordinary
methods. A phrase must never pass through `LocalBusFrame.body`, generic response
logging, retry receipts, events, or a JSON value in a trusted client. The typed
creation client decodes it directly into `Zeroizing<String>` and serializes
confirmation words and the passphrase directly from erasing buffers.

Read `daemon.status.body.born_v3_creation` before offering creation. An absent
field means false for older daemons. Current daemons always report true; native
creation has no enable/disable option. Vault availability is checked by begin.

1. Send `account.create` with exactly
   `{"display_name":"Example Human","principal_kind":"human"}`. The daemon
   allocates the account, principal and device identifiers. No seeds, phrase,
   passphrase, or caller-selected identifiers belong in this request. Its body is
   `{"ceremony":"pending","ceremony_id":"ceremony-…","expires_in_ms":300000}`;
   the remaining lifetime can be shorter than the example's five minutes.
2. On that same connection, send `account.create.show_once` with `{}`. The response
   body contains only `phrase`, a 24-word BIP39 phrase. Display it once. Do not
   retain a second copy, log it, or move it into a generic JSON response model.
3. After hiding and erasing the display buffer, send
   `account.create.hidden_challenge` with `{}`. Its body contains `positions`,
   three distinct one-based word positions. Obtain those words from the user's
   saved recovery material; do not derive the answers from a retained UI phrase.
4. Send `account.create.confirm` with exactly `words` (three strings in the
   requested order) and `passphrase`. The passphrase seals the independent random
   account data key under the existing account data-key KDF. It is not a BIP39
   passphrase and does not change identity derivation. There is one word-check
   attempt with no per-word feedback. Wrong words publish no account and discard
   the passphrase. The primary credential is stored separately in the supported
   non-synchronizing provider; data unlock never requires that credential.
5. Successful confirmation returns
   `{"account_id":"account-…","display_name":"Example Human","state":"unlocked","networking":"networking_pending"}`
   only after the ordinary account actor has opened its data database and reader
   pool. `networking` becomes `live` after authenticated registration and ordinary
   session handoff succeed. Node absence, an unavailable branch credential or a
   network failure can leave data unlocked with networking pending. A missing
   networking session does not authorize a legacy proof fallback.

`account.create.cancel {}` is idempotent, including after a consumed or failed
confirmation. Disconnect and daemon shutdown erase pending phrase/word buffers.
Confirmation persistence runs outside the socket thread. Disconnect before its
durable commit gate prevents authority publication and removes newly written
credential entries. Once that gate wins, connection loss can leave a completed
locked account available in `account.list`; reconnect rather than replaying
creation. Failed persistence retains an incomplete mode reservation, never an
alternative identity scheme.

`CustodyExpired` distinguishes expired setup from bad ordering or malformed
input (`CustodySetupInvalid`), wrong words (`CustodyConfirmationFailed`) and an
unavailable credential provider (`CustodyVaultUnavailable`). A ceremony cannot be
resumed from another connection. Setup rejects request identifiers and public
envelope string fields longer than 128 bytes before producing secret output.
Secret output uses a fixed 8192-byte buffer that cannot reallocate after writing
secret bytes. Creation requests cannot carry retry operation identifiers.

## Headless participant creation

A trusted frontend for an unlocked, live native human owner may create a
`headless_ai` account. On the exclusive ceremony connection, send
`account.create.begin` with the owner as both the envelope `account_id` and
`custodian_account`:

```json
{
  "display_name": "Demo Assistant",
  "principal_kind": "headless_ai",
  "custodian_account": "account-owner"
}
```

Creation without a custodian, with a non-human custodian, with an authority-blocked
or networking-pending custodian, or with different envelope/body custodians is
refused. The owner completes the same show-once phrase and hidden-word challenge.
Each service has its own phrase, which is shown only in this owner ceremony. For
`headless_ai`, `account.create.confirm` contains only `words`; the daemon generates
the independent random data passphrase. Neither the agent process nor the confirm
response receives the phrase or passphrase.

After the agent account is live, the attended owner connection sends
`account.export_agent_credentials {"account":"account-agent","path":"/private/path"}`.
The target must be a native `headless_ai` account governed by that exact owner. The
daemon refuses an existing destination and creates a 0600 file containing only
`account_id` and `data_passphrase`. The credential is exportable once. Human
accounts are always refused. If the bundle is lost or an import fails, use the owner's
saved service recovery phrase; the daemon will not export the same credential again.

Start `ramflux-agent-host --provisioning-bundle /private/path`. It checks that the
file is private and matches the configured account, imports the passphrase into the
operator Mac Keychain, deletes the file after the successful import, and unlocks the
account before processing messages. Integration builds may explicitly use
`--itest-memory-vault`; that volatile provider is unavailable in production. Linux
production provisioning waits for `ID-02-VAULT-LINUX-01`, so run the demo agent on
the operator Mac until that provider exists. No environment-variable, command-line,
or piped phrase/passphrase path is accepted.

After confirmation use ordinary methods on a normal connection. `account.lock`
closes the actor and readers. `account.unlock {"passphrase":"…"}` opens the same
data after lock or daemon restart, without loading the primary credential.
`account.list.account_details` includes locked accounts whose networking is
pending, with separate `state` and `networking` fields. Account status and the
identity directory derive native provenance from the signed master certificate
and account anchor, without a synthetic legacy root.

## Reference CLI

Run `rf account create --display-name "Example Human"` from a local interactive
terminal. The CLI uses the ordinary exclusive ceremony, displays the phrase once
in an alternate terminal screen, clears it before selecting challenge words, and
reads the requested words and independent local data passphrase with echo disabled.
Only the public account result goes to stdout. There are no seed, phrase, account
identifier or passphrase arguments for creation, and no environment-variable or
piped-input creation flow. The old `account login` seed-taking alias is removed.

For a headless participant, keep the native human custodian unlocked and active, then
run `rf account create --display-name "Service" --kind headless_ai --custodian <owner>`.
The same attended terminal displays and clears the service phrase, while rfd generates
the data passphrase. Once registration is Live, run
`rf account export-agent-credentials --account <agent> --out <private-path>`. The export
uses the active owner session and is refused for a different, locked, pending, or
non-human custodian.

Integration builds can explicitly select `rf daemon start --itest-memory-vault`
only when compiled with the gated `itest-memory-vault` feature. Credentials then
exist only in the daemon process; restarting that daemon loses them. Production
builds do not expose that option or silently substitute this provider.

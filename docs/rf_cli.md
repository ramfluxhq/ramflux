# Reference CLI

`rf` sends commands to the local daemon selected by `--socket`. Start that daemon
with `rf daemon start` and configure its node before creating an account.

## Daemon diagnostics

Set `RUST_LOG` when starting the daemon to enable diagnostics, for example
`RUST_LOG=ramflux_sdk=info rf daemon start`. Logs go to stderr, so redirect the
daemon's stderr to a file if persistent diagnostics are needed. Without
`RUST_LOG`, logging is off. Held inbound entries are logged at info with their
`inbox_seq`, error `kind` and `reason`; terminal dead letters and retry exhaustion
are logged at warn with the same fields and an `outcome`. Use
`RUST_LOG=ramflux_sdk=debug` for additional SDK diagnostics. Set the filter before
starting the daemon; changing the environment of a later CLI command does not
change a running daemon's filter.

For background operation, use `RUST_LOG=ramflux_sdk=info rf daemon start
2>daemon.log &`. A ready daemon writes an info event to that file. Attachment
failures log the object id, failing check and fixed error category; access grants,
keys and transport response bodies are excluded.

## Born-v3 DM attachments

Create both accounts through `rf account create` after selecting and confirming
their node, then complete contact consent. Send with the usual DM recipient
selectors and `--attach /path/to/file --relay-url quic://HOST:PORT
--attachment-chunk-size 1024`. Use the selected node profile's `relay.quic_addr`
for `HOST:PORT` (`rf node list` shows the profiles). Keep the profile's node
identity and certificate pin; the relay address can be an IP address and need
not equal the node id. Do not substitute the discovery HTTP or gateway address.

The receiver runs `rf dm read --account=ACCOUNT --conversation=CONVERSATION`.
It automatically fetches, verifies and decrypts received attachments, returning
their bytes in `decrypted_messages[].attachments[].plaintext_base64` (base64url).
Pass `--wait 240` to poll deferred fetches within a caller-owned budget in seconds.
The default, `--wait 0`, makes one read. While waiting, a generic failure exits
immediately; `attachment fetch deferred; retry object.fetch` exits with status 1
only when the wait budget ends. Each daemon page remains bounded to 20 seconds,
and each SDK fetch to 60 seconds. Deferred fetches resume verified chunks and
confirmed relay acknowledgements. The daemon logs `scheduler_fetch_deadline`
when a page window expires.

An upload grant expires 240 seconds after it is issued at upload, rather than
240 seconds after the recipient starts reading. Missing bytes still require a
valid grant. Once all encrypted chunks are cached, the receiver can verify and
finish locally even after expiry, without contacting the relay or renewing the
grant. A completed import removes its durable ACK progress rows. Repeat a read
or invoke SDK `object.fetch` to resume after a failed attempt.
`rf object list --account=ACCOUNT` lists available metadata on either side, using
bounded directory pages rather than embedding ciphertext.
Existing object data and attachment references remain readable.
After fetching, save the file with
`rf object get --account=ACCOUNT --object=OBJECT_ID output.bin`.
Scripts that previously consumed payload fields from `rf object list` should use
`object get` or the SDK's bounded object-read APIs; `object_id` remains the list
selector. The legacy SDK `object.list` response remains unchanged when it fits
the bus frame limit; oversized responses return an error directing callers to
`object.directory`.

## Native groups

A born-v3 group has one signed conversation, selected at creation. `rf group
create` uses the group id for that conversation. Later `group send` and `group
read` commands resolve their conversation selector to that same thread; the send
response reports its conversation id. Both participants therefore use the same
group history even when their commands supply a different local conversation
name.

An invalid `RUST_LOG` value produces one stderr warning and leaves daemon logging disabled; the daemon continues to start. Hold and dead-letter diagnostics include the envelope, source device and target delivery identifiers. Unrouted inbound entries also emit an info-level hold with a reason.

On the next native group operation, cached group links from earlier CLI versions are reconciled with the signed group conversation. Existing conversation and history records are retained.

## Native backup and fresh installation restore

A native backup contains account data and public identity evidence. It contains no
private signing credentials and cannot authorize a new device. Export an unlocked
account with an archive passphrase supplied through an environment variable:

```sh
rf --socket /tmp/source.sock account backup export --account=SOURCE_ACCOUNT \
  --out account.rfb --passphrase-env=RAMFLUX_ACCOUNT_BACKUP_PASSPHRASE
```

On a fresh daemon, import requires a separate local data passphrase. Set
`RESTORED_LOCAL_PASSPHRASE` privately to the new local encryption password; it is
independent of `RAMFLUX_ACCOUNT_BACKUP_PASSPHRASE`, which decrypts the archive.
Neither password belongs on the command line or in a log.

```sh
rf --socket /tmp/restored.sock account backup import --in account.rfb \
  --passphrase-env=RAMFLUX_ACCOUNT_BACKUP_PASSPHRASE \
  --new-passphrase-env=RESTORED_LOCAL_PASSPHRASE
rf --socket /tmp/restored.sock account list
rf --socket /tmp/restored.sock account status --account=RESTORED_ACCOUNT
```

Import verifies and installs contacts, conversations, history, groups and
attachments entirely offline. Missing fresh-install setup returns
`restore_setup_required`, naming `--new-passphrase-env`; the CLI refuses before
verifying an archive on an empty daemon. Existing-installation merges keep the
independently installed authority and local data key; omit the new-passphrase
option for those merges.

Success returns `local_account_id`, `networking: networking_pending` and
`next_command` as an exact argument array including the selected socket. The
SDK job row also includes `installed_account` with the local id and networking
state captured at installation. `account list.account_details` contains the
persisted account; `accounts` contains only unlocked accounts. The fresh account
is locked and its device is uncertified. `account status` shows this pending
state without unlocking it.

Configure and confirm the restored daemon's home node through `rf node add`,
`rf node confirm` and `rf node set-default` before recovery. Then run:

```sh
rf --socket /tmp/restored.sock account recover --account=RESTORED_ACCOUNT
rf --socket /tmp/restored.sock account status --account=RESTORED_ACCOUNT
rf --socket /tmp/restored.sock dm list --account=RESTORED_ACCOUNT --conversation=DM_THREAD
rf --socket /tmp/restored.sock group read --account=RESTORED_ACCOUNT \
  --group=GROUP_ID --conversation=GROUP_ID
```

Recovery requires a local controlling terminal. Confirm the displayed account
fingerprint, enter the original account's 24 recovery words in the hidden prompt,
and enter the restored local data passphrase (the value of
`RESTORED_LOCAL_PASSPHRASE`, not the archive password). Recovery revokes all other
devices and certifies this installation's fresh signing branch. Ordinary custody
admission then publishes the replacement authority; networking becomes `live`
only after the exact durable publication acknowledgement. A node or admission
failure leaves the restored data persisted with networking pending; it does not
undo the offline import. Inspect `account status` and retry ordinary activation
with `rf account unlock --account=RESTORED_ACCOUNT
--passphrase-env=RESTORED_LOCAL_PASSPHRASE` after resolving node availability.
Never enter recovery words in response to an unsolicited network prompt.

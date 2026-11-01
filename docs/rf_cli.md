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
Repeat `dm read` after a fetch failure to retry; SDK clients can also invoke
`object.fetch`. Automatic reads have a bounded work window. A deferred fetch
resumes verified chunks and confirmed relay acknowledgements on the next read;
it does not restart the acknowledgement pass. The daemon logs
`scheduler_fetch_deadline` when that window expires.
`rf object list --account=ACCOUNT` lists available metadata on either side, using
bounded directory pages rather than embedding ciphertext.
Existing object data and attachment references remain readable.

## Native groups

A born-v3 group has one signed conversation, selected at creation. `rf group
create` uses the group id for that conversation. Later `group send` and `group
read` commands resolve their conversation selector to that same thread; the send
response reports its conversation id. Both participants therefore use the same
group history even when their commands supply a different local conversation
name.

An invalid `RUST_LOG` value produces one stderr warning and leaves daemon logging disabled; the daemon continues to start. Hold and dead-letter diagnostics include the envelope, source device and target delivery identifiers. Unrouted inbound entries also emit an info-level hold with a reason.

On the next native group operation, cached group links from earlier CLI versions are reconciled with the signed group conversation. Existing conversation and history records are retained.

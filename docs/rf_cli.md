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

## Native groups

A born-v3 group has one signed conversation, selected at creation. `rf group
create` uses the group id for that conversation. Later `group send` and `group
read` commands resolve their conversation selector to that same thread; the send
response reports its conversation id. Both participants therefore use the same
group history even when their commands supply a different local conversation
name.

An invalid `RUST_LOG` value produces one stderr warning and leaves daemon logging disabled; the daemon continues to start. Hold and dead-letter diagnostics include the envelope, source device and target delivery identifiers. Unrouted inbound entries also emit an info-level hold with a reason.

On the next native group operation, cached group links from earlier CLI versions are reconciled with the signed group conversation. Existing conversation and history records are retained.

# Agent host

`ramflux-agent-host` is an ordinary headless participant using an existing unlocked
rfd account. rfd retains its keys and performs normal authenticated message delivery.
The host accepts no root seeds, device seeds, passphrases, human credentials or grant
confirmations. Rules match trimmed whole messages exactly and return one text reply.

Provision the account with `rf account create --client-mode headless_ai` using the
normal account setup options. Add its principal as a contact and group member through
normal rfd flows. The host verifies both persisted `client_mode` and self identity
kind before acting. Persisted local-device authorization is checked independently of
the display device list, which always includes the active device. Conversation
membership and device authorization are checked again
before every reply. No surface, task or tool methods are sent by this version.

Copy `example.json` and set the socket, account and durable state paths. Create the
state directory with mode 0700. Use persistent local storage for the state path when
resuming across machine restarts. The example uses a runtime directory for an ephemeral
demo; moving to persistent storage is an operator choice.

```sh
install -d -m 700 "$HOME/.local/state/ramflux-agent"
cargo run -p ramflux-agent-host -- --config /path/to/agent.json
```

For remote rfd, supply an operator-managed authenticated Unix-socket forward, such as
OpenSSH StreamLocal forwarding, as `socket`. The host speaks the existing local bus;
it does not expose an unauthenticated TCP listener or manage remote credentials.
Do not run a second host with a different checkpoint against the same account.
An exclusive lock prevents two hosts sharing one checkpoint.

The checkpoint is atomically replaced, fsynced and written mode 0600. It contains an
account/device binding, applied journal sequence, bounded rate counters and at most
one prepared reply. A prepared reply includes plaintext output: protect the directory.
The host stores it before sending with a stable operation ID, so a lost response can
reuse rfd's durable receipt. After successful delivery it checkpoints the cursor and
clears that output. A revoked membership discards pending output rather than sending.
A changed group binding also invalidates pending output.

Subscription cursor jumps are legal for filtered topics. A retention gap reloads the
current conversation/group snapshots and resumes at the new journal head. Unavailable
historical commands are not synthesized from message history. Fresh startup similarly
starts at the current head. A pending prepared output still recovers after a gap if
current authorization allows it. Reconnection resumes from the last applied cursor.

Replies in one conversation within the configured interval are skipped. Rate counters
survive restart; each new conversation consumes one bounded counter slot. When the
counter/directory limit is exhausted the host stops, requiring operator review. It
never evicts counters to bypass rate limits. Directory scans cap total response bytes
at 1 MiB and rows at the configured conversation bound (identity scans: 1024 rows).
Config is capped at 64 KiB, rules at 64, input/reply text at 16 KiB, and checkpoint at
512 KiB. The SDK bounds individual wire frames and its event queue.

`EngineProvider` receives approved conversation text and returns typed `Intent`s.
`Intent` is non-exhaustive for future protocol extensions; this host executes at most
one `ReplyText` per input. Future providers must honor that bound. Normal input content
is never logged. CLI errors omit rfd response bodies and message data.

Run unit/fake-bus tests with `cargo test -p ramflux-agent-host`. The companion integration
suite provides `k5a_realnet_agent_replies_in_dm_and_group`, covering authenticated DM
and group replies and host restart without duplicate replies. The QA controller runs
that gated slice on a container host; unit tests do not claim realnet acceptance.

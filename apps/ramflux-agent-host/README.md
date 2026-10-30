# Agent host

`ramflux-agent-host` is an ordinary native headless participant. rfd retains authority
keys and performs normal authenticated message delivery. On first start the host may
consume the daemon-generated one-use provisioning bundle; it never receives a recovery
phrase, master key, branch key, human credential, or grant confirmation. Rules match
trimmed whole messages exactly and return one text reply or one bounded
surface batch.

The live native human owner creates the `headless_ai` account through the local-bus
ceremony in an unlocked owner session documented in `docs/local_bus_account_creation.md`, saves the service phrase,
and exports the agent credentials to a new private path. Add the resulting principal as
a contact through normal rfd flows. The host verifies self identity
kind before acting. Native status checks the local branch's message authorization against
the current persisted custody record, independently of
the display device list, which always includes the active device. Conversation
membership and device authorization are checked again
before every output. Direct-message replies resolve the projected sender principal
inside that conversation and prepare one durable delivery for every current device
from that principal's directory entry, with one logical message ID and distinct
per-device envelope and operation IDs; device display names cannot select a different principal. Surface output uses `surface.send`, the author `surface.resync` RPC and typed protocol
builders; the host sends no task/tool/approval operations.

Native group commands use the verified principal in `sender_id`; the received
projection retains the authenticated branch in `sender_device_id` and its root in
`sender_root_commitment`. Before reading a command and immediately before output,
the host requires effective local device membership and a signed roster pin matching
its verified self principal/root and current branch key. A display name alone cannot
authorize a reply. Removal or a changed group binding discards prepared output.
`GroupLeaseUnavailable` retires that intent with the typed checkpoint
`group_reason: "lease_unavailable"`; refresh branch authority through the owner's
normal custody flow and send a fresh command. The host never obtains primary authority
or retries a refused intent after restart.

Copy `example.json` and set the socket, account and durable state paths. Create the
state directory with mode 0700. Use persistent local storage for the state path when
resuming across machine restarts. The example uses a runtime directory for an ephemeral
demo; moving to persistent storage is an operator choice.

```sh
install -d -m 700 "$HOME/.local/state/ramflux-agent"
cargo run -p ramflux-agent-host -- \
  --config /path/to/agent.json \
  --provisioning-bundle /private/path/agent.bundle
```

The first successful import stores the data passphrase in the operator Mac Keychain,
removes the bundle, and unlocks the rfd account. Later starts need only `--config`.
For an sd001 demo, run rfd and the agent host on the operator Mac, configure rfd with
the signed sd001 node profile, create and unlock the human owner first, then run:

```sh
rf account create --display-name "Demo agent" --kind headless_ai --custodian "$OWNER_ACCOUNT"
rf account export-agent-credentials --account "$AGENT_ACCOUNT" --out /private/path/agent.bundle
```

The owner account must remain the active unlocked account for export. Record the service
phrase shown once by the first command. Export is one-shot: if the bundle is lost, recover
the agent with that phrase rather than trying to export the credential again. Add the two
native principals as contacts, and then start the host with the bundle. Linux production
is not supported until `ID-02-VAULT-LINUX-01`; do not copy the
bundle to the Linux service host. Integration tests compile the explicit
`--itest-memory-vault` alternative, which is volatile and unavailable in production.

For remote rfd, supply an operator-managed authenticated Unix-socket forward, such as
OpenSSH StreamLocal forwarding, as `socket`. The host speaks the existing local bus;
it does not expose an unauthenticated TCP listener or manage remote credentials.
Do not run a second host with a different checkpoint against the same account.
An exclusive lock prevents two hosts sharing one checkpoint.

The checkpoint is atomically replaced, fsynced and written mode 0600. It contains an
account/device binding, applied journal sequence, bounded rate counters and at most
one prepared output batch. A batch includes plaintext output: protect the directory.
The host stores the entire batch before sending with stable operation/message IDs,
so a lost response can reuse rfd's durable receipt. Each completed step is checkpointed
before the next begins. After successful delivery it checkpoints the cursor and
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

`EngineProvider` receives approved conversation text and returns typed `Intent`s:
`ReplyText`, `CreateSurface`, `StreamAppend`, `PatchSurface`, and `CloseSurface`.
All protocol events are encoded with `SurfaceSendRequest` and the existing A2UI
commands; version/hash checks and signed transport remain in rfd. A surface batch
has at most 96 outputs with one surface identity. Plain text remains one reply.
Normal input content and rfd response bodies are never logged.

A rule may add a `surface` object (see `example.json`). `chunk_bytes` is 256–4096
(default 512); UTF-8 boundaries are preserved, with at most 64 chunks and exactly
one final chunk. The final fallback is patched using the authoritative protocol
BLAKE3 hash. A plain streamed reply closes when complete. Up to 16 `choices` declare
normal surface action IDs/labels. They are conversational choices, never grants.

On `surface.changed`, the host explicitly reads the selected accepted action and
current snapshot. It requires the account to be the recorded author and creator
executor, and the action to be `actionable`. Replica terminals never execute mirrored
actions. The rule patches a result block and fallback, clears actions and optionally
closes (default `close_on_action: true`). It never appends to a finalized reply block.
The host trusts rfd's accepted action provenance; it still parses original action
bytes through `from_wire_bytes` and checks surface/conversation bindings.

A conflicting result is rebuilt from a fresh `surface.get` with a new request ID;
the old patch/hash is not resent. At most two rebuilds are allowed. Persistent
conflicts retire that output with a typed last_refusal, advance its event cursor,
and leave the host available for later events. Restart does not submit that rejected
result again. If a result patch was accepted before a stale close refusal, the rule
rederives only the missing close from the retained accepted action and matching
result/fallback, even though the action is no longer actionable. An interrupted successful batch
reuses its exact pending bytes. A conflicting ordinary stream reloads its scoped snapshot and validates its hash.
The prepared target may resume only an unchanged reply whose current text is a
prefix of the target: it appends the missing suffix, finalizes the stream, and
recomputes the fallback patch. Changes to choices or unrelated content stop that
output rather than overwriting newer decisions. At most two rebuilds are allowed.
The complete target is checked against the protocol's whole-snapshot size budget
before its first create, including both reply text and fallback.

Daemon refusal codes are preserved as typed fields; diagnostic text is neither
parsed nor logged. `not_author`, `too_large` and other terminal refusals stop the
batch and persist one bounded `last_refusal` record (conversation, surface and code).
Stale refusals checkpoint the need to reload before doing I/O, so a disconnect or
restart cannot replay a request already known to be stale. Own out-of-sync surface
notifications and interrupted action batches use the existing author resync RPC
with a durable message ID before rederiving from the recovered snapshot. Lost
resync responses retry the same ID. If a completed resync leaves the prepared surface
out of sync, the batch stops with a recorded refusal rather than sending another
resync in a loop. Older checkpoints without prepared target
metadata remain readable; stale legacy streams stop instead of guessing a target.

Handled action IDs are scoped and persisted as a FIFO of the most recent 2048 IDs.
This cache is an optimization: rfd's actionable/action_already_used checks remain
the authoritative replay guard. Expired last-reply entries are pruned before each
event; max_conversations bounds recent rate history, not directory size. Directory
lookups scan pages of at most 100 rows and 1 MiB per page without retaining the whole
directory (a 10,000-cursor ceiling and cycle detection bound a corrupt pager).
Recent conversation keys also have a 64 KiB budget; prepared output bodies are
bounded to 256 KiB so an individual output cannot exhaust checkpoint space.

Message triggers inside the configured interval are dropped with rate_limited.
User actions and resync notifications are deferred durably and rechecked by the next
poll after the interval ends. The queue holds at most 64 scoped references / 32 KiB,
with at most four references / 2 KiB per conversation. Eight busy conversations
can use at most half the queue, leaving headroom for a new conversation. Only the newest work in a
conversation above its share is refused. Older checkpoints are compacted by the same
rule on startup, keeping the oldest references. Each poll processes all due rows in
sequence order within these bounds, with no copied action values. Current
author/executor/actionability is read again
before use. It survives restart and keeps the account cursor moving. Its timestamp
records the actual recheck time. The event loop never sleeps for a conversation interval. A peer losing
its devices, a stale executor notification, an unusable surface or an invalid provider
output records a typed last_refusal and advances the cursor. Lost transport replies
retain the exact durable pending request and reconnect. Only loss of the host's own
identity/authorization or unrecoverable checkpoint I/O stops the running host.
Configuration rejects unsafe reply and choice-label text before connecting. Fresh/gap startup does not synthesize commands from old snapshots;
only already prepared work resumes. This deterministic skeleton has no automatic
executor takeover, task engine, provider networking or approval capability.

Run unit/fake-bus tests with `cargo test -p ramflux-agent-host`. Native `account.status`
requires a Live networking state (and no networking refusal reason when supplied), an
unlocked local account, an unfenced authority, and a verified headless self identity.
The companion integration
suite provides five native realnet slices under `tests::agent_v3_native`: k5a DM
reply and bundle consumption, k5a group reply/restart/removal, k5a2 agent surfaces,
k2b receiver-side surface refusals and streaming, and k3b single-device task approval.
The native group slice checks exact reply counts across process restart and a fresh
post-restart command, verified principal/device attribution, and removal fences.
Its volatile test vault restarts against the still-unlocked daemon; production restart
uses the persistent operator Keychain. The legacy k5a/k5a2 slices retain group surface
coverage, and legacy k3b retains second-device convergence until native pairing exists.
Run realnet slices on a container host; unit tests do not establish realnet acceptance.

Malformed read-model fields are permanent typed refusals, never transport retries.
Connection failures, explicit Unavailable/Busy/DeadlineExceeded refusals and gateway
authentication races with a valid local identity reconnect the host. Per-poll validation failures are recorded without abandoning the
event stream; an unchanged poll refusal does not rewrite the checkpoint. Confirmed
identity loss stops the host. An `Unauthenticated` refusal on another
method rechecks `account.status`, `device.list` and the self identity directory. A
valid identity makes the original operation retryable. Only terminal identity or
storage errors from revalidation stop the host; other recheck errors stay retryable. This check never automatically resends the original operation. The first poll waits one interval. A connection-level
stream gap triggers reconnect before account filtering. Foreign-account, non-event and
unsequenced data frames are logged without consuming an account cursor. Error logs
contain only fixed error classes and field names, never field values or reply bodies.

Reconnect failures use a process-owned exponential delay of 1, 2, 4, 8, 16, 32,
then at most 60 seconds, including repeated gateway authentication races with a
valid local identity. The counter survives socket reconnects. After four failures
stderr includes a persistent retry-status line with the count and delay, without
endpoint paths or response data. An attempt lasting at least 60 seconds resets
the delay to one second; Ctrl-C interrupts both requests and backoff sleeps.

The daemon's typed `AccountNotOpen` refusal confirms that the configured account
is closed, locked or missing and stops the host. The host does not parse diagnostic
messages to infer this condition. `Unauthenticated` (and the compatibility code
`NotAuthenticated`) during startup or reconnect remains retryable: the host backs
off and re-verifies its local identity before resuming work.

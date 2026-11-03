# Agent host

`ramflux-agent-host` is an ordinary native headless participant. rfd retains authority
keys and performs normal authenticated message delivery. On first start the host may
consume the daemon-generated one-use provisioning bundle; it never receives a recovery
phrase, master key, branch key, human credential, or grant confirmation. Choose exactly
one engine: deterministic rules, the local PRX HTTP console API, or the PRX Unix channel.
Rules match trimmed whole messages exactly and return one text reply or one bounded
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
builders. The rule engine sends no task/tool/approval operations; the PRX bridge uses
the signed task and grant flow described below.

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

## PRX HTTP engine

PRX can provide the model and tool-execution layer while rfd remains responsible for identity,
membership, signed delivery, and human approval evidence. Initialize PRX, then edit its active
configuration for the chosen authorization mode. The default supervised mode requires
the causal decision plane:

```sh
prx init --interactive
```

```toml
[autonomy]
level = "supervised"

[causal_tree]
enabled = true
```

Start the local PRX daemon. It prints a one-time pairing code when no client is paired. Exchange
that code locally and write only the returned bearer to a private file:

```sh
install -d -m 700 "$HOME/.local/state/ramflux-agent"
umask 077
curl --fail --silent --show-error -X POST \
  -H "X-Pairing-Code: $PAIR_CODE" \
  http://localhost:16830/pair \
  | jq -er .token > "$HOME/.local/state/ramflux-agent/prx.token"
chmod 600 "$HOME/.local/state/ramflux-agent/prx.token"
```

Do not put the bearer in the agent configuration. Select PRX instead of `rules` with an
`engine.prx` object:

```json
{
  "socket": "/private/path/to/rfd.sock",
  "state_file": "/private/path/to/agent-state.json",
  "account_id": "agent-account",
  "engine": {
    "prx": {
      "base_url": "http://localhost:16830/",
      "token_file": "/private/path/to/prx.token",
      "session_scope": "per_conversation",
      "request_timeout_s": 30,
      "turn_timeout_s": 120,
      "approval_timeout_s": 600,
      "authorization": "supervised",
      "max_in_flight_per_conversation": 1
    }
  }
}
```

Use the native headless provisioning and one-shot bundle flow above.
After the account is provisioned and unlocked, launch with the PRX configuration above.
The bundle and the PRX bearer are separate credentials and neither belongs in the checkpoint.

Each Ramflux conversation owns one persisted PRX session and at most one detached job. A second
message while a job or human decision is pending receives `engine_busy`; it is not forwarded or
queued. Busy hints bypass the ordinary reply interval; they do not admit another provider turn.
Replies are
final text, not streamed. PRX tool access is scoped in PRX configuration, including
`[autonomy.scopes]`, `[tool_tiering]`, and `exposed_tools`; the agent host does not broaden it.
In `authorization: "supervised"` (the default), the host fetches the authoritative PRX approval
view and creates a conversation task with a fresh high-risk grant request binding its tool,
redacted arguments summary, effect, call digest and decision ID. Model-written reply text never
supplies the consent label. Only the human's signed task decision is sent back to PRX. Standing
grants never approve a fresh supervised PRX decision. The approval deadline is PRX's
`pending_expires_at`, capped by `approval_timeout_s` (default 600 seconds). If PRX omits the expiry,
that configuration bound is the fallback. An unavailable decision after a signed human resolution
fails its task and returns a typed reply while other conversations continue. At expiry the host
declines PRX and attempts a failed task update. The existing signed task rules prohibit an agent
from clearing an unaccepted proposal or unresolved human step: if that update is refused, the host
records the refusal, retires the bridge, and returns `approval_timeout` while the signed task
remains available for human resolution. It never retries a permanently refused update in a
host-wide loop. A resumed turn can request another fresh human decision.

After PRX confirms an approval, transient resume failures retry only the resume request, never
the single-use approval POST. The shared core retry policy bounds this to three attempts with
100/200 ms backoff; each attempt retains the configured HTTP timeout. Permanent resume refusals
or exhausted retries retire the approval with `approval_unavailable`. Restoring state caps job
and approval deadlines to their configured remaining maxima without extending expired work.

For full authorization, set `authorization: "full"` here and `[autonomy] level = "full"` in PRX.
PRX must execute within its own configured scopes without asking the bridge for human approval.
An unexpected `awaiting_approval` is declined with `authorization_mismatch` and a fixed diagnostic
logged once per host process. This configuration setting is the interim authorization control;
the per-account runtime bus switch remains a separate feature.

Every detached job, including a resumed job, has a persisted wall-clock deadline set by
`turn_timeout_s` (default 120 seconds). At expiry the host cancels the job, returns
`engine_turn_timeout`, fails any resumed task, and frees the conversation after handling the
result. `request_timeout_s` separately bounds individual HTTP requests. Removing conversation
access, locking the account, or revoking the local device cancels jobs, best-effort revokes pending
PRX decisions, and removes local session mappings. PRX's console API exposes no session deletion
endpoint, so remote console history remains under PRX's retention policy.

PRX `[IMAGE:path]` markers are removed from text replies and no attachment is sent in this release.
Attachment transfer remains unsupported. The separate Unix channel engine below streams turns. PRX network
failures are silent with one log per 60-second window. A message whose submission fails while PRX
is unavailable is dropped after the host advances its cursor; it is not retried automatically.
Other terminal failures produce one short typed reply. The owner-only token file is read at
startup, is never checkpointed, and is never included in diagnostics. The bearer is an owner-wide
PRX credential, including access to other `/api/*` controls; keep it on the agent's own operating
system account and private volume. In groups, member-authored text reaches PRX under this single
owner credential. Supervised human decisions or the deliberately selected full mode, together with
PRX tool scopes, define the execution authority; a prompt header is only context and conveys no
permission. Headers include only the bounded sender display label, chat kind and mention flag,
never group member lists.

## PRX Unix channel engine

The channel adapter targets PRX bridge protocol v1 at revision
`0785e3f82c87da243b6fd1e64c9a9ba3769d17f7`. Run PRX separately as the same Unix
user as agent-host. The host connects to PRX; it does not launch it, edit its config,
read its secret store or use an HTTP bearer. Start rfd, unlock/provision the native
agent account, start PRX, then start agent-host. Keep the socket directory on a local
private volume. PRX creates the socket mode 0600 inside a directory mode 0700;
both must belong to the host's effective uid. Symlinks are refused.

Configure PRX's SQLite memory backend (required for erase), encrypted channel
storage, the actual agent account identifier and an operator-reviewed tool scope.
Use local autonomy that allows the intended tools so the channel gate is the only
human approval path. Local PRX durable approvals cannot be resolved over this channel.
A supervised example, added to an initialized PRX config, is:

```toml
[memory]
backend = "sqlite"

[autonomy]
level = "full"
workspace_only = true

[channels_config]
cli = false

[channels_config.ramflux]
socket_path = "/private/path/prx-run/ramflux.sock"
authorization_mode = "follow_rf"
max_in_flight_per_conversation = 1
on_new_message = "queue"
turn_wall_clock_secs = 300
encrypt_at_rest = true

[channels_config.ramflux.accounts."agent-account"]
cross_conversation_retrieval = false
```

```sh
prx --config-dir /private/path/prx-config channel start
```

Select the channel provider instead of `rules` or `engine.prx`:

```json
{
  "socket": "/private/path/rfd.sock",
  "state_file": "/private/path/agent-state.json",
  "account_id": "agent-account",
  "engine": {
    "prx_bridge": {
      "socket_path": "/private/path/prx-run/ramflux.sock",
      "authorization": "supervised",
      "turn_timeout_s": 330,
      "approval_timeout_s": 600,
      "stream_flush_ms": 500,
      "stream_max_bytes": 15360,
      "max_queued_inbound": 64
    }
  }
}
```

`authorization` is the interim per-account configuration control, not a runtime bus
switch or standing grant. In supervised mode every channel tool request needs a fresh
signed decision. On the agent's authenticated bus, use `contact.safety_number` and
`contact.verify` to verify the initiating human's current safety number; compare it
through an authenticated operator channel first. The human accepts the proposed task,
then approves or denies its fresh grant. Decide on the **same device that sent the
message**. A verified different device or a different group member cannot decide this
PRX turn. The bridge requires rfd's authenticated decision signer principal and device;
missing provenance, stale verification or a device mismatch returns `approval_unavailable`
and forwards no human decision. Re-verify changed safety numbers and send a new command
from the device that will decide. Never alter the checkpoint or substitute a device id.
The lower of PRX's expiry and `approval_timeout_s` wins; no action defaults to deny
and produces `approval_timeout`. A late approval never starts a tool.

For full authorization set the host `authorization` to `full`; PRX's channel mode must
be `follow_rf` or `full`. Use a 120-second PRX turn budget and a host timeout of at
least 150 seconds. Tools still emit progress but no grant is opened. An unexpected
channel approval expires with `authorization_mismatch`: correct both configurations
and send a new command. `prx_internal_approval_unavailable` means PRX asked its local
durable approval plane; configure the intended local tool scope to allow it before
retrying. Full authorization deliberately allows all tools within that PRX scope.
The host cannot enforce the PRX turn budget from its own config: keep
`turn_timeout_s` at least PRX's budget, preferably 30 seconds higher. Scripted tests use
45 seconds in PRX and at least 75 in the host; this is not the operator example.

Streaming synthesizes a StatusPanel, coalesces deltas at the configured interval,
rolls ordered blocks at 15 KiB, and bounds the whole turn to 60 appends. Final text is
one logical signed message per turn, across all recipient devices. Text above 16 KiB
is split into at most four messages and then truncated. Non-streamed turns use PRX's
final-surface fallback. Generic surfaces degrade to fallback text. Attachments and
surface actions are unsupported; typing is acknowledged but not displayed. Tool events
update an existing human-started/accepted running task only when the agent is assignee;
otherwise they appear as progress on the stream. The agent never starts audit tasks.

There is one active turn per conversation. Pending input is checkpointed until PRX
acknowledges it; reconnect resends the same turn and idempotency keys. Queues admit at
most eight inputs per conversation and 64 overall by default (configurable up to 256).
A full queue returns `engine_busy`. Queued inputs older than ten minutes are discarded
silently apart from a fixed diagnostic. A turn without terminal status is cancelled
at `turn_timeout_s` and returns `engine_turn_timeout`. PRX reply replay is process-local:
a PRX restart can lose unacknowledged output; such turns end at the host timeout.

Group deletion, disappearing-message expiry and local deletion on the agent's account
forward every tombstone to PRX. An erase stays in the durable outbox until PRX answers
`erased:true`, retrying errors with 1–60 second backoff. Queued input, local turn text,
stream buffers and pending notices for that message are cleared. Later inputs in that
conversation wait behind the erase. Deleting a human DM only tombstones the human's
local account; it does **not** retract that message on the agent or erase PRX memory.
Deleting the agent's own reply does not erase its input context. Removing the agent
sends `agent_revoked`, which erases PRX's scope, while Ramflux retains its existing
conversation data and removal marker. The host sends no Ramflux erase on removal.

Recovery is explicit:

- Socket ownership, mode or symlink failure stops startup with `invalid host configuration`.
  Stop both processes, restore the private directory and correct user, and restart PRX
  to recreate its socket. Do not relax the permissions.
- A missing/unreachable socket leaves the host running and retries with 1–60 second
  backoff. Restore PRX as the same user. A refused hello backs off for a minute;
  correct protocol version, account, authorization or the competing connection first.
- A paused or missing-hello erase waits for a fresh handshake; storage failure keeps
  retrying. Repair PRX storage and allow the outbox to drain. At 1024 erases the bridge
  stops new forwarding; it never evicts an erase to make space.
- Corrupt/bound-exceeding state or a checkpoint from another engine fails closed.
  Stop the host, preserve then move `state_file` aside and restart. Engine changes need
  the same procedure. Fresh state subscribes at the journal head: messages sent while
  down are not replayed. Never run two hosts against one account.
- An rfd disconnect while a human approval is pending retains the existing fail-safe
  policy: abandon/decline that approval rather than resume it after a bounded reconnect.
  A failed visible notice is checkpointed and delivered after reconnect; send a new
  command to request another decision. HTTP resume-POST idempotency remains an HTTP-only
  concern and is not supplied by this channel.

Only the existing atomic checkpoint writer persists bridge state; the file contains
queued plaintext and in-progress reply buffers, so protect its directory. Dedupe keys
are bounded to 512 per turn through ten minutes after terminal status. Socket queues
are bounded to 256 in each direction. Frame processing performs no bus reads; ordinary
periodic inbox/approval maintenance is separate. Changed body-free counters are printed
every minute and at shutdown as `agent host bridge stats {...}`. No input text, delta,
fallback, tool arguments, summaries or display names belong in diagnostics.

For remote rfd, supply an operator-managed authenticated Unix-socket forward, such as
OpenSSH StreamLocal forwarding, as `socket`. The host speaks the existing local bus;
it does not expose an unauthenticated TCP listener or manage remote credentials.
Do not run a second host with a different checkpoint against the same account.
An exclusive lock prevents two hosts sharing one checkpoint.

The checkpoint is atomically replaced, fsynced and written mode 0600. It contains an
account/device binding, applied journal sequence, bounded rate counters, PRX session/job/task
metadata when enabled, and at most one prepared output batch. It never contains the PRX bearer.
A batch includes plaintext output: protect the directory.
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
512 KiB for rules/HTTP, or 16 MiB for the bounded Unix bridge state. The SDK bounds individual wire frames and its event queue.

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
only already prepared work resumes. The host has no automatic executor takeover. Its PRX adapter
uses only the bounded provider and approval operations described below.

Run unit/fake-bus, fake-HTTP and fake-Unix-channel tests with `cargo test -p ramflux-agent-host`. Native `account.status`
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

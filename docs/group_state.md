# Signed group state

A shared group has one writer: its creator account root. Any current verified
creator device can sign a complete state snapshot with the root master key. The
snapshot binds the group, epoch, previous hash, root-qualified roster and roles,
name/name epoch, exclusions and creator. A separate device signature authenticates
the transport issuer, who must match the authenticated transport source and a
fresh signed device manifest. A forwarding member cannot alter creator authority.

Receivers accept a higher creator-certified epoch, including an arbitrary gap.
There is no operation history, delegated checkpoint or cross-root state writer.
A verified ownership transfer must bind the issuing device's current base hash
and a transferee countersignature. It wins a sibling edit at the transfer's epoch;
it cannot roll back a receiver more than one epoch beyond its base. Such a stale
transfer returns `transfer_requires_sync` and a signed current-head refusal. The
issuer records `group.state.conflict` with reason `transfer_refused_stale` and the
rejected `base_hash`. Pre-commit refusal lets the issuer synchronize and reissue;
a refusal cannot reverse an already committed handover. A fresh transfer from the newer head still
wins the higher-epoch case. This freshness rule supersedes unconditional transfer
chain dominance. Once a fresh transfer at epoch E is known, old-owner snapshots
at E or later are rejected. Reusing a certificate cannot replace known handover
content. Lagging members below the transfer base can follow its certified line.
Receiver-owned root-removal and device-exclusion floors survive branch changes,
wire exclusion pruning and restarts. A winning branch may restore a root/device
only through an explicit joined epoch later than its accepted removal. Missing
exclusions in a different signed snapshot never silently restore access. The
floor store uses indexed rows capped at 4096 irreducible fences per group.
Device fences subsumed by a departed-root fence are pruned. Only an operation
adding a new irreducible fence beyond that cap returns a typed
`GroupStateCapacity` refusal for `RemovalFences` rather than discarding safety state.
A receiver at the cap rejects a snapshot requiring another irreducible fence and
cannot follow later snapshots carrying that removal. This per-receiver limit is
accepted for this phase; receivers never discard a floor to catch up.
Conflicting snapshots within the same transfer chain can only be creator-device
writes; the lowest content hash wins, and the losing creator device reapplies its own pending
intents. Requests from other roots are always revalidated against the winning
current roster. This is an honest same-user concurrency rule, not multi-writer
consensus. A newly joining member cannot discover a creator snapshot withheld by
its inviter; the signature authenticates authority rather than global freshness.

## Bus contract

All calls select an unlocked account. The local device signs the operation or
request; an optional `actor_id` must equal that device.

```json
{"method":"group.create","body":{"group_id":"g","conversation_id":"thread","creator_id":"owner-device","name":"Checklist"}}
{"method":"group.member.add","body":{"group_id":"g","member_id":"peer-device","member_principal_commitment":"ROOT","role":"member"}}
{"method":"group.role.set","body":{"group_id":"g","member_id":"peer-device","member_principal_commitment":"ROOT","role":"admin"}}
{"method":"group.name.set","body":{"group_id":"g","name":"Reviewed checklist","request_id":"optional-retry-id"}}
{"method":"group.member.remove","body":{"group_id":"g","member_id":"peer-device","member_principal_commitment":"ROOT"}}
{"method":"group.requests.list","body":{"group_id":"g"}}
{"method":"group.invitations.list","body":{}}
{"method":"group.invitation.accept","body":{"group_id":"g"}}
{"method":"group.invitation.decline","body":{"group_id":"g"}}
```

An explicit root makes `member_id` literal, including address-shaped names.
Otherwise the selector must be unambiguous. Existing owner/admin role rules apply;
a member cannot grant itself an administrative role. Names must pass the protocol
single-line text rule and fit 256 UTF-8 bytes. Initial `title` aliases `name`.

Creator mutations commit immediately. Authorized non-creator mutations return
`pending: true`, `status: waiting_for_owner` and `request_id`. The signed request
binds actor root/device, group genesis, creator root, base epoch, intent, id and
expiry. A request is revalidated against current roles, even when based on an
older epoch. Duplicate ids with identical intent reuse the retained request;
different intent is refused. Results are creator-root signed and bound to the
original request hash. Statuses include `applied`, `already_applied`,
`permission_denied`, `capacity` and local `expired`.

**When the creator is offline, changes wait for the group owner.** No admin or
member device signs replacement group state. There are at most 8 pending requests
per requester root/group and 64 per group, with seven-day expiry. Admission checks current membership before directory IO and before persistence;
removed roots cannot stage new requests. The account retains at most 4096
request/result records, partitioned to at most 256 per group and 64 per requester
root/group, including completed results. Pending limits remain 64 per group and
8 per root/group. A valid member whose pending queue is full receives a signed
capacity result within the retained-result limits. Exhausting the retained pool
returns a typed refusal without adding another row. One group therefore cannot
fill the account pool. Controls
are limited to 32 per minute per authenticated source root before directory IO.
A refusal of a removal is returned as a typed signed result, not a silent success.

Only the creator may call `group.owner.transfer`. Its body contains `group_id`,
the selected `member_id`/`member_principal_commitment`, and `creator_actor` (the
new creator's root-certified device actor). The new creator must already be an
explicit verified member. A creator-signed transfer certificate permits the new
root to sign future snapshots; the old root loses write authority. The bounded
transfer chain supports at most 32 transfers. Transfer is a creator command,
not an admin request.

The first transfer call stages signed encrypted head probes and returns
`transfer_requires_sync`. Retry the same command after delivery; a new command
is needed if the base changed. Every currently active, group-selected creator
sibling and the selected transferee must confirm the exact head within 60 seconds.
The SDK fails closed when an active device cannot be reached; it never guesses
that a silent device is offline. Revoke an unavailable device through the account's
normal device-set flow before retrying. This is deliberately stricter than a
best-effort reachability check. Honest creator devices reserve that head for the
proposal until its signed outcome is observed or its issue deadline plus the
five-minute clock-skew allowance has passed. Local mutations and admin requests
wait during that reservation. The 60-second bound still limits issuing a transfer;
no valid issue can use the later release deadline. An unrelated changed head does
not release a live reservation.

Bounded reservation time favors liveness over guaranteed convergence under
unbounded delivery delay: a sibling may release on time and write before a validly
committed transfer reaches it. Two intervening epochs, or a removal at the
transfer's epoch, can make that delayed transfer stale for the sibling and its
followers and leave a group fork. The issue deadline does not bound delivery time;
clock skew can make this release overlap the issuer's last valid issue instant.

Deadline maintenance checks at most 128 pending proposals, 4096 reservations and
512 cancellation deliveries per tick. Each item updates in its own transaction;
a failing item is logged and left for retry under the existing retention bounds
while healthy deadline items and other group courier work continue. Transfer-delivery collection also skips a
failed item rather than letting it block request/result selection.

On the first courier tick after the issue deadline plus five minutes, an issuer
without a committed transfer stages a durable signed cancellation. Siblings also
release an expired reservation without requiring the issuer to return. A revoked
or no-longer-selected issuer releases its sibling reservations sooner. New
proposals wait for cancellation acknowledgements from still-active selected
targets; revoked or deselected targets count as released. Silence alone is not
revocation. A short durable outcome fence rejects delayed completed probes.
Devices need synchronized clocks within ±5 minutes. Probe/reply validation permits
that skew; transferee acceptance uses the issuer's probe timestamp so skew cannot
extend the issuer's strict 60-second completion window. Typed
`transfer_requires_sync` errors carry a reason (such as `transfer_outcome_pending`,
`clock_skew_or_expired_control`, or `head_check_pending`). The transferee signs the group,
genesis, previous creator, exact base hash/epoch, target actor, nonce and expiry.
Snapshots retain this acceptance and the root-signed transfer certificate so
receivers can verify it offline after the handshake expires. Head probes and
signed refusals use the existing bounded group-control pair courier, with 60-second
issue lifetime plus the five-minute transport skew allowance, at most 8 retained
controls per group and 512 per account. Signed cancellations remain durable until
all still-active selected participants acknowledge observation;
their seven-day signed transport lifetime is renewed while outstanding. Gateway
submission alone does not count as a cancellation acknowledgement. Other completed
deliveries are retired; retries never renew a reservation.

A malicious former creator can still equivocate and seek countersignatures from
two different transferees. Receivers keep their first accepted transfer chain,
so such double transfers can split a group. Freshness checks, exclusive creator
leases and transferee countersigning prevent an ordinary honest SDK transfer
from doing this; they do not provide a global sequencer or consensus against a
malicious former owner. Resolving this limitation belongs to the future group
protocol. A malicious former owner can also keep signing its old line without a
second transfer: unaware members can advance beyond the transfer base, reject the
handover as stale, and remain split. This is the accepted availability limit of
sticky removals and transfer freshness, not global consensus. Withheld snapshots
remain an explicit limitation as described above.

## Consent, membership and names

An unknown group is adopted automatically only if its creator is an
accepted contact (or the local root). A transport forwarder is never an inviter;
currently only the creator grants implicit contact consent. Any future explicit
v2 invitation must separately authenticate its inviter. Otherwise the verified snapshot is held as
an invitation, outside joined group/conversation/message projections. A
legacy bootstrap cannot bypass consent, even when forwarded by a contact: it is
refused and requires a v2 invitation.
Known legacy groups retain their existing receive path. Explicit
acceptance adopts the signed state; decline retains a replay fence. Either decision
also produces a root-certified branch-signed own-account control carried inside
authenticated encrypted own-device delivery. Other active siblings adopt that
same genesis without another prompt, or honor the decline. A delayed acceptance
cannot override a live decline, a block, an excluded device or another genesis.
The signed decision has a fixed seven-day lifetime and bounded retained state;
ordinary own-device restore handles devices enrolled later. Blocked
creators or inviters are rejected. A joined member need not be a contact to send
group messages; individual source blocks still apply.

Invitations have a receiver-chosen seven-day lifetime, unchanged by replays or
newer snapshots. Limits are four live invitations per inviter, 32 live per account
and 128 total including declined fences. Authentication precedes quota charging.

`group.members` includes the signed `member_roster`, `excluded_devices`, `name`
and `name_epoch`. Legacy `members`/`roles` are display fields; duplicate literal
device names cannot identify an authorization principal. Signed names project
into the linked conversation title; ordinary traffic cannot replace them.

Current signed device sets expand root membership into implicit siblings. Explicit
active devices have priority, then device selection proceeds fairly across roots.
There are at most 200 member roots, 1024 selected devices total and 16 devices per
root. Excess devices receive typed capacity refusals; one root's excess devices
do not stop other roots' delivery. Account device revocation is checked separately.
Group-only device exclusions remain while their root is still a member; a timer
never re-admits an excluded sibling. Explicit adds cannot override that exclusion.
Members plus retained exclusions share the 16-device per-root add budget, and
removing implicit devices cannot create more than 16 exclusions for one root.
After the root leaves, its exclusions may expire after the seven-day boundary
window; a deliberate re-add starts a new root membership. Signed account revocation
independently disables the device everywhere.

## Delivery, recovery and identity

Snapshots and pointer delivery intents commit atomically; the account actor drains
them later. Local removals have priority and cannot be refused by the 32-group
recovery admission cap. A drain visits at most four roots and attempts four devices;
partial drains keep a cursor. The 1024-device work window yields and resumes.
Successful recipients stay recorded across retries and same-head coalescing.

Frozen removal boundaries store root/device/head pointers and one immutable proof
per head. They remain durable for seven days, even beyond the normal eight-round,
one-hour retry window. Failed boundary windows resume after five minutes. Removed
recipients receive their original boundary without a new sender key or later
roster/name. Boundaries freeze the eligible devices rather than expanding removals
into newly enrolled devices.

Own-device-set epoch changes trigger bounded activation backfill and a small
authenticated device-set beacon to existing members. Receiving a beacon refreshes
the sender root's verified device directory without advancing the group epoch.
This exposes implicit siblings to existing peers. Idle ticks never resend full
snapshots. First-send controls still carry the current signed snapshot and sender
key, so missed state does not lose the first application message.

Requests, results and beacons use the existing pair/federation control transport.
Each queued control retains its own sealed attempt before submit, a bounded
network deadline and fair retry rotation. An offline recipient cannot hold other
groups' controls. Federation hints are routing metadata, not membership authority;
recipient manifests and branch keys remain verified.

`group.send` returns a sender-qualified `message_id` and the caller's original
`client_message_id`. The canonical id hashes group, authenticated root, device and
logical caller id. Authenticated routing carries the original logical id so every
recipient derives the same canonical id, independently of arrival order. Retries
may use the returned id. Another member cannot reserve that sender's id by sending
first. Callers should use returned ids for message references.

Sender keys and message AEAD bind the complete content hash, sender root/device
and epoch. Only locally committed verified heads may allocate key scopes. At most
64 known heads per group and 64 active checkpoints per group/sender/direction are
retained; historical event bodies follow normal account history retention. Replay
of a bootstrap cannot reset an advanced ratchet or substitute a different seed.
Diagnostic delivery failures retain per-device attribution; conflict/delivery rows
are bounded to eight per subject and 4096 combined, with a seven-day age bound.

## Budgets and compatibility

The independent full-snapshot budget is 98,304 bytes:
`floor((1 MiB gateway frame - 64 KiB metadata reserve) / 10)`. Typed refusals cover
member roots, devices, bytes, requests and transfers, surfaced as
`GroupStateCapacity`. Long identifiers or exclusions can reach the byte limit
before the roster limit. A native regression seals and submits a 200-root snapshot
through the ordinary gateway frame path.

Shared packets use `ramflux.sdk.group_state.v2` and creator snapshots use
`ramflux.group_state.snapshot.v2`. Older experimental multi-writer shared proofs
are not accepted as v2. Unsigned legacy groups remain on their existing path;
legacy storage mutators cannot modify a shared-group projection. All participants
need v2 support. Transfer participants must also support the r7 signed cancellation
and observation acknowledgement fields; finish any outstanding experimental
handover before upgrading devices piecemeal. Large-group multi-writer consensus
is outside this protocol.

## Message identifier upgrade and retention

The `groupmsg:` namespace is reserved: direct-message callers are escaped into
the authenticated routed namespace. Outgoing group aliases follow their message
history: deletion/redaction removes the alias in the same database statement;
uncommitted aliases expire after one day and are cleaned on the next send.
In-flight messages without a logical group id are accepted only for seven days
from the account's first startup on this version, and only if their signed
creation time is no later than that startup. Their envelope id supplies the
logical component inside the authenticated sender namespace. After that window,
missing ids fail closed. Modern messages are unaffected.

### Transfer upgrade

Transfers now require the countersignature fields and the v2 transfer-certificate
signature domain. There is no permissive decoder for an earlier unsigned
handover. Existing groups without transfers retain their snapshot encoding;
experimental pre-upgrade transfer chains must be migrated explicitly rather than
accepted without the new authority proof.

## Restore compatibility

BACKUP restore archives outbound sender chains and starts a fresh seed-bound
chain, even when the signed group head has not changed. Shared-group distribution
v4 binds this fresh chain to the verified state head and authenticates its seed
hash with the current sender device's branch signature. Receivers retain previous
chains for historical decryption; reading an old chain or replaying a distribution
never resets an advanced ratchet or replaces the active fresh chain. Legacy shared
v3 distributions retain their original head-bound transcript and immutable seed;
legacy groups' BACKUP v3 distributions retain their seed-bound transcript. These
two v3 formats are distinguished by the presence of `group_state_hash`.

A private backup merge verifies the creator-signed full snapshots before selecting
a group head. It unions durable receiver removal floors from both generations,
including older inactive-member projections when upgrading, and rebuilds the
roster, local role and conversation name from the selected signed state. A stale
transfer cannot displace a later live head. If neither selected line preserves
the combined removal fences, merge refuses before the private generation can be
installed; it never repairs a signature by editing its snapshot. Existing contact,
object, message-erasure, profile and kind merge policies remain independent.

Own-account invitation decisions are ordered by their branch-signed `issued_at`:
the latest explicit decision wins, and decline wins an exact timestamp tie.
A new local decision signs at `max(now, stored_issued_at + 1)` and is saved before
local adoption in the same transaction, so a clock-ahead stored decision cannot
contradict a successful local reply. Replays never renew decision expiry. An older decline cannot undo a later
acceptance; account blocks, group exclusions and genesis checks remain mandatory.
Creator devices repair losing branches from the durable receiver removal floors,
even after the seven-day pending-intent log expires, then re-sign the removals
before replaying other pending edits.

Backup restore and merge archive `group-transfer/*` rows as inert audit data and
start without live reservations, pending proposals, deliveries or outcome fences.
A restore cannot resume a pre-backup handshake. It must synchronize current group
state before attempting another ownership transfer; remote reservations still
observe their bounded release rules.

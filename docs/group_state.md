# Signed group state

A shared group has one writer: its creator account root. Any current verified
creator device can sign a complete state snapshot with the root master key. The
snapshot binds the group, epoch, previous hash, root-qualified roster and roles,
name/name epoch, exclusions and creator. A separate device signature authenticates
the transport issuer, who must match the authenticated transport source and a
fresh signed device manifest. A forwarding member cannot alter creator authority.

Receivers accept a higher creator-certified epoch, including an arbitrary gap.
There is no operation history, delegated checkpoint or cross-root state writer.
Conflicting snapshots at the same epoch can only be creator-device writes; the
lowest content hash wins, and the losing creator device reapplies its own pending
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
per requester root/group and 64 per group, with seven-day expiry. The account
retains at most 4096 request/result records, including short-lived replay receipts.
A refusal of a removal is returned as a typed signed result, not a silent success.

Only the creator may call `group.owner.transfer`. Its body contains `group_id`,
the selected `member_id`/`member_principal_commitment`, and `creator_actor` (the
new creator's root-certified device actor). The new creator must already be an
explicit verified member. A creator-signed transfer certificate permits the new
root to sign future snapshots; the old root loses write authority. The bounded
transfer chain supports at most 32 transfers. Transfer is a creator command,
not an admin request.

## Consent, membership and names

An unknown group is adopted automatically only if its creator or inviter is an
accepted contact (or the local root). Otherwise its verified snapshot is held as
an invitation, outside joined group/conversation/message projections. A stranger's
legacy bootstrap cannot bypass consent: it is refused and requires a v2 invitation.
Known legacy groups retain their existing receive path. Explicit
acceptance adopts the signed state; decline retains a replay fence. Blocked
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
Group-only device exclusions expire after their seven-day boundary window and
are pruned on the next creator mutation. If the root remains a member, an active,
unrevoked device may then follow its root again. Permanent removal uses signed
account device revocation.

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
need v2 support. Large-group multi-writer consensus is outside this protocol.

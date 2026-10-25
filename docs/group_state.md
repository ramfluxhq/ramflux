# Signed group state

New `group.create` bus calls create an authenticated shared group. Membership,
roles and the group name advance together through root-authorized operations.
Each operation binds the previous state hash and next epoch; full snapshots carry
its verified history or a root-signed checkpoint with creator-certified delegation. A transport issuer must also
match its current root-bound device manifest. Group declarations alone never grant
device-key authority.

## Bus contract

All calls select an unlocked account through the bus frame. The actual local
account/device signs mutations; an optional `actor_id` must name that device.

```json
{"method":"group.create","body":{"group_id":"g","conversation_id":"thread","creator_id":"owner-device","name":"Checklist"}}
{"method":"group.member.add","body":{"group_id":"g","member_id":"peer-device","member_principal_commitment":"ROOT_COMMITMENT","role":"member"}}
{"method":"group.role.set","body":{"group_id":"g","member_id":"peer-device","member_principal_commitment":"ROOT_COMMITMENT","role":"admin"}}
{"method":"group.name.set","body":{"group_id":"g","name":"Reviewed checklist"}}
{"method":"group.member.remove","body":{"group_id":"g","member_id":"peer-device","member_principal_commitment":"ROOT_COMMITMENT"}}
```

An explicit root makes `member_id` a literal name, including names shaped like
qualified addresses. Without a root, a selector must be unambiguous. Existing
owner/admin role rules apply; creator ownership cannot be removed or transferred. Names
are at most 256 UTF-8 bytes and must pass the protocol's single-line text-safety
rule. The initial `title` field remains an alias for `name`.

Shared entries in `group.list` include `name` and `name_epoch`. `group.members`
also includes `member_roster` and `excluded_devices`; its signed roster contains
root-qualified member identities and roles. The legacy `members`/`roles` fields are display views;
they cannot identify an authorization principal when device names collide.
Delivery routes expand verified root membership through current usable device
manifests, so active siblings follow their account's membership without an
explicit join. Explicit exclusions still deny that device.

A signed name projects into the linked conversation title. Ordinary group sends,
reads and directory refreshes preserve that title. Caller-selected local display
metadata cannot replace the signed name or membership.

## Delivery and recovery

Mutations atomically persist state and a durable delivery intent, then return.
Every current device receives the complete proof. Removed recipients receive their
frozen removal boundary without a new epoch's sender key; an earlier device
removal remains frozen even if the whole root is removed later. A first bootstrap
packet supplies the issuer's sender key. Idempotent replays cannot reset a receive
ratchet, and changing a seed within the same content head is rejected. Sender keys and message AEAD bind the full content head, in addition to the root-qualified sender and epoch. Other senders distribute
their own keys through the ordinary group-send path.

The account actor drains one group per tick, with at most four member roots and
four undelivered recipient attempts per drain. Partial drains retain a cursor and
share one retry round. The 1024-device work window yields and resumes rather than
rejecting a large account roster. Successful recipients remain recorded across
failed rounds and same-head coalescing. Local removals run first; local mutation
pointers have no recovery queue cap. Recovery has its own 32-group admission
budget, so recovery saturation cannot roll back a committed removal.

An intent contains the group/epoch/content-head pointer and delivery progress;
the current proof is read from storage. Frozen removal boundaries contain only
root/device/head references, with each immutable proof stored once. Boundaries
survive the normal eight-round, one-hour retry window and remain durable for seven
days. A failed boundary window resumes after a five-minute backoff. A recipient
removed earlier gets its original boundary, never a later roster/name or sender
seed. Network operations have bounded deadlines, and one group's preparation
failure does not prevent another group's turn.

Own-device activation restages up to four groups per tick when the authenticated
own-device-set epoch changes. Idle ticks never resend full state. A verified stale
or competing peer head is an explicit detected gap and can restage the current
head; same-head receives do not echo it. First-send key distribution also carries
the current signed proof so a peer that missed controls can catch up before data.
Encrypted own history retains signed names and membership. Legacy wrapper roles
cannot replace them.

Authorized forks resolve at their first divergent epoch: the lowest raw operation
hash wins, independent of branch length. A losing device re-signs its own durable
local writes on the winner before publishing the repaired state; removals are
preserved. A device does not impersonate another writer. Proofs that cannot be
related within retained ancestry, and local writes that cannot be reauthorized,
produce a typed `group.state.conflict` journal event rather than a retry loop.
The last 64 contiguous operation heads survive checkpoints; unrelated older heads
require an explicit conflict decision rather than an invented ancestry claim.

A locally configured federation hint remains scoped to its verified member root.
It is checked during member addition, retained atomically with the mutation and
shared by that root's implicit sibling routes. Manifest refresh and state forwarding
use the configured federation transport; the hint itself grants no membership.

## Limits and compatibility

A gateway frame is 1 MiB. The shared proof budget is
`floor((1 MiB - 64 KiB) / 10) = 98,304 bytes`, reserving transport/key metadata and
a conservative factor of ten for JSON/base64 and sealing expansion. A native
regression seals and submits a 200-member state through the ordinary envelope
path and checks the resulting submit frame (64,953 proof bytes and approximately 558,000 submit bytes in the native fixture). The explicit member cap is 200;
long identifiers, many privileged members, or exclusions can reach the independent
byte limit sooner. Capacity refusals are typed `GroupStateLimit::Members` or
`GroupStateLimit::Bytes`, surfaced on the bus as `GroupStateCapacity`. Larger groups
and object/chunk state transport are deferred.

Proofs retain at most 512 operations, with automatic checkpoints after 32 operations
or earlier when the byte budget requires it. The creator root certifies a compact
checkpoint authority: genesis, epoch/head and the complete owner/admin root roster,
including lower-role overrides and exclusions for those privileged roots. A
delegated admin can checkpoint ordinary member and name changes while preserving
that certified privileged roster exactly. Admins cannot invent ownership, promote
admins, remove privileged root overrides, or rewrite the creator's signature.
Creator changes to privileges immediately publish refreshed authority. Existing
members reject a delegated checkpoint older than their known authority floor.
Old proofs without delegation remain verifiable; the creator must publish an
updated checkpoint before admins can compact that old history.

New members accept a delegated checkpoint under the creator-root certificate and
the issuer's freshly authenticated device manifest. This authenticates delegation
and current membership in the supplied state, not a global freshness oracle: a
new member cannot discover a withheld newer group head from the proof alone.
Known members enforce their retained authority and fork history. Names and roster
changes continue to require the existing owner/admin permissions. Device-set
revocation checks remain independent of group checkpoint delegation.

Unsigned legacy storage mutators cannot alter shared-group projections.

Existing legacy groups remain on their previous path; there is no automatic
migration of an unsigned group into a new signed group. All participants need
support for the shared-group packet to receive the new state protocol. Group
name and state delivery use the existing account actor and transport architecture.

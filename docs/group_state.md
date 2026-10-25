# Signed group state

New `group.create` bus calls create an authenticated shared group. Membership,
roles and the group name advance together through root-authorized operations.
Each operation binds the previous state hash and next epoch; full snapshots carry
its verified history or a creator-root checkpoint. A transport issuer must also
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
ratchet, and changing a seed within an epoch is rejected. Other senders distribute
their own keys through the ordinary group-send path.

The account actor drains one group per tick in round-robin order, with at most
four member roots and four recipient attempts per drain. Partial drains retain a
cursor and share one retry round. Successful recipients remain recorded across
failed rounds. There are at most eight rounds within the original one-hour
window; coalescing a mutation preserves that budget. Capacity is 32 pending groups,
32 MiB of pending state and 1024 devices per round. Network operations have
bounded deadlines. Preparation errors are isolated per group; lost membership
or device revocation discards its pending broadcast.

Own-device activation restages up to four groups per tick when the authenticated
own-device-set epoch changes. Periodic recovery runs once per five-minute window;
same-epoch receives do not trigger an echo broadcast. Encrypted own history carries
the signed proof and name. Untrusted legacy wrapper roles cannot replace it.
Historical message projection checks membership presence without using a literal
device name to select a cryptographic identity.

A locally configured federation hint remains scoped to its verified member root.
It is checked during member addition, retained atomically with the mutation and
shared by that root's implicit sibling routes. Manifest refresh and state forwarding
use the configured federation transport; the hint itself grants no membership.

## Limits and compatibility

Proofs allow at most 512 steps, 512 KiB, 1000 explicit members and 2048 device
exclusions. Creator-root checkpoints compact history after 32 operations.
Unsigned legacy storage mutators cannot alter shared-group projections.

Existing legacy groups remain on their previous path; there is no automatic
migration of an unsigned group into a new signed group. All participants need
support for the shared-group packet to receive the new state protocol. Group
name and state delivery use the existing account actor and transport architecture.

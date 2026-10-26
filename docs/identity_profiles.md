# Verified public identity profiles

A profile is a root-signed assertion, not a proof of biological humanity. Its
`kind` is `human`, `headless_ai` or `bot`; it also carries `display_name` and a
positive, monotonic `epoch`. The signature binds the principal ID, root commitment
and `ramflux.identity.profile.v1` domain. No node or contact card can sign for the
root. The immutable device-set kind must match the profile kind.

Device-set v2 (`ramflux.identity.signed_device_set.v2`) includes the entire signed
profile inside its root-signed canonical body. Both signatures use the same
root authority. Legacy device-set v1 remains readable with no profile; after
observing v2, a newer set cannot omit the profile, lower its epoch or change it at
the same epoch. A receiver persists this floor across restarts. Profile changes
also advance the enclosing device-set epoch. Device enrollment and revocation
retain the profile.

All signature inputs use existing canonical I-JSON serialization. Local input
normalizes to Unicode NFC and trims outer spacing. Display names must occupy one
line, be nonempty, use at most 128 scalars and 256 UTF-8 bytes, and contain no
Unicode control/format or line/paragraph separator characters. Verification
requires exact normalized bytes; it does not normalize signed remote content.
Unnormalized, unsigned, forged and oversized records fail closed.

New owned publications default the public display name to the principal ID.
Private account labels are not published. The SDK's `set_identity_display_name`
updates a root-signed desired profile for the next normal device-set publication;
it does not acknowledge network publication. No new bus method is introduced.
Workflow principals retain legacy behavior without a verified public profile.

`identity.directory` exposes the public name, kind and `kind_verified:true` after
root authentication. This flag is independent of `verified` / `safety_state`,
which still describe manual contact verification. `kind_asserted` is an enum
string or null. Principal lookup in `contact.add` returns the authenticated kind
and name; a card's older asserted label does not override them. Legacy card-only
assertions remain unverified.

Task actor metadata exposes the actual `actor_kind` alongside
`actor_kind_verified`. A signed public profile and a current member device are
required for verification. A relation-derived human role cannot attest a signed
bot/headless-AI kind as human. Existing task relation authorization is unchanged;
this flag authenticates metadata, not a new permission or proof of personhood.

The profile code borrows the same root signer as device-set signing; it creates
no new signing authority or root-seed storage. The planned primary/external
custodian boundary must provide both signatures together. Secondary devices
must obtain a root-authorized profile publication, not self-sign one with their
branch key. This is compatible with a future root-custody signer abstraction;
the present SDK retains its existing root ownership requirements.

Upgrades must be coordinated: old clients/servers that only implement complete
device-set v1 reject v2 rather than silently discarding its profile.

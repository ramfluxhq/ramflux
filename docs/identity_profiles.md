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

All signature inputs use existing canonical I-JSON serialization. The acceptance
policy below, including its pinned Unicode validation data, is frozen under
`ramflux.identity.profile.v1`. Because profile validation runs inside device-set
verification, future tightening or a Unicode table update that changes accepted
names requires a new profile domain version and coordinated rollout. It must not
invalidate already valid v1 signatures. The two additional check-like glyphs in
this pre-1.0 follow-up complete the freeze before deployment.

Local input normalizes to Unicode NFC and trims outer spacing. Display names must
occupy one line, be nonempty, use at most 128 scalars and 256 UTF-8 bytes, and
contain at least one letter or number. Reject controls, format/line/paragraph
separators, private-use/unassigned characters, default-ignorables, non-ASCII
spacing, blank fillers and leading/lone combining marks. Reject check-like glyphs
U+221A, U+237B, U+2611, U+2705, U+2713, U+2714, U+1F5F8 and U+1F5F9. Emoji ZWJ
sequences and keycaps consequently fail this policy. Verification requires exact
normalized bytes; it never normalizes signed remote content. Unnormalized,
unsigned, forged and oversized records fail closed.

Warning-only confusable comparison uses NFKC, locale-independent simple Unicode
case folding and whitespace collapse before the pinned UTS #39 skeleton. This
comparison key never changes displayed/signed names, identifiers, root commitments
or authorization. `mixed_script` applies the Highly Restrictive script-mix rule:
single resolved scripts and Latin with one of Han/Hiragana/Katakana, Han/Hangul or
Han/Bopomofo do not warn (for example `John 田中`). Other script mixes still warn;
whole-script lookalikes remain detectable through skeleton collisions. These are
public-name warning heuristics, not identifier acceptance restrictions or equality.
Their tuning must not change v1 signature validation. The name must never render
as a verification affordance: kind/verification chips belong to authenticated
claims, regardless of whether a lookalike glyph escapes this finite blocklist.

New owned publications default the public display name to the principal ID when
it meets the name policy; otherwise they use the fixed safe name `Account`.
A long or unsafe legacy identifier therefore remains publishable without
weakening the display-name policy.
Private account labels are not published. The SDK's `set_identity_display_name`
updates a root-signed desired profile for the next normal device-set publication;
it does not acknowledge network publication. If a stale restore encounters a newer
acknowledged profile, an outstanding rename is re-signed at the next available
profile epoch and persisted before retry. Exhaustion refuses publication without
dropping the intent. Matching acknowledged intents are cleared, so a rename whose
confirmation was saved locally does not overwrite a later sibling rename. A
restore taken before that confirmation cannot distinguish published-but-unconfirmed
from never published: the restored intent is reapplied and may win over a later
sibling rename (last restore wins). No new bus method is introduced.
Workflow principals retain legacy behavior without a verified public profile.

`identity.directory` exposes the public name, kind and `kind_verified:true` after
root authentication. This flag is independent of `verified` / `safety_state`,
which still describe manual contact verification. `kind_asserted` is an enum
string or null. Principal lookup in `contact.add` returns the authenticated kind
and name; a card's older asserted label does not override them. Legacy card-only
assertions remain unverified. `contact.verification.status` and contact safety
responses use the complete signed-authority stamp as well as the active-device
hash, matching `identity.directory` even for tombstone-only changes. Stored manual
verification is retained for audit. A fresh manual verification without an observed
signed set can remain `verified` for its synthetic safety material; this does not
authenticate a kind. Legacy v0.1.0 verifications without an authority stamp are
baselined once per account at the first writer unlock after upgrade, only when the
current active-device hash still matches the verified one. Eligible stamps and
`identity/safety-verification-migration/v1` commit atomically; a failed migration
leaves no completion marker and can be retried. Reader pools check that marker
before opening query-only snapshots and do not repeat a completed scan.
Verification reads never write stamps. After migration, an unstamped record with
observed signed authority is `verification_stale` until explicit re-verification;
new confirmation writers persist their authority stamp in the verification
transaction. An existing stamp is never replaced by migration, and later authority
changes remain stale. A mismatched active-device hash cannot acquire a migration
stamp. Legacy verifications imported after a completed migration also require
explicit confirmation when they lack signed-authority stamps.

Without an observed signed set, all views compare the synthetic safety-material
hash, ignoring a legacy card row's historical device hash. This can preserve
manual verification but never authenticates a public kind. A prior authority stamp
whose signed set is now unavailable still reads stale.

Task actor metadata exposes the actual `actor_kind` alongside
`actor_kind_verified`. A signed public profile and a current member device are
required for verification. A relation-derived human role cannot attest a signed
bot/headless-AI kind as human. Existing task relation authorization is unchanged;
this flag authenticates metadata, not a new permission or proof of personhood.
Actor-bearing journal events and message metadata include `actor_kind` (null if
no current authenticated device/profile) alongside the role-aware boolean. A
non-null kind with `actor_kind_verified:false` means an authenticated kind does
not match the action's role class; for example a headless requester on a
Human-class action. Actorless lifecycle compaction/removal events have neither
claim. Legacy journal entries may omit `actor_kind`; consumers treat that as
unknown and must not infer a kind from the role or the boolean alone.

The profile code borrows the same root signer as device-set signing; it creates
no new signing authority or root-seed storage. The planned primary/external
custodian boundary must provide both signatures together. Secondary devices
must obtain a root-authorized profile publication, not self-sign one with their
branch key. This is compatible with a future root-custody signer abstraction;
the present SDK retains its existing root ownership requirements.

Upgrades must be coordinated: old clients/servers that only implement complete
device-set v1 reject v2 rather than silently discarding its profile.

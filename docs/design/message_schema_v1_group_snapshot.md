# S10a native group snapshot amendment

Controller decision OV-GROUP-SNAPSHOT-ARM (2026-11-12) is FINAL after GROUP-SNAPSHOT-ARM-AUDIT-r1 (M1–M3 adopted). It adds the fixed typed replacement for the native full-state bootstrap packet before S10a activation:

```proto
message GroupControlBodySnapshot {
  NativeGroupSnapshot snapshot = 1;
  optional GroupKeyDistribution distribution = 2;
}
// GroupControlBody.value: GroupControlBodySnapshot snapshot = 5;
```

The selected arm invokes the existing canonical GroupStateSnapshot codec and native verification/state machine. Its schema field is checked against the native fixed value; it never selects a different codec. Native issuer/transport, current directory and membership, state continuity/removal floors and invitation-consent checks remain mandatory. A sender omits the distribution for recipients outside the signed membership. A present distribution must match the authenticated issuer, group, snapshot epoch and state hash, and pass the existing native key authentication before installation. Required consent precedes membership, route, joined-floor and key installation. Working seed copies are zeroized; private retained native invitation/key material follows the existing lifecycle. A typed control that is Unsupported never applies its native action.

The activation PR must identify this schema amendment. LAST removes the old live group-state wrapper admission. Scoped acceptance includes exact typed/canonical round-trip, missing/noncanonical snapshot, wrong issuer/epoch/hash/seed, nonmember and consent-before-install rows, plus a production break-the-fix.

The snapshot is required, nonempty and exactly canonical native JSON (duplicate/unknown native keys refuse), verified before installation. Raw generated scanning enforces minimal encoding, ordered singleton fields and oneof presence before decoding. Unknown generated fields remain Unsupported and never execute. Every NativeGroupSnapshot canonical leaf, including Transfer, OwnContext, OwnGroupConsent and original/history evidence, has the native 98,304-byte bound; other native leaves retain 8,192 bytes. Encoded GroupKeyDistribution is bounded to 4,096 bytes before parsing. Inner aggregate/depth/frame limits still apply.

Typed distribution maps explicitly to native v3/v4 schema/version, with exactly32 seed bytes, transport sender equal to snapshot issuer, pinned signing key, group/epoch/state-head equality, native v4 seed-bound signature and native v3 same-head seed fence. Identical replay cannot rewind a receiver; a valid v4 fresh chain remains permitted. State reconciliation and eligible key import form one transaction, and import requires that snapshot hash remain the installed head and local membership be effective. Production sealing derives eligibility from the selected root/device plus verified directory and snapshot; terminal/nonmember recipients receive no seed. Removed previously joined recipients may install terminal state without keys. History evidence never installs live state; reparsing Control never executes it.

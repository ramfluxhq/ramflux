# S10a native group snapshot amendment

Controller decision OV-GROUP-SNAPSHOT-ARM (2026-11-12) is provisional pending independent audit. It adds the fixed typed replacement for the native full-state bootstrap packet before S10a activation:

```proto
message GroupControlBodySnapshot {
  NativeGroupSnapshot snapshot = 1;
  optional GroupKeyDistribution distribution = 2;
}
// GroupControlBody.value: GroupControlBodySnapshot snapshot = 5;
```

The selected arm invokes the existing canonical GroupStateSnapshot codec and native verification/state machine. Its schema field is checked against the native fixed value; it never selects a different codec. Native issuer/transport, current directory and membership, state continuity/removal floors and invitation-consent checks remain mandatory. A sender omits the distribution for recipients outside the signed membership. A present distribution must match the authenticated issuer, group, snapshot epoch and state hash, and pass the existing native key authentication before installation. Required consent precedes membership, route, joined-floor and key installation. Working seed copies are zeroized; private retained native invitation/key material follows the existing lifecycle. A typed control that is Unsupported never applies its native action.

The activation PR must identify this schema amendment. LAST removes the old live group-state wrapper admission. Scoped acceptance includes exact typed/canonical round-trip, missing/noncanonical snapshot, wrong issuer/epoch/hash/seed, nonmember and consent-before-install rows, plus a production break-the-fix.

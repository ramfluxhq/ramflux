# ramflux-card

A bounded interpreter for authorized Surface v3 snapshots. ABI **5** consumes
`urn:ramflux:catalog:rf-card:1.0` through the public `ramflux-protocol` resolver.
The sole schema is `ramflux-protocol/catalogs/rf-card-v1.json`; the signed package
binds its digest, ABI, engine, bytecode and host-pinned release floor. There is
one catalog and one renderer path.

## Input and authority

`CardSpec` is the SDK-supplied envelope:

```json
{
  "conversation_id": "conversation",
  "author_principal_id": "own-agent",
  "surface_ref": "surface",
  "signed_version": 1,
  "signed_hash": "<signed snapshot commitment>",
  "render_allowed": true,
  "snapshot": {"surfaceId":"surface", "catalogId":"urn:ramflux:catalog:rf-card:1.0", "fallbackText":"Example", "components":[], "dataModel":{}, "final":[], "closed":false}
}
```

The example documents the shape; an empty component list is not an admitted
surface. `surface_ref` is the snapshot's `surfaceId`. The SDK must authenticate
the conversation and author and set `render_allowed` from its own-agent read
gate. A supplied boolean is not proof of authority. This crate validates the
signed snapshot commitment and protocol state; it has no account registry,
network, signing credentials, approval authority or attachment access. Closure
or loss of `render_allowed` retires an existing session and removes its tree and
host requests. SDK lifecycle/author-retirement wiring belongs to M3.

The parser bounds the envelope at 32 KiB and uses strict I-JSON. Protocol
admission separately bounds signed state at 16 KiB, model at 12 KiB, definitions
at 32, nesting at 16, templates at 16 items/two scopes, expanded instances at
256 and resolved properties at 64 KiB. Static references share memoized reachability,
maximum depth/template depth and a 2048-visit cap. Admission, action validation
and each resolve bound literal expression/read work from the 64 KiB expanded
source cap and depth 16: at most eight walks, 17 recursive levels and 17 enclosing
program evaluations per source byte. Model-computed `formatString` programs also
share a separate 4096-step allowance per expanded instance across admission,
read-closure collection, display and checks; nested programs never renew it.
The aggregate step ceiling is `8 * 17 * 17 * 65536 + 256 * 4096 = 152567808`.
Independent cells therefore do not spend one another's indirect-program allowance.
Expanded JSON bytes are charged before
bound values are cloned or inserted. The SDK passes presentation separately;
peer `theme`, `host`, script and unknown fields are refused.

## Shared evaluation and drafts

The resolver owns graph expansion, input ownership, expressions, checks and
action declarations. Rust resolves display calls before the library runs.
`resolve_for_locale` supports launch locales `en` and `zh-CN`, including nested
`formatString`, grouped numbers, currency, TR35 date tokens and plural category
selection. Unknown locale identifiers, malformed dates/patterns and unsupported
patterns refuse. Both locales use three-digit numeric groups, `.` decimals,
zero number decimals by default and two currency decimals (JPY/KRW use zero).
Date-only values use midnight UTC, RFC3339 values retain their encoded offset,
and integer timestamps are Unix milliseconds. Formats are display only; raw
values drive checks and egress. No JS `Intl` or second expression evaluator.

The signed base remains immutable. Session drafts hold at most 32 owned
pointers/4 KiB and are never persisted or sent as model updates. Signed updates
retain only drafts with matching component instance, pointer and base value
whose new constraints accept them. `draft_conflict()` reports discarded drafts.
Tab selection survives by key; Modal presentation and outstanding confirmations
are cancelled on a signed update. Every accepted edit increments `editSeq`.

## Native tree and events

`ramflux.card.tree.v1` is a flat preorder tree with session, signed version/hash,
edit sequence, tree version, root key, nodes and a complete host-slot array.
Keys canonically encode `[component_id, source_instance, route]`; edges are keys.
Every node corresponds to exactly one resolver instance. The library handles
all 20 kinds: Text, Icon, Row, Column, List, Card, Tabs, Modal, Divider, Button,
TextField, CheckBox, ChoicePicker, Slider, DateTimeInput, Image, Approval, Task,
Chart and Table. Structural references and executable declarations are removed
from attrs. Input pointers, action refs, disabled state, errors and accessibility
are runtime-owned. Rust compares the entire library output to its projection;
the library cannot change semantics or introduce CSS, geometry or host chrome.
Native hosts select host theme tokens for kinds/variants.

`ramflux.card.mutations.v1` carries `session`, `previous_version`, `version`,
`signed_version`, `signed_hash`, `edit_seq`, shallow remove/upsert operations and
the complete replacement `host_slots`. Removals are descendants first; upserts
are parents first and detach/reinsert by index. Hosts stage a batch atomically
at the matching session/version or pause interaction and request a reset tree.
Tree/batch transport is bounded at 256 KiB and 512 operations.

Host events contain `token:{session,signedVersion,editSeq,treeVersion,key}` and
`event:{kind,...}`. Kinds are `input{value}`, `activate`, `select_tab{index}`,
`modal_open`, `modal_close`. Only mounted, compatible current controls can act.
Stale tokens return `stale_dropped`. Activation consumes the Button until a
signed update; there is no automatic resend. A submit returns a resolver-selected
action, not success or network dispatch. M3 uses the current resolved surface's
`action_frame` with the exact shown `SurfaceState`, then signs and submits it.
Suspend drops the VM/requests while retaining drafts, surviving tab selection and consumed submits; resume creates a fresh token session identity. `complete_link` accepts an SDK-handled link completion, clears only its local pending slot and re-enables its Button; it performs no browser or authority effect.
Counters never wrap and are bounded to positive safe JSON integers (edit starts
at zero). The C handle remains stable across resume; use the batch session for
event tokens, not the registry handle.

## Host-only requests

`host_slots` replaces the previous array on every commit. Slot ids encode
`[kind,key]`; tokens and request ids fence all callbacks. Replacing/removing a
slot cancels its old work. Hidden tabs and closed Modal content cannot activate
controls or request images. The host retains local Tabs selection and Modal
presentation after its accepted semantic event; signed update/suspend cancels
sheets. Only one sheet may be active, with security sheets taking precedence.

- Approval contains `request_ref` and typed optional `task_binding`. The SDK
  resolves current facts and authority. The host draws facts, Deny and a single
  tap Confirm outside the tree. `request_ref`, explanation and every card field
  are untrusted lookup/display hints, never verified facts. The slot `request_id`
  serializes a runtime token; it is not an SDK-issued approval-record identity.
  M3 must look up its own current request record, derive and display verified
  facts itself, and bind a one-shot reply to both that record and the exact
  current slot/token. Recheck authority immediately before applying the reply;
  stale, missing, mismatched or cancelled records must refuse. Card explanation
  must never appear as verified security-sheet facts. No hold gesture; no
  approval card event.
- Modal contains trigger/content keys. The host owns the trigger affordance,
  sheet, scrim, focus and close/back/Escape. Nested trigger actions never dispatch.
- Link activation yields the canonical ASCII https URL validated by the protocol.
  The host shows that identical full URL, trusted author and privacy notice with
  Cancel and a single tap Open. M3 consumes the request, rechecks authority and
  uses a qualified browser-only handoff; no author event or prefetch.
- Image contains only an attachment selector, description, fit and variant.
  M3 verifies conversation membership, exact manifest digest, access and erasure
  before delivering encoded bytes out of band. JSON/JS never receive bytes,
  paths, URLs or data URIs. B owns PNG/JPEG header checks and decoding: encoded
  <=8 MiB, dimension <=4096, <=4,194,304 pixels/16 MiB RGBA, <=32 MiB decoded per
  session and one decode in flight. It copies borrowed callback bytes before
  posting to UI and releases buffers on cancellation/erasure. These decoder and
  authenticated-fetch behaviors are downstream requirements, not runtime proof.

`HostSlotReply` and borrowed `ImageResult` define the downstream boundary; the
runtime grants no authority to them. M3 must consume each confirmation once.
Chart retains independent series/labels/raw integers and requires a complete
native table alternative (up to 32 rows). Table keys are unique and rows must be
rectangular. Task is untrusted reported status. Icon accepts bounded named icons
or path data (4 KiB/1024 commands/finite coordinates), never an SVG document.

## Sandbox and packages

QuickJS-NG 0.16.2 / rquickjs 0.14.0 is interpreter-only. The sole bridge is
immutable `__rf_commit`; eval compilation, module loading, network and storage
are absent. The host bootstrap freezes reachable intrinsics before the signed
library loads. Signature/policy checks precede bytecode loading. Trust keys and
rollback floors come from the app release, never the received envelope/package.
Limits remain 32 MiB heap, 256 KiB stack, 50 ms per evaluation, 100 ms/s cumulative,
128 admissions/s, 32 queued events and two resident VMs. These are engine budgets,
not OS/RSS isolation. Failed evaluation preserves the last published data but
makes the VM inactive; hosts must cancel requests. Resume drops a failed VM,
clears old callbacks/sheets, retains consumed submits and drafts, and rebuilds
with a fresh token identity using the same cumulative execution budget.

The offline `card-pack` tool signs the linted `library/form.js` from a 32-byte
Ed25519 seed (`SigningKey::from_bytes`) plus release metadata. The seed is an
operator file and is never committed. The ABI 5 development public key bundled
in the SDK was produced that way; the seed file was not retained with the
bundle. Do not ship that development key in a release. Production custody is
an owner decision: an offline seed, used only by `card-pack`.

The ABI 4 development key is retired. Its descriptor pin
`56436c14b29b5b4f2b2c4672ffd346a3406ed8f2f4a832487b6a9f68d38cafa9`
(host ABI 4, catalog `rf-card/v1`, release 1:2) is not admitted. SDK
`include/card/policy.json` `exact_descriptor_sha256` admits only the ABI 5
descriptor `0b50eae6d66a57455d21b3854e2de6d58da90740bd4303db60d7f427b984792d`.
ABI 5 requires fresh artifacts; old artifacts fail admission.
`card-render PACKAGE_PREFIX ENVELOPE [UPDATED]`
loads `.qjb`, `.descriptor.json`, `.sig`, `.pub` and the independently pinned
`.policy.json` and prints the actual tree/mount/update batches. It accepts only
local operator files and performs no authentication on their behalf. Production
release-key custody/rotation is an owner release-process decision. C/wasm
callers supply the trust root and policy; this crate cannot establish their
provenance. The SDK must obtain both independently from its authenticated app
release, never from card JSON, the accompanying package, or a downloaded key.
It must pin catalog/engine/ABI and release floors before any unsafe bytecode
load. A valid signature under an attacker-selected key grants no trust; QuickJS
does not validate bytecode. Shipping remains conditional on the owner choosing
production key custody and rotation; fixture/operator keys prove no production
trust-root provisioning.

Native C calls are synchronous/thread-affine; callback JSON is borrowed for the
call and must be copied before posting to UI. The header documents status codes.
C builds require unwind mode (`ffi-release`), with the existing defensive C
boundary retained. Web uses the same Rust core in a dedicated worker. The web
preview maps semantic nodes with text/native controls, stages mutations and
forwards host slots; it does not implement SDK approval/link/image authority or
native Modal sheets. Mobile and desktop hosts are separate modules.

## Validation

Existing parser, keyed-diff, session, signed-library, C bridge and packer tests
were adapted to the replacement contract; no new tests were added. Existing
fixtures now contain authorized ABI-5 envelopes and snapshots, including
Image/Tabs/Modal and nested locale display. `.styles.json` snapshots now contain
host-owned theme tokens, rather than VM style geometry. Security hardening,
bytecode signature/floor and failure-budget regressions remain intact.

Cargo runs on QA through the lane wrapper; PR CI owns full suites/platform and
WASM checks. The controller's real run must feed actual `rf surface get` reads
from rf-produced own-agent cards through a `card-pack`-signed package and this
real-process driver, inspect mutations and refusals (bad id, bounds, tamper),
and retain the authenticated read evidence. Fixture/engine proof is not that
real account flow. SDK trust regeneration/session wiring, mobile linking,
authenticated actions and bounded native image decoding remain M3/B/host work.

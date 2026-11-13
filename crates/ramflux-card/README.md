# ramflux-card

A dormant interpreter-only card renderer, with no SDK dependency, network,
storage or approval authority. `rf-card/v1` is a local closed form profile; it
activates no wire catalog. Native hosts retain identity, Surface/hash binding,
permission checks, signing, delivery and receipts.

The application validates `CardSpec`, admits a project package using its own
release-pinned key **and acceptance policy**, and opens `CardSession` on a renderer
thread. The engine is exactly rquickjs/core/sys 0.14.0 / QuickJS-NG 0.16.2. Each VM
has 32 MiB engine heap, 256 KiB stack, a 50 ms evaluation deadline, rolling
100 ms/second allowance, and 128 admissions/second. At most two VMs are resident
per linked crate instance, with 32 events per session. Suspend/resume preserves
CPU accounting. These are engine limits, not RSS limits or OS isolation.

The execution context has JSON/Promise intrinsics and no Eval compiler, loader,
network or storage API. Before any package evaluates, a host-owned bootstrap
freezes the global object and every reachable intrinsic/prototype, including
function, async-function, generator and Promise chains. Hardening failure refuses
initialization. The bootstrap is compiled by the same pinned build engine with
little-endian bytecode. Package source never reaches that compiler. The sole
native JS bridge is immutable `__rf_commit`; the render function remains private
to Rust. Engine objects never cross a thread or await.

Project modules export synchronous `render(inputJson)` and must commit exactly
once. Rust validates the whole tree before producing any mutation. Unknown
controls/props, duplicate keys, wrong values/bindings and security chrome fail
closed. Input is capped at 16 KiB, 32 forms, a 4 KiB string model, and **16 JSON
nesting levels** (wrapper objects and children arrays count). A separate semantic
node-depth ceiling is 16; the JSON ceiling currently admits fewer node levels.
Expanded output is capped at 256 nodes / 64 KiB. Each form owns one local text
binding; submit returns a declarative intent containing that form's field only.
The host SDK must independently authorize any operation.

Every accepted update, edit, submit, suspend and resume advances a monotonic token
version. Events also carry a process-unique session ID; stale/foreign tokens are
dropped at dequeue and submit consumes its version. Invalid input and no-work
budget admission rejection preserve the live VM. An actual failed evaluation
drops the VM, advances the token epoch and retains the last mounted tree/version.
Disable interaction and show host fallback on that failure; retain the keyed
native tree until a suspend/removal batch or resume delta arrives. Resume can be
called directly and diffs against that retained tree, avoiding duplicate mounts.
A suspend clears the tree and queue; the next resume mounts a complete tree.

## Release descriptor and rollback policy

Enable `compiler` only for offline build tooling. Run `npm ci && npm test && npm
run typecheck && npm run build && npm run check` in `library/`. Source and bundled
AST checks reject eval/Function, imports, ambient APIs, reflection/prototype
mutation and intrinsic aliasing; permitted globals are narrowly used
`Object.freeze`, `JSON.parse`, `JSON.stringify`, and `__rf_commit`. Runtime
hardening enforces the boundary independently of lint.

```sh
cargo run -p ramflux-card --features compiler --bin card-pack -- \
  crates/ramflux-card/library/form.js /secure/release-seed release.json /release/form.v1
```

`release.json` is closed JSON with `app_id`, `package_id`, `security_epoch` and
`version` (nonzero u32 values). The tool appends `.qjb`, `.descriptor.json`, `.sig`
and `.pub`, preserving dotted prefixes. It uses the exact compile-and-sign path
exercised by tests. Never distribute the private 32-byte seed.

The canonical descriptor binds application/package identity, catalog identity and
SHA-256 of the exact LF-normalized catalog file, host ABI, exact engine pin,
security epoch/version, and SHA-256 of the complete bytecode. Fixed lexicographic
fields, ASCII metadata and u32 values give one JSON encoding; other encodings are
rejected. Ed25519 authenticates a v2 domain plus those complete descriptor bytes.
There are no additional package assets or OTA channel. Future assets must be
explicitly authenticated before introduction.

Admission requires an `AcceptancePolicy` supplied independently by the embedding
release: expected app/package IDs, nonzero minimum epoch/version, and optional
exact descriptor SHA-256. Floors compare `(epoch, version)` lexicographically.
The current catalog, host ABI, engine and bytecode digest must also match before
`SignedPackage` exists. Never derive the key, floor or exact digest from a peer or
received package. Applications persist/pin their own rollback policy. Engine or
host-contract changes regenerate packages and fixtures.

## Optional C bridge (`c-abi`, standalone ABI major 2)

`include/ramflux_card.h` defines open/update/event/suspend/resume/dispose plus a
version query. ABI 2 adds separate descriptor and application-pinned policy spans
to open. The SDK lane links this rlib into its existing core static/dynamic library;
do not create a second Rust static runtime or infer SDK ABI numbers from this ABI.
All calls run synchronously on the creating renderer thread. There is no detached
work or cancellation handle. Up to 32 logical sessions may be retained per thread.

Callbacks are mandatory, execute before return and borrow UTF-8 JSON
`{session,payload}`. Copy before posting to a UI thread. Inputs are borrowed only
for the call and copied within explicit limits. No callback/user pointer is
retained. Callbacks must return normally, without reentry or foreign unwinding.
Success invokes exactly one callback; errors invoke none. Open zeros its output
on failure. Serialization/output-cap failure disposes the handle; discard that
native view. Other input/admission errors preserve valid session state as above.

Events use `{token:{session,version,key},event:{kind:"text",value:"..."}}` or
`{token:{session,version,key},event:{kind:"submit"}}`. Outputs are mutation batches,
stale drops, edits or submit intents. Upserts are shallow; removals precede
parent-before-child upserts. Removing a parent removes its native subtree;
reparenting re-emits retained descendants. Apply the batch's `previous_version`
to the last mounted version and refresh all tokens even for an empty mutation
list. Statuses: 0 success, 1 invalid input/JSON, 2 resource limit (including
memory/stack), 3 signature/policy, 4 script/engine/hardening, 5 budget, 6 inactive,
7 stale/foreign-thread handle, 8 reentry/busy. Engine memory/stack classification
uses exact messages from the pinned engine; these diagnostics confer no authority.

## Validation boundary

CI builds, strict-clippies and tests every feature on Linux x86_64, Apple Silicon
macOS and Windows MSVC; each row also runs TS types, capability lint and bundle
freshness. Real-engine tests cover hardening, release floors, exact error kinds,
recovery, multi-form diffs, replay and C error/lifetime paths. A bounded child
process integration test runs the shipping packer and loads its output. Mobile,
Intel macOS, ARM64 Linux and WASM compile checks complement those native tests;
compilation alone establishes no device, worker, SDK or end-to-end acceptance.

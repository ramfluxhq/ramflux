# Card gallery

The static reference renderer uses the signed Rust card library in a dedicated
WebAssembly worker. Its 20 presentation modules draw the admitted semantic tree;
Rust retains validation, drafts, input bounds, action consumption and event tokens.
Native iOS, Android and desktop appearance remains each client's responsibility.

## Build

Cargo and wasm generation run serially on the authorized QA host through the lane
wrapper. Build the optimized wasm and use wasm-bindgen-cli 0.2.126:

```sh
CC_wasm32_unknown_unknown=clang cargo build --release --locked -p ramflux-card --features web --lib --target wasm32-unknown-unknown
wasm-bindgen "$CARGO_TARGET_DIR/wasm32-unknown-unknown/release/ramflux_card.wasm" --target web --out-dir crates/ramflux-card/web/pkg
```

Copy `web/pkg/` back to the worktree, then run from the workspace root:

```sh
npm ci --ignore-scripts --prefix crates/ramflux-card/library
npm run typecheck:web --prefix crates/ramflux-card/library
node crates/ramflux-card/web/build-web.mjs crates/ramflux-sdk/include/card/library crates/ramflux-sdk/include/card/policy.json
node crates/ramflux-card/web/build-web.mjs --check crates/ramflux-sdk/include/card/library crates/ramflux-sdk/include/card/policy.json
```

Serve only `web/dist/` using any static HTTP server. It includes the release wasm,
CSS, local product fonts and their licenses, reference image, public verification
material and `stories.json`. Assets are relative, with no CDN or backend dependency.
Module workers require HTTP; opening the HTML with `file://` is unsupported.
The independently pinned host policy must never come from the card author.

## Presentation and stories

`card/render-metrics.json` is the generated presentation specification: type scale,
sizes, density, per-kind geometry, motion and token roles. Import an approved
specification with `node web/generate-render-metrics.mjs <approved-spec.json>` from
this crate's directory. The importer removes provenance notes; it retains values.
`card/tokens.ts` maps those values and the app's light/dark tokens to CSS variables.
`card/frame.ts` owns the card frame and width observer; `card/kinds/` has one module
per kind; `card/parts/` supplies shared field, status, overlay and control parts.
Only text-entry elements use native inputs/textarea. Checkbox, radio, slider,
calendar, progress, choice menus and sheets use the reference controls.

The generated `stories.json` has schema `ramflux.card.stories.v1`. Story IDs remain
stable: `component/<Kind>/<variant-or-unset>/<state>`, `example/<name>` and
`agent/<scenario>`. The fixture index supplies catalog variants; `gallery-stories.mjs`
generates realistic author examples and applicable states without editing product
test snapshots. Obscured TextField is an intentional runtime refusal. State coverage
shows “Not applicable” for unsupported combinations. The all-variants grid is a
static comparison sheet; select its story heading to interact on the live canvas.
The grid resolves stories serially and never exceeds the two-worker resident limit.

Links preserve story, kind, variant, state, locale, theme, width, direction and grid.
Reference widths are phone 360, dock 480 and wide 960 (cards cap at 640). The canvas
scrolls when a reference width exceeds the window. The Rust resolver owns locale
fallback and formatting. The 15 launch locales plus `en-XA` are selectable; author
fixtures remain English, with long pseudo-localization available for layout review.
Host copy falls back to English. Arabic changes card direction; chart time axes
and clocks retain their order. Product fonts are bundled with their SIL OFL notices;
scripts outside those faces use the platform fallback.

## Host reference boundary

Reference host slots are on by default and explicitly labelled. Approval facts,
risk, expiry, decisions, task activity, image bytes and dispatch outcomes shown by
the gallery are mock reference data unless actual host-slot facts are supplied.
The card author's explanation is quoted separately from facts. Allow opens a
reference security sheet and its single-tap Confirm changes the reference display
only. Links show the complete runtime-selected URL, author and privacy note;
Open records a reference event and does not navigate. Images use a bundled local
fixture; the gallery never fetches peer attachments or grants attachment authority.
Modal open/close and tab selection are actual tokened Rust events.

The submit walkthrough explicitly simulates host busy and consumed presentations.
The result step uses a second, serial preview worker to compute a local author
commitment, then calls the real versioned update path on the live session. The
reference author update button also demonstrates actual conflicting-draft replacement
and shows its notice for six seconds. These local author fixtures carry no signature
or production authority; there is no timed or optimistic result. Real canvas submission
emits the runtime intent and consumes the action; no SDK action is signed or sent.
A later signed update can settle the consumed presentation. “Send stale event”
submits an obsolete token to the real worker and displays its `stale_dropped` reply.
Dispatch failure/retry is a labelled host reference, preserving draft values.
The read-only DateTime story retains an admitted temporal type: the current
runtime refuses a nonempty temporal value when both picker flags are false.

The development verification key and signed package are showcase material only.
No private signing key is distributed. `open_preview` is an unauthenticated author
helper: bounded raw input/model go through strict Rust I-JSON, a local commitment
is recomputed, then normal admission runs. It supplies no signature or SDK authority.
Production trust-root custody remains a separate owner decision.

# Card gallery

A static component workbench for authors and native host developers. The canvas
uses `ramflux-card` compiled to WebAssembly in a dedicated worker and the SDK's
signed development library. JavaScript only maps admitted semantic mutations to
reference controls. No application backend is required; serve the output with
any static HTTP host (module workers cannot be opened through `file://`).

## Build

Cargo and wasm generation run on the authorized QA build host via the lane
wrapper. From the workspace root on QA:

```sh
CC_wasm32_unknown_unknown=clang cargo build --locked -p ramflux-card --features web --lib --target wasm32-unknown-unknown
wasm-bindgen "$CARGO_TARGET_DIR/wasm32-unknown-unknown/debug/ramflux_card.wasm" --target web --out-dir crates/ramflux-card/web/pkg
```

Use wasm-bindgen-cli 0.2.126, matching the crate. Copy `web/pkg/` back to the
worktree. Then, from the workspace root:

```sh
npm ci --ignore-scripts --prefix crates/ramflux-card/library
node crates/ramflux-card/web/build-web.mjs crates/ramflux-sdk/include/card/library crates/ramflux-sdk/include/card/policy.json
node crates/ramflux-card/web/build-web.mjs --check crates/ramflux-sdk/include/card/library crates/ramflux-sdk/include/card/policy.json
```

Publish only `web/dist/`. It contains `index.html`, CSS, bundled ES modules,
public verification material, the wasm module and `stories.json`. All assets
are relative so the same output works under a website subdirectory. It needs
neither CDN scripts nor runtime network services. The build input policy is an
independently pinned host policy, never one received from a card author.

## Story contract

`stories.json` has schema `ramflux.card.stories.v1` and ordered `stories`:
`id`, `kind`, `variant`, `state`, `group`, `source`, `outcome`, `input`.
Component IDs are `component/<Kind>/<variant-or-unset>/<state>`, composed IDs
are `example/<fixture-name>`, and agent IDs are `agent/<scenario-name>`.
These IDs are the cross-host native-capture keys. Keep them stable; append
stories when extending coverage. Expected refused variants remain selectable.
The fixture index is the source of component kinds and variants. State stories
use ordinary catalog inputs and checks, not simulated renderer states.

Links carry `story`, `kind`, `variant`, `state`, `locale`, `theme`, `width`, and
`direction`. A link using just `kind` and `variant` selects the default state.
Widths are `phone` (360), `dock` (480) and `wide` (960 CSS pixels). The stage
scrolls when the selected reference width exceeds the available window.

The locale menu includes all 15 launch tags, Arabic RTL, and `en-XA` for long
text. The real Rust resolver owns locale fallback and CLDR formatting. Host UI
strings use the bundled en / zh-CN tables; other host strings fall back to en.
Pseudo-localization expands local author display text, not validation or raw
model values. Direction is a host presentation override; the tree still reports
the resolver's intrinsic locale direction.

## Development boundary

The development public verification key and signed package are for this
showcase only. There is no private signing seed in its output. Never use this
key for a production release. Production key custody remains a separate owner
decision.

`CardWorker.open_preview` accepts bounded raw input and model strings, parses
both through strict Rust I-JSON, substitutes the model, recomputes the local
snapshot commitment and calls normal `open`. This is an unauthenticated author
preview helper, never a source of SDK authority or a signature. It does not
change production snapshot admission. Input JSON and the model editor are sent
raw; the model editor explicitly replaces `snapshot.dataModel`. Typed resolver
refusals are displayed without HTML interpretation.

The tree, host slots and latest 100 interaction records expose the runtime
contract. Host events include current tokens; replies include draft results,
action frames and stale drops. Slots are inspection-only requests: the gallery
never approves, opens links, fetches images or supplies native modal/security
sheets. Web styling is a semantic reference; each native client owns its look.

# Host card fixtures

ABI 5 inputs and expected documents for every catalog kind and every `variant`
enum. `index.json` lists `kind`, `variant`, `fixture`, and `expected`.

`*.input.json` is a card envelope (`render_allowed` true, catalog
`urn:ramflux:catalog:rf-card:1.0`). `*.tree.json` is `ramflux.card.tree.v1`
produced by `CardSession::open` on the signed library in
`crates/ramflux-sdk/include/card/`. Session identifiers in the committed tree
are 1. A host that opens one card compares equal after rewriting its live
session to 1 in `session`, `token.session`, and the `session` field inside
`request_id`. Compare parsed JSON. Object key order is the runtime serializer's
order.

`*.refusal.json` is a catalog `variant` the runtime refuses. There is no tree.
`outcome` in the index is `tree` or `refused`.

`variant` is null when the component schema has no `variant` property. Other
enums (`fit`, `axis`, `kind`, `status`, `displayStyle`, icon `name`) are not
separate rows. The one row for that kind uses the catalog default, or the
required value when the field has no default.

These files are the semantic tree. They do not specify sizes, spacing, colors,
type, or accessibility chrome.

The published locale is `en`. `LOCALE_FIXTURE_HOOK` in
`src/bin/card_fixtures/cases.rs` is the place to add launch-locale rows after
the resolver accepts them.

Regenerate with:

```sh
cargo run -p ramflux-card --bin card-fixtures -- --write
```

`card-fixtures --check` fails when a committed file differs from that run.
`scripts/check-card-fixtures.py` fails when the index misses a catalog kind or
`variant`.

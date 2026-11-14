# Local search

The Rust SDK and local bus share an account-local search service. It has no network
side effects. `LOCAL_SEARCH_V1` defaults to false: query and rebuild return
`SearchNotActivated` before acquiring an account database, and status reports
`disabled`. Message protocol generation remains unchanged. A separate
`LOCAL_SEARCH_ENGINE_QUALIFIED` guard also defaults to false. Enabling the capability
alone is insufficient: production activation requires controller acceptance of the
pinned engine's native scratch allocation and worst-case corpus bounds.

An admitted service uses FTS5 inside the existing SQLCipher account database. It
requires memory-only temporary storage, secure deletion, FTS secure deletion and
verified dbstat page accounting. Its private `local_search_*` namespace contains
reversible search terms and source IDs, with no stored snippets. Export candidates
strip the entire namespace and compact before publication. Compaction preserves
rowid-based message erasure locators by stable source keys. Merge never imports an
archive's search cache. Fresh restore requires the trusted local restore owner to
validate visibility and erasure floors and explicitly admit the selected generation;
the archive cannot grant itself admission.

Ordinary words match exactly, using pinned Unicode 16 normalization, case folding
and word segmentation. Accents remain significant. Han, Hiragana, Katakana and
Hangul use unigrams/bigrams and authoritative contiguous matching for longer runs.
Words intersecting a spoiler are omitted as a whole, so hiding a suffix cannot
create a prefix match; other visible words and admitted basenames remain eligible.
There are no prefix, wildcard, boolean or FTS expression operators in user input.
Queries contain at most 1,024 UTF-8 bytes, 16 clauses and 128 derived terms; words
contain at most 256 bytes. Source normalization processes at most 32 KiB at a
grapheme boundary, 4,096 terms and bounded normalized/token buffers.

Opening a service returns the shared runtime for one open account, so multiple
handles share query, queue, cursor and maintenance limits. Readers inherit a
volatile account incarnation; reopening the same database creates a new one.
Closing its writer revokes pending completions.

`LocalSearch::query` returns a revocable `SearchCompletion`. Call `take` to consume
its typed page and `check_current` immediately before publishing encoded bytes.
A completion retains admission until dropped. Search text redacts Debug and
zeroizes on drop. Data already returned to a caller remains that caller's
responsibility. The bus queues only an opaque completion token and resolves it at
the final writer boundary. Canonical mutations, lock, account switch, publication,
erasure and source expiry invalidate pending results. These are logical erasure
and publication guarantees, not forensic SSD/WAL erasure guarantees.

Queries execute one per account, with two queued and a global limit of two workers.
The cooperative execution budget is 100 ms / two million VM steps, checked every
1,000 steps, including SQL preparation and lock waits. Filesystem calls may exceed
the wall-clock budget. A page examines at most 128 candidates and returns at most
50 items / 64 KiB in deterministic kind then descending document-ID order. Every
candidate is checked against the currently authorized source, scope, revision and
full query. Snippets are opt-in and bounded to 160 graphemes / 512 bytes; highlights
are UTF-8 byte ranges over original snippet text and include whole graphemes.

Cursors are unpredictable, volatile, single-consumption tokens, expire after 60
seconds and bind the client, account, unlock/publication/erasure/index epochs,
query and filters. Eight cursors per client fit within 32 KiB. An empty page with
`incomplete=true` is not a complete no-match result. Inspect coverage separately:
`building`, `lagging`, `truncated`, `quota_limited`, `failed` and `complete` differ.
At one million documents / 512 MiB of live search B-tree pages, insertion stops
without eviction; synchronous privacy purges remain available.

`LocalSearch::rebuild` and `search.index.rebuild` share the bounded maintenance
loop. Each lease lasts at most 30 seconds, yields between batches and resumes a
format-bound ID checkpoint. Batches process at most 128 sources, 256 KiB or 20 ms.
Tokenization precedes the managed writer transaction; canonical revision checks
refuse racing edits. Dirty overflow collapses to a rebuild marker. Status includes
the volatile job state. Dropping/cancelling a lease leaves resumable ID work.
Cancellation requires the owning client and current unlock epoch, preventing old
frames from cancelling a reused request ID.

The bus methods are `search.query`, `search.cancel`, `search.cursor.close`,
`search.index.status`, `search.index.rebuild` and `search.index.rebuild.cancel`.
Epochs and revisions use decimal JSON strings. They create no persistent operation
receipts. C ABI negotiation, numeric error reservations, policy/header generation
and exposure belong to the binding integration; this module does not enable them.

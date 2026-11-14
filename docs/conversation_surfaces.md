# Conversation surfaces

Surface v3 carries A2UI 1.0 inside signed, end-to-end encrypted ramflux frames.
A surface is scoped by `(conversation_id, author_principal_id, surface_id)`;
`surface_ref` commits to that tuple. Only the authenticated author may mutate it.
There is one v3 wire path. Legacy surface DTOs and the standalone local
`a2ui.render` / `a2ui.action` signing path are removed.

## Frames and canonical state

`ramflux.surface.event.v3` has exactly one of an `a2ui` mutation message,
`appendText`, or `resync`. The A2UI envelope uses `version: "1.0"`;
`surfaceVersion` is the independent ramflux sequence. An ordinary delta requires
version N+1 and the current `baseSurfaceHash`. Create requires fallback text and
has no base hash. Delete closes the surface permanently.

`SurfaceSnapshot::hash` commits to the surface/catalog identifiers, fallback,
optional nonempty metadata, components sorted by identifier, data model, sorted
finality records and closed status. The hash excludes conversation and sequence,
which the authenticated frame/carrier binds. Drafts never enter this commitment.
All received frame bytes must be original I-JSON and byte-equal to their JCS form.
The pinned upstream schemas/catalog/cases live under
`crates/ramflux-protocol/vendor/a2ui`, with their license and byte-hash manifest.
Upstream schema validity and the stricter ramflux profile are separate checks.

Only `urn:ramflux:catalog:rf-card:1.0` is admitted. State is complete: `root` and
all references must resolve, cycles are refused, and unreachable components are
pruned. Inputs have unique, nonoverlapping owned model pointers. Whole canonical
state is limited to 16 KiB, the data model to 12 KiB, and component declarations
to 32. Templates have at most 16 items, at most two nested template scopes, and
at most 256 expanded nodes. Model numbers are safe integers.

`appendText` targets an existing string through a canonically escaped object-only
JSON Pointer. It never traverses arrays or `-`. A final append records the pointer
and a text commitment in the signed state. All later updates, including ancestor
or root replacement/deletion, must preserve every committed string. Finality is
retained across close and checkpoint/reopen.

Resync validates the full proof and its hash. If stored state exists, replacement
also enforces scope, rollback, equal-version, terminal-close and finality-superset
fences. Known records are never silently reinserted. Bootstrap is available only
when no state exists, and scope/author-device authority comes from the
authenticated carrier and conversation authorization. A successful bootstrap at
N requires N+1 for its next ordinary delta. Stored state is never discarded to
enter bootstrap.

## Action and renderer authority

`ramflux.surface.action.v3` binds the shown version/hash, source component and
outer-to-inner template-instance pointers. Declared context entries are either
author literals or raw values of enabled inputs owned by the same form scope.
Computed context, author-data paths and computed `userMessage` are refused.
Button checks may read only author data and inputs sent by that action;
input-level checks are local display only. The author reconstructs the submitted
input overlay, checks types and button checks, and verifies `argsHash`.
Decision identity includes the source instance; receipts bind the original signed
action carrier. Actions travel to the author through authenticated pair controls,
including when their conversation is a group.

The SDK's renderer gate resolves a headless agent from the user's verified local
creator registry and matches its authenticated account root. Peer-supplied actor
labels grant no authority. Other agents and human authors have plain fallback
presentation only: no card session, link request or RPC processing. Explicit
content reads expose `render_allowed`; the author can still read its own state
for planning. Local device metadata advertises static per-release capabilities
under the upstream `a2uiRendererCapabilities` transport key.

## RPC and errors

`function_call`, `function_response` and `error` use `ramflux.surface.rpc.v3`.
Its `a2ui` member holds the unchanged upstream message. `knownVersion` and its
optional `knownHash` describe sender context and never consume a surface version.
`~rpc` denotes a call without a surface. Frame bounds are 4 KiB; call identifiers
are printable ASCII of 1–128 bytes.

Only calls from the user's own agents are processed. No function is callable by
an agent: a well-formed call gets `INVALID_FUNCTION_CALL`; a malformed inner call
with a usable frame identifier gets the pinned malformed-call error. Invalid
frames and non-own authors get no response. Processing is capped at eight calls
per author per minute.

The replay ledger retains at most 256 entries per author for 24 hours. An entry
holds the exact original request fingerprint, authenticated scope and exact
response frame bytes. An exact bound retry in a fresh carrier reuses those bytes,
including their original known version/hash. Changed scope or inner bytes under
the same key are refused and cannot replace or rebind the entry. Calls, replies,
retries and refusals do not mutate surface state. Error reports go only to own
agents, once per surface and rejected event version.

## Local transport and retries

`surface.send` accepts a v3 event or RPC frame; `surface.action` accepts a v3
action. Both take `conversation_id`, `message_id`, `wire_base64` and optional
`author_principal_id`. `SurfaceSendRequest` is an output-only local builder.
Message identifiers contain 128 random bits. Persist a request before sending
and reuse its identifier and bytes for retries. `rf surface` reads `--wire-file`;
`--message` is optional. Original remote bytes always enter through the protocol
admission constructors.

`surface.get` accepts `surface_ref`, or `surface_id` with optional conversation and
author selectors; ambiguous short identifiers fail. It returns version/hash,
closed/out-of-sync status, retained hash history and explicitly selected action
receipts. `surface.list` is paginated; `surface.changed` exposes metadata only.
Stream metadata is keyed by canonical model pointer. Author-signed timestamps
are untrusted display metadata, preserved separately from sequence ordering.

Author event publication uses ordinary encrypted message/group delivery and
existing own-device history replication. Actions and RPC use private pair
controls with the conversation's membership context. Transport failure remains
visible to the caller, which owns durable retry. A queued or submitted transport
does not establish recipient projection or native host acceptance.

The card runtime/session and platform host adapters are separate modules. A link
is declarative `Button.action.functionCall` `openUrl`, with commit-time Rust URL
validation. Actual opening requires a later host-owned sheet and a qualified
browser-only path. Wire admission does not launch a URL or confer approval
execution authority.

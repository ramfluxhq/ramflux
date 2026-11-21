<!-- SPDX-License-Identifier: BSD-3-Clause -->
<!-- Copyright (c) 2026 Span Brain -->

# Full-transfer source of truth

PRIMARY-TRANSFER-PROOF-01, controller r3. These are source-code observations and
implementation contracts; each runtime acceptance claim needs its named witness.
Declaration coverage and proof level are separate. A codec/import implementation,
a private SQL projection, an SDK component and a real-binary transfer are different
milestones. Ordinary product reads and authorization checks decide acceptance.

| Concern | Authoritative source and existing owner | Transfer contract and witness |
|---|---|---|
| Received native content | Exact Inner and first-hand origin; `crates/ramflux-sdk/src/client/raw_inner_origin.rs` (`RetainedOrigin::verify`), `client/generated_history.rs` (`authority`), `client/routed/generated_receive.rs` (`Provenance`) | Preserve exact bytes, original qualified author and receive-time provenance. Verify original public custody/signature/commitment bindings; never manufacture peer-origin evidence from a local MAC or an own-authored capture. Read the restored message through the native product reader. |
| Own-authored history | `client/own_sent_message/authored.rs` (`Captured`, `capture_own_authored_revision`), `own-history/capture/{owner}` | Keep original/current identities and exact authored content in their own evidence class. The original author's account anchor determines own-authorship; B's new branch name does not replace A's author. A missing peer-origin record is not repaired by inventing one. |
| Own-copy attestation | `client/own_sent_message/attestation.rs` (`OwnSentAttestation`) | Preserve the exact enclosing own-copy and its origin evidence. Its commitment authenticates the enclosing copy, not a fabricated first-hand receipt of the nested Message. |
| Event order | `crates/ramflux-protocol/src/message/identity.rs` (`EventOrder`, `order_key`); native readers in SDK `client/typed_messages.rs`, `client/typed_read_model.rs` | Preserve HLC, original account/device/epoch/sequence and event id as original event identity. Compare the ordinary reader's own and peer order, including after a tail and restart. Do not relabel the author as B. |
| Local change cursor | Storage `account_db/journal/mod.rs:58`, `message_footprint/schema.rs:359`; `account_db/messages.rs:194` | `runtime_message_sequence.seq` comes from local journal `NEW.seq`. It is not the original event order or an imported B counter. Rebuild under B's journal/generation owner. An already-running B consumer must observe imported history without accepting A's cursor. |
| SQL read path | Storage `account_db/messages.rs` (`direct_messages`, `generated_message_identities`), SDK native readers above | The direct SQL list sorts `created_at,message_id`; native readers also use original EventOrder. Codec or SQL row order alone proves neither CLI ordering nor live-consumer refresh. The process slice must assert actual product output. |
| Raw copy identity | Storage `account_db/raw_inner/writer.rs`, `schema.rs`, `reparse.rs` | Preserve copy id, exact digest/bytes, qualified source and per-copy provenance. Four declared kinds have distinct native limits. Stage parent/child dependencies; a generic BLOB copy or raised helper cap is insufficient. |
| Nested copy ownership | Storage `account_db/message_footprint/`, raw writer `bind`, `message_copy_binding` | Rebuild every locator and owner edge transactionally. Any erased owner invalidates a multi-owner history container. Verify ordinary readers and reparse/authorization after erasure and reopening, not only copied rows. |
| Erasure and denial | Storage `account_db/deleted_messages.rs`, `receive/erased_input.rs`, `mac_subkeys/full.rs`; transfer `message_denial.rs`, `input_denial.rs` | Apply restrictions before content. Imported MAC bundles remain source-qualified denial/data verifiers; B's active MAC and authority sets stay local. A tombstone must also block the product redelivery path. Derived B-local markers need explicit contribution provenance before full materialization acceptance. |
| Independent B data | Transfer `receiver_contributions*`, `monotonic.rs`, `receiver_materialization.rs` | Retain originals separately from normalized output. Absence removes only its contributor's content; denials survive. Expected bytes derive from inputs, not arbitrary private values. Check the actual generation independently. |
| Local preferences and expiry | Storage `conversation_list.rs`, `conversation_state.rs`; typed metadata resolver | B originals decide existing archive/pin/mute preferences. Hidden/clear bounds union restrictively. The shortest positive matching expiry policy survives; a disabled import cannot disable an independent timer. Different expiry contexts refuse rather than inventing a wider command. |
| Execution-only state | Transfer catalog excludes/rebuilds local work; SDK authored delivery `own-history/pending/`, `own-history/staged/`; bus `own-device/send/`, `own-device/sequence` | Preserve authored content before dropping delivery work. Never resume A's outbox, old callbacks, approvals, ratchets, sender chains, device counters or pins. Every actor variant needs a closed classification; unknown variants refuse. |
| Public agent files | SDK `agent_record/store.rs`, `custody/agent_creation/store.rs`, `agent_creation/rebind*` | Freeze the public projection with the source cut and install with B's fenced generation. No master/vault/provider/approval state. Visible metadata stays rebind_pending until the existing desktop request, new-primary approval and publication receipt complete. |

## Shared native evidence boundary

The received `RetainedOrigin` and receive `Provenance` currently live privately in
SDK; storage cannot depend on SDK. Controller r3 authorizes moving a closed data
and verifier contract to a dependency storage can use. That move has not landed.
Its eventual location and consumers must be recorded here and in the report.
Group mutation authorization and current B head/pin checks remain with their
ordinary owners; imported history must not fabricate those capabilities.

## Revised execution order

Checkpoint0 is the committed census and cut/install contract. Checkpoint1 now has
an early vertical gate, then expansion; checkpoints2–5 keep their numbers:

1. **1v, before widening:** commit a reproducible populated seed; use the existing
   real-binary process harness with automatic couriers for one received and one
   authored native message, erasure, independent B data and reverse restrictions.
   Exercise product reads/authorization and an already-running B consumer. Record
   the source preflight's unsupported categories honestly. Implement only owner
   classes needed by that seed until the vertical path passes.
2. **1r:** expand the shared machinery to remaining D1/contact/provenance shapes.
3. **2, 3, 4:** groups, objects, then remaining daemon/identity/card/agent owners.
4. **5:** the complete original normal-account binary proof, interruption cases,
   old-primary/node authority/key exclusion, plus green exact-head CI.

One neutral-title draft PR opens now and receives every owner group. It stays
unready until checkpoint5 and CI pass. The current metadata storage witnesses are
not a received/own-native-message process proof. No assertion is removed to make
that proof pass. A source-of-truth gap is an explicit open item, never a fallback.

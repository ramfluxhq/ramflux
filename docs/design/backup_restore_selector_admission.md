# Restore selector admission contract

This is the implementation boundary between backup restore and attachment consumers.
Restore classifies both authenticated inputs before importing graph rows or copies.
Grants use target-owned evidence; restrictions combine both inputs. A completed
private generation is checked before the account index selects it. This changes
neither live registration nor receive, own-device import, or export authorization.

## Entry points and readers

`backup_jobs/service.rs` calls `BackupJobs::verify_archive`; `routing.rs` calls
`BackupJobs::install_generation`. Both select the complete admission pipeline.
Archive preview and existing-identity checks use the same input-open boundary.
The full restore worker chooses `merge_backup_candidate_with_group_actor`; native
restore chooses `merge_native_backup_candidate`. Fresh full restore calls
`normalize_backup_candidate` before strict reopen and index publication.

| Reader | Previous public path | Selected restore path |
| --- | --- | --- |
| Initial archive worker | Strict open before cleanup | Explicit pre-normalization input, physical schema/count observation captured before upgrades |
| Live target before private copy | Strict live open | Owner-guarded live input; grants still read only its own state |
| Fresh source and private copy | Strict opens | Retained complete observation checked, then single-input normalization |
| Full/native private merge | Legacy merge | Bilateral validation and classification, filtered merge, final deletion and strict integrity check |
| Completed generation | Strict open | Remains strict; unresolved ownership cannot pass publication |

`BackupDatabase::open` remains strict. Only worker-owned staging inputs use the
explicit pre-normalization boundary. The initial archive open ignores supplied
private-origin metadata; trusted intermediate reopens retain the original physical
schema observation. Counts, schema and legacy ownership classification must match
before installation. Input archives are attached read-only and never rewritten.

## Admission caller inventory

| Shared responsibility | Production caller and active admission branch |
| --- | --- |
| merge_object_erasure | merge_backup_pipeline and normalize_backup_candidate in private generations |
| merge_graph | merge_object_erasure; active classification selects backup_selector_admission::writer |
| merge_objects | merge_backup_pipeline, after graph and placeholder classification |
| preserve_imported_archives and projected_columns/projected_actor | merge_backup_pipeline, using preservation decisions at every historical/generic writer |
| Missing-selector and object-copy erased checks | merge_object_erasure; active scratch selects the shared placeholder resolver |
| preservation::prepare and placeholders::erased | merge_object_erasure and preservation copy traversal, with the same side-qualified decisions |
| Full/native/fresh installation hooks | install_legacy_generation, install_native and prepare_fresh_restore; only the public restore service selects these admission branches |

Legacy storage helpers and export can share lower-level code while admission
scratch is inactive; their existing branch remains unchanged. No live receive,
own-device import or publication-authorization entrypoint is redirected.

## Reference producer encodings

| Producer | Encoding validated by restore |
| --- | --- |
| client/deferred_attachment.rs | Wrapped ReceivedAttachment or unwrapped SdkDmAttachmentRef; attachment.reference.v1 hashes canonical inner reference JSON |
| client/object.rs signed-history transport owner | Empty reference/metadata JSON only with selector equal to wire; object.transport.owner.v1 hashes canonical (wire, manifest, message) |
| object_retention/legacy.rs discovery | Reconstructs the attachment encoding and requires a live message; it introduces no additional encoding or historical grant |

The literal hash domains are `ramflux.attachment.reference.v1` and
`ramflux.object.transport.owner.v1`. They are not interchangeable. Reference-actor
registration associates existing hashes with actor keys; it is not another
reference producer. Inline dispatch fixtures are tests, not production producers.

## Decision interface

| Condition | Result |
| --- | --- |
| Authenticated identities, roots, hashes or graph edges disagree | Reject the whole restore before union/import |
| Surviving owner, no bilateral deletion/fence, target grants permit it | Admit that reference/owner edge; selector is `keep` |
| Incoming-only partial lookup, otherwise admitted reference | Preserve the permitted survivor; a payload fence still dominates |
| Closed target selector without an admitted target witness | Incoming rows cannot grant ownership or reopen it |
| Known resolved placeholder vetoed by deletion or fence | `erase`, retain restriction lookup/fence and retire rejected provenance |
| Unresolved placeholder with a registered revocation footprint | Typed ownership refusal; target remains unchanged |
| Bare unowned legacy placeholder without a restriction | `unowned_legacy` omission; do not invent a payload commitment |
| Incoming registered placeholder exactly matches target wire/manifest/commitment/owner | Inherit target keep, including both self-backup merge directions |
| Exact standalone replacement with verified ciphertext | Replacement exception applies to that identity only; never private aliases |

`backup_reference_admission` contains accepted owner edges only. Pending target
cleanup is separate work and must survive until the final deleted-message pass.
An alias selector is never used as a payload wire identity. Shared copies are
reprojected from surviving references; rejected references do not return through
archived copies, missing preparation, timestamp arbitration or generic SQL merge.

## Private operation schema

All identifier-bearing operation tables live in encrypted staging `main`. Classification
indexes exist before their query window. Generic merges and snapshots exclude these tables;
normalization drops them before commit. The existing `backup_erased_copy` TEMP
set contains only source/table labels and row IDs, never private identifiers.

| Table | Columns; primary key | Additional indexes |
| --- | --- | --- |
| backup_reference_admission | side, reference_hash, message_id, selector, commitment; (side,reference_hash,message_id) | (side,selector,commitment), (side,commitment,reference_hash) |
| backup_selector_admission | side, selector, commitment, decision; (side,selector,commitment) | none; decision is keep/erase/unowned_legacy |
| backup_lookup_origin | side, lookup, commitment; (side,lookup) | (lookup,side) |
| backup_target_delete | reference_hash, message_id, selector, commitment; (reference_hash,message_id) | (selector,commitment), (message_id,reference_hash) |
| backup_message_delete | side, message_id; (side,message_id) | pre-union DM tombstones and deleted projections from each input |
| backup_group_delete | side, message_id, copy_id; (side,message_id,copy_id) | (side,copy_id); source-qualified before union |
| backup_preserved_copy | table_name, row_id, body; (table_name,row_id) | none |
| backup_replacement_hash | schema_name, object_row_id, ciphertext_hash; (schema_name,object_row_id) | target update/delete invalidation triggers |
| backup_input_origin | singleton, schema_version; singleton | private input-open state, excluded from export and removed at normalized commit |

`backup_excluded_actor_kind(state_kind PRIMARY KEY)` is a shorter-lived encrypted
preservation worklist, created and dropped within target-copy retirement before
generic writers run. Existing payload/reference erasure work is drained by the
shared erasure implementation; it is not an accepted-owner set.

## Destination coverage

Source paths below are under `crates/ramflux-storage/src/account_db/`.

| Destination or copy class | Filtering boundary | Existing witness |
| --- | --- | --- |
| object_index payloads, placeholders and aliases | backup_merge::merge_objects plus shared placeholder resolver before arbitration | e5_target_payload_fence_excludes_incoming_alias_graph; e12_unowned_zero_omitted |
| object_retention_payload, object_payload_dependency, object_payload_actor, object_transport_actor | dedicated graph import checks payload/dependency fences and rejected actor rows | e6_incoming_fence_captures_local_alias_before_delete; review_transport_actor_of_fenced_container_not_preserved |
| object_retention_reference, object_message_reference, object_reference_actor | backup_selector_admission/writer admission joins | admitted_graph_writer_excludes_unadmitted_reference_edges |
| message_copy_binding and message_footprint | admitted graph writer and rejected-copy exclusions | review_r3_sibling_binding_survives_archived_copy_exclusion |
| runtime_actor_state attachment/reference, chunk, directory and sync copies | preservation redaction/row exclusions and projected columns | e7_d7_style_object_exclusion_retained |
| Shared transport/history actors | per-reference reprojection; retain surviving owners | review_transport_actor_of_fenced_container_not_preserved; e20_incoming_deletion_retires_linked_target_alias |
| local_event_log | bounded selector redaction; retire signature and clear bytes | e7_lookup_only_restore_does_not_import_alias |
| backup_archived_actor_state, including imported DM/group-transfer archives | preservation pass plus projected_actor at each archive writer | e7_incoming_reference_without_placeholder_excluded; review_r3_sibling_binding_survives_archived_copy_exclusion |
| backup_archived_local_event | same body projection and signature retirement as live events | e7_incoming_reference_without_placeholder_excluded |
| Missing attachment preparations and diagnostics copied by merge | backup_missing applies the same erased/admitted decisions | e17_historical_lookup_alone_omits_never_deleted_m3_attachment |
| object_manifest, object_key_slot, object_chunk | backup_object_erasure wire-copy exclusions and object arbitration | backup_fence_wins_over_old_payload_references_and_archives_in_both_merge_modes |
| object_transfer_state, object_operation, object_share_grant_projection, object_tombstone | identity-qualified wire-copy exclusions; preserve other manifests | incoming_backup_fence_retires_preexisting_payload_regardless_of_payload_timestamp |
| object_runtime_response, runtime_operation, runtime_journal, runtime_outbox, outbox_queue, ack_state, nack_state | excluded from generic arbitration; restore never resumes archived retry/outbound work | object_erasure_compacts_retry_responses_including_responses_without_an_object_id; native_merge_cannot_install_authority_or_resume_saved_outbound_sessions |
| message_footprint_actor_stage, message_footprint_outbox_stage, message_footprint_journal_stage | per-writer registration drains staging; no independent lifetime authority | footprint_registration_rolls_back_and_late_copies_cannot_recreate_deleted_content |
| Replacement receipts and all remaining generic SQL copies | skip_merge_table, projected_columns, row exclusions and verified replacement checks | e9_checked_replacement_restores_new_wire; e7_d7_style_object_exclusion_retained |
| Native authority, secrets, replay/outbound state and segment progress | native exclusions, dedicated MAC-key merge, segment-transfer filters retained | native_merge_cannot_install_authority_or_resume_saved_outbound_sessions; e14_native_data_restore_uses_two_input_classification |
| Final selected full/native/fresh generation | strict integrity checks with writer/generation leases held through publication | e14_fresh_full_restore_normalizes_before_index_selection; e14_full_restore_local_then_merge_normalized |

Dedicated MAC-authority merge is not generic arbitration. Main's schema-only
segment upgrade and physical transfer exclusions remain in the restore path;
no archived segment progress is installation authority.

## Failure and publication boundary

Ownership failures surface as `ObjectOwnershipUnverified` / job
`object_ownership_unverified`; authorization failures surface as
`AuthorizationRejected` / job `authorization_rejected`. Restore checking and
installation preserve those codes and do not retry them as generic unreadable
input. Storage busy/I/O classifications remain unchanged. Export keeps its
existing error policy. See `backup_jobs/storage_error_tests.rs` and
`backup_authorization_rejection_has_specific_job_and_bus_codes`.

| Failure cut | Existing witness | Invariant |
| --- | --- | --- |
| Lookup origin capture | e14_fault_after_lookup_origin_capture | Transaction rolls back, source and selected generation unchanged |
| Fence union / graph admission | e14_fault_after_fence_union; e14_fault_after_graph_admission | Same |
| Archived preservation | e14_fault_after_archive_preservation | Same; rejected copy cannot survive |
| Before SQL commit, child abort | e14_child_abort_before_commit | Private stage cannot publish partial state |
| Before index selection | e14_fault_before_index_selection | Previous generation selected; staged generation discarded/recovered |
| After index commit | e14_fault_after_index_commit | Selected generation already normalized; existing recovery applies |
| Private schema advance | e14_staged_v12_upgrade_rollback | Production guard disposes failed stage; actual archive retry retains original version/counts |

The final deleted-message pass retires pending target links before the bounded
postcheck and operation-table cleanup. Index publication is a separate durable
boundary. Failure preserves the source archive and selected account; another
archive can be retried without accepting a partial import.

## Regression ports and work bounds

The selector normalization, observation and review fixtures call the public
archive-check/install methods, preserving their original success, refusal,
source-byte, generation-selection and all-table canary assertions. The storage
fault fixture supplies a valid observed private stage so its independently
faulted live account remains the failing boundary. No assertion is weakened.

The exact `BackupDatabase.db` meter covers eleven fully stepped standalone
classification statements and the shared grouped production point operations.
Unrelated N=0/1000/10000 populations include N DM tombstones and N deleted DM
projections, with 2N rows checked in the indexed input-qualified restriction cache.
M=1/10/100 distinct candidates exercise
fixed-candidate independence and linear candidate work. Calibration observes a
known scan. Setup, validation and whole-restore traversal are outside the window.
Tests: b2_classification_independent_of_unrelated_local_n and
b2_classification_linear_in_incoming_candidates.

Cross-service acceptance and broader SDK/restore regression coverage remain
separate from these process-local checks. This contract does not claim network
lifecycle acceptance or change receive-side refusal consumption.

Group restrictions are mirrored independently of copy-binding provenance.
`archive_only_group_tombstone_with_target_binding_vetoes_candidate` requires an
archive-only group tombstone and a target-only binding to veto the candidate.
`archive_only_group_tombstone_second_generation_vetoes_candidate` first restores
without that binding, exports the kept candidate and restriction through the
production encrypted backup-copy API, then checks the same veto on merge.
Both exclude alternative DM deletion, fence and lookup explanations.

Target-side fence retention is pinned by `probe_r5r_target_fence_retained`, which
requires erasure, the original fence, and its selector lookup after merge.
`probe_r5r_surviving_second_owner_keeps` compares restore with live deletion of
one of two owners and requires the live surviving-owner control to remain kept.

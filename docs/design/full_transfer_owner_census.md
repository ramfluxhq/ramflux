<!-- SPDX-License-Identifier: BSD-3-Clause -->
<!-- Copyright (c) 2026 Span Brain -->

# Full-transfer owner source census

Snapshot: 5750bf6d (checkpoint 0). Catalog shape plus static SQL write sites; dynamic SQL and actor calls are separately listed. These source references do not certify runtime reachability or portable bytes. Test-named files are excluded from writer scanning. Field notation: name:type/disposition/merge; ? = nullable. Required/deferred policy is the approved TRANSFER-TYPED-OWNERS-plan r1. No owner is activated by this census.

| Family / declaration | Declared fields | SQL writer references |
|---|---|---|
| `sql/contact_link_decision` (crates/ramflux-storage/src/account_db/full_transfer/catalog/contacts.rs:10) | link_id:Utf8?/Transfer/Immutable, state:Utf8/Transfer/RestrictUnion, decided_at:I64/Transfer/RestrictUnion | crates/ramflux-storage/src/schema_contact_requests.rs:71; crates/ramflux-storage/src/account_db/contact_consent.rs:127; crates/ramflux-storage/src/account_db/backup_consent_merge.rs:92; crates/ramflux-storage/src/account_db/backup_consent_merge.rs:98 |
| `sql/contact_message_fence_retention` (crates/ramflux-storage/src/account_db/full_transfer/catalog/contacts.rs:45) | sender_identity:Utf8/Transfer/Immutable, message_id:Utf8/Transfer/Immutable, until:I64/Transfer/RestrictUnion | crates/ramflux-storage/src/schema_contact_requests.rs:85; crates/ramflux-storage/src/schema_contact_requests.rs:89; crates/ramflux-storage/src/account_db/contact_request_retention.rs:219; crates/ramflux-storage/src/account_db/backup_contact_merge.rs:17; crates/ramflux-storage/src/account_db/backup_contact_merge.rs:19 |
| `sql/contact_message_request` (crates/ramflux-storage/src/account_db/full_transfer/catalog/contacts.rs:83) | contact_identity_commitment:Utf8/Transfer/Immutable, sender_identity:Utf8/Transfer/Immutable, message_id:Utf8/Transfer/Immutable, conversation_id:Utf8/Transfer/Immutable, message_json:Bytes/Transfer/Immutable, byte_count:I64/Transfer/Immutable, expires_at:I64/Transfer/Immutable, created_at:I64/Transfer/Immutable | crates/ramflux-storage/src/account_db/contact_requests.rs:245; crates/ramflux-storage/src/account_db/contact_requests.rs:270; crates/ramflux-storage/src/account_db/contact_requests.rs:280; crates/ramflux-storage/src/account_db/backup_contact_merge.rs:23; crates/ramflux-storage/src/account_db/message_footprint/erasure.rs:99 |
| `sql/contact_message_request_fence` (crates/ramflux-storage/src/account_db/full_transfer/catalog/contacts.rs:161) | sender_identity:Utf8/Transfer/Immutable, message_id:Utf8/Transfer/Immutable | crates/ramflux-storage/src/schema_contact_requests.rs:88; crates/ramflux-storage/src/account_db/contact_request_retention.rs:218; crates/ramflux-storage/src/account_db/backup_contact_merge.rs:13 |
| `sql/contact_request_authority_floor` (crates/ramflux-storage/src/account_db/full_transfer/catalog/contacts.rs:191) | root:Utf8?/Transfer/Immutable, epoch:I64/Transfer/RestrictUnion, record_hash:Utf8/Transfer/RestrictUnion, until:I64/Transfer/RestrictUnion | crates/ramflux-storage/src/account_db/contact_request_retention.rs:31; crates/ramflux-storage/src/account_db/contact_request_retention.rs:36; crates/ramflux-storage/src/account_db/contact_request_retention.rs:40; crates/ramflux-storage/src/account_db/contact_request_retention.rs:61; crates/ramflux-storage/src/account_db/contact_request_retention.rs:69; crates/ramflux-storage/src/account_db/backup_contact_merge.rs:9 |
| `sql/contact_request_decision` (crates/ramflux-storage/src/account_db/full_transfer/catalog/contacts.rs:237) | root:Utf8?/Transfer/Immutable, state:Utf8/Transfer/RestrictUnion, decided_at:I64/Transfer/RestrictUnion | crates/ramflux-storage/src/schema_contact_requests.rs:74; crates/ramflux-storage/src/schema_contact_requests.rs:76; crates/ramflux-storage/src/account_db/contact_consent.rs:52; crates/ramflux-storage/src/account_db/backup_consent_merge.rs:46; crates/ramflux-storage/src/account_db/backup_consent_merge.rs:55 |
| `sql/contact_request_delivery` (crates/ramflux-storage/src/account_db/full_transfer/catalog/contacts.rs:275) | request_id:Utf8/Transfer/Immutable, recipient_identity:Utf8/Transfer/Immutable, material_hash:Utf8/Transfer/Immutable, submitted_at:I64/Transfer/Immutable | crates/ramflux-storage/src/account_db/contact_requests.rs:52; crates/ramflux-storage/src/account_db/contact_requests.rs:281 |
| `sql/contact_request_fence` (crates/ramflux-storage/src/account_db/full_transfer/catalog/contacts.rs:321) | root:Utf8?/Transfer/Immutable, state:Utf8/Transfer/RestrictUnion, until:I64/Transfer/RestrictUnion | crates/ramflux-storage/src/account_db/contact_consent.rs:46; crates/ramflux-storage/src/account_db/contact_consent.rs:49; crates/ramflux-storage/src/account_db/contact_request_retention.rs:215; crates/ramflux-storage/src/account_db/backup_consent_merge.rs:58; crates/ramflux-storage/src/account_db/backup_consent_merge.rs:59; crates/ramflux-storage/src/account_db/backup_consent_merge.rs:64 |
| `sql/contact_request_projection` (crates/ramflux-storage/src/account_db/full_transfer/catalog/contacts.rs:356) | contact_identity_commitment:Utf8/Transfer/Immutable, direction:Utf8/Transfer/Immutable, request_id:Utf8/Transfer/Immutable, principal_id:Utf8/Transfer/Immutable, link_id:Utf8/Transfer/Immutable, state:Utf8/Transfer/Immutable, request_json:Bytes/Transfer/Immutable, expires_at:I64/Transfer/Immutable, updated_at:I64/Transfer/Immutable | crates/ramflux-storage/src/account_db/contact_requests.rs:110; crates/ramflux-storage/src/account_db/contact_requests.rs:131; crates/ramflux-storage/src/account_db/contact_requests.rs:147; crates/ramflux-storage/src/account_db/contact_requests.rs:207; crates/ramflux-storage/src/account_db/contact_requests.rs:279; crates/ramflux-storage/src/account_db/contact_request_retention.rs:106; crates/ramflux-storage/src/account_db/contact_request_retention.rs:158; crates/ramflux-storage/src/account_db/backup_contact_merge.rs:23 |
| `sql/contact_request_retirement` (crates/ramflux-storage/src/account_db/full_transfer/catalog/contacts.rs:470) | root:Utf8/Transfer/Immutable, direction:Utf8/Transfer/Immutable, next_at:I64/Transfer/RestrictUnion | crates/ramflux-storage/src/account_db/contact_request_retention.rs:143; crates/ramflux-storage/src/account_db/contact_request_retention.rs:155 |
| `sql/contact_verification_projection` (crates/ramflux-storage/src/account_db/full_transfer/catalog/contacts.rs:508) | contact_identity_commitment:Utf8?/Transfer/Immutable, verification_state:Utf8/Transfer/Revision, safety_number_hash:Utf8/Transfer/Revision, verified_device_set_hash:Utf8/Transfer/Revision, verified_lineage_head:Utf8/Transfer/Revision, verified_at:I64/Transfer/Revision, verified_by_device_id:Utf8/Transfer/Revision, last_change_event_id:Utf8?/Transfer/Revision, last_change_seen_at:I64?/Transfer/Revision, kt_tree_size:I64?/Transfer/Revision, kt_tree_root_hash:Utf8?/Transfer/Revision, kt_leaf_index:I64?/Transfer/Revision, last_gossip_lineage_head:Utf8?/Transfer/Revision | crates/ramflux-storage/src/account_db/identity_verification.rs:110; crates/ramflux-storage/src/account_db/identity_verification.rs:162; crates/ramflux-storage/src/account_db/identity_verification.rs:198; crates/ramflux-storage/src/account_db/identity_verification.rs:224; crates/ramflux-storage/src/account_db/identity_verification.rs:249 |
| `sql/friend_link_projection` (crates/ramflux-storage/src/account_db/full_transfer/catalog/contacts.rs:626) | link_id:Utf8?/Transfer/Immutable, requester_id:Utf8/Transfer/Revision, target_id:Utf8/Transfer/Revision, state:Utf8/Transfer/Revision, remove_scope:Utf8?/Transfer/Revision, blocked:I64/Transfer/Revision, capability_revoked_at:I64?/Transfer/Revision, updated_at:I64/Transfer/Revision | crates/ramflux-storage/src/account_db/contact_consent.rs:117; crates/ramflux-storage/src/account_db/contact_consent.rs:118; crates/ramflux-storage/src/account_db/contact_consent.rs:121; crates/ramflux-storage/src/account_db/contact_consent.rs:122; crates/ramflux-storage/src/account_db/contact_consent.rs:123; crates/ramflux-storage/src/account_db/friend.rs:63; crates/ramflux-storage/src/account_db/contact_root.rs:30; crates/ramflux-storage/src/account_db/contact_root.rs:31; crates/ramflux-storage/src/account_db/contact_request_retention.rs:89; crates/ramflux-storage/src/account_db/backup_consent_merge.rs:77 |
| `sql/friend_projection` (crates/ramflux-storage/src/account_db/full_transfer/catalog/contacts.rs:687) | link_id:Utf8?/Transfer/Immutable, peer_principal_id:Utf8/Transfer/Revision, link_state:Utf8/Transfer/Revision, capability_id:Utf8?/Transfer/Revision, blocked_at:I64?/Transfer/Revision, removed_at:I64?/Transfer/Revision, updated_at:I64/Transfer/Revision | No literal writer found; inspect formatted SQL before activation |
| `sql/conversation_delivery_state` (crates/ramflux-storage/src/account_db/full_transfer/catalog/conversations.rs:10) | conversation_id:Utf8/Transfer/Immutable, receiver_device_id:Utf8/Transfer/Immutable, delivered_through_message_id:Utf8/Transfer/CursorMax, delivered_at:I64/Transfer/CursorMax, ttl_seconds:I64/Transfer/CursorMax | crates/ramflux-storage/src/account_db/conversation_projection.rs:57; crates/ramflux-storage/src/account_db/conversation_projection.rs:172; crates/ramflux-storage/src/account_db/message_footprint/erasure.rs:106 |
| `sql/conversation_disappearing_policy` (crates/ramflux-storage/src/account_db/full_transfer/catalog/conversations.rs:64) | conversation_id:Utf8?/Transfer/Immutable, timer_seconds:I64/Transfer/PreferLocal, countdown_mode:Utf8/Transfer/PreferLocal, scope:Utf8/Transfer/PreferLocal, updated_at:I64/Transfer/PreferLocal | crates/ramflux-storage/src/account_db/conversation_state.rs:20 |
| `sql/conversation_list_state` (crates/ramflux-storage/src/account_db/full_transfer/catalog/conversations.rs:118) | conversation_id:Utf8?/Transfer/Immutable, archived:I64/Transfer/PreferLocal, pin_order:I64?/Transfer/PreferLocal, mute_until:I64?/Transfer/PreferLocal, hidden_at:I64?/Transfer/PreferLocal, cleared_at:I64?/Transfer/PreferLocal, updated_at:I64/Transfer/PreferLocal | crates/ramflux-storage/src/account_db/conversation_list.rs:17; crates/ramflux-storage/src/account_db/conversation_list.rs:34; crates/ramflux-storage/src/account_db/conversation_list.rs:47; crates/ramflux-storage/src/account_db/conversation_list.rs:64; crates/ramflux-storage/src/account_db/conversation_list.rs:77; crates/ramflux-storage/src/account_db/conversation_list.rs:94; crates/ramflux-storage/src/account_db/conversation_list.rs:112; crates/ramflux-storage/src/account_db/conversation_list.rs:184 |
| `sql/conversation_projection` (crates/ramflux-storage/src/account_db/full_transfer/catalog/conversations.rs:188) | conversation_id:Utf8?/Transfer/Immutable, conversation_kind:Utf8/Transfer/Revision, root_ref:Utf8?/Transfer/Revision, hidden_at:I64?/Transfer/Revision, archived_at:I64?/Transfer/Revision, pinned_order:I64?/Transfer/Revision, muted_until:I64?/Transfer/Revision, cleared_at:I64?/Transfer/Revision, projection_version:I64/Transfer/Revision, updated_at:I64/Transfer/Revision | No literal writer found; inspect formatted SQL before activation |
| `sql/conversation_read_state` (crates/ramflux-storage/src/account_db/full_transfer/catalog/conversations.rs:282) | conversation_id:Utf8/Transfer/Immutable, reader_id:Utf8/Transfer/Immutable, read_through_message_id:Utf8/Transfer/CursorMax, read_at:I64/Transfer/CursorMax | crates/ramflux-storage/src/account_db/conversation_projection.rs:20; crates/ramflux-storage/src/account_db/message_footprint/erasure.rs:100 |
| `sql/conversation_tombstone` (crates/ramflux-storage/src/account_db/full_transfer/catalog/conversations.rs:328) | tombstone_id:Utf8?/Transfer/Immutable, target_id:Utf8/Transfer/RestrictUnion, target_kind:Utf8/Transfer/RestrictUnion, actor_device_id:Utf8/Transfer/RestrictUnion, reason:Utf8/Transfer/RestrictUnion, created_at:I64/Transfer/RestrictUnion, causal_event_id:Utf8?/Transfer/RestrictUnion, signature:Bytes/Transfer/RestrictUnion | No literal writer found; inspect formatted SQL before activation |
| `sql/conversation_unread_marker` (crates/ramflux-storage/src/account_db/full_transfer/catalog/conversations.rs:403) | conversation_id:Utf8/Transfer/Immutable, marker_owner:Utf8/Transfer/Immutable, message_id:Utf8/Transfer/CursorMax, marker_epoch:I64/Transfer/CursorMax, active:I64/Transfer/CursorMax, updated_at:I64/Transfer/CursorMax | crates/ramflux-storage/src/account_db/conversation_projection.rs:226; crates/ramflux-storage/src/account_db/conversation_projection.rs:251; crates/ramflux-storage/src/account_db/message_footprint/erasure.rs:113 |
| `sql/direct_message_projection` (crates/ramflux-storage/src/account_db/full_transfer/catalog/conversations.rs:458) | conversation_id:Utf8/Transfer/Immutable, message_id:Utf8?/Transfer/Immutable, sender_id:Utf8/Transfer/Immutable, encrypted_body:Bytes/Transfer/Immutable, metadata_json:Bytes/Transfer/Immutable, deleted:I64/Transfer/Immutable, is_own:I64/Transfer/Immutable, scrub_version:I64/Transfer/Immutable, created_at:I64/Transfer/Immutable | crates/ramflux-storage/src/account_db/deleted_messages.rs:39; crates/ramflux-storage/src/account_db/deleted_messages.rs:444; crates/ramflux-storage/src/account_db/deleted_messages.rs:603; crates/ramflux-storage/src/account_db/surface.rs:202; crates/ramflux-storage/src/account_db/messages.rs:65; crates/ramflux-storage/src/account_db/messages.rs:101; crates/ramflux-storage/src/account_db/messages.rs:120; crates/ramflux-storage/src/account_db/messages.rs:133; crates/ramflux-storage/src/account_db/messages.rs:514; crates/ramflux-storage/src/account_db/backup_merge.rs:503; crates/ramflux-storage/src/account_db/message_footprint/mod.rs:35; crates/ramflux-storage/src/account_db/message_footprint/mod.rs:314; crates/ramflux-storage/src/account_db/message_footprint/schema.rs:266; crates/ramflux-storage/src/account_db/message_footprint/schema.rs:270; crates/ramflux-storage/src/account_db/message_footprint/schema.rs:320; crates/ramflux-storage/src/account_db/message_footprint/schema.rs:364; crates/ramflux-storage/src/account_db/message_footprint/schema.rs:387; crates/ramflux-storage/src/account_db/message_footprint/schema.rs:421; crates/ramflux-storage/src/account_db/message_footprint/generic_copy.rs:186; crates/ramflux-storage/src/account_db/backup_selector_admission/final_deletion.rs:14; crates/ramflux-sdk/src/bus/receipt_tests/erasure_audit.rs:598; crates/ramflux-sdk/src/bus/receipt_tests/erasure_audit.rs:654 |
| `sql/legacy_conversation_delivery_state` (crates/ramflux-storage/src/account_db/full_transfer/catalog/conversations.rs:537) | conversation_id:Utf8?/Transfer/CursorMax, receiver_device_id:Utf8?/Transfer/CursorMax, delivered_through_message_id:Utf8?/Transfer/CursorMax, delivered_at:I64?/Transfer/CursorMax, ttl_seconds:I64?/Transfer/CursorMax | crates/ramflux-storage/src/account_db/conversation_projection.rs:176 |
| `sql/legacy_conversation_read_state` (crates/ramflux-storage/src/account_db/full_transfer/catalog/conversations.rs:591) | conversation_id:Utf8?/Transfer/CursorMax, reader_id:Utf8?/Transfer/CursorMax, read_through_message_id:Utf8?/Transfer/CursorMax, read_at:I64?/Transfer/CursorMax | No literal writer found; inspect formatted SQL before activation |
| `sql/legacy_conversation_unread_marker` (crates/ramflux-storage/src/account_db/full_transfer/catalog/conversations.rs:630) | conversation_id:Utf8?/Transfer/CursorMax, marker_owner:Utf8?/Transfer/CursorMax, message_id:Utf8?/Transfer/CursorMax, marker_epoch:I64?/Transfer/CursorMax, active:I64?/Transfer/CursorMax, updated_at:I64?/Transfer/CursorMax | No literal writer found; inspect formatted SQL before activation |
| `sql/audit_log` (crates/ramflux-storage/src/account_db/full_transfer/catalog/events.rs:10) | audit_id:Utf8?/Transfer/Immutable, audit_type:Utf8/Transfer/InertHistory, actor_device_id:Utf8/Transfer/InertHistory, subject_hash:Bytes?/Transfer/InertHistory, redacted_summary:Utf8/Transfer/InertHistory, created_at:I64/Transfer/InertHistory, audit_body:Bytes?/Transfer/InertHistory | crates/ramflux-storage/src/account_db/mcp.rs:115 |
| `sql/event_causal_dependency` (crates/ramflux-storage/src/account_db/full_transfer/catalog/events.rs:77) | event_id:Utf8/Transfer/Immutable, depends_on_event_id:Utf8/Transfer/Immutable, dependency_state:Utf8/Transfer/Immutable | crates/ramflux-storage/src/account_db/message_footprint/erasure.rs:80 |
| `sql/event_tombstone` (crates/ramflux-storage/src/account_db/full_transfer/catalog/events.rs:115) | tombstone_id:Utf8?/Transfer/Immutable, target_id:Utf8/Transfer/RestrictUnion, target_kind:Utf8/Transfer/RestrictUnion, actor_device_id:Utf8/Transfer/RestrictUnion, reason:Utf8/Transfer/RestrictUnion, created_at:I64/Transfer/RestrictUnion, causal_event_id:Utf8?/Transfer/RestrictUnion, signature:Bytes/Transfer/RestrictUnion | No literal writer found; inspect formatted SQL before activation |
| `sql/local_event_log` (crates/ramflux-storage/src/account_db/full_transfer/catalog/events.rs:217) | event_id:Utf8?/Transfer/Immutable, event_type:Utf8/Transfer/Immutable, actor_principal_id:Utf8/Transfer/Immutable, actor_device_id:Utf8/Transfer/Immutable, device_counter:I64/Transfer/Immutable, lamport_time:I64/Transfer/Immutable, created_at:I64/Transfer/Immutable, causal_prev_json:Utf8?/Transfer/Immutable, event_body:Bytes/Transfer/Immutable, signature:Bytes/Transfer/Immutable, signature_status:Utf8/Transfer/Immutable, projection_status:Utf8/Transfer/Immutable | crates/ramflux-storage/src/event_store.rs:136; crates/ramflux-storage/src/account_db/deleted_messages.rs:123; crates/ramflux-storage/src/account_db/deleted_messages.rs:607; crates/ramflux-storage/src/account_db/backup.rs:407; crates/ramflux-storage/src/account_db/history.rs:61; crates/ramflux-storage/src/account_db/message_edit_retirement.rs:163; crates/ramflux-storage/src/account_db/message_footprint/erasure.rs:88; crates/ramflux-storage/src/account_db/runtime/recovery.rs:111 |
| `sql/raw_envelope_log` (crates/ramflux-storage/src/account_db/full_transfer/catalog/events.rs:324) | envelope_id:Utf8?/Transfer/Immutable, source_device_id:Utf8?/Transfer/Immutable, target_delivery_id:Utf8/Transfer/Immutable, routing_set_id:Utf8?/Transfer/Immutable, delivery_class:Utf8/Transfer/Immutable, received_at:I64/Transfer/Immutable, payload_hash:Bytes/Transfer/Immutable, encrypted_payload:Bytes/Transfer/Immutable | crates/ramflux-storage/src/account_db/message_footprint/erasure.rs:82 |
| `sql/raw_inner_copy` (crates/ramflux-storage/src/account_db/full_transfer/catalog/events.rs:399) | copy_id:Utf8?/Transfer/Immutable, owner_id:Utf8/Transfer/Immutable, copy_kind:Utf8/Transfer/Immutable, raw_digest:Bytes/Transfer/Immutable, raw_bytes:Bytes/Transfer/Immutable, attempted_decoder:Utf8/Transfer/Immutable, copy_metadata:Bytes/Transfer/Immutable | crates/ramflux-storage/src/account_db/message_edit_retirement.rs:166; crates/ramflux-storage/src/account_db/backup_message_footprint.rs:187; crates/ramflux-storage/src/account_db/backup_message_footprint.rs:199; crates/ramflux-storage/src/account_db/message_footprint/erasure.rs:133; crates/ramflux-storage/src/account_db/raw_inner/reparse.rs:153; crates/ramflux-storage/src/account_db/raw_inner/reparse.rs:179; crates/ramflux-storage/src/account_db/raw_inner/schema.rs:53; crates/ramflux-storage/src/account_db/raw_inner/schema.rs:93; crates/ramflux-storage/src/account_db/raw_inner/writer.rs:160 |
| `sql/raw_inner_evidence` (crates/ramflux-storage/src/account_db/full_transfer/catalog/events.rs:466) | message_id:Utf8?/Transfer/Immutable, provenance:Bytes/Transfer/Immutable, report_opening:Bytes/Transfer/Immutable | crates/ramflux-storage/src/account_db/surface.rs:205; crates/ramflux-storage/src/account_db/message_edit_retirement.rs:88; crates/ramflux-storage/src/account_db/message_edit_retirement.rs:118; crates/ramflux-storage/src/account_db/backup_message_footprint.rs:202; crates/ramflux-storage/src/account_db/message_footprint/erasure.rs:135; crates/ramflux-storage/src/account_db/raw_inner/evidence.rs:72 |
| `sql/raw_inner_owner` (crates/ramflux-storage/src/account_db/full_transfer/catalog/events.rs:501) | owner_id:Utf8?/Transfer/Immutable, source_anchor:Utf8/Transfer/Immutable, metadata:Bytes/Transfer/Immutable | crates/ramflux-storage/src/account_db/message_edit_retirement.rs:89; crates/ramflux-storage/src/account_db/backup_message_footprint.rs:188; crates/ramflux-storage/src/account_db/message_footprint/erasure.rs:134; crates/ramflux-storage/src/account_db/raw_inner/schema.rs:27; crates/ramflux-storage/src/account_db/raw_inner/schema.rs:54; crates/ramflux-storage/src/account_db/raw_inner/schema.rs:84; crates/ramflux-storage/src/account_db/raw_inner/writer.rs:155 |
| `sql/group_ban_projection` (crates/ramflux-storage/src/account_db/full_transfer/catalog/groups.rs:10) | group_id:Utf8/Transfer/Immutable, member_id:Utf8/Transfer/Immutable, ban_id:Utf8/Transfer/RestrictUnion, actor_device_id:Utf8/Transfer/RestrictUnion, banned_epoch:I64/Transfer/RestrictUnion, reason:Utf8/Transfer/RestrictUnion, active:I64/Transfer/RestrictUnion, created_at:I64/Transfer/RestrictUnion | crates/ramflux-storage/src/account_db/groups.rs:983 |
| `sql/group_control_event_seen` (crates/ramflux-storage/src/account_db/full_transfer/catalog/groups.rs:85) | group_id:Utf8/Transfer/Immutable, event_id:Utf8/Transfer/Immutable, event_kind:Utf8/Transfer/Immutable, actor_device_id:Utf8/Transfer/Immutable, target_member_id:Utf8/Transfer/Immutable, previous_epoch:I64/Transfer/Immutable, new_group_epoch:I64/Transfer/Immutable, applied_at:I64/Transfer/Immutable | No literal writer found; inspect formatted SQL before activation |
| `sql/group_invite_projection` (crates/ramflux-storage/src/account_db/full_transfer/catalog/groups.rs:163) | group_id:Utf8/Transfer/Immutable, invite_id:Utf8/Transfer/Immutable, invitee_identity:Utf8/Transfer/Immutable, invitee_signing_public_key:Utf8/Transfer/Immutable, invited_role:Utf8/Transfer/Immutable, inviter_device_id:Utf8/Transfer/Immutable, invite_epoch:I64/Transfer/Immutable, expires_at:I64/Transfer/Immutable, state:Utf8/Transfer/Immutable, reason:Utf8/Transfer/Immutable, created_at:I64/Transfer/Immutable, updated_at:I64/Transfer/Immutable | crates/ramflux-storage/src/account_db/groups.rs:685; crates/ramflux-storage/src/account_db/groups.rs:758 |
| `sql/group_member_device_key` (crates/ramflux-storage/src/account_db/full_transfer/catalog/groups.rs:273) | group_id:Utf8/Transfer/Immutable, member_id:Utf8/Transfer/Immutable, device_signing_public_key:Utf8/Transfer/Immutable, verified_at:I64/Transfer/Immutable, raw_device_id:Utf8?/Transfer/Immutable, principal_commitment:Utf8?/Transfer/Immutable, member_principal_id:Utf8?/Transfer/Immutable | crates/ramflux-storage/src/schema_device_namespace.rs:110; crates/ramflux-storage/src/schema_device_namespace.rs:116; crates/ramflux-storage/src/schema_device_namespace.rs:139; crates/ramflux-storage/src/schema.rs:788; crates/ramflux-storage/src/schema.rs:805; crates/ramflux-storage/src/account_db/groups.rs:388; crates/ramflux-storage/src/account_db/group_key_safety.rs:37; crates/ramflux-storage/src/account_db/group_key_safety.rs:45; crates/ramflux-storage/src/account_db/group_key_safety.rs:195; crates/ramflux-storage/src/account_db/group_device_address.rs:36; crates/ramflux-storage/src/account_db/group_device_address.rs:77 |
| `sql/group_member_projection` (crates/ramflux-storage/src/account_db/full_transfer/catalog/groups.rs:343) | group_id:Utf8/Transfer/Immutable, member_principal_id:Utf8/Transfer/Immutable, member_id:Utf8?/Transfer/Revision, role:Utf8/Transfer/Revision, joined_epoch:I64/Transfer/Revision, removed_epoch:I64?/Transfer/Revision, active:I64/Transfer/Revision, updated_at:I64/Transfer/Revision, principal_commitment:Utf8?/Transfer/Revision | crates/ramflux-storage/src/schema_device_namespace.rs:24; crates/ramflux-storage/src/schema.rs:796; crates/ramflux-storage/src/account_db/shared_group_state.rs:65; crates/ramflux-storage/src/account_db/shared_group_state.rs:102; crates/ramflux-storage/src/account_db/groups.rs:29; crates/ramflux-storage/src/account_db/groups.rs:68; crates/ramflux-storage/src/account_db/groups.rs:201; crates/ramflux-storage/src/account_db/groups.rs:213; crates/ramflux-storage/src/account_db/groups.rs:216; crates/ramflux-storage/src/account_db/groups.rs:264; crates/ramflux-storage/src/account_db/groups.rs:286; crates/ramflux-storage/src/account_db/groups.rs:322; crates/ramflux-storage/src/account_db/groups.rs:359; crates/ramflux-storage/src/account_db/groups.rs:389; crates/ramflux-storage/src/account_db/groups.rs:482; crates/ramflux-storage/src/account_db/groups.rs:740; crates/ramflux-storage/src/account_db/groups.rs:751; crates/ramflux-storage/src/account_db/groups.rs:973; crates/ramflux-storage/src/account_db/backup_shared_groups.rs:204; crates/ramflux-storage/src/account_db/backup_shared_groups.rs:293; crates/ramflux-storage/src/account_db/group_snapshot.rs:41; crates/ramflux-storage/src/account_db/group_device_address.rs:64; crates/ramflux-sdk/src/client/task/group_fixture.rs:80 |
| `sql/group_message_tombstone_projection` (crates/ramflux-storage/src/account_db/full_transfer/catalog/groups.rs:415) | group_id:Utf8/Transfer/Immutable, message_id:Utf8/Transfer/Immutable, tombstone_id:Utf8/Transfer/RestrictUnion, actor_device_id:Utf8/Transfer/RestrictUnion, delete_scope:Utf8/Transfer/RestrictUnion, deleted_epoch:I64/Transfer/RestrictUnion, reason:Utf8/Transfer/RestrictUnion, deleted_at:I64/Transfer/RestrictUnion | crates/ramflux-storage/src/account_db/groups.rs:600; crates/ramflux-storage/src/account_db/message_footprint/erasure.rs:114 |
| `sql/group_projection` (crates/ramflux-storage/src/account_db/full_transfer/catalog/groups.rs:493) | group_id:Utf8?/Transfer/Immutable, group_epoch:I64/Transfer/Revision, role:Utf8?/Transfer/Revision, notification_state:Utf8?/Transfer/Revision, max_members:I64/Transfer/Revision, new_member_history:Utf8/Transfer/Revision, deleted_at:I64?/Transfer/Revision, created_at:I64/Transfer/Revision, updated_at:I64/Transfer/Revision | crates/ramflux-storage/src/account_db/shared_group_state.rs:64; crates/ramflux-storage/src/account_db/groups.rs:23; crates/ramflux-storage/src/account_db/groups.rs:64; crates/ramflux-storage/src/account_db/groups.rs:176; crates/ramflux-storage/src/account_db/groups.rs:252; crates/ramflux-storage/src/account_db/groups.rs:318; crates/ramflux-storage/src/account_db/groups.rs:358; crates/ramflux-storage/src/account_db/groups.rs:478; crates/ramflux-storage/src/account_db/groups.rs:668; crates/ramflux-storage/src/account_db/groups.rs:735; crates/ramflux-storage/src/account_db/groups.rs:969; crates/ramflux-storage/src/account_db/backup_shared_groups.rs:202 |
| `sql/group_sender_key_counter_seen` (crates/ramflux-storage/src/account_db/full_transfer/catalog/groups.rs:586) | group_id:Utf8/Transfer/Immutable, group_key_epoch:I64/Transfer/Immutable, sender_id:Utf8/Transfer/Immutable, counter:I64/Transfer/Immutable, message_id:Utf8/Transfer/CursorMax, seen_at:I64/Transfer/CursorMax | crates/ramflux-storage/src/schema_group_sender_identity.rs:16; crates/ramflux-storage/src/account_db/group_pending.rs:115; crates/ramflux-storage/src/account_db/message_footprint/erasure.rs:98 |
| `sql/legacy_group_member_device_key` (crates/ramflux-storage/src/account_db/full_transfer/catalog/groups.rs:648) | group_id:Utf8?/Transfer/Immutable, member_id:Utf8?/Transfer/Immutable, device_signing_public_key:Utf8?/Transfer/Immutable, verified_at:I64?/Transfer/Immutable, raw_device_id:Utf8?/Transfer/Immutable, principal_commitment:Utf8?/Transfer/Immutable, member_principal_id:Utf8?/Transfer/Immutable | crates/ramflux-storage/src/schema.rs:804; crates/ramflux-storage/src/account_db/group_device_address.rs:35; crates/ramflux-storage/src/account_db/group_device_address.rs:75 |
| `sql/legacy_group_sender_key_counter_seen` (crates/ramflux-storage/src/account_db/full_transfer/catalog/groups.rs:718) | group_id:Utf8?/Transfer/CursorMax, group_key_epoch:I64?/Transfer/CursorMax, sender_id:Utf8?/Transfer/CursorMax, counter:I64?/Transfer/CursorMax, message_id:Utf8?/Transfer/CursorMax, seen_at:I64?/Transfer/CursorMax | crates/ramflux-storage/src/schema_group_sender_identity.rs:16 |
| `sql/root_group_control_event_seen` (crates/ramflux-storage/src/account_db/full_transfer/catalog/groups.rs:766) | group_id:Utf8/Transfer/Immutable, actor_identity:Utf8/Transfer/Immutable, event_id:Utf8/Transfer/Immutable, event_kind:Utf8/Transfer/Immutable, actor_device_id:Utf8/Transfer/Immutable, target_member_id:Utf8/Transfer/Immutable, previous_epoch:I64/Transfer/Immutable, new_group_epoch:I64/Transfer/Immutable, applied_at:I64/Transfer/Immutable | crates/ramflux-storage/src/account_db/groups.rs:459; crates/ramflux-storage/src/account_db/groups.rs:1037 |
| `sql/root_group_invite_identity` (crates/ramflux-storage/src/account_db/full_transfer/catalog/groups.rs:852) | group_id:Utf8/Transfer/Immutable, invite_id:Utf8/Transfer/Immutable, expected_root:Utf8/Transfer/Immutable, device_name:Utf8/Transfer/Immutable | crates/ramflux-storage/src/account_db/groups.rs:672; crates/ramflux-storage/src/account_db/groups.rs:896 |
| `sql/root_group_sender_key_counter_seen` (crates/ramflux-storage/src/account_db/full_transfer/catalog/groups.rs:898) | group_id:Utf8/Transfer/Immutable, group_key_epoch:I64/Transfer/Immutable, sender_reference:Utf8/Transfer/Immutable, session_id:Utf8/Transfer/Immutable, counter:I64/Transfer/Immutable, message_id:Utf8/Transfer/CursorMax, seen_at:I64/Transfer/CursorMax | crates/ramflux-storage/src/account_db/group_pending.rs:57; crates/ramflux-storage/src/account_db/message_footprint/erasure.rs:97 |
| `sql/shared_group_member_projection` (crates/ramflux-storage/src/account_db/full_transfer/catalog/groups.rs:985) | group_id:Utf8/Transfer/Immutable, root_commitment:Utf8/Transfer/Immutable, device_id:Utf8/Transfer/Immutable, principal_id:Utf8/Transfer/Immutable, declared_signing_key:Utf8/Transfer/Immutable, current_signing_key:Utf8/Transfer/Immutable, target_delivery_id:Utf8/Transfer/Immutable, role:Utf8/Transfer/Immutable, joined_epoch:I64/Transfer/Immutable, active:I64/Transfer/Immutable | crates/ramflux-storage/src/account_db/shared_group_state.rs:66; crates/ramflux-storage/src/account_db/shared_group_state.rs:103; crates/ramflux-storage/src/account_db/backup_shared_groups.rs:208; crates/ramflux-storage/src/account_db/backup_shared_groups.rs:294; crates/ramflux-storage/src/account_db/group_key_safety.rs:186 |
| `sql/shared_group_removal_floor` (crates/ramflux-storage/src/account_db/full_transfer/catalog/groups.rs:1065) | group_id:Utf8/Transfer/Immutable, root_commitment:Utf8/Transfer/Immutable, device_id:Utf8/Transfer/Immutable, epoch:I64/Transfer/RestrictUnion | crates/ramflux-storage/src/account_db/shared_group_floor_index.rs:115; crates/ramflux-storage/src/account_db/shared_group_floor_index.rs:120 |
| `sql/device_directory` (crates/ramflux-storage/src/account_db/full_transfer/catalog/identity.rs:10) | device_id:Utf8?/Transfer/Immutable, principal_commitment:Utf8/Transfer/Immutable, source:Utf8/Transfer/Immutable, verified_at:I64/Transfer/Immutable, raw_device_id:Utf8?/Transfer/Immutable | crates/ramflux-storage/src/schema_device_namespace.rs:86; crates/ramflux-storage/src/schema_device_namespace.rs:89; crates/ramflux-storage/src/schema_device_namespace.rs:135; crates/ramflux-storage/src/schema.rs:781; crates/ramflux-storage/src/account_db/contact_root.rs:15; crates/ramflux-storage/src/account_db/contact_request_retention.rs:88; crates/ramflux-storage/src/account_db/device_directory.rs:15; crates/ramflux-storage/src/account_db/device_directory.rs:16 |
| `sql/device_identity` (crates/ramflux-storage/src/account_db/full_transfer/catalog/identity.rs:61) | device_id:Utf8?/Transfer/Immutable, principal_id:Utf8/Transfer/Immutable, principal_commitment:Utf8/Transfer/Immutable, device_epoch:I64/Transfer/Immutable, branch_proof_hash:Bytes/Transfer/Immutable, capability_scope_json:Utf8/Transfer/Immutable, client_mode:Utf8/Transfer/Immutable, created_at:I64/Transfer/Immutable, updated_at:I64/Transfer/Immutable | No literal writer found; inspect formatted SQL before activation |
| `sql/identity_lifecycle_projection` (crates/ramflux-storage/src/account_db/full_transfer/catalog/identity.rs:220) | identity_commitment:Utf8?/Transfer/Immutable, lifecycle_state:Utf8/Transfer/Revision, lifecycle_epoch:I64/Transfer/Revision, causal_event_id:Utf8/Transfer/Revision, reason_code:Utf8?/Transfer/Revision, timelock_until:I64?/Transfer/Revision, grace_window_until:I64?/Transfer/Revision, finalization_time:I64?/Transfer/Revision, updated_at:I64/Transfer/Revision | crates/ramflux-storage/src/account_db/identity_verification.rs:28 |
| `sql/self_device_control_log` (crates/ramflux-storage/src/account_db/full_transfer/catalog/identity.rs:350) | control_event_id:Utf8?/Transfer/Immutable, control_domain:Utf8/Transfer/InertHistory, action:Utf8/Transfer/InertHistory, source_device_id:Utf8/Transfer/InertHistory, target_device_id:Utf8/Transfer/InertHistory, correlation_id:Utf8/Transfer/InertHistory, encrypted_subject:Bytes/Transfer/InertHistory, created_at:I64/Transfer/InertHistory | No literal writer found; inspect formatted SQL before activation |
| `sql/bot_install_grant` (crates/ramflux-storage/src/account_db/full_transfer/catalog/integrations.rs:10) | grant_id:Utf8?/Transfer/Immutable, bot_identity_commitment:Utf8/Transfer/InertHistory, bot_manifest_hash:Bytes/Transfer/InertHistory, installer_identity:Utf8/Transfer/InertHistory, installer_device_id:Utf8/Transfer/InertHistory, scope_json:Bytes/Transfer/InertHistory, conversation_id:Utf8?/Transfer/InertHistory, group_id:Utf8?/Transfer/InertHistory, expires_at:I64/Transfer/InertHistory, signature:Bytes/Transfer/InertHistory, revoked_at:I64?/Transfer/InertHistory, revocation_event_id:Utf8?/Transfer/InertHistory, grant_hash:Utf8?/Transfer/InertHistory, grant_body:Bytes?/Transfer/InertHistory, consent_member_ids_json:Bytes?/Transfer/InertHistory, state:Utf8/Transfer/InertHistory, created_at:I64/Transfer/InertHistory | crates/ramflux-storage/src/account_db/bot.rs:91; crates/ramflux-storage/src/account_db/bot.rs:125 |
| `sql/bot_trust_pin` (crates/ramflux-storage/src/account_db/full_transfer/catalog/integrations.rs:280) | bot_identity_commitment:Utf8?/Transfer/Immutable, bot_public_key:Utf8/Transfer/InertHistory, signing_key_id:Utf8/Transfer/InertHistory, trust_source:Utf8/Transfer/InertHistory, pinned_at:I64/Transfer/InertHistory | crates/ramflux-storage/src/account_db/bot.rs:12 |
| `sql/mcp_grant` (crates/ramflux-storage/src/account_db/full_transfer/catalog/integrations.rs:331) | grant_id:Utf8?/Transfer/Immutable, target_ai_device_id:Utf8/Transfer/InertHistory, source_app_device_id:Utf8/Transfer/InertHistory, capability:Utf8/Transfer/InertHistory, risk_level:Utf8/Transfer/InertHistory, mcp_registry_hash:Bytes?/Transfer/InertHistory, tool_manifest_set_hash:Bytes?/Transfer/InertHistory, expires_at:I64/Transfer/InertHistory, signature:Bytes/Transfer/InertHistory, created_at:I64/Transfer/InertHistory, grant_body:Bytes/Transfer/InertHistory, revoked:I64/Transfer/InertHistory | crates/ramflux-storage/src/account_db/mcp.rs:17; crates/ramflux-storage/src/account_db/mcp.rs:60 |
| `sql/mcp_server_registry` (crates/ramflux-storage/src/account_db/full_transfer/catalog/integrations.rs:438) | server_id:Utf8?/Transfer/Immutable, registry_hash:Bytes/Transfer/InertHistory, tool_manifest_set_hash:Bytes/Transfer/InertHistory, server_label:Utf8?/Transfer/InertHistory, transport:Utf8/Transfer/InertHistory, endpoint_or_command_hash:Bytes/Transfer/InertHistory, server_public_key:Bytes?/Transfer/InertHistory, trust_state:Utf8/Transfer/InertHistory, server_state:Utf8/Transfer/InertHistory, revocation_cursor:Utf8?/Transfer/InertHistory, updated_at:I64/Transfer/InertHistory | crates/ramflux-storage/src/account_db/mcp.rs:168 |
| `sql/mcp_standing_approval` (crates/ramflux-storage/src/account_db/full_transfer/catalog/integrations.rs:537) | standing_approval_id:Utf8?/Transfer/Immutable, server_id:Utf8/Transfer/InertHistory, tool_name:Utf8/Transfer/InertHistory, capability:Utf8/Transfer/InertHistory, risk_level:Utf8/Transfer/InertHistory, mcp_registry_hash:Bytes/Transfer/InertHistory, tool_manifest_set_hash:Bytes/Transfer/InertHistory, expires_at:I64/Transfer/InertHistory, created_at:I64/Transfer/InertHistory, created_by_device_id:Utf8/Transfer/InertHistory, approval_body:Bytes/Transfer/InertHistory, revoked:I64/Transfer/InertHistory | crates/ramflux-storage/src/account_db/mcp.rs:226; crates/ramflux-storage/src/account_db/mcp.rs:269 |
| `sql/mcp_tool_manifest` (crates/ramflux-storage/src/account_db/full_transfer/catalog/integrations.rs:644) | tool_manifest_hash:Bytes?/Transfer/Immutable, server_id:Utf8/Transfer/InertHistory, tool_name:Utf8/Transfer/InertHistory, manifest_body:Bytes/Transfer/InertHistory, required_capability:Utf8/Transfer/InertHistory, risk_level:Utf8/Transfer/InertHistory, updated_at:I64/Transfer/InertHistory | crates/ramflux-storage/src/account_db/mcp.rs:176; crates/ramflux-storage/src/account_db/mcp.rs:195 |
| `sql/runtime_message_sequence` (crates/ramflux-storage/src/account_db/full_transfer/catalog/message_sequence.rs:9) | message_id:Utf8?/Transfer/Immutable, seq:I64/Transfer/Immutable | crates/ramflux-storage/src/account_db/backup_native.rs:78; crates/ramflux-storage/src/account_db/backup_native.rs:288; crates/ramflux-storage/src/account_db/backup_native.rs:291; crates/ramflux-storage/src/account_db/journal/mod.rs:63; crates/ramflux-storage/src/account_db/message_footprint/schema.rs:359 |
| `sql/message_projection` (crates/ramflux-storage/src/account_db/full_transfer/catalog/messages.rs:213) | message_id:Utf8?/Transfer/Immutable, conversation_id:Utf8/Transfer/Immutable, sender_device_id:Utf8/Transfer/Immutable, event_id:Utf8/Transfer/Immutable, body_cipher:Bytes/Transfer/Immutable, edit_counter:I64/Transfer/Immutable, deleted_at:I64?/Transfer/Immutable, event_tombstone_id:Utf8?/Transfer/Immutable, created_at:I64/Transfer/Immutable, updated_at:I64/Transfer/Immutable | crates/ramflux-storage/src/account_db/message_footprint/erasure.rs:95 |
| `sql/message_tombstone_projection` (crates/ramflux-storage/src/account_db/full_transfer/catalog/messages.rs:304) | tombstone_id:Utf8?/Transfer/Immutable, conversation_id:Utf8/Transfer/RestrictUnion, message_id:Utf8/Transfer/RestrictUnion, delete_scope:Utf8/Transfer/RestrictUnion, created_at:I64/Transfer/RestrictUnion | crates/ramflux-storage/src/account_db/messages.rs:429; crates/ramflux-storage/src/account_db/conversation_state.rs:100 |
| `sql/runtime_message_content` (crates/ramflux-storage/src/account_db/full_transfer/catalog/messages.rs:358) | message_id:Utf8?/Transfer/Immutable, conversation_id:Utf8/Transfer/Immutable, body:Bytes/Transfer/Immutable | crates/ramflux-storage/src/account_db/surface.rs:30; crates/ramflux-storage/src/account_db/backup_merge.rs:503; crates/ramflux-storage/src/account_db/journal/mod.rs:61; crates/ramflux-storage/src/account_db/journal/mod.rs:62; crates/ramflux-storage/src/account_db/journal/mod.rs:214; crates/ramflux-storage/src/account_db/message_footprint/erasure.rs:94; crates/ramflux-storage/src/account_db/raw_inner/evidence.rs:67; crates/ramflux-sdk/src/bus/receipt_tests/erasure_audit.rs:658 |
| `sql/object_chunk/portable` (crates/ramflux-storage/src/account_db/full_transfer/catalog/objects.rs:120) | chunk_id:Utf8?/Transfer/Immutable, object_id:Utf8/Transfer/Immutable, chunk_index:I64/Transfer/Immutable, chunk_cipher_hash:Bytes/Transfer/Immutable, chunk_plain_hash:Bytes?/Transfer/Immutable, cipher_size:I64/Transfer/Immutable, local_path:Utf8?/Exclude/PreferLocal, chunk_state:Utf8/Exclude/PreferLocal, updated_at:I64/Transfer/Immutable | No literal writer found; inspect formatted SQL before activation |
| `sql/object_index/portable` (crates/ramflux-storage/src/account_db/full_transfer/catalog/objects.rs:438) | object_id:Utf8?/Transfer/Immutable, chunk_manifest_hash:Bytes/Transfer/Immutable, object_created_group_key_epoch:I64?/Transfer/Immutable, object_state:Utf8/Transfer/Immutable, total_cipher_size:I64/Transfer/Immutable, chunk_count:I64/Transfer/Immutable, created_at:I64/Transfer/Immutable, updated_at:I64/Transfer/Immutable, manifest_hash:Bytes?/Transfer/Immutable, nonce:Utf8?/Transfer/Immutable, ciphertext:Bytes?/Exclude/PreferLocal, plaintext_hash:Utf8?/Transfer/Immutable, tombstoned:I64/Transfer/Immutable, backup_excluded:I64/Transfer/Immutable, object_content_key:Bytes?/Transfer/Immutable, object_body:Bytes?/Transfer/Immutable | crates/ramflux-storage/src/account_db/object.rs:106; crates/ramflux-storage/src/account_db/object.rs:199; crates/ramflux-storage/src/account_db/object.rs:227; crates/ramflux-storage/src/account_db/backup_merge.rs:712; crates/ramflux-storage/src/account_db/backup_merge.rs:740; crates/ramflux-storage/src/account_db/object_retention/selector_erasure.rs:14; crates/ramflux-storage/src/account_db/object_retention/selector_erasure.rs:20; crates/ramflux-storage/src/account_db/object_retention/selector_erasure.rs:26; crates/ramflux-storage/src/account_db/object_retention/selector_legacy.rs:24; crates/ramflux-storage/src/account_db/object_retention/schema.rs:114; crates/ramflux-storage/src/account_db/backup_selector_admission/replacements.rs:110 |
| `sql/object_key_slot` (crates/ramflux-storage/src/account_db/full_transfer/catalog/objects.rs:570) | slot_id:Utf8?/Transfer/Immutable, object_id:Utf8/Transfer/Immutable, recipient_kind:Utf8/Transfer/Immutable, recipient_id_hash:Bytes/Transfer/Immutable, group_key_epoch:I64?/Transfer/Immutable, wrapped_key:Bytes/Transfer/Immutable, key_wrap_alg:Utf8/Transfer/Immutable | No literal writer found; inspect formatted SQL before activation |
| `sql/object_legacy_reference_context` (crates/ramflux-storage/src/account_db/full_transfer/catalog/objects.rs:637) | selector:Utf8?/Transfer/Immutable, message_id:Utf8/Transfer/Immutable, manifest_hash:Utf8/Transfer/Immutable, metadata_json:Bytes/Transfer/Immutable | crates/ramflux-storage/src/account_db/object_retention/legacy.rs:115; crates/ramflux-storage/src/account_db/object_retention/legacy.rs:127; crates/ramflux-storage/src/account_db/object_retention/schema.rs:129 |
| `sql/object_manifest` (crates/ramflux-storage/src/account_db/full_transfer/catalog/objects.rs:683) | object_id:Utf8?/Transfer/Immutable, manifest_hash:Bytes/Transfer/Immutable, encrypted_owner_ref:Bytes/Transfer/Immutable, encrypted_relation_ref:Bytes?/Transfer/Immutable, encrypted_metadata:Bytes/Transfer/Immutable, object_key_slots:Bytes/Transfer/Immutable, object_created_group_key_epoch:I64?/Transfer/Immutable, chunk_manifest_hash:Bytes/Transfer/Immutable, chunk_count:I64/Transfer/Immutable, total_cipher_size:I64/Transfer/Immutable, signature:Bytes?/Transfer/Immutable, updated_at:I64/Transfer/Immutable | No literal writer found; inspect formatted SQL before activation |
| `sql/object_message_reference` (crates/ramflux-storage/src/account_db/full_transfer/catalog/objects.rs:790) | message_id:Utf8/Transfer/Immutable, reference_hash:Utf8/Transfer/Immutable, metadata_json:Bytes/Transfer/Immutable | crates/ramflux-storage/src/account_db/backup_object_erasure.rs:188; crates/ramflux-storage/src/account_db/backup_object_erasure.rs:415; crates/ramflux-storage/src/account_db/object_retention/mod.rs:315; crates/ramflux-storage/src/account_db/object_retention/schema.rs:127; crates/ramflux-storage/src/account_db/object_retention/schema.rs:143; crates/ramflux-storage/src/account_db/backup_selector_admission/writer.rs:23 |
| `sql/object_operation` (crates/ramflux-storage/src/account_db/full_transfer/catalog/objects.rs:828) | object_id:Utf8?/Transfer/Immutable, operation_id:Utf8/Transfer/InertHistory, state:Utf8/Transfer/InertHistory, request_hash:Bytes/Transfer/InertHistory, manifest_hash:Utf8?/Transfer/InertHistory, plaintext_hash:Utf8?/Transfer/InertHistory, terminal_result:Bytes?/Transfer/InertHistory, last_error:Utf8?/Transfer/InertHistory, created_at:I64/Transfer/InertHistory, updated_at:I64/Transfer/InertHistory | crates/ramflux-storage/src/account_db/object.rs:529 |
| `sql/object_segment_floor` (crates/ramflux-storage/src/account_db/full_transfer/catalog/objects.rs:1340) | directory:Utf8?/Transfer/Immutable, generation:I64/Transfer/RestrictUnion | crates/ramflux-storage/src/schema_large_segments.rs:44; crates/ramflux-storage/src/account_db/large_segments/orphan.rs:45 |
| `sql/object_share_grant_projection` (crates/ramflux-storage/src/account_db/full_transfer/catalog/objects.rs:1475) | object_id:Utf8/Transfer/Immutable, recipient_principal_id:Utf8/Transfer/Immutable, recipient_principal_commitment:Utf8?/Transfer/InertHistory, recipient_device_id:Utf8?/Transfer/InertHistory, conversation_id:Utf8?/Transfer/InertHistory, shared_at:I64/Transfer/InertHistory, revoked_at:I64?/Transfer/InertHistory | crates/ramflux-storage/src/account_db/object.rs:243; crates/ramflux-storage/src/account_db/object.rs:315 |
| `sql/object_tombstone` (crates/ramflux-storage/src/account_db/full_transfer/catalog/objects.rs:1545) | tombstone_id:Utf8?/Transfer/Immutable, target_id:Utf8/Transfer/RestrictUnion, target_kind:Utf8/Transfer/RestrictUnion, actor_device_id:Utf8/Transfer/RestrictUnion, reason:Utf8/Transfer/RestrictUnion, created_at:I64/Transfer/RestrictUnion, causal_event_id:Utf8?/Transfer/RestrictUnion, signature:Bytes/Transfer/RestrictUnion | crates/ramflux-storage/src/account_db/object_retention/schema.rs:111 |
| `sql/lineage_checkpoint` (crates/ramflux-storage/src/account_db/full_transfer/catalog/progress.rs:61) | checkpoint_id:Utf8?/Transfer/Immutable, lineage_head:Utf8/Transfer/Immutable, device_id:Utf8/Transfer/Immutable, device_epoch:I64/Transfer/Immutable, checkpoint_hash:Bytes/Transfer/Immutable, created_at:I64/Transfer/Immutable | No literal writer found; inspect formatted SQL before activation |
| `sql/legacy_receipt_projection` (crates/ramflux-storage/src/account_db/full_transfer/catalog/receipts.rs:61) | receipt_id:Utf8?/Transfer/CursorMax, conversation_id:Utf8?/Transfer/CursorMax, message_id:Utf8?/Transfer/CursorMax, receipt_type:Utf8?/Transfer/CursorMax, actor_device_id:Utf8?/Transfer/CursorMax, created_at:I64?/Transfer/CursorMax | No literal writer found; inspect formatted SQL before activation |
| `sql/receipt_projection` (crates/ramflux-storage/src/account_db/full_transfer/catalog/receipts.rs:199) | receipt_id:Utf8?/Transfer/Immutable, conversation_id:Utf8/Transfer/CursorMax, message_id:Utf8?/Transfer/CursorMax, receipt_type:Utf8/Transfer/CursorMax, actor_device_id:Utf8/Transfer/CursorMax, created_at:I64/Transfer/CursorMax | crates/ramflux-storage/src/account_db/conversation_projection.rs:93; crates/ramflux-storage/src/account_db/message_footprint/erasure.rs:96 |
| `sql/receive_erased_input` (crates/ramflux-storage/src/account_db/full_transfer/catalog/receive.rs:10) | selector:Utf8/Transfer/Immutable, bundle_id:Utf8/Transfer/RestrictUnion, expires_at:I64/Transfer/RestrictUnion | crates/ramflux-storage/src/account_db/receive/erased_capture.rs:754; crates/ramflux-storage/src/account_db/receive/erased_input.rs:22; crates/ramflux-storage/src/account_db/receive/erased_input.rs:97 |
| `sql/rejected_inbox_projection` (crates/ramflux-storage/src/account_db/full_transfer/catalog/receive.rs:45) | conversation_id:Utf8/Transfer/Immutable, message_id:Utf8?/Transfer/Immutable, sender_id:Utf8/Transfer/Immutable, reason:Utf8/Transfer/Immutable, rejected_at:I64/Transfer/Immutable | crates/ramflux-storage/src/account_db/friend.rs:214; crates/ramflux-storage/src/account_db/message_footprint/erasure.rs:112 |
| `sql/runtime_inbox_dead_letter` (crates/ramflux-storage/src/account_db/full_transfer/catalog/receive.rs:134) | envelope_key:Utf8?/Transfer/Immutable, entry_json:Bytes/Transfer/InertHistory, error_code:Utf8/Transfer/InertHistory, received_at:I64/Transfer/InertHistory | crates/ramflux-storage/src/account_db/replay_markers.rs:188; crates/ramflux-storage/src/account_db/journal/inbox_legacy.rs:65; crates/ramflux-storage/src/account_db/journal/inbox_failure.rs:46; crates/ramflux-storage/src/account_db/journal/inbox_failure.rs:115; crates/ramflux-storage/src/account_db/message_footprint/erasure.rs:93 |
| `sql/runtime_inbox_retry` (crates/ramflux-storage/src/account_db/full_transfer/catalog/receive.rs:298) | envelope_key:Utf8?/Transfer/Immutable, entry_json:Bytes/Transfer/InertHistory, attempts:I64/Transfer/InertHistory, next_at:I64/Transfer/InertHistory, created_at:I64/Transfer/InertHistory | crates/ramflux-storage/src/account_db/journal/inbox_legacy.rs:63; crates/ramflux-storage/src/account_db/journal/inbox_legacy.rs:98; crates/ramflux-storage/src/account_db/journal/inbox_policy.rs:82; crates/ramflux-storage/src/account_db/journal/inbox_policy.rs:162; crates/ramflux-storage/src/account_db/journal/inbox_failure.rs:89; crates/ramflux-storage/src/account_db/journal/inbox_failure.rs:126; crates/ramflux-storage/src/account_db/journal/inbox_failure.rs:177; crates/ramflux-storage/src/account_db/journal/inbox_failure.rs:224; crates/ramflux-storage/src/account_db/message_footprint/erasure.rs:92; crates/ramflux-storage/src/account_db/receive/hold.rs:373 |
| `sql/guardian_recovery_share_projection/portable` (crates/ramflux-storage/src/account_db/full_transfer/catalog/recovery.rs:150) | owner_principal_id:Utf8/Transfer/Immutable, guardian_principal_id:Utf8/Transfer/Immutable, recovery_quorum_id:Utf8/Transfer/Immutable, share_id:I64/Transfer/InertHistory, threshold:I64/Transfer/InertHistory, total:I64/Transfer/InertHistory, member_kind:Utf8/Transfer/InertHistory, share_value:Bytes/Exclude/PreferLocal, inviter_device_id:Utf8/Transfer/InertHistory, inviter_device_public_key_base64url:Utf8/Transfer/InertHistory, invite_id:Utf8/Transfer/InertHistory, accepted_at:I64/Transfer/InertHistory, accepted_by_device_id:Utf8/Transfer/InertHistory, accept_signature:Utf8/Transfer/InertHistory, state:Utf8/Transfer/InertHistory, created_at:I64/Transfer/InertHistory, updated_at:I64/Transfer/InertHistory | crates/ramflux-storage/src/account_db/recovery.rs:19; crates/ramflux-storage/src/account_db/backup_native.rs:81 |
| `sql/pending_recovery_approval_projection` (crates/ramflux-storage/src/account_db/full_transfer/catalog/recovery.rs:300) | recovery_id:Utf8/Transfer/Immutable, signing_key_id:Utf8/Transfer/Immutable, member_kind:Utf8/Transfer/InertHistory, approval_json:Bytes/Transfer/InertHistory, approved_at:I64/Transfer/InertHistory | crates/ramflux-storage/src/account_db/recovery.rs:190; crates/ramflux-storage/src/account_db/backup_native.rs:80 |
| `sql/pending_recovery_projection` (crates/ramflux-storage/src/account_db/full_transfer/catalog/recovery.rs:354) | recovery_id:Utf8?/Transfer/Immutable, owner_principal_id:Utf8/Transfer/InertHistory, recovery_quorum_id:Utf8/Transfer/InertHistory, lifecycle_epoch:I64/Transfer/InertHistory, lineage_head:Utf8?/Transfer/InertHistory, event_type:Utf8/Transfer/InertHistory, timelock_started_at:I64?/Transfer/InertHistory, timelock_until:I64?/Transfer/InertHistory, state:Utf8/Transfer/InertHistory, recovery_quorum_json:Bytes/Transfer/InertHistory, context_json:Bytes/Transfer/InertHistory, created_at:I64/Transfer/InertHistory, updated_at:I64/Transfer/InertHistory | crates/ramflux-storage/src/account_db/recovery.rs:117; crates/ramflux-storage/src/account_db/recovery.rs:168; crates/ramflux-storage/src/account_db/backup_native.rs:80 |
| `sql/home_node_binding` (crates/ramflux-storage/src/account_db/full_transfer/catalog/routing.rs:10) | binding_id:Utf8?/Transfer/Immutable, home_node_id:Utf8/Transfer/Immutable, target_delivery_id:Utf8/Transfer/Immutable, routing_set_id:Utf8?/Transfer/Immutable, binding_state:Utf8/Transfer/Immutable, migration_proof_hash:Bytes?/Transfer/Immutable, updated_at:I64/Transfer/Immutable | No literal writer found; inspect formatted SQL before activation |
| `sql/runtime_unrouted` (crates/ramflux-storage/src/account_db/full_transfer/catalog/routing.rs:196) | envelope_id:Utf8?/Transfer/Immutable, inbox_seq:I64/Transfer/InertHistory, entry_json:Bytes/Transfer/InertHistory, received_at:I64/Transfer/InertHistory | crates/ramflux-storage/src/account_db/journal/quarantine.rs:55; crates/ramflux-storage/src/account_db/journal/quarantine.rs:59; crates/ramflux-storage/src/account_db/journal/quarantine.rs:70; crates/ramflux-storage/src/account_db/journal/quarantine.rs:99; crates/ramflux-storage/src/account_db/journal/inbox_failure.rs:91; crates/ramflux-storage/src/account_db/message_footprint/erasure.rs:91; crates/ramflux-storage/src/account_db/receive/removal.rs:290; crates/ramflux-storage/src/account_db/receive/removal.rs:311; crates/ramflux-storage/src/account_db/receive/hold.rs:368 |
| `sql/outbox_queue` (crates/ramflux-storage/src/account_db/full_transfer/catalog/runtime.rs:10) | outbox_id:Utf8?/Transfer/Immutable, envelope_id:Utf8/Transfer/InertHistory, target_delivery_id:Utf8/Transfer/InertHistory, delivery_class:Utf8/Transfer/InertHistory, encrypted_envelope:Bytes/Transfer/InertHistory, state:Utf8/Transfer/InertHistory, retry_count:I64/Transfer/InertHistory, next_retry_at:I64?/Transfer/InertHistory, created_at:I64/Transfer/InertHistory, updated_at:I64/Transfer/InertHistory | crates/ramflux-storage/src/account_db/backup_retirement.rs:10; crates/ramflux-storage/src/account_db/backup_native.rs:79; crates/ramflux-storage/src/account_db/message_footprint/erasure.rs:83 |
| `sql/runtime_actor_state` (crates/ramflux-storage/src/account_db/full_transfer/catalog/runtime.rs:101) | state_kind:Utf8?/Transfer/Immutable, state_json:Bytes/Transfer/InertHistory | crates/ramflux-storage/src/database_work.rs:138; crates/ramflux-storage/src/database_work.rs:139; crates/ramflux-storage/src/database_work.rs:140; crates/ramflux-storage/src/database_work.rs:177; crates/ramflux-storage/src/schema_device_namespace.rs:29; crates/ramflux-storage/src/schema_device_namespace.rs:30; crates/ramflux-storage/src/schema_device_namespace.rs:60; crates/ramflux-storage/src/schema_device_namespace.rs:65; crates/ramflux-storage/src/account_db/identity_verification.rs:134; crates/ramflux-storage/src/account_db/shared_group_delivery.rs:23; crates/ramflux-storage/src/account_db/contact_request_retention.rs:82; crates/ramflux-storage/src/account_db/contact_request_retention.rs:83; crates/ramflux-storage/src/account_db/contact_request_retention.rs:84; crates/ramflux-storage/src/account_db/group_retention.rs:10; crates/ramflux-storage/src/account_db/group_retention.rs:12; crates/ramflux-storage/src/account_db/group_retention.rs:15; crates/ramflux-storage/src/account_db/group_retention.rs:17; crates/ramflux-storage/src/account_db/group_retention.rs:27; crates/ramflux-storage/src/account_db/group_retention.rs:99; crates/ramflux-storage/src/account_db/deleted_messages.rs:110; crates/ramflux-storage/src/account_db/deleted_messages.rs:598; crates/ramflux-storage/src/account_db/self_sync_retirement.rs:36; crates/ramflux-storage/src/account_db/backup_database.rs:357; crates/ramflux-storage/src/account_db/task.rs:52; crates/ramflux-storage/src/account_db/task.rs:90; crates/ramflux-storage/src/account_db/task.rs:98; crates/ramflux-storage/src/account_db/task.rs:171; crates/ramflux-storage/src/account_db/task.rs:197; crates/ramflux-storage/src/account_db/group_snapshot.rs:67; crates/ramflux-storage/src/account_db/surface.rs:41; crates/ramflux-storage/src/account_db/surface.rs:183; crates/ramflux-storage/src/account_db/backup_generated_identity.rs:80; crates/ramflux-storage/src/account_db/backup_generated_identity.rs:85; crates/ramflux-storage/src/account_db/backup_retirement.rs:10; crates/ramflux-storage/src/account_db/backup_retirement.rs:18; crates/ramflux-storage/src/account_db/backup_retirement.rs:29; crates/ramflux-storage/src/account_db/backup_retirement.rs:73; crates/ramflux-storage/src/account_db/backup_retirement.rs:95; crates/ramflux-storage/src/account_db/backup_native.rs:77; crates/ramflux-storage/src/account_db/message_edit_retirement.rs:136; crates/ramflux-storage/src/account_db/backup_self_sync.rs:61; crates/ramflux-storage/src/account_db/backup_self_sync.rs:66; crates/ramflux-storage/src/account_db/backup_self_sync.rs:307; crates/ramflux-storage/src/account_db/backup_self_sync.rs:309; crates/ramflux-storage/src/account_db/backup_merge.rs:415; crates/ramflux-storage/src/account_db/backup_merge.rs:518; crates/ramflux-storage/src/account_db/backup_merge.rs:761; crates/ramflux-storage/src/account_db/journal/inbox_legacy.rs:12; crates/ramflux-storage/src/account_db/journal/inbox_legacy.rs:100; crates/ramflux-storage/src/account_db/object_retention/selector_erasure.rs:36; crates/ramflux-storage/src/account_db/object_retention/selector_erasure.rs:53; crates/ramflux-storage/src/account_db/object_retention/selector_erasure.rs:54; crates/ramflux-storage/src/account_db/object_retention/selector_erasure.rs:55; crates/ramflux-storage/src/account_db/object_retention/selector_erasure.rs:58; crates/ramflux-storage/src/account_db/object_retention/selector_erasure.rs:61; crates/ramflux-storage/src/account_db/object_retention/schema.rs:146; crates/ramflux-storage/src/account_db/object_retention/schema.rs:152; crates/ramflux-storage/src/account_db/message_footprint/erasure.rs:42; crates/ramflux-storage/src/account_db/message_footprint/erasure.rs:44; crates/ramflux-storage/src/account_db/message_footprint/erasure.rs:60; crates/ramflux-storage/src/account_db/message_footprint/erasure.rs:128; crates/ramflux-storage/src/account_db/message_footprint/generic_copy.rs:157; crates/ramflux-storage/src/account_db/runtime/control.rs:32; crates/ramflux-storage/src/account_db/runtime/control.rs:38; crates/ramflux-storage/src/account_db/runtime/control.rs:103; crates/ramflux-storage/src/account_db/runtime/recovery.rs:101; crates/ramflux-storage/src/account_db/runtime/own_copy.rs:98; crates/ramflux-storage/src/account_db/runtime/own_copy.rs:116; crates/ramflux-storage/src/account_db/runtime/own_copy.rs:121; crates/ramflux-storage/src/account_db/runtime/actor_backoff.rs:59; crates/ramflux-storage/src/account_db/runtime/actor_backoff.rs:107; crates/ramflux-storage/src/account_db/runtime/receipt_retention.rs:77; crates/ramflux-storage/src/account_db/runtime/retention.rs:66; crates/ramflux-storage/src/account_db/runtime/retention.rs:71; crates/ramflux-storage/src/account_db/runtime/ratchet_metadata.rs:50; crates/ramflux-storage/src/account_db/runtime/ratchet_metadata.rs:52; crates/ramflux-storage/src/account_db/runtime/ratchet_metadata.rs:53; crates/ramflux-storage/src/account_db/runtime/ratchet_metadata.rs:64; crates/ramflux-sdk/src/bus/receipt_tests/erasure_audit.rs:606; crates/ramflux-sdk/src/bus/receipt_tests/erasure_audit.rs:662 |
| `sql/runtime_journal` (crates/ramflux-storage/src/account_db/full_transfer/catalog/runtime.rs:128) | seq:I64?/Transfer/Immutable, at:I64/Transfer/InertHistory, topic:Utf8/Transfer/InertHistory, body_json:Bytes/Transfer/InertHistory, source_key:Utf8/Transfer/InertHistory, sticky:I64/Transfer/InertHistory, acknowledged:I64/Transfer/InertHistory, subject:Utf8?/Transfer/InertHistory | crates/ramflux-storage/src/account_db/contact_request_retention.rs:224; crates/ramflux-storage/src/account_db/group_retention.rs:75; crates/ramflux-storage/src/account_db/deleted_messages.rs:446; crates/ramflux-storage/src/account_db/deleted_messages.rs:605; crates/ramflux-storage/src/account_db/replay_markers.rs:190; crates/ramflux-storage/src/account_db/backup_native.rs:78; crates/ramflux-storage/src/account_db/message_edit_retirement.rs:169; crates/ramflux-storage/src/account_db/messages.rs:524; crates/ramflux-storage/src/account_db/journal/generated.rs:72; crates/ramflux-storage/src/account_db/journal/mod.rs:106; crates/ramflux-storage/src/account_db/journal/mod.rs:185; crates/ramflux-storage/src/account_db/journal/mod.rs:195; crates/ramflux-storage/src/account_db/journal/retention.rs:25; crates/ramflux-storage/src/account_db/message_footprint/erasure.rs:89; crates/ramflux-storage/src/account_db/runtime/receipt_retention.rs:82; crates/ramflux-sdk/src/bus/receipt_tests/erasure_audit.rs:677 |
| `sql/runtime_operation` (crates/ramflux-storage/src/account_db/full_transfer/catalog/runtime.rs:231) | operation_id:Utf8?/Transfer/Immutable, fingerprint:Utf8/Transfer/InertHistory, response_json:Utf8?/Transfer/InertHistory, operation_kind:Utf8?/Transfer/InertHistory | crates/ramflux-storage/src/account_db/backup_native.rs:78; crates/ramflux-storage/src/account_db/message_edit_retirement.rs:172; crates/ramflux-storage/src/account_db/object_retention/schema.rs:150; crates/ramflux-storage/src/account_db/message_footprint/erasure.rs:131; crates/ramflux-storage/src/account_db/runtime/operations.rs:81; crates/ramflux-storage/src/account_db/runtime/operations.rs:108; crates/ramflux-storage/src/account_db/runtime/operations.rs:114; crates/ramflux-storage/src/account_db/runtime/operations.rs:289 |
| `sql/runtime_own_copy_state` (crates/ramflux-storage/src/account_db/full_transfer/catalog/runtime.rs:345) | state_kind:Utf8?/Exclude/PreferLocal, namespace:Utf8/Exclude/PreferLocal, bytes:I64/Exclude/PreferLocal, expires_at:I64/Exclude/PreferLocal, completed:I64/Exclude/PreferLocal, next_attempt_at:I64?/Exclude/PreferLocal | crates/ramflux-storage/src/account_db/runtime/own_copy/schema.rs:57; crates/ramflux-storage/src/account_db/runtime/own_copy/schema.rs:63; crates/ramflux-storage/src/account_db/runtime/own_copy/schema.rs:67; crates/ramflux-storage/src/account_db/runtime/own_copy/schema.rs:76 |

## Formatted legacy writers

- `schema_receipt_identity.rs:20`: formatted INSERT populates legacy_receipt_projection and legacy_conversation_delivery_state/read_state/unread_marker during current upgrade invocation; no ordinary qualified receipt writer targets them.
- `schema.rs:804`, `account_db/group_device_address.rs:35,75`: legacy_group_member_device_key still has current schema/quarantine writers.
- `schema_group_sender_identity.rs:16`: legacy_group_sender_key_counter_seen still has a current upgrade writer.
- `account_db/object_retention/legacy.rs:115`: object_legacy_reference_context still has a current retention projection writer. These seven families stay UnsupportedRecord when nonempty; their removal is outside this module.

## Actor call-site worklist

All persist_actor_state call sites outside test-named files are listed, including generated/dynamic keys. This is a conservative worklist: cfg(test) functions inside ordinary files may appear. Each concrete normal-account variant must gain an exact typed field declaration; unknown/dynamic descendants stay refused. No prefix default exclusion is authorized. Separate public agent files are covered by the contract, not this SQL scan.

| Source | Key expression |
|---|---|
| crates/ramflux-storage/src/schema_device_namespace.rs:130 | `&format!("directory/device/{address}")` |
| crates/ramflux-storage/src/schema_device_namespace.rs:140 | `"dm-pair/session/old"` |
| crates/ramflux-storage/src/schema_device_namespace.rs:144 | `"dm-pair/session/scoped"` |
| crates/ramflux-storage/src/account_db/shared_group_state.rs:81 | `&state_key(&state.group_id)` |
| crates/ramflux-storage/src/account_db/shared_group_heads.rs:35 | `&key` |
| crates/ramflux-storage/src/account_db/shared_group_heads.rs:45 | `&signed_key(&state.view().group_id)` |
| crates/ramflux-storage/src/account_db/shared_group_delivery.rs:21 | `&key` |
| crates/ramflux-storage/src/account_db/restore_floor.rs:52 | `key` |
| crates/ramflux-storage/src/account_db/restore_floor.rs:137 | `"message-identity/hlc/unreachable"` |
| crates/ramflux-storage/src/account_db/contact_request_retention.rs:225 | `MARKER` |
| crates/ramflux-storage/src/account_db/group_retention.rs:50 | `&id` |
| crates/ramflux-storage/src/account_db/deleted_messages.rs:192 | `&self.deleted_envelope_marker_key(&envelope)?` |
| crates/ramflux-storage/src/account_db/deleted_messages.rs:218 | `&marker` |
| crates/ramflux-storage/src/account_db/deleted_messages.rs:227 | `&self.deletion_marker_key(message)?` |
| crates/ramflux-storage/src/account_db/deleted_messages.rs:390 | `"directory/object/attachment"` |
| crates/ramflux-storage/src/account_db/deleted_messages.rs:394 | `"attachment/reference/attachment"` |
| crates/ramflux-storage/src/account_db/deleted_messages.rs:512 | `"routed/message-owner/message"` |
| crates/ramflux-storage/src/account_db/deleted_messages.rs:513 | `"routed/committed/receipt"` |
| crates/ramflux-storage/src/account_db/deleted_messages.rs:529 | `&seen` |
| crates/ramflux-storage/src/account_db/deleted_messages.rs:773 | `"delivery-receipt/pending/status-id"` |
| crates/ramflux-storage/src/account_db/deleted_messages.rs:777 | `"delivery-receipt/status/status-id"` |
| crates/ramflux-storage/src/account_db/backup.rs:337 | `&format!("backup-fixture/{number}")` |
| crates/ramflux-storage/src/account_db/backup.rs:339 | `"surface/state/fixture"` |
| crates/ramflux-storage/src/account_db/backup.rs:340 | `"task/view/fixture"` |
| crates/ramflux-storage/src/account_db/group_snapshot.rs:62 | `&key` |
| crates/ramflux-storage/src/account_db/backup_generated_identity.rs:118 | `&key(private)?` |
| crates/ramflux-storage/src/account_db/backup_generated_identity.rs:122 | `&key(private)?` |
| crates/ramflux-storage/src/account_db/backup_generated_identity.rs:131 | `&clock` |
| crates/ramflux-storage/src/account_db/backup_generated_identity.rs:132 | `&clock` |
| crates/ramflux-storage/src/account_db/backup_generated_identity.rs:137 | `&newer_clock` |
| crates/ramflux-storage/src/account_db/backup_generated_identity.rs:138 | `&newer_clock` |
| crates/ramflux-storage/src/account_db/backup_retirement.rs:46 | `"identity/recovery-outbound-head"` |
| crates/ramflux-storage/src/account_db/backup_retirement.rs:81 | `&format!("dm-pair/retired/{id}")` |
| crates/ramflux-storage/src/account_db/backup_retirement.rs:85 | `"secrets/retired"` |
| crates/ramflux-storage/src/account_db/backup_retirement.rs:117 | `"dm-pair/session/old"` |
| crates/ramflux-storage/src/account_db/backup_retirement.rs:122 | `"backup/inactive-pair/old"` |
| crates/ramflux-storage/src/account_db/replay_markers.rs:157 | `&marker` |
| crates/ramflux-storage/src/account_db/replay_markers.rs:160 | `&marker` |
| crates/ramflux-storage/src/account_db/replay_markers.rs:234 | `&marker` |
| crates/ramflux-storage/src/account_db/read_model.rs:77 | `&format!("directory/{directory}/{id}")` |
| crates/ramflux-storage/src/account_db/backup_native.rs:133 | `"own-device/sequence-locator/source"` |
| crates/ramflux-storage/src/account_db/backup_native.rs:169 | `"draft/pinned-cut"` |
| crates/ramflux-storage/src/account_db/backup_native.rs:172 | `"draft/pinned-cut"` |
| crates/ramflux-storage/src/account_db/backup_native.rs:338 | `key` |
| crates/ramflux-storage/src/account_db/backup_native.rs:339 | `key` |
| crates/ramflux-storage/src/account_db/backup_native.rs:341 | `"identity/custody/unknown"` |
| crates/ramflux-storage/src/account_db/backup_native.rs:342 | `"dm-pair/session/imported"` |
| crates/ramflux-storage/src/account_db/backup_native.rs:343 | `"dm-pair/active/imported"` |
| crates/ramflux-storage/src/account_db/backup_native.rs:344 | `"dm-pair/bootstrap/imported"` |
| crates/ramflux-storage/src/account_db/backup_native.rs:347 | `"own-device/status/imported"` |
| crates/ramflux-storage/src/account_db/backup_native.rs:348 | `"own-device/status/local"` |
| crates/ramflux-storage/src/account_db/device_metadata.rs:91 | `&format!(` |
| crates/ramflux-storage/src/account_db/device_metadata.rs:105 | `&format!("directory/device/{address}")` |
| crates/ramflux-storage/src/account_db/journal/inbox_legacy.rs:32 | `&format!("inbox/legacy-held/{key}")` |
| crates/ramflux-storage/src/account_db/journal/inbox_legacy.rs:61 | `&name` |
| crates/ramflux-storage/src/account_db/journal/inbox_policy.rs:166 | `"inbox/redrive-at"` |
| crates/ramflux-storage/src/account_db/message_footprint/replay_reference.rs:95 | `key` |
| crates/ramflux-storage/src/account_db/message_footprint/mod.rs:280 | `key` |
| crates/ramflux-storage/src/account_db/message_footprint/mod.rs:312 | `key` |
| crates/ramflux-storage/src/account_db/runtime/control.rs:60 | `kind` |
| crates/ramflux-storage/src/account_db/runtime/control.rs:178 | `key` |
| crates/ramflux-storage/src/account_db/runtime/outbox.rs:93 | `"account/networking"` |
| crates/ramflux-storage/src/account_db/runtime/outbox.rs:95 | `"account/networking"` |
| crates/ramflux-storage/src/account_db/runtime/outbox.rs:98 | `"account/other"` |
| crates/ramflux-storage/src/account_db/runtime/actor_backoff.rs:91 | `id` |
| crates/ramflux-storage/src/account_db/runtime/actor_backoff.rs:93 | `"retry/lease/a"` |
| crates/ramflux-storage/src/account_db/runtime/actor_backoff.rs:101 | `"retry/lease/a"` |
| crates/ramflux-storage/src/account_db/runtime/actor_backoff.rs:113 | `"retry/lease/missing"` |
| crates/ramflux-storage/src/account_db/runtime/receipt_retention.rs:30 | `kind` |
| crates/ramflux-storage/src/account_db/runtime/receipt_retention.rs:62 | `CURSOR` |
| crates/ramflux-storage/src/account_db/runtime/receipt_retention.rs:101 | `&key` |
| crates/ramflux-storage/src/account_db/runtime/retention.rs:86 | `key` |
| crates/ramflux-storage/src/account_db/runtime/retention.rs:91 | `"receipt0/neighbor"` |
| crates/ramflux-storage/src/account_db/runtime/retention.rs:115 | `&format!("receipt/{i:05}")` |
| crates/ramflux-storage/src/account_db/runtime/retention.rs:124 | `"receipt/pending"` |
| crates/ramflux-storage/src/account_db/runtime/retention.rs:128 | `"receipt/unconfirmed"` |
| crates/ramflux-storage/src/account_db/runtime/retention.rs:132 | `"receipt0/neighbor"` |
| crates/ramflux-storage/src/account_db/runtime/retention.rs:165 | `&format!("receipt/{id}")` |
| crates/ramflux-storage/src/account_db/runtime/retention.rs:170 | `"receipt/legacy"` |
| crates/ramflux-storage/src/account_db/runtime/retention.rs:171 | `"receipt0/neighbor"` |
| crates/ramflux-storage/src/account_db/runtime/ratchet_retirement.rs:72 | `&format!("dm-pair/retired/{id}")` |
| crates/ramflux-storage/src/account_db/runtime/ratchet_retirement.rs:82 | `"secrets/retired"` |
| crates/ramflux-storage/src/account_db/runtime/ratchet_retirement.rs:158 | `"dm-pair/session/affected"` |
| crates/ramflux-storage/src/account_db/runtime/ratchet_retirement.rs:159 | `"dm-pair/session/unaffected"` |
| crates/ramflux-storage/src/account_db/runtime/ratchet_retirement.rs:163 | `&pair` |
| crates/ramflux-storage/src/account_db/runtime/ratchet_retirement.rs:164 | `&other_pair` |
| crates/ramflux-storage/src/account_db/runtime/ratchet_retirement.rs:165 | `&format!("dm-pair/reset-work/{pair}")` |
| crates/ramflux-storage/src/account_db/runtime/ratchet_retirement.rs:169 | `&format!("{pair}/manual")` |
| crates/ramflux-storage/src/account_db/runtime/ratchet_retirement.rs:171 | `&floor` |
| crates/ramflux-storage/src/account_db/raw_inner/reparse.rs:359 | `"test/projection"` |
| crates/ramflux-sdk/src/bus/sync_status.rs:23 | `&key` |
| crates/ramflux-sdk/src/bus/sync_status.rs:70 | `&format!("{storage}/event")` |
| crates/ramflux-sdk/src/bus/sync_status.rs:73 | `storage` |
| crates/ramflux-sdk/src/bus/sync_status.rs:75 | `"sync/tick"` |
| crates/ramflux-sdk/src/bus/sync_status.rs:146 | `key` |
| crates/ramflux-sdk/src/bus/sync_status.rs:184 | `"sync/status/event"` |
| crates/ramflux-sdk/src/bus/delivery_receipts.rs:32 | `SCAN_CURSOR` |
| crates/ramflux-sdk/src/bus/delivery_receipts.rs:64 | `&key` |
| crates/ramflux-sdk/src/bus/delivery_receipts.rs:97 | `GATEWAY_RETRY_AT` |
| crates/ramflux-sdk/src/bus/delivery_receipts.rs:129 | `key` |
| crates/ramflux-sdk/src/bus/delivery_receipts.rs:140 | `key` |
| crates/ramflux-sdk/src/bus/delivery_receipts.rs:153 | `key` |
| crates/ramflux-sdk/src/bus/control_state.rs:51 | `&format!("call/{id}")` |
| crates/ramflux-sdk/src/bus/sync_driver.rs:705 | `key` |
| crates/ramflux-sdk/src/bus/readers.rs:452 | `&crate::client::task::scoped("message"` |
| crates/ramflux-sdk/src/bus/readers.rs:492 | `"attachment/reference/remote"` |
| crates/ramflux-sdk/src/bus/readers.rs:498 | `"attachment/fetch/remote"` |
| crates/ramflux-sdk/src/bus/task_courier_apply.rs:24 | `&format!("task/courier_failure/{id}")` |
| crates/ramflux-sdk/src/bus/task_courier_apply.rs:55 | `&item.key` |
| crates/ramflux-sdk/src/bus/task_courier_apply.rs:89 | `&item.key` |
| crates/ramflux-sdk/src/bus/task_courier_apply.rs:94 | `&item.key` |
| crates/ramflux-sdk/src/bus/task_courier_apply.rs:123 | `key` |
| crates/ramflux-sdk/src/bus/task_courier_queue.rs:82 | `&format!("task/courier_dead/{id}")` |
| crates/ramflux-sdk/src/bus/task_courier_queue.rs:87 | `"task/courier_dead_count"` |
| crates/ramflux-sdk/src/bus/own_contact_backfill.rs:21 | `"own-contact/last-refresh"` |
| crates/ramflux-sdk/src/bus/networking_events.rs:80 | `"account/networking"` |
| crates/ramflux-sdk/src/bus/attachment_scheduler.rs:25 | `&key` |
| crates/ramflux-sdk/src/bus/attachment_scheduler.rs:115 | `&format!("attachment/reference/{id}")` |
| crates/ramflux-sdk/src/bus/attachment_scheduler.rs:121 | `"sync/attachment/a"` |
| crates/ramflux-sdk/src/bus/attachment_scheduler.rs:125 | `"sync/attachment/b"` |
| crates/ramflux-sdk/src/bus/attachment_scheduler.rs:129 | `"attachment/fetch/c"` |
| crates/ramflux-sdk/src/bus/attachment_scheduler.rs:152 | `"attachment/reference/with-ref"` |
| crates/ramflux-sdk/src/bus/contact_backpressure.rs:46 | `KEY` |
| crates/ramflux-sdk/src/bus/own_device_copy.rs:178 | `"own-device/sequence"` |
| crates/ramflux-sdk/src/bus/own_device_copy.rs:182 | `&key` |
| crates/ramflux-sdk/src/bus/own_device_copy.rs:214 | `key` |
| crates/ramflux-sdk/src/bus/own_device_copy.rs:272 | `&key` |
| crates/ramflux-sdk/src/bus/own_device_copy.rs:356 | `&key` |
| crates/ramflux-sdk/src/bus/native_account.rs:51 | `"account/node-id"` |
| crates/ramflux-sdk/src/bus/native_account.rs:52 | `"sync/node-id"` |
| crates/ramflux-sdk/src/bus/native_account.rs:357 | `"account/node-id"` |
| crates/ramflux-sdk/src/bus/native_account.rs:358 | `"sync/node-id"` |
| crates/ramflux-sdk/src/client/contact_verification_cas.rs:286 | `&super::identity_authority::record_key(&record.principal_commitment)` |
| crates/ramflux-sdk/src/client/contact_verification_cas.rs:292 | `&format!("identity/manifest-root/{}"` |
| crates/ramflux-sdk/src/client/contact_verification_cas.rs:530 | `&confirmation_key(commitment)` |
| crates/ramflux-sdk/src/client/contact_verification_cas.rs:534 | `&origin_inner_key(commitment)` |
| crates/ramflux-sdk/src/client/contact_verification_cas.rs:547 | `&format!("identity/safety_verified_set/{commitment}")` |
| crates/ramflux-sdk/src/client/delivery_receipts.rs:158 | `&format!("{PREFIX}{key}")` |
| crates/ramflux-sdk/src/client/delivery_receipts.rs:245 | `&format!("{PREFIX}{status_id}")` |
| crates/ramflux-sdk/src/client/backup_activation.rs:35 | `"backup/reestablishing"` |
| crates/ramflux-sdk/src/client/group_control_roots.rs:168 | `&exact` |
| crates/ramflux-sdk/src/client/group_control_roots.rs:173 | `&key` |
| crates/ramflux-sdk/src/client/group_key_safety.rs:48 | `&owner_key` |
| crates/ramflux-sdk/src/client/group_key_safety.rs:96 | `&bucket` |
| crates/ramflux-sdk/src/client/generated_identity.rs:100 | `&key` |
| crates/ramflux-sdk/src/client/generated_delete_fence.rs:57 | `&key` |
| crates/ramflux-sdk/src/client/generated_delete_fence.rs:78 | `&key` |
| crates/ramflux-sdk/src/client/self_sync.rs:260 | `&state_key` |
| crates/ramflux-sdk/src/client/self_sync.rs:271 | `&state_key` |
| crates/ramflux-sdk/src/client/self_sync.rs:407 | `&key` |
| crates/ramflux-sdk/src/client/contact.rs:329 | `&format!("contact/removal-event/{link_id}")` |
| crates/ramflux-sdk/src/client/contact.rs:1504 | `&key` |
| crates/ramflux-sdk/src/client/generated_restore.rs:49 | `ramflux_storage::PARKED_EDIT_REVIEW` |
| crates/ramflux-sdk/src/client/own_contact.rs:381 | `&backfill_retry::parked_key(&link.link_id)` |
| crates/ramflux-sdk/src/client/own_contact.rs:390 | `"own-contact/backfill"` |
| crates/ramflux-sdk/src/client/own_contact.rs:400 | `"own-contact/backfill"` |
| crates/ramflux-sdk/src/client/own_contact.rs:411 | `"own-contact/backfill"` |
| crates/ramflux-sdk/src/client/own_contact.rs:421 | `"own-contact/backfill"` |
| crates/ramflux-sdk/src/client/own_contact.rs:463 | `"own-contact/backfill"` |
| crates/ramflux-sdk/src/client/generated_capacity.rs:30 | `&key` |
| crates/ramflux-sdk/src/client/generated_capacity.rs:41 | `&format!("raw-capacity/held/{id}")` |
| crates/ramflux-sdk/src/client/raw_inner_reparse.rs:419 | `key` |
| crates/ramflux-sdk/src/client/own_group_lazy_authority.rs:58 | `&key` |
| crates/ramflux-sdk/src/client/own_group_lazy_authority.rs:163 | `&key` |
| crates/ramflux-sdk/src/client/reply_outbox.rs:252 | `&stored` |
| crates/ramflux-sdk/src/client/reply_outbox.rs:253 | `&marker` |
| crates/ramflux-sdk/src/client/group.rs:1028 | `&id` |
| crates/ramflux-sdk/src/client/group.rs:1036 | `&id` |
| crates/ramflux-sdk/src/client/private_prekeys.rs:167 | `&format!("identity/signed_set/{}"` |
| crates/ramflux-sdk/src/client/own_sent_delivery.rs:86 | `"own-device/manifest-refresh"` |
| crates/ramflux-sdk/src/client/own_sent_delivery.rs:159 | `"own-device/sent-failures"` |
| crates/ramflux-sdk/src/client/deferred_attachment.rs:579 | `&chunk_key(reference` |
| crates/ramflux-sdk/src/client/deferred_attachment.rs:694 | `&reference_key(&selector)` |
| crates/ramflux-sdk/src/client/deferred_attachment.rs:695 | `&scoped_key` |
| crates/ramflux-sdk/src/client/deferred_attachment.rs:697 | `&slot_key` |
| crates/ramflux-sdk/src/client/authored_send.rs:340 | `&operation` |
| crates/ramflux-sdk/src/client/shared_group/message_ids.rs:70 | `&format!("group-message/alias/{canonical}")` |
| crates/ramflux-sdk/src/client/shared_group/maintenance.rs:90 | `WARNING` |
| crates/ramflux-sdk/src/client/shared_group/maintenance.rs:101 | `&retry_key` |
| crates/ramflux-sdk/src/client/shared_group/maintenance.rs:109 | `WARNING` |
| crates/ramflux-sdk/src/client/shared_group/bootstrap.rs:317 | `&marker` |
| crates/ramflux-sdk/src/client/shared_group/transfer_outcome.rs:38 | `&id` |
| crates/ramflux-sdk/src/client/shared_group/transfer_outcome.rs:66 | `&id` |
| crates/ramflux-sdk/src/client/shared_group/controls.rs:63 | `&id` |
| crates/ramflux-sdk/src/client/shared_group/federation.rs:35 | `&key(group` |
| crates/ramflux-sdk/src/client/shared_group/creator_conflicts.rs:91 | `&key(&state.view().group_id)` |
| crates/ramflux-sdk/src/client/shared_group/creator_conflicts.rs:112 | `&key(&state.view().group_id)` |
| crates/ramflux-sdk/src/client/shared_group/creator_conflicts.rs:282 | `&marker_key` |
| crates/ramflux-sdk/src/client/shared_group/creator_conflicts.rs:359 | `&marker_key` |
| crates/ramflux-sdk/src/client/shared_group/creator_conflicts.rs:386 | `&key` |
| crates/ramflux-sdk/src/client/shared_group/snapshot_generated.rs:229 | `&key` |
| crates/ramflux-sdk/src/client/shared_group/own_consent.rs:147 | `&id` |
| crates/ramflux-sdk/src/client/shared_group/own_consent.rs:339 | `&key(group)` |
| crates/ramflux-sdk/src/client/shared_group/requests.rs:80 | `&request_key(&record.request` |
| crates/ramflux-sdk/src/client/shared_group/invitations.rs:118 | `&id` |
| crates/ramflux-sdk/src/client/shared_group/invitations.rs:137 | `&id` |
| crates/ramflux-sdk/src/client/shared_group/invitations.rs:187 | `&key(group)` |
| crates/ramflux-sdk/src/client/shared_group/invitations.rs:221 | `&key(group)` |
| crates/ramflux-sdk/src/client/shared_group/invitations.rs:232 | `&key(group)` |
| crates/ramflux-sdk/src/client/shared_group/transfer.rs:158 | `&id` |
| crates/ramflux-sdk/src/client/shared_group/transfer.rs:220 | `id` |
| crates/ramflux-sdk/src/client/shared_group/transfer.rs:280 | `&id` |
| crates/ramflux-sdk/src/client/shared_group/transfer.rs:363 | `&id` |
| crates/ramflux-sdk/src/client/shared_group/transfer.rs:435 | `&key(LEASE` |
| crates/ramflux-sdk/src/client/shared_group/transfer.rs:588 | `&id` |
| crates/ramflux-sdk/src/client/shared_group/transfer.rs:819 | `&id` |
| crates/ramflux-sdk/src/client/contact_requests/native_delivery.rs:84 | `&key(&updated)` |
| crates/ramflux-sdk/src/client/contact_requests/delivery.rs:76 | `&id` |
| crates/ramflux-sdk/src/client/contact_requests/delivery.rs:167 | `&id` |
| crates/ramflux-sdk/src/client/contact_requests/delivery.rs:433 | `&id` |
| crates/ramflux-sdk/src/client/contact_requests/delivery.rs:510 | `&key(intent)` |
| crates/ramflux-sdk/src/client/contact_requests/retention.rs:53 | `&key` |
| crates/ramflux-sdk/src/client/contact_requests/retention.rs:62 | `&key` |
| crates/ramflux-sdk/src/client/contact_requests/retention.rs:200 | `KEY` |
| crates/ramflux-sdk/src/client/contact_requests/native_history.rs:105 | `&id` |
| crates/ramflux-sdk/src/client/generated_control/receive.rs:181 | `&key` |
| crates/ramflux-sdk/src/client/own_device_copy/receipts.rs:90 | `key` |
| crates/ramflux-sdk/src/client/own_device_copy/receipts.rs:167 | `&binding.committed_key` |
| crates/ramflux-sdk/src/client/own_device_copy/receipts.rs:201 | `&format!("{REPLAYS}{i:05}")` |
| crates/ramflux-sdk/src/client/own_device_copy/w1.rs:173 | `&key` |
| crates/ramflux-sdk/src/client/own_device_copy/w1.rs:267 | `&key` |
| crates/ramflux-sdk/src/client/identity_authority/custody_directory.rs:167 | `&state_key` |
| crates/ramflux-sdk/src/client/identity_authority/custody_directory.rs:255 | `&format!("identity/manifest-root/{expected}")` |
| crates/ramflux-sdk/src/client/identity_authority/custody_directory.rs:432 | `&key` |
| crates/ramflux-sdk/src/client/identity_authority/custody_directory.rs:691 | `&storage_key` |
| crates/ramflux-sdk/src/client/identity_authority/custody_directory.rs:697 | `&storage_key` |
| crates/ramflux-sdk/src/client/identity_authority/profile.rs:30 | `DESIRED` |
| crates/ramflux-sdk/src/client/identity_authority/profile.rs:69 | `DESIRED` |
| crates/ramflux-sdk/src/client/identity_authority/profile.rs:102 | `&format!("identity/root_public/{}"` |
| crates/ramflux-sdk/src/client/identity_authority/owned.rs:103 | `"identity/legacy_authorizations"` |
| crates/ramflux-sdk/src/client/identity_authority/owned.rs:294 | `"identity/owned_pending_set"` |
| crates/ramflux-sdk/src/client/identity_authority/owned.rs:313 | `&record_key(&record.principal_commitment)` |
| crates/ramflux-sdk/src/client/identity_authority/registration.rs:67 | `REFRESH_AT` |
| crates/ramflux-sdk/src/client/identity_authority/registration.rs:99 | `"identity/registration_set"` |
| crates/ramflux-sdk/src/client/identity_authority/registration.rs:128 | `"identity/registration_set"` |
| crates/ramflux-sdk/src/client/identity_authority/registration.rs:160 | `"identity/registration_set"` |
| crates/ramflux-sdk/src/client/identity_authority/custody_lifecycle.rs:59 | `&Self::device_revocation_key(&identity)` |
| crates/ramflux-sdk/src/client/identity_authority/reconcile.rs:46 | `INTENTS` |
| crates/ramflux-sdk/src/client/identity_authority/directory.rs:29 | `&format!("identity/manifest-root/{}"` |
| crates/ramflux-sdk/src/client/identity_authority/directory.rs:33 | `&format!("identity/manifest/{}"` |
| crates/ramflux-sdk/src/client/identity_authority/directory.rs:67 | `&record_key(&record.principal_commitment)` |
| crates/ramflux-sdk/src/client/identity_authority/directory.rs:77 | `&format!("identity/manifest/{}"` |
| crates/ramflux-sdk/src/client/identity_authority/directory.rs:82 | `&format!("identity/manifest-root/{}"` |
| crates/ramflux-sdk/src/client/identity_authority/directory.rs:104 | `&format!("identity/rejected_set/{key}")` |
| crates/ramflux-sdk/src/client/generated_history/page.rs:205 | `&key` |
| crates/ramflux-sdk/src/client/generated_history/producer.rs:194 | `&marker` |
| crates/ramflux-sdk/src/client/generated_history/producer.rs:256 | `&key` |
| crates/ramflux-sdk/src/client/generated_history/delivery.rs:99 | `&key` |
| crates/ramflux-sdk/src/client/generated_history/delivery.rs:112 | `&key` |
| crates/ramflux-sdk/src/client/generated_history/delivery.rs:207 | `&plan.key` |
| crates/ramflux-sdk/src/client/generated_history/delivery.rs:215 | `&plan.key` |
| crates/ramflux-sdk/src/client/generated_history/delivery.rs:237 | `&page` |
| crates/ramflux-sdk/src/client/generated_history/delivery.rs:258 | `&plan.key` |
| crates/ramflux-sdk/src/client/generated_history/delivery.rs:285 | `&plan.key` |
| crates/ramflux-sdk/src/client/generated_history/delivery.rs:340 | `&key` |
| crates/ramflux-sdk/src/client/surface/own_delivery.rs:84 | `&key` |
| crates/ramflux-sdk/src/client/surface/pending.rs:127 | `&pending_key(carrier)?` |
| crates/ramflux-sdk/src/client/surface/pending.rs:222 | `&key("out_of_sync"` |
| crates/ramflux-sdk/src/client/surface/pending.rs:258 | `"surface/pending_expiry_cursor"` |
| crates/ramflux-sdk/src/client/surface/decision.rs:87 | `&decision_key(original` |
| crates/ramflux-sdk/src/client/surface/decision.rs:105 | `&action_key` |
| crates/ramflux-sdk/src/client/surface/decision.rs:139 | `&actor_key` |
| crates/ramflux-sdk/src/client/surface/persist.rs:47 | `&key("state"` |
| crates/ramflux-sdk/src/client/surface/persist.rs:50 | `&history` |
| crates/ramflux-sdk/src/client/surface/persist.rs:80 | `&key("snapshot_floor"` |
| crates/ramflux-sdk/src/client/surface/own_checkpoint.rs:110 | `&key("import_skip"` |
| crates/ramflux-sdk/src/client/surface/own_checkpoint.rs:115 | `&key("out_of_sync"` |
| crates/ramflux-sdk/src/client/surface/own_checkpoint.rs:222 | `&key("state"` |
| crates/ramflux-sdk/src/client/surface/own_checkpoint.rs:223 | `&key("snapshot_floor"` |
| crates/ramflux-sdk/src/client/surface/own_checkpoint.rs:227 | `&key("group_epoch"` |
| crates/ramflux-sdk/src/client/surface/own_checkpoint.rs:231 | `&history` |
| crates/ramflux-sdk/src/client/surface/delivery.rs:120 | `&receipt_key` |
| crates/ramflux-sdk/src/client/surface/delivery.rs:152 | `&epoch_key` |
| crates/ramflux-sdk/src/client/surface/own_history.rs:111 | `"surface/export_metadata"` |
| crates/ramflux-sdk/src/client/surface/projection.rs:172 | `&key("snapshot_floor"` |
| crates/ramflux-sdk/src/client/surface/projection.rs:194 | `&super::receipt_key(&original)?` |
| crates/ramflux-sdk/src/client/surface/authored.rs:41 | `&key` |
| crates/ramflux-sdk/src/client/surface/authored.rs:82 | `&key` |
| crates/ramflux-sdk/src/client/surface/authored.rs:110 | `&id` |
| crates/ramflux-sdk/src/client/surface/history_generated.rs:97 | `&super::key("import_metadata"` |
| crates/ramflux-sdk/src/client/surface/history_generated.rs:108 | `&super::key(` |
| crates/ramflux-sdk/src/client/surface/history_generated.rs:155 | `&super::key(` |
| crates/ramflux-sdk/src/client/surface/resync_request.rs:139 | `id` |
| crates/ramflux-sdk/src/client/surface/resync_request.rs:301 | `&rate` |
| crates/ramflux-sdk/src/client/surface/resync_request.rs:302 | `&budget` |
| crates/ramflux-sdk/src/client/surface/resync_request.rs:303 | `&format!(` |
| crates/ramflux-sdk/src/client/routed/session.rs:69 | `&record_key` |
| crates/ramflux-sdk/src/client/routed/session.rs:289 | `&format!("dm-pair/bootstrap/{}"` |
| crates/ramflux-sdk/src/client/routed/pair_lifecycle.rs:138 | `&Self::device_revocation_key(&self.device_identity(&reference)?)` |
| crates/ramflux-sdk/src/client/routed/pair_lifecycle.rs:185 | `&format!("{}/manual"` |
| crates/ramflux-sdk/src/client/routed/generated_applications.rs:167 | `&crate::client::task::key("import_metadata"` |
| crates/ramflux-sdk/src/client/routed/control.rs:73 | `&key` |
| crates/ramflux-sdk/src/client/routed/recovery.rs:43 | `&format!("dm-pair/retired/{id}")` |
| crates/ramflux-sdk/src/client/routed/recovery.rs:44 | `"secrets/retired"` |
| crates/ramflux-sdk/src/client/routed/committed.rs:67 | `&marker` |
| crates/ramflux-sdk/src/client/routed/committed.rs:110 | `&key` |
| crates/ramflux-sdk/src/client/routed/committed.rs:112 | `&format!("{key}/projected")` |
| crates/ramflux-sdk/src/client/routed/committed.rs:137 | `key` |
| crates/ramflux-sdk/src/client/routed/committed.rs:302 | `&format!("routed/projection/{scoped}")` |
| crates/ramflux-sdk/src/client/routed/committed.rs:303 | `&format!("routed/message-owner/{id}")` |
| crates/ramflux-sdk/src/client/routed/receive.rs:758 | `&format!("dm-pair/collapse-scope/{}/{tag}"` |
| crates/ramflux-sdk/src/client/routed/receive.rs:874 | `&format!("routed/message-metadata/{}"` |
| crates/ramflux-sdk/src/client/routed/receive.rs:964 | `receipt` |
| crates/ramflux-sdk/src/client/routed/bootstrap_sequence.rs:39 | `&key` |
| crates/ramflux-sdk/src/client/routed/bootstrap_sequence.rs:112 | `&self.bootstrap_high_water_key(local` |
| crates/ramflux-sdk/src/client/routed/reset_prepare.rs:241 | `&format!("dm-pair/reset/{}"` |
| crates/ramflux-sdk/src/client/routed/mod.rs:289 | `&format!("dm-pair/local/{}"` |
| crates/ramflux-sdk/src/client/routed/reset_work.rs:99 | `&key` |
| crates/ramflux-sdk/src/client/routed/reset_policy.rs:60 | `&key` |
| crates/ramflux-sdk/src/client/routed/reset_policy.rs:82 | `&key` |
| crates/ramflux-sdk/src/client/routed/reset_policy.rs:93 | `&format!("{pair}/reset-times")` |
| crates/ramflux-sdk/src/client/routed/reset_policy.rs:94 | `&format!("{pair}/reset-at")` |
| crates/ramflux-sdk/src/client/routed/reset_policy.rs:95 | `&format!("{pair}/reset-pending")` |
| crates/ramflux-sdk/src/client/routed/object_slot.rs:61 | `&format!("dm-pair/local/{}"` |
| crates/ramflux-sdk/src/client/routed/object_slot.rs:194 | `&slot_receipt(slot)?` |
| crates/ramflux-sdk/src/client/routed/object_slot.rs:195 | `&super::object_watermark(` |
| crates/ramflux-sdk/src/client/routed/typing.rs:145 | `&seals_key` |
| crates/ramflux-sdk/src/client/routed/archive.rs:39 | `&format!("{}/archive"` |
| crates/ramflux-sdk/src/client/routed/archive.rs:63 | `&format!("{key}/archive")` |
| crates/ramflux-sdk/src/client/routed/archive.rs:64 | `&key` |
| crates/ramflux-sdk/src/client/routed/archive.rs:96 | `&format!("dm-pair/confirmed/{id}")` |
| crates/ramflux-sdk/src/client/typing/send.rs:80 | `"settings/share_typing"` |
| crates/ramflux-sdk/src/client/own_contact/backfill_retry.rs:30 | `"own-contact/directory-generation"` |
| crates/ramflux-sdk/src/client/call/control.rs:94 | `&format!("voice/public/{}"` |
| crates/ramflux-sdk/src/client/call/control.rs:374 | `&receipt` |
| crates/ramflux-sdk/src/client/call/intent.rs:291 | `key` |
| crates/ramflux-sdk/src/client/own_sent_message/replay.rs:63 | `&replay.fence` |
| crates/ramflux-sdk/src/client/self_sync/fence.rs:46 | `&floor_key(scope)` |
| crates/ramflux-sdk/src/client/self_sync/fence.rs:89 | `&fence_key(own.root_commitment()` |
| crates/ramflux-sdk/src/client/self_sync/fence.rs:102 | `&fence_key(own.root_commitment()` |
| crates/ramflux-sdk/src/client/self_sync/bootstrap.rs:91 | `&marker` |
| crates/ramflux-sdk/src/client/self_sync/retirement.rs:31 | `key` |
| crates/ramflux-sdk/src/client/self_sync/restore.rs:33 | `GENERATION` |
| crates/ramflux-sdk/src/client/self_sync/publication.rs:65 | `&state_key` |
| crates/ramflux-sdk/src/client/self_sync/refresh.rs:74 | `BARRIER` |
| crates/ramflux-sdk/src/client/self_sync/refresh.rs:112 | `BARRIER` |
| crates/ramflux-sdk/src/client/dm/legacy_receive.rs:110 | `&terminal` |
| crates/ramflux-sdk/src/client/task/pending.rs:109 | `&self.task_pending_key(c)?` |
| crates/ramflux-sdk/src/client/task/decision.rs:137 | `&reservation` |
| crates/ramflux-sdk/src/client/task/approval_retention.rs:106 | `storage` |
| crates/ramflux-sdk/src/client/task/approval_retention.rs:160 | `&key("approval_receipt"` |
| crates/ramflux-sdk/src/client/task/quota.rs:250 | `&scoped("lifecycle"` |
| crates/ramflux-sdk/src/client/task/quota.rs:254 | `&view_key` |
| crates/ramflux-sdk/src/client/task/quota.rs:312 | `&key` |
| crates/ramflux-sdk/src/client/task/control.rs:126 | `&id` |
| crates/ramflux-sdk/src/client/task/control.rs:307 | `&id` |
| crates/ramflux-sdk/src/client/task/local_pending.rs:191 | `&target` |
| crates/ramflux-sdk/src/client/task/local_pending.rs:223 | `&key.replace("task/local_pending/"` |
| crates/ramflux-sdk/src/client/task/certificate.rs:191 | `&key` |
| crates/ramflux-sdk/src/client/task/approval_decision.rs:86 | `&storage` |
| crates/ramflux-sdk/src/client/task/rejected_task.rs:18 | `&key` |
| crates/ramflux-sdk/src/client/task/roster.rs:50 | `&key` |
| crates/ramflux-sdk/src/client/task/own_history.rs:425 | `&metadata_key` |
| crates/ramflux-sdk/src/client/task/own_history.rs:426 | `&cursor_key` |
| crates/ramflux-sdk/src/client/task/own_history.rs:440 | `&metadata_key` |
| crates/ramflux-sdk/src/client/task/own_history.rs:441 | `&cursor_key` |
| crates/ramflux-sdk/src/client/task/own_history.rs:454 | `&metadata_key` |
| crates/ramflux-sdk/src/client/task/own_history.rs:455 | `&cursor_key` |
| crates/ramflux-sdk/src/client/task/own_history.rs:464 | `&super::key("import_skip"` |
| crates/ramflux-sdk/src/client/task/projection.rs:167 | `&key` |
| crates/ramflux-sdk/src/client/task/projection.rs:292 | `if outcome.accepted { &receipt_key } else { &rejected_key }` |
| crates/ramflux-sdk/src/client/task/projection.rs:303 | `&key` |
| crates/ramflux-sdk/src/client/task/projection.rs:394 | `&history_key` |
| crates/ramflux-sdk/src/client/task/projection.rs:397 | `&key` |
| crates/ramflux-sdk/src/client/task/projection.rs:418 | `&scoped("view"` |
| crates/ramflux-sdk/src/client/task/lifecycle.rs:93 | `&scoped("lifecycle"` |
| crates/ramflux-sdk/src/client/task/lifecycle.rs:135 | `&scoped("lifecycle"` |
| crates/ramflux-sdk/src/client/task/lifecycle.rs:217 | `&key` |
| crates/ramflux-sdk/src/client/task/lifecycle.rs:261 | `&checkpoint` |
| crates/ramflux-sdk/src/client/task/lifecycle.rs:277 | `&view_key` |
| crates/ramflux-sdk/src/client/task/lifecycle.rs:284 | `&index_key` |
| crates/ramflux-sdk/src/client/deferred_attachment/job.rs:215 | `&key` |
| crates/ramflux-sdk/src/client/native_test_support/pairing_history.rs:139 | `&key` |
| crates/ramflux-sdk/src/client/native_test_support/history.rs:75 | `&key` |
| crates/ramflux-sdk/src/client/routed/native_control/produce.rs:86 | `&key` |
| crates/ramflux-sdk/src/client/routed/native_control/produce.rs:203 | `&key` |
| crates/ramflux-sdk/src/client/routed/native_control/mod.rs:138 | `&key` |
| crates/ramflux-sdk/src/client/routed/native_control/guardian.rs:313 | `&key` |
| crates/ramflux-sdk/src/client/routed/native_control/guardian.rs:329 | `&key` |
| crates/ramflux-sdk/src/client/contact_requests/delivery/background.rs:303 | `&key(&intent)` |
| crates/ramflux-sdk/src/client/contact_requests/delivery/background.rs:373 | `&key(&intent)` |
| crates/ramflux-sdk/src/client/contact_requests/delivery/background.rs:549 | `&key(&plan.plan.intent)` |
| crates/ramflux-sdk/src/custody/pairing/coordinator/registry.rs:265 | `"account/node-id"` |
| crates/ramflux-sdk/src/custody/pairing/coordinator/registry.rs:266 | `"sync/node-id"` |
| crates/ramflux-sdk/src/bus/journal/mod.rs:82 | `&format!("stream/a2ui/{id}")` |
| crates/ramflux-sdk/src/bus/journal/mod.rs:115 | `"attachment/reference/remote"` |
| crates/ramflux-sdk/src/bus/journal/mod.rs:126 | `"attachment/fetch/remote"` |
| crates/ramflux-sdk/src/bus/journal/mod.rs:193 | `"routed/message-metadata/received"` |
| crates/ramflux-sdk/src/bus/runtime_tests/stream.rs:409 | `"sync/node-id"` |
| crates/ramflux-sdk/src/bus/runtime_tests/group_actor.rs:41 | `"routed/message-metadata/corrupt-group-msg"` |
| crates/ramflux-sdk/src/bus/runtime_tests/contact_verification.rs:58 | `&format!("identity/safety_verified_set/{peer_root}")` |
| crates/ramflux-sdk/src/bus/runtime_tests/status_snapshot.rs:114 | `"sync/node-id"` |
| crates/ramflux-sdk/src/bus/own_device_copy/background.rs:270 | `&key` |
| crates/ramflux-sdk/src/bus/own_device_copy/background.rs:596 | `&key` |
| crates/ramflux-sdk/src/bus/receipt_tests/followups.rs:52 | `"message/origin/legacy"` |
| crates/ramflux-sdk/src/bus/receipt_tests/followups.rs:53 | `"message/origin/recent"` |
| crates/ramflux-sdk/src/bus/receipt_tests/followups.rs:54 | `"unrelated/record"` |
| crates/ramflux-sdk/src/bus/receipt_tests/followups.rs:110 | `&format!("delivery-receipt/status/{n:02}")` |
| crates/ramflux-sdk/src/bus/receipt_tests/followups.rs:181 | `&stale_key` |
| crates/ramflux-sdk/src/bus/receipt_tests/limits.rs:55 | `&p.key` |
| crates/ramflux-sdk/src/bus/receipt_tests/limits.rs:64 | `&format!("{PREFIX}placeholder-{n}")` |
| crates/ramflux-sdk/src/bus/receipt_tests/limits.rs:96 | `&p.key` |
| crates/ramflux-sdk/src/bus/receipt_tests/limits.rs:111 | `&p.key` |
| crates/ramflux-sdk/src/bus/receipt_tests/limits.rs:192 | `&p.key` |
| crates/ramflux-sdk/src/bus/receipt_tests/limits.rs:194 | `&format!("device/revoked/{}"` |
| crates/ramflux-sdk/src/bus/receipt_tests/limits.rs:203 | `&p.key` |
| crates/ramflux-sdk/src/bus/receipt_tests/limits.rs:352 | `&due_key` |
| crates/ramflux-sdk/src/bus/receipt_tests/limits.rs:358 | `&format!("{PREFIX}blocked-{n:03}")` |
| crates/ramflux-sdk/src/bus/receipt_tests/limits.rs:446 | `SCAN_CURSOR` |
| crates/ramflux-sdk/src/bus/receipt_tests/limits.rs:469 | `&p.key` |
| crates/ramflux-sdk/src/bus/receipt_tests/limits.rs:509 | `&p.key` |
| crates/ramflux-sdk/src/bus/receipt_tests/limits.rs:517 | `&status_key` |
| crates/ramflux-sdk/src/bus/receipt_tests/limits.rs:581 | `&p.key` |
| crates/ramflux-sdk/src/bus/receipt_tests/limits.rs:646 | `&p.key` |
| crates/ramflux-sdk/src/bus/receipt_tests/limits.rs:750 | `GATEWAY_RETRY_AT` |
| crates/ramflux-sdk/src/bus/receipt_tests/limits.rs:764 | `"delivery-receipt/retention-cursor"` |
| crates/ramflux-sdk/src/bus/receipt_tests/mod.rs:201 | `&key` |
| crates/ramflux-sdk/src/bus/receipt_tests/mod.rs:212 | `&key` |
| crates/ramflux-sdk/src/bus/couriers/layer_publish.rs:67 | `LAST_ERROR_KEY` |
| crates/ramflux-sdk/src/bus/task_courier_apply/background.rs:339 | `&crate::client::task::key("ack_sent"` |
| crates/ramflux-sdk/src/bus/dispatch/task_approval_apply.rs:72 | `&rejected` |
| crates/ramflux-sdk/src/bus/dispatch/task_approval_apply.rs:132 | `&format!("mcp/denied/{}"` |
| crates/ramflux-sdk/src/bus/dispatch/conversation_journal.rs:81 | `key` |
| crates/ramflux-sdk/src/bus/dispatch/conversation_journal.rs:115 | `&format!("{PREFIX}{n:04}")` |
| crates/ramflux-sdk/src/bus/dispatch/conversation_journal.rs:129 | `&format!("{PREFIX}{n:04}")` |
| crates/ramflux-sdk/src/bus/dispatch/conversation_journal.rs:134 | `"conversation-intent/0001"` |
| crates/ramflux-sdk/src/bus/dispatch/task_approval_cleanup.rs:52 | `&storage` |
| crates/ramflux-sdk/src/bus/dispatch/task_approval_cleanup.rs:100 | `&storage` |
| crates/ramflux-sdk/src/bus/dispatch/conversation_send.rs:334 | `&key` |
| crates/ramflux-sdk/src/bus/dispatch/conversation_send.rs:365 | `&key` |
| crates/ramflux-sdk/src/bus/dispatch/conversation_send.rs:428 | `"conversation-send/expired"` |
| crates/ramflux-sdk/src/bus/dispatch/conversation_send.rs:444 | `&format!("conversation-send/{n:04}")` |
| crates/ramflux-sdk/src/bus/dispatch/conversation_send.rs:471 | `key` |
| crates/ramflux-sdk/src/bus/dispatch/task_approval.rs:282 | `storage` |
| crates/ramflux-sdk/src/bus/dispatch/task_transport.rs:450 | `&quarantine` |
| crates/ramflux-sdk/src/bus/dispatch/task_transport.rs:471 | `&crate::client::task::key("ack_sent"` |
| crates/ramflux-sdk/src/bus/dispatch/task_transport.rs:481 | `&key` |
| crates/ramflux-sdk/src/bus/dispatch/task_transport.rs:514 | `&key` |
| crates/ramflux-sdk/src/bus/dispatch/group.rs:635 | `&submitted_key` |
| crates/ramflux-sdk/src/bus/dispatch/group.rs:654 | `&key` |
| crates/ramflux-sdk/src/bus/dispatch/group.rs:686 | `&key` |
| crates/ramflux-sdk/src/bus/dispatch/grant_mcp.rs:162 | `&format!("mcp/denied/{}"` |
| crates/ramflux-sdk/src/bus/shared_group_sync/recovery.rs:61 | `PROGRESS` |
| crates/ramflux-sdk/src/bus/shared_group_sync/recovery.rs:67 | `PROGRESS` |
| crates/ramflux-sdk/src/bus/shared_group_sync/outbox.rs:184 | `&proof_key(&state.snapshot().state_hash)` |
| crates/ramflux-sdk/src/bus/shared_group_sync/outbox.rs:188 | `&boundary_key(&state.view().group_id)` |
| crates/ramflux-sdk/src/bus/shared_group_sync/outbox.rs:316 | `&id` |
| crates/ramflux-sdk/src/bus/shared_group_sync/outbox.rs:337 | `DRIVER_PROGRESS` |
| crates/ramflux-sdk/src/bus/shared_group_sync/outbox.rs:363 | `&id` |
| crates/ramflux-sdk/src/bus/shared_group_sync/outbox.rs:454 | `&key(&intent.snapshot.group_id)` |
| crates/ramflux-sdk/src/bus/shared_group_sync/outbox.rs:476 | `&delivered_key(&intent.snapshot.group_id)` |
| crates/ramflux-sdk/src/bus/shared_group_sync/requests.rs:58 | `"group-courier/cursor"` |
| crates/ramflux-sdk/src/bus/shared_group_sync/requests.rs:147 | `&active_key(id)` |
| crates/ramflux-sdk/src/bus/shared_group_sync/requests.rs:195 | `&root_cursor_key` |
| crates/ramflux-sdk/src/bus/shared_group_sync/requests.rs:299 | `&id` |
| crates/ramflux-sdk/src/bus/shared_group_sync/requests.rs:341 | `id` |
| crates/ramflux-sdk/src/bus/shared_group_sync/requests.rs:347 | `id` |
| crates/ramflux-sdk/src/bus/shared_group_sync/requests.rs:419 | `&attempt.id` |
| crates/ramflux-sdk/src/bus/shared_group_sync/requests.rs:423 | `&attempt.id` |
| crates/ramflux-sdk/src/bus/shared_group_sync/requests.rs:436 | `&id` |
| crates/ramflux-sdk/src/bus/shared_group_sync/requests.rs:518 | `"group-courier/process-cursor"` |
| crates/ramflux-sdk/src/bus/account_runtime/readers.rs:27 | `"sync/node-id"` |
| crates/ramflux-sdk/src/bus/account_runtime/directory.rs:118 | `"own-contact/last-refresh"` |
| crates/ramflux-sdk/src/bus/push_receiver/erase_support.rs:40 | `&format!("attachment/reference/{alias}")` |
| crates/ramflux-sdk/src/bus/push_receiver/erase_support.rs:46 | `&slot` |
| crates/ramflux-sdk/src/bus/push_receiver/apply_w1_real_own_copy.rs:214 | `"fixture/direct-conversation"` |
| crates/ramflux-sdk/src/bus/push_receiver/apply_w1_real_own_copy.rs:353 | `&format!("attachment/reference/{alias}")` |
| crates/ramflux-sdk/src/bus/push_receiver/apply_w1_real_own_copy.rs:359 | `&slot` |
| crates/ramflux-sdk/src/bus/push_receiver/compat.rs:309 | `&suspend_key(target` |
| crates/ramflux-sdk/src/bus/delivery_receipts/background.rs:218 | `&key` |
| crates/ramflux-sdk/src/bus/delivery_receipts/background.rs:234 | `SCAN_CURSOR` |
| crates/ramflux-sdk/src/bus/delivery_receipts/background.rs:282 | `&plan.key` |
| crates/ramflux-sdk/src/bus/delivery_receipts/background.rs:312 | `&plan.key` |
| crates/ramflux-sdk/src/bus/delivery_receipts/background.rs:313 | `SCAN_CURSOR` |
| crates/ramflux-sdk/src/bus/delivery_receipts/background.rs:355 | `GATEWAY_RETRY_AT` |
| crates/ramflux-sdk/src/bus/delivery_receipts/background.rs:426 | `&key` |
| crates/ramflux-sdk/src/bus/delivery_receipts/background.rs:431 | `&key` |
| crates/ramflux-sdk/src/bus/delivery_receipts/background.rs:435 | `&key` |
| crates/ramflux-sdk/src/bus/shared_group_sync/outbox/background.rs:162 | `DRIVER_PROGRESS` |
| crates/ramflux-sdk/src/bus/shared_group_sync/outbox/background.rs:404 | `&delivered_key(&plan.intent.snapshot.group_id)` |
| crates/ramflux-sdk/src/bus/shared_group_sync/requests/background.rs:128 | `&root_cursor_key(&captured.id)` |
| crates/ramflux-sdk/src/bus/shared_group_sync/requests/background.rs:245 | `"group-courier/cursor"` |
| crates/ramflux-sdk/src/bus/shared_group_sync/requests/background.rs:479 | `&active_key(&plan.id)` |
| crates/ramflux-sdk/src/bus/shared_group_sync/requests/background.rs:555 | `"group-courier/process-cursor"` |
| crates/ramflux-sdk/src/bus/dispatch/surface_own_tests/followups.rs:22 | `&key` |
| crates/ramflux-sdk/src/bus/dispatch/surface_own_tests/followups.rs:178 | `&key` |
| crates/ramflux-sdk/src/bus/dispatch/surface_own_tests/followups.rs:193 | `&key` |
| crates/ramflux-sdk/src/bus/dispatch/surface_own_tests/followups.rs:418 | `&format!("own-device/committed-packet/budget-{i:05}")` |
| crates/ramflux-sdk/src/bus/dispatch/surface_own_tests/retry.rs:78 | `&key` |

// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use ramflux_crypto::{
    FIXTURE_SIGNING_KEY_ID, FrankingCommitmentInput, event_id, franking_commitment,
    sign_canonical_bytes,
};
use ramflux_protocol::{
    FIXTURE_OBJECTS, FixtureObject, domain, fixture_canonical_path, fixture_hash_path,
    fixture_invalid_signature_path, fixture_json_path, fixture_replay_path, fixture_sig_path,
    hash_hex, signed_value,
};
use serde_json::{Value, json};
use std::fs;
use std::path::{Path, PathBuf};

#[test]
fn generate_protocol_fixtures() -> Result<(), Box<dyn std::error::Error>> {
    let protocol_root = Path::new("../ramflux-protocol");
    for object in FIXTURE_OBJECTS {
        let fixture = fixture_value(object);
        write_fixture(protocol_root, object, fixture)?;
    }
    Ok(())
}

fn write_fixture(
    protocol_root: &Path,
    object: FixtureObject,
    mut value: Value,
) -> Result<(), Box<dyn std::error::Error>> {
    if object.signed {
        set_field(&mut value, "signing_key_id", Value::String(FIXTURE_SIGNING_KEY_ID.to_owned()))?;
        set_field(&mut value, "signature_alg", Value::String("ed25519".to_owned()))?;
    }

    let canonical = fixture_signed_bytes(object, &value)?;
    let signature = sign_canonical_bytes(&canonical);

    if object.signed {
        set_field(&mut value, "signature", Value::String(signature.clone()))?;
    }

    let object_dir = protocol_root.join(format!("fixtures/protocol/v1/{}", object.dir));
    fs::create_dir_all(&object_dir)?;

    fs::write(
        protocol_root.join(fixture_json_path(object)),
        serde_json::to_string_pretty(&value)?,
    )?;
    fs::write(protocol_root.join(fixture_canonical_path(object)), &canonical)?;
    fs::write(protocol_root.join(fixture_hash_path(object)), hash_hex(object.domain, &canonical))?;
    fs::write(protocol_root.join(fixture_sig_path(object)), signature)?;

    let mut invalid_signature = value.clone();
    if object.signed {
        set_field(&mut invalid_signature, "signature", Value::String(invalid_signature_value()))?;
    }
    fs::write(
        protocol_root.join(fixture_invalid_signature_path(object)),
        serde_json::to_string_pretty(&invalid_signature)?,
    )?;
    fs::write(
        protocol_root.join(fixture_replay_path(object)),
        serde_json::to_string_pretty(&value)?,
    )?;
    Ok(())
}

fn set_field(value: &mut Value, key: &str, field_value: Value) -> Result<(), String> {
    let object =
        value.as_object_mut().ok_or_else(|| "fixture value must be a JSON object".to_owned())?;
    object.insert(key.to_owned(), field_value);
    Ok(())
}

fn invalid_signature_value() -> String {
    ramflux_protocol::encode_base64url([0_u8; 64])
}

fn b64(input: &str) -> String {
    ramflux_protocol::encode_base64url(input.as_bytes())
}

// MVP fixture generation is intentionally table-shaped until schema fixtures split per object.
// Review after MVP-0 fixture schemas are moved into per-object builders.
#[allow(clippy::too_many_lines)]
fn fixture_value(object: FixtureObject) -> Value {
    match object.dir {
        "envelope" => json!({
            "schema": domain::ENVELOPE,
            "version": 1,
            "domain": domain::ENVELOPE,
            "envelope_id": "env_01",
            "source_principal_id": "opaque_id_a",
            "source_device_id": "dev_a",
            "target_delivery_id": "deliv_b",
            "routing_set_id": "route_epoch_08",
            "delivery_class": "opaque_event",
            "priority": "normal",
            "ttl": 604_800,
            "created_at": 1_760_000_000,
            "encrypted_payload": b64("encrypted-envelope-payload"),
            "payload_hash": b64("payload-hash")
        }),
        "signed_request" => json!({
            "schema": domain::SIGNED_REQUEST,
            "version": 1,
            "domain": domain::SIGNED_REQUEST,
            "source_device_id": "dev_a",
            "request_id": "req_01",
            "method": "POST",
            "path": "/client/v1/envelope",
            "device_proof_hash": b64("device-proof-hash"),
            "body_hash": b64("body-hash"),
            "nonce": b64("request-nonce"),
            "created_at": 1_760_000_000,
            "expires_at": 1_760_000_060
        }),
        "device_proof" => json!({
            "schema": domain::DEVICE_PROOF,
            "version": 1,
            "domain": domain::DEVICE_PROOF,
            "principal_id": "id_a",
            "device_id": "dev_a",
            "device_epoch": 1,
            "branch_proof_hash": b64("branch-proof-hash"),
            "capability_scope": ["delivery.send"],
            "nonce": b64("device-proof-nonce"),
            "expires_at": 1_760_000_060
        }),
        "branch_proof" => json!({
            "schema": domain::BRANCH_PROOF,
            "version": 1,
            "domain": domain::BRANCH_PROOF,
            "proof_id": "bp_01",
            "principal_id": "id_a",
            "device_id": "dev_a",
            "device_epoch": 1,
            "lineage_head": "lin_01",
            "audience": "node",
            "capability_scope": ["delivery.send"],
            "issued_at": 1_760_000_000,
            "expires_at": 1_760_000_060
        }),
        "home_node_migration_proof" => json!({
            "schema": domain::HOME_NODE_MIGRATION_PROOF,
            "domain": domain::HOME_NODE_MIGRATION_PROOF,
            "proof_id": "mig_01",
            "identity_commitment": "id_a",
            "lineage_head": "lin_01",
            "actor_device_id": "dev_a",
            "actor_device_epoch": 7,
            "old_home_node": "node_a.example",
            "new_home_node": "node_c.example",
            "new_home_node_key_hash": b64("new-node-key-hash"),
            "route_record_hash": b64("route-record-hash"),
            "effective_at": 1_760_000_000,
            "expires_at": 1_762_592_000,
            "issued_at": 1_759_999_900,
            "nonce": b64("migration-nonce"),
            "branch_proof_hash": b64("branch-proof-hash"),
            "previous_home_node_binding_hash": b64("old-binding-hash")
        }),
        "identity_deletion_proof" => json!({
            "schema": domain::IDENTITY_DELETION_PROOF,
            "version": 1,
            "domain": domain::IDENTITY_DELETION_PROOF,
            "proof_id": "del_01",
            "identity_commitment": "id_a",
            "lifecycle_epoch": 4,
            "identity_deleted_event_id": "evt_delete_01",
            "identity_lifecycle_tombstone_hash": b64("tombstone-hash"),
            "deletion_scope": ["cursor_ack_state", "opaque_device_inbox", "push_alias"],
            "deleted_metadata_hash": b64("deleted-metadata-hash"),
            "retained_summary_hash": b64("retained-summary-hash"),
            "retention_policy_id": "retention_default_v1",
            "legal_hold_ids": [],
            "node_id": "node_a.example",
            "node_epoch": 2,
            "finalized_at": 1_760_086_400,
            "completed_at": 1_760_086_460,
            "nonce": b64("deletion-nonce")
        }),
        "ack" => json!({
            "schema": domain::ACK,
            "version": 1,
            "domain": domain::ACK,
            "ack_id": "ack_01",
            "envelope_id": "env_01",
            "receiver_device_id": "dev_b",
            "received_at": 1_760_000_001,
            "cursor_after": "cur_01"
        }),
        "nack" => json!({
            "schema": domain::NACK,
            "version": 1,
            "domain": domain::NACK,
            "nack_id": "nack_01",
            "envelope_id": "env_01",
            "receiver_device_id": "dev_b",
            "reason": "home_node_migrated",
            "received_at": 1_760_000_001
        }),
        "cursor" => json!({
            "schema": domain::CURSOR,
            "version": 1,
            "domain": domain::CURSOR,
            "cursor_id": "cur_01",
            "principal_id": "id_b",
            "device_id": "dev_b",
            "inbox_seq": 42,
            "last_envelope_id": "env_01",
            "acked_event_ids": ["evt_msg_01"],
            "pending_event_ids": [],
            "lamport_time": 7
        }),
        "event_id" => {
            let nonce = b"event-id-nonce-0001";
            json!({
                "domain": domain::EVENT,
                "actor_device_id": "dev_a",
                "device_counter": 1,
                "random_nonce": ramflux_protocol::encode_base64url(nonce),
                "event_id": event_id("dev_a", 1, nonce)
            })
        }
        "identity_event" => json!({
            "schema": domain::IDENTITY_EVENT,
            "version": 1,
            "domain": domain::IDENTITY_EVENT,
            "event_id": "evt_id_01",
            "event_type": "identity.deactivated",
            "actor_principal_id": "id_a",
            "actor_device_id": "dev_a",
            "device_counter": 1,
            "lamport_time": 7,
            "created_at": 1_760_000_000,
            "body": {
                "identity_commitment": "id_a",
                "lifecycle_epoch": 3,
                "reason_code": "user_requested",
                "timelock_until": 1_760_086_400,
                "recovery_quorum_proof_hash": b64("recovery-quorum-proof")
            }
        }),
        "friend_event" => json!({
            "schema": domain::FRIEND_EVENT,
            "version": 1,
            "domain": domain::FRIEND_EVENT,
            "event_id": "evt_friend_01",
            "event_type": "friend.capability_revoked",
            "actor_principal_id": "id_a",
            "actor_device_id": "dev_a",
            "device_counter": 3,
            "lamport_time": 9,
            "created_at": 1_760_000_000,
            "body": {
                "link_id": "fl_01",
                "revoked_capability_id": "cap_01",
                "reason": "blocked",
                "effective_at": 1_760_000_000,
                "causal_event_id": "evt_friend_prev"
            }
        }),
        "group_event" => json!({
            "schema": domain::GROUP_EVENT,
            "version": 1,
            "domain": domain::GROUP_EVENT,
            "event_id": "evt_group_01",
            "event_type": "group.bot_joined",
            "actor_principal_id": "id_a",
            "actor_device_id": "dev_a",
            "device_counter": 4,
            "lamport_time": 10,
            "created_at": 1_760_000_000,
            "body": {
                "group_id": "grp_01",
                "previous_epoch": 7,
                "new_group_epoch": 8,
                "bot_identity": "bot_01",
                "granted_permissions": ["read.group_context"]
            }
        }),
        "conversation_event" => json!({
            "schema": domain::CONVERSATION_EVENT,
            "version": 1,
            "domain": domain::CONVERSATION_EVENT,
            "event_id": "evt_conv_01",
            "event_type": "conversation.disappearing_updated",
            "actor_principal_id": "id_a",
            "actor_device_id": "dev_a",
            "device_counter": 2,
            "lamport_time": 8,
            "created_at": 1_760_000_000,
            "body": {
                "conversation_id": "conv_01",
                "timer_seconds": 86400,
                "countdown_mode": "on_read",
                "scope": "conversation_members"
            }
        }),
        "message_event" => json!({
            "schema": domain::MESSAGE_EVENT,
            "version": 1,
            "domain": domain::MESSAGE_EVENT,
            "event_id": "evt_msg_01",
            "event_type": "message.created",
            "actor_principal_id": "id_a",
            "actor_device_id": "dev_a",
            "device_counter": 5,
            "lamport_time": 11,
            "created_at": 1_760_000_000,
            "body": {
                "conversation_id": "conv_01",
                "message_id": "msg_01",
                "encrypted_body": b64("message-ciphertext"),
                "object_refs": [],
                "reply_to": {"message_id": "msg_prev", "quoted_cipher": b64("quoted-cipher")},
                "mentions": ["id_b_commitment"],
                "forwarded_from": {"source_message_id_hash": b64("source-message-id")},
                "forward_count": 1
            }
        }),
        "object_manifest" => json!({
            "schema": domain::OBJECT_MANIFEST,
            "version": 1,
            "domain": domain::OBJECT_MANIFEST,
            "object_id": "obj_01",
            "encrypted_owner_ref": b64("owner-ref"),
            "encrypted_relation_ref": b64("relation-ref"),
            "encrypted_metadata": b64("metadata"),
            "object_key_slots": [],
            "object_created_group_key_epoch": 8,
            "chunk_manifest_hash": b64("chunk-manifest-hash"),
            "chunk_count": 2,
            "total_cipher_size": 2048
        }),
        "object_chunk_request" => json!({
            "schema": domain::OBJECT_CHUNK_REQUEST,
            "version": 1,
            "domain": domain::OBJECT_CHUNK_REQUEST,
            "request_id": "ocr_01",
            "object_id": "obj_01",
            "manifest_hash": b64("manifest-hash"),
            "missing_chunk_bitmap": b64("bitmap"),
            "resume_token": "resume_01",
            "max_chunks": 32
        }),
        "a2i_control" => json!({
            "schema": domain::A2I_CONTROL,
            "version": 1,
            "domain": domain::A2I_CONTROL,
            "event_type": "a2i.control",
            "control_domain": "mcp_tool",
            "action": "request_approval",
            "subject": {"tool": "send_message"},
            "correlation_id": "corr_01",
            "source_device_id": "dev_app",
            "target_device_id": "dev_cli"
        }),
        "a2ui_surface" => json!({
            "schema": domain::A2UI_SURFACE,
            "version": 1,
            "domain": domain::A2UI_SURFACE,
            "event_type": "ramflux.a2ui.surface",
            "surface_id": "surf_01",
            "a2ui_profile": "ramflux.a2ui.v1",
            "a2ui_profile_version": 1,
            "upstream_a2ui_version": "0.9.1",
            "catalog_id": "ramflux.basic.v1",
            "catalog_version": "1.0.0",
            "surface_hash": b64("surface-hash"),
            "source_device_id": "dev_cli",
            "target_device_id": "dev_app",
            "correlation_id": "corr_01",
            "encrypted_surface_payload": b64("a2ui-payload")
        }),
        "mcp_grant" => json!({
            "schema": domain::MCP_GRANT,
            "version": 1,
            "domain": domain::MCP_GRANT,
            "grant_id": "grant_01",
            "principal_id": "id_a",
            "source_app_device_id": "dev_app",
            "target_ai_device_id": "dev_cli",
            "capability": "send_message",
            "risk_level": "medium",
            "expires_at": 1_760_003_600
        }),
        "bot_manifest" => json!({
            "schema": domain::BOT_MANIFEST,
            "version": 1,
            "domain": domain::BOT_MANIFEST,
            "bot_identity_commitment": "bot_idc_01",
            "actor_type": "bot",
            "display_name": "Deploy Bot",
            "manifest_version": "1.0.0",
            "home_node": "bots.example.com",
            "capabilities": ["message:send", "a2ui:render", "call:tool:ci.deploy"],
            "permissions": ["conversation:read:mentioned_context", "call:tool:ci.deploy"],
            "owner_identity_commitment": "id_owner",
            "hosting_model": "federated",
            "a2ui_profiles": ["ramflux.a2ui.v1"],
            "safety_disclosure": {
                "disclosure_version": 1,
                "disclosure_text": "This hosted bot operator can read messages sent to the bot and group messages made visible to it.",
                "hosting_model": "federated",
                "key_custody_class": "federated_operator_key",
                "operator_identity_commitment": "id_operator",
                "operator_display_name": "Example Bot Operator",
                "can_read_dm_plaintext": true,
                "can_read_group_messages_when_member": true,
                "disclosure_hash": b64("disclosure-hash")
            },
            "created_at": 1_760_000_000,
            "signature_by_bot_identity": b64("bot-signature")
        }),
        "bot_event" => json!({
            "schema": domain::BOT_EVENT,
            "version": 1,
            "domain": domain::BOT_EVENT,
            "event_id": "evt_bot_01",
            "event_type": "bot.install_approved",
            "actor_principal_id": "id_a",
            "actor_device_id": "dev_a",
            "device_counter": 6,
            "lamport_time": 12,
            "created_at": 1_760_000_000,
            "body": {
                "bot_identity_commitment": "bot_idc_01",
                "bot_manifest_hash": b64("bot-manifest-hash"),
                "bot_install_grant_hash": b64("bot-install-grant-hash")
            }
        }),
        "bot_install_grant" => json!({
            "schema": domain::BOT_INSTALL_GRANT,
            "version": 1,
            "domain": domain::BOT_INSTALL_GRANT,
            "grant_id": "big_01",
            "bot_identity_commitment": "bot_idc_01",
            "bot_manifest_hash": b64("bot-manifest-hash"),
            "installer_identity": "id_a",
            "installer_device_id": "dev_a",
            "scope": ["conversation:read:mentioned_context", "call:tool:ci.deploy"],
            "group_id": "grp_01",
            "expires_at": 1_760_003_600,
            "signature_by_installer_device": b64("installer-signature")
        }),
        "notification_wake" => json!({
            "schema": domain::NOTIFICATION_WAKE,
            "version": 1,
            "domain": domain::NOTIFICATION_WAKE,
            "wake_id": "wake_01",
            "push_alias": "push_alias_01",
            "delivery_class": "self_device_control_notification",
            "priority": "high",
            "ttl": 60
        }),
        "federation_handshake" => json!({
            "schema": domain::FEDERATION_HANDSHAKE,
            "version": 1,
            "domain": domain::FEDERATION_HANDSHAKE,
            "handshake_id": "fh_01",
            "source_node_id": "node_a",
            "target_node_id": "node_b",
            "source_capabilities": ["opaque_delivery"],
            "protocol_versions": ["v1"],
            "transport_backends": ["quic_quinn"],
            "trust_state_hash": b64("trust-state-hash"),
            "nonce": b64("federation-nonce"),
            "created_at": 1_760_000_000
        }),
        "franking_commitment" => {
            let input = FrankingCommitmentInput {
                plaintext: b"fixture plaintext",
                sender_device_id_hash: b"sender-device-hash",
                message_event_id: "evt_msg_01",
                canonical_header_bytes: br#"{"header":"fixture"}"#,
                associated_data: b"associated-data",
                ciphertext: b"ciphertext",
                opening_key: &[0x21; 32],
                commitment_key: &[0x42; 32],
            };
            let commitment = franking_commitment(&input);
            json!({
                "schema": domain::COMMITTING_AEAD,
                "version": 1,
                "domain": domain::COMMITTING_AEAD,
                "plaintext_hash": commitment.plaintext_hash,
                "ciphertext_hash": commitment.ciphertext_hash,
                "header_hash": commitment.header_hash,
                "associated_data_hash": commitment.associated_data_hash,
                "key_commitment": commitment.key_commitment,
                "franking_commitment": commitment.franking_commitment,
                "commitment": commitment.commitment
            })
        }
        _ => json!({}),
    }
}

fn fixture_signed_bytes(
    object: FixtureObject,
    value: &Value,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    if object.dir == "home_node_migration_proof" {
        let mut value = value.clone();
        set_field(&mut value, "signature", Value::String(String::new()))?;
        let proof: ramflux_protocol::HomeNodeMigrationProof = serde_json::from_value(value)?;
        return Ok(ramflux_protocol::home_node_migration_proof_signed_bytes(&proof)?);
    }
    let canonical_value = signed_value(value)?;
    Ok(ramflux_protocol::canonical_json_bytes(&canonical_value)?)
}

#[allow(dead_code)]
fn fixture_path(protocol_root: &Path, object: FixtureObject, file_name: &str) -> PathBuf {
    protocol_root.join("fixtures/protocol/v1").join(object.dir).join(file_name)
}

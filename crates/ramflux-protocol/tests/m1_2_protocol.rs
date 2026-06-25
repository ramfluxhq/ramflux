// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain
use ed25519_dalek::SigningKey;
use ramflux_protocol::{
    A2uiCommand, CreateSurfaceCommand, CursorState, DeleteSurfaceCommand, DeleteSurfaceReason,
    EventOrderingState, FIXTURE_OBJECTS, HeaderField, HeaderKind, McpCapability, ProtocolError,
    ReplayGuard, RiskLevel, SignedRequest, SurfaceType, UpdateComponentsCommand,
    UpdateDataModelCommand, canonical_header_bytes, canonical_json_bytes, decode_base64url,
    event_sort_key, fixture_canonical_path, fixture_hash_path, fixture_invalid_signature_path,
    fixture_json_path, fixture_replay_path, fixture_sig_path, hash_hex, header_hash_base64url,
    parse_fixture_value, signed_value, surface_hash, verify_canonical_signature,
    verify_json_signature,
};
use serde_json::{Value, json};
use std::fs;
use std::path::{Path, PathBuf};

const FIXTURE_SIGNING_KEY_BYTES: [u8; 32] = [
    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00,
    0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0x90, 0xa0, 0xb0, 0xc0, 0xd0, 0xe0, 0xf0, 0x01,
];

#[test]
fn signed_fixtures_verify_and_invalid_signatures_reject() -> Result<(), Box<dyn std::error::Error>>
{
    let root = fixture_root();
    let public_key = fixture_public_key_base64url();

    for object in FIXTURE_OBJECTS {
        let json_path = root.join(fixture_json_path(object));
        let fixture = read_json(&json_path)?;
        parse_fixture_value(object, fixture.clone())?;

        let canonical = canonical_json_bytes(&signed_value(&fixture)?)?;
        let expected_canonical = fs::read(root.join(fixture_canonical_path(object)))?;
        assert_eq!(canonical, expected_canonical, "canonical mismatch for {}", object.dir);

        let expected_hash = fs::read_to_string(root.join(fixture_hash_path(object)))?;
        assert_eq!(hash_hex(object.domain, &canonical), expected_hash, "hash mismatch");

        let fixture_sig = fs::read_to_string(root.join(fixture_sig_path(object)))?;
        if object.signed {
            let json_sig = required_str(&fixture, "signature")?;
            assert_eq!(json_sig, fixture_sig, "fixture.sig mismatch for {}", object.dir);
            verify_json_signature(&fixture, &public_key)?;
            verify_canonical_signature(&canonical, &fixture_sig, &public_key)?;

            let invalid = read_json(&root.join(fixture_invalid_signature_path(object)))?;
            assert!(
                verify_json_signature(&invalid, &public_key).is_err(),
                "invalid signature accepted for {}",
                object.dir
            );
        }
    }
    Ok(())
}

#[test]
fn signed_request_replay_guard_enforces_m1_1_window() -> Result<(), Box<dyn std::error::Error>> {
    let root = fixture_root();
    let signed_request_fixture = fixture_object("signed_request")?;
    let fixture = read_json(&root.join(fixture_json_path(signed_request_fixture)))?;
    let request: SignedRequest = serde_json::from_value(fixture)?;
    let mut guard = ReplayGuard::new();

    guard.check_signed_request(&request, request.created_at + 1)?;
    assert!(matches!(
        guard.check_signed_request(&request, request.created_at + 2),
        Err(ProtocolError::Replay(_))
    ));

    let replay_fixture = read_json(&root.join(fixture_replay_path(signed_request_fixture)))?;
    let replay_request: SignedRequest = serde_json::from_value(replay_fixture)?;
    assert!(matches!(
        ReplayGuard::new().check_signed_request(&replay_request, replay_request.created_at + 901),
        Err(ProtocolError::SignedRequestExpired)
    ));

    let mut long_validity = request.clone();
    long_validity.request_id = "fixture-request-long-validity".to_owned();
    long_validity.expires_at = long_validity.created_at + 3_600;
    let mut long_guard = ReplayGuard::new();
    long_guard.check_signed_request(&long_validity, long_validity.created_at + 901)?;
    assert!(matches!(
        long_guard.check_signed_request(&long_validity, long_validity.created_at + 902),
        Err(ProtocolError::Replay(_))
    ));

    let mut too_long = request;
    too_long.request_id = "fixture-request-too-long".to_owned();
    too_long.expires_at = too_long.created_at + ramflux_protocol::MAX_ENVELOPE_TTL_SECONDS + 1;
    assert!(matches!(
        ReplayGuard::new().check_signed_request(&too_long, too_long.created_at),
        Err(ProtocolError::SignedRequestExpiryTooLong)
    ));
    Ok(())
}

#[test]
fn rfh1_header_hash_is_reproducible() -> Result<(), Box<dyn std::error::Error>> {
    let device_hash = [0x11; 32];
    let recipient_hash = [0x22; 32];
    let public_key = [0x33; 32];
    let dm_fields = [
        HeaderField::string(1, "ratchet_01"),
        HeaderField::bytes32(2, device_hash),
        HeaderField::bytes32(3, recipient_hash),
        HeaderField::bytes32(4, public_key),
        HeaderField::u64(5, 7),
        HeaderField::u64(6, 8),
        HeaderField::u64(7, 9),
        HeaderField::string(8, "evt_msg_01"),
    ];

    let first = canonical_header_bytes(HeaderKind::DmMessage, &dm_fields)?;
    let second = canonical_header_bytes(HeaderKind::DmMessage, &dm_fields)?;
    assert_eq!(first, second);
    assert_eq!(&first[..4], b"RFH1");
    assert_eq!(first[4], HeaderKind::DmMessage as u8);
    assert_eq!(first[5], 1);
    assert_eq!(u16::from_be_bytes([first[6], first[7]]), 8);

    let first_hash = header_hash_base64url(HeaderKind::DmMessage, &dm_fields)?;
    let second_hash = header_hash_base64url(HeaderKind::DmMessage, &dm_fields)?;
    assert_eq!(first_hash, second_hash);
    assert_eq!(decode_base64url(&first_hash)?.len(), 32);
    Ok(())
}

#[test]
fn mcp_capability_default_risk_matrix_is_canonical() {
    assert_eq!(McpCapability::ReadConversation.default_risk(), RiskLevel::Low);
    assert_eq!(McpCapability::DraftMessage.default_risk(), RiskLevel::Low);
    assert_eq!(McpCapability::SendMessage.default_risk(), RiskLevel::Medium);
    assert_eq!(McpCapability::ReadLocalFiles.default_risk(), RiskLevel::Low);
    assert_eq!(McpCapability::WriteLocalFiles.default_risk(), RiskLevel::High);
    assert_eq!(McpCapability::RunShell.default_risk(), RiskLevel::High);
    assert_eq!(McpCapability::ManageContacts.default_risk(), RiskLevel::Medium);
    assert_eq!(McpCapability::ManageGroup.default_risk(), RiskLevel::Medium);
    assert_eq!(McpCapability::ManageMedia.default_risk(), RiskLevel::High);
    assert_eq!(McpCapability::ManageNode.default_risk(), RiskLevel::High);
    assert_eq!(McpCapability::ExternalToolInvoke.default_risk(), RiskLevel::High);
}

#[test]
fn a2ui_commands_and_surface_hash_are_canonical() -> Result<(), Box<dyn std::error::Error>> {
    let mut data_model = serde_json::Map::new();
    data_model.insert("status".to_owned(), Value::String("pending".to_owned()));
    let create = A2uiCommand::CreateSurface(CreateSurfaceCommand {
        surface_id: "surf_01".to_owned(),
        surface_type: SurfaceType::ApprovalCard,
        catalog: "ramflux.basic.v1".to_owned(),
        catalog_version: "1.0.0".to_owned(),
        fallback_text: "Approve request".to_owned(),
        fallback_markdown: None,
        components: vec![json!({"id":"approve","kind":"button"})],
        data_model,
        allowed_actions: vec![json!({"name":"approve"})],
    });
    let update_components = A2uiCommand::UpdateComponents(UpdateComponentsCommand {
        surface_id: "surf_01".to_owned(),
        base_surface_hash: "base".to_owned(),
        components: vec![json!({"id":"deny","kind":"button"})],
        remove_component_ids: vec!["approve".to_owned()],
        new_surface_hash: "new".to_owned(),
    });
    let mut patch = serde_json::Map::new();
    patch.insert("status".to_owned(), Value::String("done".to_owned()));
    let update_data = A2uiCommand::UpdateDataModel(UpdateDataModelCommand {
        surface_id: "surf_01".to_owned(),
        base_surface_hash: "base".to_owned(),
        data_patch: patch,
        new_surface_hash: "new".to_owned(),
    });
    let delete = A2uiCommand::DeleteSurface(DeleteSurfaceCommand {
        surface_id: "surf_01".to_owned(),
        reason: Some(DeleteSurfaceReason::Completed),
    });

    for command in [create, update_components, update_data, delete] {
        let canonical = canonical_json_bytes(&command)?;
        assert!(!canonical.is_empty());
    }

    let with_hash = json!({"surfaceId":"surf_01","surface_hash":"ignored","components":[]});
    let without_hash = json!({"surfaceId":"surf_01","components":[]});
    assert_eq!(surface_hash(&with_hash)?, surface_hash(&without_hash)?);
    Ok(())
}

#[test]
fn cursor_and_epoch_states_roundtrip() -> Result<(), Box<dyn std::error::Error>> {
    assert_eq!(
        serde_json::to_string(&CursorState::PendingUnknownEpoch)?,
        "\"pending_unknown_epoch\""
    );
    assert_eq!(
        serde_json::to_string(&EventOrderingState::RejectedEpochRollback)?,
        "\"rejected_epoch_rollback\""
    );

    let root = fixture_root();
    let group_fixture = fixture_object("group_event")?;
    let fixture = read_json(&root.join(fixture_json_path(group_fixture)))?;
    let event: ramflux_protocol::GroupEvent = serde_json::from_value(fixture)?;
    let key = event_sort_key(&event);
    assert_eq!(key.lamport_time, 10);
    assert_eq!(key.actor_device_id, "dev_a");
    assert_eq!(key.event_id, "evt_group_01");
    Ok(())
}

fn fixture_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).to_path_buf()
}

fn fixture_object(dir: &'static str) -> Result<ramflux_protocol::FixtureObject, ProtocolError> {
    FIXTURE_OBJECTS
        .iter()
        .copied()
        .find(|object| object.dir == dir)
        .ok_or(ProtocolError::MissingReplayKey)
}

fn read_json(path: &Path) -> Result<Value, Box<dyn std::error::Error>> {
    let bytes = fs::read(path)?;
    Ok(serde_json::from_slice(&bytes)?)
}

fn required_str<'a>(value: &'a Value, field: &'static str) -> Result<&'a str, ProtocolError> {
    value.get(field).and_then(Value::as_str).ok_or(ProtocolError::MissingSignatureField(field))
}

fn fixture_public_key_base64url() -> String {
    let signing_key = SigningKey::from_bytes(&FIXTURE_SIGNING_KEY_BYTES);
    ramflux_protocol::encode_base64url(signing_key.verifying_key().to_bytes())
}

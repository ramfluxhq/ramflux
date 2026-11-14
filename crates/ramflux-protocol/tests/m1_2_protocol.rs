// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use ed25519_dalek::SigningKey;
use ramflux_protocol::{
    CursorState, EventOrderingState, FIXTURE_OBJECTS, HeaderField, HeaderKind, McpCapability,
    ProtocolError, ReplayGuard, RiskLevel, SignedRequest, canonical_header_bytes,
    canonical_json_bytes, decode_base64url, event_sort_key, fixture_canonical_path,
    fixture_hash_path, fixture_invalid_signature_path, fixture_json_path, fixture_replay_path,
    fixture_sig_path, hash_hex, header_hash_base64url, home_node_migration_proof_signed_bytes,
    parse_fixture_value, signed_value, verify_canonical_signature, verify_json_signature,
};
use serde_json::{Value, json};
use std::fs;
use std::path::{Path, PathBuf};

struct ReplaySource<'a>(&'a str);
impl ramflux_protocol::RootQualifiedDeviceIdentity for ReplaySource<'_> {
    fn root_commitment(&self) -> &'static str {
        "protocol-test-root"
    }
    fn device_id(&self) -> &str {
        self.0
    }
}

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

        let canonical = fixture_signed_bytes(object, &fixture)?;
        let expected_canonical = fs::read(root.join(fixture_canonical_path(object)))?;
        assert_eq!(canonical, expected_canonical, "canonical mismatch for {}", object.dir);

        let expected_hash = fs::read_to_string(root.join(fixture_hash_path(object)))?;
        assert_eq!(hash_hex(object.domain, &canonical), expected_hash, "hash mismatch");

        let fixture_sig = fs::read_to_string(root.join(fixture_sig_path(object)))?;
        if object.signed {
            let json_sig = required_str(&fixture, "signature")?;
            assert_eq!(json_sig, fixture_sig, "fixture.sig mismatch for {}", object.dir);
            if object.dir == "home_node_migration_proof" {
                verify_canonical_signature(&canonical, json_sig, &public_key)?;
            } else {
                verify_json_signature(&fixture, &public_key)?;
            }
            verify_canonical_signature(&canonical, &fixture_sig, &public_key)?;

            let invalid = read_json(&root.join(fixture_invalid_signature_path(object)))?;
            let invalid_signature = required_str(&invalid, "signature")?;
            assert!(
                verify_canonical_signature(&canonical, invalid_signature, &public_key).is_err(),
                "invalid signature accepted for {}",
                object.dir
            );
        }
    }
    Ok(())
}

fn fixture_signed_bytes(
    object: ramflux_protocol::FixtureObject,
    value: &Value,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    if object.dir == "home_node_migration_proof" {
        let proof: ramflux_protocol::HomeNodeMigrationProof =
            serde_json::from_value(value.clone())?;
        return Ok(home_node_migration_proof_signed_bytes(&proof)?);
    }
    Ok(canonical_json_bytes(&signed_value(value)?)?)
}

#[test]
fn signed_request_replay_guard_enforces_m1_1_window() -> Result<(), Box<dyn std::error::Error>> {
    let root = fixture_root();
    let signed_request_fixture = fixture_object("signed_request")?;
    let fixture = read_json(&root.join(fixture_json_path(signed_request_fixture)))?;
    let request: SignedRequest = serde_json::from_value(fixture)?;
    let mut guard = ReplayGuard::new();

    guard.check_signed_request(
        &ReplaySource(&request.source_device_id),
        &request,
        request.created_at + 1,
    )?;
    assert!(matches!(
        guard.check_signed_request(
            &ReplaySource(&request.source_device_id),
            &request,
            request.created_at + 2
        ),
        Err(ProtocolError::Replay(_))
    ));

    let replay_fixture = read_json(&root.join(fixture_replay_path(signed_request_fixture)))?;
    let replay_request: SignedRequest = serde_json::from_value(replay_fixture)?;
    assert!(matches!(
        ReplayGuard::new().check_signed_request(
            &ReplaySource(&replay_request.source_device_id),
            &replay_request,
            replay_request.created_at + 901
        ),
        Err(ProtocolError::SignedRequestExpired)
    ));

    let mut long_validity = request.clone();
    long_validity.request_id = "fixture-request-long-validity".to_owned();
    long_validity.expires_at = long_validity.created_at + 3_600;
    let mut long_guard = ReplayGuard::new();
    long_guard.check_signed_request(
        &ReplaySource(&long_validity.source_device_id),
        &long_validity,
        long_validity.created_at + 901,
    )?;
    assert!(matches!(
        long_guard.check_signed_request(
            &ReplaySource(&long_validity.source_device_id),
            &long_validity,
            long_validity.created_at + 902
        ),
        Err(ProtocolError::Replay(_))
    ));

    let mut too_long = request;
    too_long.request_id = "fixture-request-too-long".to_owned();
    too_long.expires_at = too_long.created_at + ramflux_protocol::MAX_ENVELOPE_TTL_SECONDS + 1;
    assert!(matches!(
        ReplayGuard::new().check_signed_request(
            &ReplaySource(&too_long.source_device_id),
            &too_long,
            too_long.created_at
        ),
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
fn surface_v3_independent_state_and_action_commitments() -> Result<(), Box<dyn std::error::Error>> {
    let create = include_bytes!("../fixtures/protocol/v1/a2ui_surface/create.event.json");
    let event = ramflux_protocol::SurfaceEvent::from_wire_bytes(create)?;
    let state = ramflux_protocol::SurfaceState::default().apply(&event)?;
    let expected = include_str!("../fixtures/protocol/v1/a2ui_surface/surface.hash").trim();
    assert_eq!(state.hash(), Some(expected), "state hash must match the independent Python oracle");
    let action = ramflux_protocol::SurfaceAction::from_wire_bytes(include_bytes!(
        "../fixtures/protocol/v1/a2ui_surface/submit.action.json"
    ))?;
    state.validate_action(&action)?;
    assert_eq!(state.version(), 1, "a raw-input submit must not consume a surface version");
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

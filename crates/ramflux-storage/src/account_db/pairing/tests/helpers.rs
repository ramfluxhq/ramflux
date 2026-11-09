// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use super::super::journal::{AdoptionRow, FloorRow, LiveRow};
use crate::StorageError;
use ramflux_protocol::custody::pairing::native::Invitation;
use ramflux_protocol::custody::pairing::{Common, PairingWire, RoleContext};
use ramflux_protocol::custody::{DeviceRef, Envelope};
use ramflux_protocol::{canonical_json_bytes, domain, encode_base64url};

pub(super) type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

pub(super) fn h(byte: u8) -> String {
    encode_base64url([byte; 32])
}

pub(super) fn device(id: &str) -> DeviceRef {
    DeviceRef { account_anchor: h(2), device_id: id.into(), device_epoch: 1 }
}

pub(super) fn ref_bytes(id: &str) -> TestResult<Vec<u8>> {
    Ok(canonical_json_bytes(&device(id))?)
}

pub(super) fn field_err(result: &Result<(), StorageError>, name: &'static str) {
    assert!(
        matches!(result, Err(StorageError::PairingField(got)) if *got == name),
        "{name}: {result:?}"
    );
}

pub(super) fn common() -> Common {
    Common {
        schema: "ramflux.pairing.Common.v2".into(),
        version: 2,
        invitation_id: h(1),
        issuer_seq: 1,
        account_anchor: h(2),
        master_public_key: h(3),
        record_hash: h(4),
        device_set_epoch: 1,
        principal_kind: "human".into(),
        sas_suite: domain::CUSTODY_PAIRING_EMOJI_SUITE.into(),
        hpke_suite: None,
        purpose: "enroll".into(),
        requested_role: "secondary".into(),
        recipient_mode: "new".into(),
        destination_ref: None,
        capabilities: vec!["message".into()],
        lease_not_before: 0,
        lease_expires_at: 300,
        expires_at: 400,
        transfer_id: None,
        data_selection: vec![],
    }
}

pub(super) fn invitation() -> Invitation {
    Invitation {
        schema: "ramflux.pairing.Invitation.v2".into(),
        version: 2,
        invitation_id: h(1),
        issuer_seq: 1,
        request_id: h(5),
        node_key: h(6),
        public_origin: "https://relay.example:443".into(),
        account_anchor: h(2),
        primary_ref: device("dev-a"),
        base_record_hash: h(4),
        base_epoch: 1,
        purpose: "enroll".into(),
        recipient_mode: "new".into(),
        destination_ref: None,
        capabilities: vec!["message".into()],
        lease_not_before: 0,
        lease_expires_at: 300,
        data_selection: vec![],
        transfer_id: None,
        created_at: 100,
        expires_at: 400,
    }
}

pub(super) fn descriptor() -> TestResult<Vec<u8>> {
    invitation().validate()?;
    let envelope = Envelope { body: invitation(), signature: encode_base64url([7; 64]) };
    Ok(canonical_json_bytes(&envelope)?)
}

pub(super) fn role(role: &str, id: &str) -> RoleContext {
    RoleContext {
        schema: "ramflux.pairing.RoleContext.v2".into(),
        version: 2,
        role: role.into(),
        common: common(),
        device_ref: device(id),
        branch_key: h(10),
        agreement_key: h(11),
        sas_key: h(12),
        hpke_key: None,
        display_name: "alice".into(),
    }
}

pub(super) fn context_bytes() -> TestResult<Vec<u8>> {
    #[derive(serde::Serialize)]
    struct LiveContext {
        initiator: RoleContext,
        responder: RoleContext,
    }
    let value = LiveContext {
        initiator: role("initiator", "dev-a"),
        responder: role("responder", "dev-b"),
    };
    value.initiator.validate()?;
    value.responder.validate()?;
    Ok(canonical_json_bytes(&value)?)
}

pub(super) fn invited() -> TestResult<LiveRow> {
    Ok(LiveRow {
        account_id: "acct".into(),
        operation_id: h(20),
        invitation_id: h(1),
        issuer_seq: 1,
        local_seq: 1,
        generation: 1,
        role: "initiator".into(),
        descriptor: descriptor()?,
        phase: "invited".into(),
        context: None,
        transcript_hash: None,
        proposal_hash: None,
        transfer_ciphertext_hash: None,
        candidate_id: None,
        branch_reservation: None,
        branch_vault_ref: None,
        primary_vault_ref: None,
        base_record_hash: h(4),
        base_epoch: 1,
        expires_at: 400,
        result: None,
    })
}

pub(super) fn floor() -> FloorRow {
    FloorRow { account_id: "acct".into(), account_anchor: h(2), issued_seq: 3, next_generation: 2 }
}

pub(super) fn adoption(role: &str, primary: Option<&str>) -> TestResult<AdoptionRow> {
    Ok(AdoptionRow {
        account_id: "acct".into(),
        operation_id: h(20),
        record_hash: h(4),
        local_ref: canonical_json_bytes(&device("dev-a"))?,
        local_role: role.into(),
        branch_vault_ref: "vault-branch".into(),
        data_vault_ref: "vault-data".into(),
        primary_vault_ref: primary.map(str::to_owned),
    })
}

// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use super::super::journal::{AdoptionRow, FloorRow, HeadRow, LiveRow, TerminalRow};
use crate::StorageError;
use ramflux_protocol::PrincipalKind;
use ramflux_protocol::custody::pairing::native::Invitation;
use ramflux_protocol::custody::pairing::{Common, PairingWire, RoleContext};
use ramflux_protocol::custody::{
    CustodyKind, DeviceRef, DeviceSet, Envelope, MasterCertificate, Profile, Publication,
    SectionHashes, object_hash,
};
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
    invited_ids(20, 1, 1)
}

pub(super) fn invited_ids(operation: u8, invitation_n: u8, local_seq: u64) -> TestResult<LiveRow> {
    let mut body = invitation();
    body.invitation_id = h(invitation_n);
    body.validate()?;
    let envelope = Envelope { body, signature: encode_base64url([7; 64]) };
    Ok(LiveRow {
        account_id: "acct".into(),
        operation_id: h(operation),
        invitation_id: h(invitation_n),
        issuer_seq: 1,
        local_seq,
        generation: 1,
        role: "initiator".into(),
        descriptor: canonical_json_bytes(&envelope)?,
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
        full_generation_nonce: None,
        full_initial_union_root: None,
    })
}

pub(super) fn publication() -> TestResult<(Vec<u8>, String, u64)> {
    publication_at(7)
}

pub(super) fn publication_at(epoch: u64) -> TestResult<(Vec<u8>, String, u64)> {
    let record = Envelope {
        body: DeviceSet {
            schema: "ramflux.identity.signed_device_set.v3".into(),
            version: 3,
            principal_id: "principal".into(),
            account_anchor: h(2),
            principal_kind: PrincipalKind::Human,
            origin: "native".into(),
            custody_mode: "local_human".into(),
            device_set_epoch: epoch,
            previous_record_hash: None,
            issued_at: 1,
            master_certificate: Envelope {
                body: MasterCertificate {
                    schema: "ramflux.identity.master_certificate.v1".into(),
                    version: 1,
                    account_anchor: h(2),
                    principal_id: "principal".into(),
                    principal_kind: PrincipalKind::Human,
                    master_public_key: h(3),
                    self_signing_public_key: h(4),
                    primary_device_ref: device("dev-a"),
                    custody_kind: CustodyKind::LocalHuman,
                    scopes: vec!["device_set".into()],
                    range_index: 1,
                    issued_at: 1,
                    cert_id: h(5),
                    legacy_binding_hash: None,
                    previous_certificate_hash: None,
                },
                signature: encode_base64url([7; 64]),
            },
            legacy_binding: None,
            profile: Profile {
                kind: PrincipalKind::Human,
                display_name: "alice".into(),
                custodian: None,
            },
            devices: vec![],
            delegations: vec![],
            revoked_delegation_ids: vec![],
            migration: None,
            revoked_device_checkpoint: None,
            section_hashes: SectionHashes {
                profile: h(10),
                devices: h(11),
                delegations: h(12),
                revoked_delegation_ids: h(13),
                migration: h(14),
                revoked_device_checkpoint: h(15),
            },
        },
        signature: encode_base64url([8; 64]),
    };
    let candidate_hash = object_hash(&record)?;
    let bytes = canonical_json_bytes(&Publication { record, compacted_ids: None })?;
    Ok((bytes, candidate_hash, epoch))
}

pub(in crate::account_db) fn head() -> TestResult<HeadRow> {
    let (candidate, candidate_hash, _) = publication()?;
    Ok(HeadRow {
        account_id: "acct".into(),
        operation_id: h(20),
        invitation_id: Some(h(1)),
        generation: 1,
        kind: "enroll".into(),
        base_record_hash: h(4),
        base_epoch: 1,
        publisher_ref: ref_bytes("dev-a")?,
        candidate,
        candidate_hash,
        state: "prepared".into(),
        ack: None,
        recipient_ref: Some(ref_bytes("dev-b")?),
        revoked_ref: None,
        created_at: 1,
    })
}

pub(super) fn ack_bytes(record_hash: &str, device_set_epoch: u64) -> TestResult<Vec<u8>> {
    #[derive(serde::Serialize)]
    struct HeadAck<'a> {
        record_hash: &'a str,
        device_set_epoch: u64,
    }
    Ok(canonical_json_bytes(&HeadAck { record_hash, device_set_epoch })?)
}

pub(super) fn live_phase(phase: &str) -> TestResult<LiveRow> {
    let mut row = invited()?;
    let early = matches!(phase, "invited" | "commitments");
    if !early {
        row.context = Some(context_bytes()?);
        row.transcript_hash = Some(h(8));
    }
    if matches!(
        phase,
        "proposal_pending"
            | "prepared"
            | "submitted"
            | "acknowledged"
            | "locally_installed"
            | "completed"
    ) {
        row.proposal_hash = Some(h(9));
    }
    if matches!(
        phase,
        "prepared" | "submitted" | "acknowledged" | "locally_installed" | "completed"
    ) {
        row.candidate_id = Some(h(20));
    }
    row.phase = phase.into();
    Ok(row)
}

pub(super) fn submitted_head() -> TestResult<HeadRow> {
    let mut row = head()?;
    row.state = "submitted".into();
    Ok(row)
}

pub(super) fn acknowledged_head() -> TestResult<HeadRow> {
    let mut row = head()?;
    row.state = "acknowledged".into();
    let hash = row.candidate_hash.clone();
    row.ack = Some(ack_bytes(&hash, 7)?);
    Ok(row)
}

pub(super) fn terminal() -> TerminalRow {
    TerminalRow {
        account_id: "acct".into(),
        operation_id: h(20),
        invitation_id: h(1),
        issuer_seq: 1,
        local_seq: 1,
        generation: 1,
        outcome: "completed".into(),
        record_hash: Some(h(4)),
        finished_at: 4_000_000_000,
        cleanup: "done".into(),
    }
}

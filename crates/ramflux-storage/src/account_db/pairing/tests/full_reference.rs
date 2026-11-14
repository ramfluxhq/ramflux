// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use super::super::recovery::{Admission, RecoveredOutcome};
use super::helpers::{TestResult, h, live_phase, terminal};
use crate::{AccountDb, AccountDbKey, AccountIndex, FULL_STAGE_REFERENCE_KIND, FullStageReference};
use ramflux_protocol::{
    canonical_json_bytes,
    custody::{
        Envelope,
        pairing::{PairingWire, full_transfer::U64, native::Invitation},
    },
};
use sha2::Digest as _;

fn linked_row() -> TestResult<crate::LiveRow> {
    let mut row = live_phase("mutually_confirmed")?;
    let mut descriptor: Envelope<Invitation> = ramflux_protocol::parse_i_json(&row.descriptor)?;
    descriptor.body.purpose = "primary_transfer".into();
    descriptor.body.transfer_id = Some(h(40));
    descriptor.body.validate()?;
    row.descriptor = canonical_json_bytes(&descriptor)?;
    row.expires_at = 604_900;
    let reference = FullStageReference {
        kind: FULL_STAGE_REFERENCE_KIND.into(),
        lease_expires_at: U64(row.expires_at),
        record_digest: h(41),
        stage_id: h(40),
    };
    row.context = Some(reference.to_wire_bytes()?);
    row.validate()?;
    Ok(row)
}

fn local_floor_record(
    base: &Envelope<ramflux_protocol::custody::DeviceSet>,
    expiry: u64,
) -> TestResult<ramflux_crypto::custody::pairing::FullResumeRecord> {
    use ramflux_protocol::custody::{object_hash, pairing::context_v3::TranscriptV3};
    use zeroize::Zeroizing;
    let now = base.body.issued_at;
    let mut record = local_stage_record_fixture()?;
    let source = base.body.master_certificate.body.primary_device_ref.clone();
    let destination = ramflux_protocol::custody::DeviceRef {
        account_anchor: base.body.account_anchor.clone(),
        device_id: "tail-target".into(),
        device_epoch: 1,
    };
    let destination_key = ramflux_crypto::public_key_base64url_from_seed([10; 32]);
    record.grant.source_ref = source.clone();
    record.grant.destination_ref = destination.clone();
    record.grant.branch_keys.source = base.body.devices[0]
        .branch_certificate
        .as_ref()
        .ok_or("source branch")?
        .body
        .branch_signing_public_key
        .clone();
    record.grant.branch_keys.destination = destination_key.clone();
    record.grant.expires_at = expiry;
    let grant = record.grant.clone();
    let mut transcript = TranscriptV3::from_wire_bytes(&record.transcript)?;
    let mut common = transcript.initiator.common.clone();
    common.account_anchor = base.body.account_anchor.clone();
    common.master_public_key = base.body.master_certificate.body.master_public_key.clone();
    common.record_hash = object_hash(base)?;
    common.device_set_epoch = base.body.device_set_epoch;
    common.recipient_mode = "new".into();
    common.destination_ref = None;
    common.transfer_id = Some(record.transfer_id.clone());
    common.lease_not_before = now;
    common.lease_expires_at = expiry;
    common.expires_at = now + 300;
    transcript.initiator.common = common.clone();
    transcript.responder.common = common.clone();
    transcript.initiator.device_ref = source;
    transcript.responder.device_ref = destination.clone();
    transcript.initiator.branch_key = grant.branch_keys.source.clone();
    transcript.responder.branch_key = destination_key.clone();
    record.base_record_hash = common.record_hash;
    record.th = sha2::Sha256::digest(
        ramflux_protocol::custody::pairing::context_v3::transcript_preimage(&transcript)?,
    )
    .into();
    record.transcript = Zeroizing::new(transcript.to_wire_bytes()?);
    Ok(record)
}

#[test]
fn pairing_full_stage_native_floor_keeps_tail_revocation_across_account_reopen() -> TestResult {
    use ramflux_crypto::custody::{
        CooperativeTransferInput, MasterKey, RecoveryPhrase, SelfSigningKey,
        cooperative_transfer_preserving_devices, pairing::PairingRole, verify_record,
    };
    use ramflux_protocol::custody::DeviceSet;
    use zeroize::Zeroizing;
    let vectors: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../../ramflux-crypto/tests/fixtures/custody_v3.json"
    ))?;
    let base: Envelope<DeviceSet> =
        ramflux_protocol::parse_i_json(&canonical_json_bytes(&vectors["record"])?)?;
    let now = base.body.issued_at;
    let expiry = now + 604_800;
    let record = local_floor_record(&base, expiry)?;
    let grant = record.grant.clone();
    let destination = grant.destination_ref.clone();
    let destination_key = grant.branch_keys.destination.clone();
    // This exercises encrypted floor persistence, not native lease/SAS consent restoration:
    // the private storage fixture's lease is deliberately not a network-acceptable lease.
    let (root, db) = crate::tests::test_db("full-tail-native-floor")?;
    let mut stage = db.create_full_stage_for_test(record, expiry)?;
    let initial = verify_record(&base, now, None, None)?;
    assert!(stage.require_full_native_floor(&initial).is_err());
    let master = MasterKey::from_phrase(&RecoveryPhrase::from_entropy(&[0; 32])?)?;
    let manager = SelfSigningKey::from_vault_seed(&Zeroizing::new([7; 32]));
    let mut branch =
        base.body.devices[0].branch_certificate.as_ref().ok_or("source branch")?.body.clone();
    branch.device_id = destination.device_id.clone();
    branch.cert_id = h(10);
    branch.branch_signing_public_key = destination_key;
    branch.agreement_identity_public_key = ramflux_protocol::encode_base64url(
        ramflux_crypto::X25519KeyPair::from_seed([11; 32]).public,
    );
    let candidate = cooperative_transfer_preserving_devices(
        &master,
        &manager,
        &initial,
        CooperativeTransferInput {
            destination,
            fresh_destination: Some(branch),
            highest_observed_range: 1,
            issued_at: now,
            master_cert_id: h(70),
        },
    )?;
    let published = verify_record(&candidate, now, None, None)?;
    assert!(
        stage.observe_full_native_head(&published).is_err(),
        "unseeded non-base head was accepted"
    );
    assert!(stage.require_full_native_floor(&initial).is_err());
    stage.observe_full_native_head(&initial)?;
    stage.observe_full_native_head(&published)?;
    ramflux_crypto::custody::pairing::verify_full_tail_authority(&grant, &published, now)?;
    let revoked = manager.revoke_device(&published, &grant.source_ref.device_id, now)?;
    let revoked = verify_record(&revoked, now, None, None)?;
    stage.observe_full_native_head(&revoked)?;
    assert!(
        ramflux_crypto::custody::pairing::verify_full_tail_authority(&grant, &revoked, now)
            .is_err()
    );
    let mut row = linked_row()?;
    row.expires_at = expiry;
    row.context = Some(stage.reference().to_wire_bytes()?);
    db.put_pairing_live(&row)?;
    drop(stage);
    drop(db);
    let index = AccountIndex::open(&root)?;
    let db =
        AccountDb::open(&index, "acct", &AccountDbKey::derive("acct", b"storage-test-secret"))?;
    let mut stage = db.open_full_transfer_stage(&row.operation_id, PairingRole::Initiator, now)?;
    // A blind/stale node's data-only predicate would admit this old published roster.
    // The endpoint's retained job floor must reject it before any import or epoch admission.
    ramflux_crypto::custody::pairing::verify_full_tail_authority(&grant, &published, now)?;
    assert!(matches!(
        stage.observe_full_native_head(&published),
        Err(crate::StorageError::PairingField("HeadChanged"))
    ));
    assert!(stage.require_full_native_floor(&published).is_err());
    assert!(stage.observe_full_native_head(&initial).is_err());
    stage.require_full_native_floor(&revoked)?;
    Ok(())
}
#[test]
fn pairing_full_stage_reference_is_closed_scoped_and_data_only_on_reopen() -> TestResult {
    let (root, db) = crate::tests::test_db("full-stage-reference")?;
    let row = linked_row()?;
    db.put_pairing_live(&row)?;
    drop(db);
    let index = AccountIndex::open(&root)?;
    let db =
        AccountDb::open(&index, "acct", &AccountDbKey::derive("acct", b"storage-test-secret"))?;
    // Deliberately no stage file: an unbacked reference must survive for explicit recovery,
    // while neither ordinary admission nor a data-resume grant is synthesized from it.
    let recovered = db.recover_pairing()?;
    assert!(
        matches!(recovered.outcome, RecoveredOutcome::DataStageRetained { ref operation_id, ref stage_id }
        if operation_id == &row.operation_id && stage_id == &h(40))
    );
    assert_eq!(recovered.admission, Admission::Closed);
    assert_eq!(recovered.live, vec![row.clone()]);
    assert_eq!(recovered.terminals, Vec::<crate::TerminalRow>::new());
    let mut cancelled = terminal();
    cancelled.operation_id.clone_from(&row.operation_id);
    cancelled.outcome = "cancelled".into();
    cancelled.record_hash = None;
    cancelled.validate()?;
    assert!(
        db.commit_pairing_terminal_cleanup(&cancelled).is_err(),
        "generic cancellation cannot discharge unknown stage/publication obligations"
    );
    assert_eq!(db.pairing_live_rows()?, vec![row]);
    Ok(())
}
#[test]
fn pairing_full_stage_reference_refuses_wrong_invitation_expiry_and_kind() -> TestResult {
    let row = linked_row()?;
    let reference = row.full_stage_reference()?.ok_or("reference")?;
    for mutation in 0..4 {
        let mut changed = reference.clone();
        match mutation {
            0 => changed.stage_id = h(42),
            1 => changed.lease_expires_at.0 += 1,
            2 => changed.kind = "full_transfer_stage_ref_v2".into(),
            _ => changed.record_digest = "invalid".into(),
        }
        let mut invalid = row.clone();
        invalid.context = Some(canonical_json_bytes(&changed)?);
        assert!(invalid.validate().is_err());
    }
    let mut enroll = row.clone();
    let mut descriptor: Envelope<Invitation> = ramflux_protocol::parse_i_json(&enroll.descriptor)?;
    descriptor.body.purpose = "enroll".into();
    descriptor.body.transfer_id = None;
    enroll.descriptor = canonical_json_bytes(&descriptor)?;
    assert!(enroll.validate().is_err());
    let mut bytes = reference.to_wire_bytes()?;
    bytes.insert(1, b' ');
    assert!(FullStageReference::from_wire_bytes(&bytes).is_err());
    Ok(())
}

#[test]
fn pairing_journal_frozen_full_v3_context_is_closed_before_stage_link() -> TestResult {
    let vectors: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../../ramflux-protocol/fixtures/pairing_v3/vectors.json"
    ))?;
    let mut value = serde_json::json!({
        "initiator": vectors["transcript"]["initiator"],
        "responder": vectors["transcript"]["responder"],
    });
    let mut row = live_phase("mutually_confirmed")?;
    let transcript = ramflux_protocol::custody::pairing::context_v3::TranscriptV3::from_wire_bytes(
        &canonical_json_bytes(&vectors["transcript"])?,
    )?;
    let common = &transcript.initiator.common;
    let mut descriptor: Envelope<Invitation> = ramflux_protocol::parse_i_json(&row.descriptor)?;
    descriptor.body.invitation_id.clone_from(&common.invitation_id);
    descriptor.body.issuer_seq = common.issuer_seq;
    descriptor.body.account_anchor.clone_from(&common.account_anchor);
    descriptor.body.primary_ref.clone_from(&transcript.initiator.device_ref);
    descriptor.body.base_record_hash.clone_from(&common.record_hash);
    descriptor.body.base_epoch = common.device_set_epoch;
    descriptor.body.purpose = "primary_transfer".into();
    descriptor.body.recipient_mode.clone_from(&common.recipient_mode);
    descriptor.body.destination_ref.clone_from(&common.destination_ref);
    descriptor.body.capabilities.clone_from(&common.capabilities);
    descriptor.body.lease_not_before = common.lease_not_before;
    descriptor.body.lease_expires_at = common.lease_expires_at;
    descriptor.body.expires_at = common.expires_at;
    descriptor.body.created_at = common.expires_at - 300;
    descriptor.body.transfer_id.clone_from(&common.transfer_id);
    descriptor.body.validate()?;
    row.invitation_id.clone_from(&common.invitation_id);
    row.issuer_seq = common.issuer_seq;
    row.base_record_hash.clone_from(&common.record_hash);
    row.base_epoch = common.device_set_epoch;
    row.expires_at = common.expires_at;
    row.descriptor = canonical_json_bytes(&descriptor)?;
    row.transcript_hash = Some(ramflux_protocol::encode_base64url(sha2::Sha256::digest(
        ramflux_protocol::custody::pairing::context_v3::transcript_preimage(&transcript)?,
    )));
    row.context = Some(canonical_json_bytes(&value)?);
    row.validate()?;
    let mut wrong_th = row.clone();
    wrong_th.transcript_hash = Some(h(99));
    assert!(wrong_th.validate().is_err());
    let mut enrollment = row.clone();
    let mut wrong_invitation = descriptor.clone();
    wrong_invitation.body.purpose = "enroll".into();
    wrong_invitation.body.transfer_id = None;
    enrollment.descriptor = canonical_json_bytes(&wrong_invitation)?;
    assert!(enrollment.validate().is_err(), "full-v3 persistence cannot masquerade as enrollment");
    value["responder"]["transfer_profile"] = serde_json::Value::Null;
    row.context = Some(canonical_json_bytes(&value)?);
    assert!(row.validate().is_err());
    value["responder"] = vectors["transcript"]["responder"].clone();
    value["initiator"]["schema"] = serde_json::json!("ramflux.pairing.RoleContext.v2");
    row.context = Some(canonical_json_bytes(&value)?);
    assert!(row.validate().is_err(), "local v2 arm cannot accept a mixed full-v3 context");
    Ok(())
}

fn local_stage_record_fixture() -> TestResult<ramflux_crypto::custody::pairing::FullResumeRecord> {
    use ramflux_crypto::custody::pairing::{FullResumeRecord, PairingRole};
    use ramflux_protocol::custody::pairing::{
        context_v3::TranscriptV3,
        full_transfer::lease::{BranchKeys, DataGrant},
    };
    use zeroize::Zeroizing;
    let vectors: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../../ramflux-protocol/fixtures/pairing_v3/vectors.json"
    ))?;
    let transcript = TranscriptV3::from_wire_bytes(&canonical_json_bytes(&vectors["transcript"])?)?;
    // Storage fixture exercises encrypted persistence only. Native lease signatures and
    // local branch/SAS trust are independently verified by the crypto restore owner.
    Ok(FullResumeRecord {
        role: PairingRole::Initiator,
        transcript: Zeroizing::new(transcript.to_wire_bytes()?),
        th: [31; 32],
        grant: DataGrant {
            schema: "ramflux.pairing.full_transfer.data_grant.v1".into(),
            version: 1,
            transfer_id: h(40),
            node_id: "node-stage-test".into(),
            source_ref: transcript.initiator.device_ref.clone(),
            destination_ref: transcript.responder.device_ref.clone(),
            branch_keys: BranchKeys {
                source: transcript.initiator.branch_key.clone(),
                destination: transcript.responder.branch_key.clone(),
            },
            opaque_commitment: h(36),
            expires_at: 604_900,
        },
        lease: Zeroizing::new(b"local-encrypted-resume-canary-no-wire-lease".to_vec()),
        transfer_id: h(40),
        base_manifest_hash: h(37),
        base_record_hash: h(38),
    })
}

#[test]
fn pairing_full_stage_metadata_survives_restart_without_account_schema_or_plaintext() -> TestResult
{
    use ramflux_crypto::custody::pairing::PairingRole;
    let (root, db) = crate::tests::test_db("full-stage-metadata")?;
    let record = local_stage_record_fixture()?;
    let schema = || {
        db.connection.query_row(
            "SELECT group_concat(sql,';') FROM (SELECT sql FROM sqlite_schema ORDER BY name)",
            [],
            |row| row.get::<_, String>(0),
        )
    };
    let before = schema()?;
    let private_cut = root.join("full-private-source-cut.db");
    let snapshot = db.pin_full_transfer_cut()?.write_private_snapshot(
        &private_cut,
        std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
    )?;
    let stage = db.create_full_stage_for_test(record, 604_900)?;
    stage.adopt_source_cut(0, &h(55), &private_cut, snapshot)?;
    assert!(!private_cut.exists());
    assert!(stage.source_cut_estimated_bytes(0, &h(55))? > 0);
    assert!(stage.source_cut_estimated_bytes(0, &h(56)).is_err());
    let reference = stage.reference().clone();
    let expected = stage.resume_record()?.stage_digest()?;
    assert_eq!(reference.record_digest, ramflux_protocol::encode_base64url(expected));
    assert!(
        db.open_full_transfer_stage(&h(20), PairingRole::Initiator, 100).is_err(),
        "orphan directory grants no admission"
    );
    let mut row = linked_row()?;
    row.context = Some(reference.to_wire_bytes()?);
    db.put_pairing_live(&row)?;
    assert!(
        db.open_full_transfer_stage(&row.operation_id, PairingRole::Initiator, 100).is_err(),
        "second local owner cannot race the staged writer"
    );
    drop(stage);
    assert_eq!(
        schema()?,
        before,
        "dedicated staging must not change the exportable account schema"
    );
    assert!(db.open_full_transfer_stage(&row.operation_id, PairingRole::Responder, 100).is_err());
    assert!(matches!(
        db.open_full_transfer_stage(&row.operation_id, PairingRole::Initiator, 604_900),
        Err(crate::StorageError::PairingField("LeaseExpired"))
    ));
    drop(db);
    let index = AccountIndex::open(&root)?;
    let db =
        AccountDb::open(&index, "acct", &AccountDbKey::derive("acct", b"storage-test-secret"))?;
    let stage = db.open_full_transfer_stage(&row.operation_id, PairingRole::Initiator, 100)?;
    assert_eq!(stage.resume_record()?.stage_digest()?, expected);
    assert!(
        stage.source_cut_estimated_bytes(0, &h(55))? > 0,
        "exact immutable cut reopens with saved independent key after restart"
    );
    drop(stage);
    let directory = root.join("custody_accounts/acct/full-transfer").join(h(40));
    if db.encryption_mode() == crate::EncryptionMode::SqlCipher {
        for name in ["stage.db", "stage.key"] {
            let bytes = std::fs::read(directory.join(name))?;
            assert!(
                !bytes
                    .windows(b"local-encrypted-resume-canary-no-wire-lease".len())
                    .any(|part| part == b"local-encrypted-resume-canary-no-wire-lease")
            );
            assert!(!bytes.windows(32).any(|part| part == [31; 32]));
        }
    }
    let mut changed = row.clone();
    let mut wrong = reference;
    wrong.record_digest = h(99);
    changed.context = Some(wrong.to_wire_bytes()?);
    db.put_pairing_live(&changed)?;
    assert!(
        db.open_full_transfer_stage(&row.operation_id, PairingRole::Initiator, 100).is_err(),
        "account link mismatch fails closed"
    );
    Ok(())
}

#[test]
fn pairing_full_terminal_live_row_refuses_data_reopen_and_retains_stage() -> TestResult {
    let (root, mut db) = crate::tests::test_db("full-terminal-data-reopen")?;
    let record = local_stage_record_fixture()?;
    let stage = db.create_full_stage_for_test(record, 604_900)?;
    let reference = stage.reference().clone();
    drop(stage);
    let mut row = linked_row()?;
    row.expires_at = 604_900;
    row.context = Some(reference.to_wire_bytes()?);
    db.put_pairing_live(&row)?;
    assert!(
        db.open_full_transfer_stage(
            &row.operation_id,
            ramflux_crypto::custody::pairing::PairingRole::Initiator,
            100
        )
        .is_ok()
    );
    let directory = root.join("custody_accounts/acct/full-transfer").join(&reference.stage_id);
    let files = ["stage.key", "stage.db"]
        .map(|name| -> Result<_, std::io::Error> {
            Ok((name, blake3::hash(&std::fs::read(directory.join(name))?)))
        })
        .into_iter()
        .collect::<Result<Vec<_>, _>>()?;
    for phase in ["cancelled", "expired", "rejected", "completed"] {
        row.phase = phase.into();
        if phase == "completed" {
            row.proposal_hash = Some(h(42));
            row.candidate_id = Some(row.operation_id.clone());
        }
        db.put_pairing_live(&row)?;
        drop(db);
        let index = AccountIndex::open(&root)?;
        db =
            AccountDb::open(&index, "acct", &AccountDbKey::derive("acct", b"storage-test-secret"))?;
        assert!(
            matches!(
                db.open_full_transfer_stage(
                    &row.operation_id,
                    ramflux_crypto::custody::pairing::PairingRole::Initiator,
                    100
                ),
                Err(crate::StorageError::PairingField("WrongContext"))
            ),
            "terminal row reopened data channel: {phase}"
        );
        for (name, expected) in &files {
            assert!(
                blake3::hash(&std::fs::read(directory.join(name))?) == *expected,
                "terminal data refusal changed retained stage artifact"
            );
        }
        assert!(
            db.pairing_live_rows()?
                .first()
                .ok_or("retained live row")?
                .full_stage_reference()?
                .as_ref()
                == Some(&reference),
            "terminal refusal removed reconciliation reference"
        );
    }
    Ok(())
}

#[test]
fn pairing_full_terminal_unprepared_stage_requires_drain_and_reclaims_only_private_data()
-> TestResult {
    use ramflux_crypto::custody::pairing::PairingRole;
    let (root, db) = crate::tests::test_db("full-terminal-unprepared-reclaim")?;
    let stage = db.create_full_stage_for_test(local_stage_record_fixture()?, 604_900)?;
    let reference = stage.reference().clone();
    let mut row = linked_row()?;
    row.context = Some(reference.to_wire_bytes()?);
    db.put_pairing_live(&row)?;
    let ordinary = db.path.clone();
    assert!(
        db.reclaim_unprepared_full_stage(&row.operation_id, PairingRole::Initiator, 100).is_err(),
        "test: active data stage was reclaimed"
    );
    drop(stage);
    db.mark_full_transfer_data_terminal(
        &row.operation_id,
        PairingRole::Initiator,
        "rejected",
        100,
    )?;
    row.phase = "rejected".into();
    db.put_pairing_live(&row)?;
    let worker = std::fs::OpenOptions::new().read(true).write(true).open(
        root.join("custody_accounts/acct/full-transfer")
            .join(&reference.stage_id)
            .join("stage.lock"),
    )?;
    fs2::FileExt::try_lock_exclusive(&worker)?;
    assert!(
        db.reclaim_unprepared_full_stage(&row.operation_id, PairingRole::Initiator, 100).is_err(),
        "test: terminal cleanup deleted an active private worker's stage"
    );
    drop(worker);
    assert!(
        db.reclaim_unprepared_full_stage(&row.operation_id, PairingRole::Initiator, 100)?,
        "test: drained unprepared terminal stage was retained"
    );
    assert!(
        !root.join("custody_accounts/acct/full-transfer").join(&reference.stage_id).try_exists()?,
        "test: terminal cleanup retained private bytes or wrapped stage key"
    );
    assert!(ordinary.try_exists()?, "test: private cleanup deleted the ordinary account database");
    assert_eq!(
        db.privacy_erasure_generation()?,
        0,
        "test: private cleanup changed ordinary privacy state"
    );
    assert!(
        db.reclaim_unprepared_full_stage(&row.operation_id, PairingRole::Initiator, 100)?,
        "test: terminal cleanup was not idempotent"
    );
    Ok(())
}

// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Independent original native heads for grant, roster, retirement and block control.
use super::*;
fn proof(owner: &Account) -> TestResult<wire::ProvenanceAuthority> {
    let mut proof = wire::ProvenanceAuthority {
        proof_hash: String::new(),
        authority: custody::CustodyAuthority {
            publication: custody::Publication {
                record: owner.record.envelope().clone(),
                compacted_ids: None,
            },
            custodian_publication: None,
        },
        custodian_history: vec![],
    };
    proof.proof_hash = proof.content_hash()?;
    Ok(proof)
}
fn advance(owner: &mut Account, time: u64) -> TestResult {
    let mut body = owner.record.envelope().body.clone();
    body.previous_record_hash = Some(custody::object_hash(owner.record.envelope())?);
    body.device_set_epoch += 1;
    body.issued_at = time;
    owner.record = verify_record(&owner.key.sign_record(body)?, time, None, None)?;
    Ok(())
}
fn denial(
    owner: &Account,
    grant: &Signed<wire::Admission>,
    decision: wire::Decision,
    revision: u8,
    time: u64,
) -> TestResult<Signed<wire::Admission>> {
    let mut body = grant.body.clone();
    body.operation_id = d(80 + revision);
    body.expected_revision = u64::from(revision);
    body.decision = decision;
    body.permissions = None;
    body.grant_until = None;
    body.notice_hash = None;
    body.evidence_hash = None;
    body.authority_head_hash = custody::object_hash(owner.record.envelope())?;
    body.master_certificate_hash =
        custody::object_hash(&owner.record.envelope().body.master_certificate)?;
    body.issued_at = time;
    body.expires_at = time + 300;
    if let wire::Subject::Group { group_epoch, .. } = &mut body.subject {
        *group_epoch = 11;
    }
    Ok(owner.key.sign_reach_admission(body, &owner.record, time)?)
}
fn fixture() -> TestResult<(Vec<wire::StateRecord>, wire::Provenance)> {
    let mut owner = account(10, None)?;
    let grant = group_grant(&owner)?;
    let mut authorities = vec![proof(&owner)?];
    advance(&mut owner, NOW + 1)?;
    let header = owner.key.sign_group_roster_header(
        wire::GroupRosterHeader {
            version: 1,
            recipient_root: grant.body.recipient_root.clone(),
            authority_head_hash: custody::object_hash(owner.record.envelope())?,
            master_certificate_hash: custody::object_hash(
                &owner.record.envelope().body.master_certificate,
            )?,
            group_id: "group".into(),
            conversation_id: "signed-thread".into(),
            grant_hash: custody::framed_hash(wire::OPERATION_HASH_DOMAIN, &grant)?,
            group_epoch: 10,
            membership_hash: d(74),
            members_hash: custody::framed_hash(
                wire::GROUP_ROSTER_MEMBERS_DOMAIN,
                &Vec::<wire::GroupRosterMember>::new(),
            )?,
            member_count: 0,
            issued_at: NOW + 1,
        },
        &owner.record,
        NOW + 1,
    )?;
    authorities.push(proof(&owner)?);
    advance(&mut owner, NOW + 2)?;
    let update = denial(&owner, &grant, wire::Decision::Revoke, 1, NOW + 2)?;
    authorities.push(proof(&owner)?);
    advance(&mut owner, NOW + 3)?;
    let block = denial(&owner, &grant, wire::Decision::Block, 2, NOW + 3)?;
    authorities.push(proof(&owner)?);
    let records = vec![wire::StateRecord::Retirement {
        subject: update.body.subject.clone(),
        revision: 3,
        update,
        group_floor: Some(Box::new(wire::GroupFloor {
            floor_epoch: 11,
            grant: Some(Box::new(grant)),
            roster_header: Some(Box::new(header)),
            block_control: Some(Box::new(block)),
        })),
    }];
    let mut signers = wire::record_signers(records.first().ok_or("retirement")?)?;
    for signer in &mut signers {
        signer.proof_hash = authorities
            .iter()
            .find(|proof| {
                custody::object_hash(&proof.authority.publication.record)
                    .is_ok_and(|head| head == signer.authority_head_hash)
            })
            .ok_or("original signer head")?
            .proof_hash
            .clone();
    }
    signers.sort_by(|a, b| a.order_key().cmp(&b.order_key()));
    authorities.sort_by(|a, b| a.proof_hash.cmp(&b.proof_hash));
    let catalogue = wire::Provenance {
        kind: wire::ProvenanceKind::ReachProvenance,
        version: 1,
        account_anchor: owner.record.envelope().body.account_anchor.clone(),
        revision: 3,
        state_hash: d(90),
        signers,
        authorities,
    };
    Ok((records, catalogue))
}
#[test]
fn cr_group_header_historical_selector() -> TestResult {
    let (records, catalogue) = fixture()?;
    assert_eq!(
        catalogue.authorities.len(),
        4,
        "all four original witnesses use distinct valid native heads"
    );
    verify_historical_state_records(&records, &catalogue)?;
    let wire::StateRecord::Retirement { group_floor: Some(floor), .. } =
        records.first().ok_or("retirement")?
    else {
        return Err("group floor".into());
    };
    let header = floor.roster_header.as_ref().ok_or("original header")?;
    let grant_head = &floor.grant.as_ref().ok_or("original grant")?.body.authority_head_hash;
    let grant_proof = catalogue
        .authorities
        .iter()
        .find(|proof| {
            custody::object_hash(&proof.authority.publication.record)
                .is_ok_and(|head| &head == grant_head)
        })
        .ok_or("grant proof")?;
    let mut wrong = catalogue.clone();
    wrong
        .signers
        .iter_mut()
        .find(|reference| reference.object_kind == wire::ObjectKind::GroupRoster)
        .ok_or("header reference")?
        .proof_hash
        .clone_from(&grant_proof.proof_hash);
    assert!(
        verify_historical_state_records(&records, &wrong).is_err(),
        "a header cannot reuse the grant's different historical signer context"
    );
    let mut missing = serde_json::to_value(&header.body)?;
    missing.as_object_mut().ok_or("header object")?.remove("authority_head_hash");
    assert!(
        wire::decode::<wire::GroupRosterHeader>(
            &ramflux_protocol::canonical_json_bytes(&missing)?,
            2048
        )
        .is_err(),
        "selector-less signed headers cannot be patched or guessed"
    );
    let mut bad_native = catalogue.clone();
    let selected = bad_native.authorities.first_mut().ok_or("native proof")?;
    let old_hash = selected.proof_hash.clone();
    selected.authority.publication.compacted_ids = Some(vec![d(91)]);
    selected.proof_hash = selected.content_hash()?;
    let new_hash = selected.proof_hash.clone();
    for reference in &mut bad_native.signers {
        if reference.proof_hash == old_hash {
            reference.proof_hash.clone_from(&new_hash);
        }
    }
    bad_native.authorities.sort_by(|a, b| a.proof_hash.cmp(&b.proof_hash));
    bad_native.validate()?;
    assert!(
        verify_historical_state_records(&records, &bad_native).is_err(),
        "consistent provenance hashes cannot authenticate invalid native compaction evidence"
    );
    Ok(())
}

#[test]
fn cr_provenance_stage_verifies_each_original_from_one_proof_at_a_time() -> TestResult {
    let (records, catalogue) = fixture()?;
    let mut stage = ProvenanceStageBuilder::new(
        &catalogue.account_anchor,
        catalogue.revision,
        &catalogue.state_hash,
        catalogue.signers.clone(),
    )?;
    for proof in &catalogue.authorities {
        stage.push(proof)?;
    }
    let stage = stage.finish()?;
    stage.verify_originals(&records)?;
    assert_eq!(
        stage.proof_hashes().count(),
        4,
        "all four independently selected original signer contexts remain encrypted stage members"
    );
    Ok(())
}

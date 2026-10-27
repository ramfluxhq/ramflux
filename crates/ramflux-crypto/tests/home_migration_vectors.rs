// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Frozen migration preimages and adversarial type/role/chain verification.
mod home_migration_support;
use home_migration_support::*;
use ramflux_crypto::{custody::*, home_migration::*};
use ramflux_protocol::home_migration::decode;
use ramflux_protocol::{custody::*, domain, home_migration::*};
use serde_json::{Value, json};
fn row<T: Message>(signed: &Signed<T>) -> TestResult<Value> {
    Ok(
        json!({"domain":T::DOMAIN,"signed":signed,"signing_hex":hex::encode(ramflux_protocol::home_migration::signing_bytes(signed)?),
        "hash":message_hash(signed)?}),
    )
}
fn prepare_vector(
    branch: &ramflux_crypto::DeviceBranch,
    authority: &VerifiedRecord,
    reference: &DeviceRef,
) -> TestResult<Value> {
    let body: Prepare = serde_json::from_value(serde_json::Value::Object(
        [
            ("version".into(), serde_json::json!(1)),
            ("migration_id".into(), serde_json::json!(hash(19))),
            ("account_anchor".into(), serde_json::json!(authority.envelope().body.account_anchor)),
            ("actor".into(), serde_json::to_value(reference)?),
            ("authority_record_hash".into(), serde_json::json!(object_hash(authority.envelope())?)),
            (
                "branch_certificate_hash".into(),
                serde_json::json!(object_hash(
                    authority.envelope().body.devices[0]
                        .branch_certificate
                        .as_ref()
                        .ok_or("branch")?
                )?),
            ),
            ("previous_home_hash".into(), serde_json::json!(hash(19))),
            ("previous_home_epoch".into(), serde_json::json!(1)),
            ("old_node".into(), serde_json::json!("A")),
            ("destination_node".into(), serde_json::json!("A")),
            ("destination_key".into(), serde_json::json!(public(8))),
            ("discovery_hash".into(), serde_json::json!(hash(19))),
            ("delivery_map_hash".into(), serde_json::json!(hash(19))),
            ("nonce".into(), serde_json::json!(hash(19))),
            ("issued_at".into(), serde_json::json!(NOW)),
            ("expires_at".into(), serde_json::json!(NOW)),
        ]
        .into_iter()
        .collect(),
    ))?;
    let signed = sign_actor(body, branch, authority, NOW)?;
    row(&signed)
}
fn offer_vector(authority: &VerifiedRecord) -> TestResult<Value> {
    let body: Offer = serde_json::from_value(serde_json::Value::Object(
        [
            ("version".into(), serde_json::json!(1)),
            ("migration_id".into(), serde_json::json!(hash(19))),
            ("account_anchor".into(), serde_json::json!(authority.envelope().body.account_anchor)),
            ("prepare_hash".into(), serde_json::json!(hash(19))),
            ("authority_record_hash".into(), serde_json::json!(object_hash(authority.envelope())?)),
            ("previous_home_hash".into(), serde_json::json!(hash(19))),
            ("next_home_epoch".into(), serde_json::json!(1)),
            ("old_node".into(), serde_json::json!("A")),
            ("destination_node".into(), serde_json::json!("A")),
            ("destination_key".into(), serde_json::json!(public(8))),
            ("discovery_hash".into(), serde_json::json!(hash(19))),
            ("server_record_hash".into(), serde_json::json!(hash(19))),
            ("gateway_tcp_addr".into(), serde_json::json!("A")),
            ("federation_endpoint".into(), serde_json::json!("A")),
            ("delivery_map_hash".into(), serde_json::json!(hash(19))),
            ("admission_id".into(), serde_json::json!(hash(19))),
            ("nonce".into(), serde_json::json!(hash(19))),
            ("issued_at".into(), serde_json::json!(NOW)),
            ("accept_until".into(), serde_json::json!(NOW)),
            ("max_commit_delay".into(), serde_json::json!(1)),
            ("forward_seconds".into(), serde_json::json!(1)),
        ]
        .into_iter()
        .collect(),
    ))?;
    let signed = sign_node(body, "A", &key(8))?;
    row(&signed)
}
fn authorization_vector(
    primary: &SelfSigningKey,
    branch: &ramflux_crypto::DeviceBranch,
    authority: &VerifiedRecord,
) -> TestResult<Value> {
    let signed = primary.sign_home_authorization(
        authorization(authority, &genesis(authority)?.record, "B", 9, NOW)?,
        branch,
        authority,
        NOW,
    )?;
    row(&signed)
}
fn genesis_message_vector(authority: &VerifiedRecord) -> TestResult<Value> {
    let body: Genesis = serde_json::from_value(serde_json::Value::Object(
        [
            ("version".into(), serde_json::json!(1)),
            ("account_anchor".into(), serde_json::json!(authority.envelope().body.account_anchor)),
            ("home_epoch".into(), serde_json::json!(0)),
            ("home_node".into(), serde_json::json!("A")),
            ("home_node_key".into(), serde_json::json!(public(8))),
            ("custody_record_hash".into(), serde_json::json!(hash(19))),
            ("registered_at".into(), serde_json::json!(NOW)),
        ]
        .into_iter()
        .collect(),
    ))?;
    let signed = sign_node(body, "A", &key(8))?;
    row(&signed)
}
fn control_vector(
    branch: &ramflux_crypto::DeviceBranch,
    authority: &VerifiedRecord,
    reference: &DeviceRef,
) -> TestResult<Value> {
    let body: Control = serde_json::from_value(serde_json::Value::Object(
        [
            ("version".into(), serde_json::json!(1)),
            ("action".into(), serde_json::json!("status")),
            ("audience_node".into(), serde_json::json!("A")),
            ("migration_id".into(), serde_json::json!(hash(19))),
            ("requester".into(), serde_json::to_value(reference)?),
            ("authority_record_hash".into(), serde_json::json!(object_hash(authority.envelope())?)),
            ("payload_hash".into(), serde_json::json!(hash(19))),
            ("nonce".into(), serde_json::json!(hash(19))),
            ("issued_at".into(), serde_json::json!(NOW)),
            ("expires_at".into(), serde_json::json!(NOW)),
        ]
        .into_iter()
        .collect(),
    ))?;
    let signed = sign_actor(body, branch, authority, NOW)?;
    row(&signed)
}
fn receipt_vector(authority: &VerifiedRecord) -> TestResult<Value> {
    let body: Receipt = serde_json::from_value(serde_json::Value::Object(
        [
            ("version".into(), serde_json::json!(1)),
            ("action".into(), serde_json::json!("status")),
            ("migration_id".into(), serde_json::json!(hash(19))),
            ("account_anchor".into(), serde_json::json!(authority.envelope().body.account_anchor)),
            ("node_id".into(), serde_json::json!("A")),
            ("request_hash".into(), serde_json::json!(hash(19))),
            ("request_nonce".into(), serde_json::json!("A")),
            ("authorization_hash".into(), serde_json::Value::Null),
            ("seal_hash".into(), serde_json::Value::Null),
            ("home_record_hash".into(), serde_json::Value::Null),
            ("phase".into(), serde_json::json!("sealed")),
            ("state_version".into(), serde_json::json!(1)),
            ("sealed_at".into(), serde_json::Value::Null),
            ("commit_deadline".into(), serde_json::Value::Null),
            ("commit_proof_hash".into(), serde_json::Value::Null),
            ("response_payload_hash".into(), serde_json::json!(hash(19))),
            ("issued_at".into(), serde_json::json!(NOW)),
            ("expires_at".into(), serde_json::json!(NOW)),
            ("reason_code".into(), serde_json::Value::Null),
        ]
        .into_iter()
        .collect(),
    ))?;
    let signed = sign_node(body, "A", &key(8))?;
    row(&signed)
}
fn commit_vector(authority: &VerifiedRecord) -> TestResult<Value> {
    let body: CommitProof = serde_json::from_value(serde_json::Value::Object(
        [
            ("version".into(), serde_json::json!(1)),
            ("migration_id".into(), serde_json::json!(hash(19))),
            ("account_anchor".into(), serde_json::json!(authority.envelope().body.account_anchor)),
            ("old_node".into(), serde_json::json!("A")),
            ("destination_node".into(), serde_json::json!("A")),
            ("destination_key".into(), serde_json::json!(public(8))),
            ("previous_home_hash".into(), serde_json::json!(hash(19))),
            ("next_home_epoch".into(), serde_json::json!(1)),
            ("authority_record_hash".into(), serde_json::json!(object_hash(authority.envelope())?)),
            ("authorization_hash".into(), serde_json::json!(hash(19))),
            ("offer_hash".into(), serde_json::json!(hash(19))),
            ("seal_hash".into(), serde_json::json!(hash(19))),
            ("commit_deadline".into(), serde_json::json!(NOW)),
            ("committed_at".into(), serde_json::json!(NOW)),
            ("forward_until".into(), serde_json::json!(NOW)),
            ("backlog_manifest_hash".into(), serde_json::json!(hash(19))),
        ]
        .into_iter()
        .collect(),
    ))?;
    let signed = sign_node(body, "A", &key(8))?;
    row(&signed)
}
fn delivery_vector(authority: &VerifiedRecord) -> TestResult<Value> {
    let body: NodeCommitDelivery = serde_json::from_value(serde_json::Value::Object(
        [
            ("version".into(), serde_json::json!(1)),
            ("migration_id".into(), serde_json::json!(hash(19))),
            ("account_anchor".into(), serde_json::json!(authority.envelope().body.account_anchor)),
            ("source_node".into(), serde_json::json!("A")),
            ("audience_node".into(), serde_json::json!("A")),
            ("authorization_hash".into(), serde_json::json!(hash(19))),
            ("offer_hash".into(), serde_json::json!(hash(19))),
            ("seal_hash".into(), serde_json::json!(hash(19))),
            ("admission_evidence_hash".into(), serde_json::json!(hash(19))),
            ("nonce".into(), serde_json::json!(hash(19))),
            ("issued_at".into(), serde_json::json!(NOW)),
            ("expires_at".into(), serde_json::json!(NOW)),
        ]
        .into_iter()
        .collect(),
    ))?;
    let signed = sign_node(body, "A", &key(8))?;
    row(&signed)
}
fn attestation_vector(authority: &VerifiedRecord) -> TestResult<Value> {
    let body: HomeAttestation = serde_json::from_value(serde_json::Value::Object(
        [
            ("version".into(), serde_json::json!(1)),
            ("account_anchor".into(), serde_json::json!(authority.envelope().body.account_anchor)),
            ("audience_node".into(), serde_json::json!("A")),
            ("previous_home_hash".into(), serde_json::json!(hash(19))),
            ("authority_record_hash".into(), serde_json::json!(object_hash(authority.envelope())?)),
            ("device_set_epoch".into(), serde_json::json!(1)),
            ("delivery_map_hash".into(), serde_json::json!(hash(19))),
            ("nonce".into(), serde_json::json!(hash(19))),
            ("issued_at".into(), serde_json::json!(NOW)),
            ("expires_at".into(), serde_json::json!(NOW)),
        ]
        .into_iter()
        .collect(),
    ))?;
    let signed = sign_node(body, "A", &key(8))?;
    row(&signed)
}
fn fence_vector() -> TestResult<Value> {
    let body: NoncommitFence = serde_json::from_value(serde_json::Value::Object(
        [
            ("version".into(), serde_json::json!(1)),
            ("migration_id".into(), serde_json::json!(hash(19))),
            ("authorization_hash".into(), serde_json::json!(hash(19))),
            ("seal_hash".into(), serde_json::json!(hash(19))),
            ("fenced_at".into(), serde_json::json!(NOW)),
        ]
        .into_iter()
        .collect(),
    ))?;
    let signed = sign_node(body, "A", &key(8))?;
    row(&signed)
}

fn vectors() -> TestResult<Value> {
    let (primary, branch, authority) = authority()?;
    let reference = &authority.envelope().body.master_certificate.body.primary_device_ref;
    let mut rows = Vec::new();
    rows.extend([
        prepare_vector(&branch, &authority, reference)?,
        offer_vector(&authority)?,
        authorization_vector(&primary, &branch, &authority)?,
        genesis_message_vector(&authority)?,
        control_vector(&branch, &authority, reference)?,
        receipt_vector(&authority)?,
        commit_vector(&authority)?,
        delivery_vector(&authority)?,
        attestation_vector(&authority)?,
        fence_vector()?,
    ]);

    let genesis = genesis(&authority)?;
    let committed = transition(&genesis.record, &primary, &branch, &authority, ("B", 9), NOW)?;
    Ok(json!({"messages":rows,"genesis":genesis,"genesis_hash":record_hash(&genesis.record)?,
        "committed_home":committed,"committed_home_hash":record_hash(&committed.record)?,
        "delivery_map_hash":delivery_map_hash(&[DeliveryMapEntry{device_ref:reference.clone(),target_delivery_id:"delivery".into()}])?}))
}
#[test]
#[ignore = "explicit fixture regeneration only"]
fn regenerate_home_migration_vectors() -> TestResult {
    std::fs::write(
        concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/home_migration_v1.json"),
        serde_json::to_string_pretty(&vectors()?)? + "\n",
    )?;
    Ok(())
}
#[test]
fn every_message_preimage_signature_and_hash_matches_frozen_vectors() -> TestResult {
    let expected: Value = serde_json::from_str(include_str!("fixtures/home_migration_v1.json"))?;
    assert_eq!(vectors()?, expected);
    Ok(())
}
fn reject_substitutions<T: Message + serde::de::DeserializeOwned>(raw: &Value) -> TestResult {
    let signed: Signed<T> = decode(&serde_json::to_vec(raw)?, MAX_MESSAGE_BYTES)?;
    verify_signatures(&signed)?;
    for domain in [
        domain::CUSTODY_MASTER_CERTIFICATE,
        domain::BRANCH_PROOF_V2,
        domain::CUSTODY_NODE_RECORD,
        domain::HOME_CONTROL,
    ] {
        if domain == T::DOMAIN {
            continue;
        }
        let mut wrong: Signed<T> = decode(&serde_json::to_vec(raw)?, MAX_MESSAGE_BYTES)?;
        wrong.schema = domain.into();
        wrong.domain = domain.into();
        assert!(verify_signatures(&wrong).is_err());
    }
    let mut wrong: Signed<T> = decode(&serde_json::to_vec(raw)?, MAX_MESSAGE_BYTES)?;
    wrong.body = serde_json::from_value({
        let mut b = serde_json::to_value(&wrong.body)?;
        b["version"] = json!(2);
        b
    })?;
    assert!(verify_signatures(&wrong).is_err());
    let mut wrong: Signed<T> = decode(&serde_json::to_vec(raw)?, MAX_MESSAGE_BYTES)?;
    wrong.signatures[0] = ramflux_protocol::encode_base64url([0; 64]);
    assert!(verify_signatures(&wrong).is_err());
    let mut wrong: Signed<T> = decode(&serde_json::to_vec(raw)?, MAX_MESSAGE_BYTES)?;
    wrong.signers[0].role =
        if wrong.signers[0].role == Role::Node { Role::Actor } else { Role::Node };
    assert!(verify_signatures(&wrong).is_err());
    let mut unknown = raw.clone();
    unknown["extra"] = json!(true);
    assert!(decode::<Signed<T>>(&serde_json::to_vec(&unknown)?, MAX_MESSAGE_BYTES).is_err());
    Ok(())
}
#[test]
fn every_type_rejects_cross_schema_role_field_and_signature_substitution() -> TestResult {
    let all = vectors()?;
    let messages = all["messages"].as_array().ok_or("messages")?;
    reject_substitutions::<Prepare>(&messages[0]["signed"])?;
    reject_substitutions::<Offer>(&messages[1]["signed"])?;
    reject_substitutions::<Authorization>(&messages[2]["signed"])?;
    reject_substitutions::<Genesis>(&messages[3]["signed"])?;
    reject_substitutions::<Control>(&messages[4]["signed"])?;
    reject_substitutions::<Receipt>(&messages[5]["signed"])?;
    reject_substitutions::<CommitProof>(&messages[6]["signed"])?;
    reject_substitutions::<NodeCommitDelivery>(&messages[7]["signed"])?;
    reject_substitutions::<HomeAttestation>(&messages[8]["signed"])?;
    reject_substitutions::<NoncommitFence>(&messages[9]["signed"])?;

    Ok(())
}
#[test]
fn original_wire_duplicate_keys_nullable_omissions_and_unsafe_integers_fail() -> TestResult {
    let value = vectors()?["messages"][0]["signed"].clone();
    let wire = serde_json::to_string(&value)?;
    let duplicate = wire.replacen("\"version\":1", "\"version\":1,\"version\":1", 1);
    assert!(decode::<Signed<Prepare>>(duplicate.as_bytes(), MAX_MESSAGE_BYTES).is_err());
    let mut unsafe_value = value;
    unsafe_value["body"]["issued_at"] = json!(9_007_199_254_740_992_u64);
    assert!(
        decode::<Signed<Prepare>>(&serde_json::to_vec(&unsafe_value)?, MAX_MESSAGE_BYTES).is_err()
    );
    let mut receipt = vectors()?["messages"][5]["signed"].clone();
    receipt["body"].as_object_mut().ok_or("body")?.remove("sealed_at");
    assert!(decode::<Signed<Receipt>>(&serde_json::to_vec(&receipt)?, MAX_MESSAGE_BYTES).is_err());
    Ok(())
}

#[test]
fn three_missed_moves_with_primary_replacement_verify_and_destination_replay_fails() -> TestResult {
    use zeroize::Zeroizing;
    let (primary, branch, authority) = authority()?;
    let genesis = genesis(&authority)?;
    let first = transition(&genesis.record, &primary, &branch, &authority, ("B", 9), NOW)?;
    let next_primary = SelfSigningKey::from_vault_seed(&Zeroizing::new([12; 32]));
    let master = MasterKey::from_phrase(&RecoveryPhrase::from_entropy(&[0; 32])?)?;
    let mut body = authority.envelope().body.clone();
    let mut certificate = body.master_certificate.body.clone();
    certificate.self_signing_public_key = next_primary.public_key();
    certificate.range_index = 2;
    certificate.issued_at = NOW + FORWARD_SECONDS;
    certificate.cert_id = hash(50);
    certificate.previous_certificate_hash = Some(object_hash(&body.master_certificate)?);
    body.master_certificate = master.certify(certificate)?;
    body.device_set_epoch = encode_epoch(2, 1)?;
    body.issued_at = NOW + FORWARD_SECONDS;
    body.previous_record_hash = Some(object_hash(authority.envelope())?);
    let mut cert = body.devices[0].branch_certificate.take().ok_or("branch")?.body;
    cert.master_certificate_hash = object_hash(&body.master_certificate)?;
    cert.cert_id = hash(51);
    cert.not_before = NOW + FORWARD_SECONDS;
    cert.expires_at = cert.not_before + MAX_BRANCH_LEASE_SECONDS;
    body.devices[0].branch_certificate = Some(next_primary.certify_branch(cert)?);
    let next_record = next_primary.sign_record(body)?;
    let next = verify_record(&next_record, NOW + FORWARD_SECONDS, None, None)?;
    let mut second = transition(
        &first.record,
        &next_primary,
        &branch,
        &next,
        ("C", 10),
        NOW + FORWARD_SECONDS + 1,
    )?;
    second
        .management_certificate_chain
        .insert(0, authority.envelope().body.master_certificate.clone());
    let third = transition(
        &second.record,
        &next_primary,
        &branch,
        &next,
        ("D", 11),
        NOW + 2 * FORWARD_SECONDS + 2,
    )?;
    let result = ResolveResult { home: third, predecessors: vec![genesis, first, second] };
    let anchor = &authority.envelope().body.account_anchor;
    let pin = public(8);
    let trust = HomeTrust {
        account_anchor: anchor,
        node_id: "A",
        node_key: &pin,
        home_epoch: 0,
        home_hash: None,
    };
    let verified = verify_home_chain(&result, &trust, NOW + 2 * FORWARD_SECONDS + 2)?;
    assert_eq!(verified.epoch(), 3);
    assert_eq!(verified.home(), ("D", public(11).as_str()));
    let HomeRecord::Committed { commit_proof, .. } = &result.home.record else {
        return Err("commit".into());
    };
    let c = &commit_proof.body;
    let expected = SealedBinding {
        destination_node: "D",
        destination_key: &public(11),
        authorization_hash: &c.authorization_hash,
        offer_hash: &c.offer_hash,
        seal_hash: &c.seal_hash,
        previous_home_hash: &c.previous_home_hash,
        next_home_epoch: 3,
        home_floor: None,
    };
    activation_allowed(&verified, &expected)?;
    let replay = SealedBinding { destination_node: "evil", ..expected };
    assert!(activation_allowed(&verified, &replay).is_err());
    let mut missing = result.clone();
    missing.predecessors[2].actor_certificate = None;
    assert!(verify_home_chain(&missing, &trust, NOW + 2 * FORWARD_SECONDS + 2).is_err());
    let mut missing = result;
    missing.predecessors.swap(1, 2);
    assert!(verify_home_chain(&missing, &trust, NOW + 2 * FORWARD_SECONDS + 2).is_err());
    Ok(())
}

#[test]
fn account_bound_and_client_clock_refuse_a_far_future_destination_offer() -> TestResult {
    let (_, _, authority) = authority()?;
    let value = vectors()?["messages"][1]["signed"]["body"].clone();
    let mut offer: Offer = serde_json::from_value(value)?;
    offer.issued_at = NOW;
    offer.accept_until = NOW + 600;
    offer.max_commit_delay = 600;
    offer.forward_seconds = 86400;
    offer_bounds(&offer, NOW)?;
    offer.issued_at = NOW + 31_536_000;
    offer.accept_until = offer.issued_at + 600;
    assert!(offer_bounds(&offer, NOW).is_err());
    let mut auth = authorization(&authority, &genesis(&authority)?.record, "B", 9, NOW)?;
    assert_eq!(hard_deadline(&auth)?, NOW + 1800);
    assert!(authorization_bounds(&auth, NOW + 1801).is_err());
    auth.seal_until = offer.accept_until;
    assert!(authorization_bounds(&auth, NOW).is_err());
    Ok(())
}

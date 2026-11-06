// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use crate::{CustodyService, RouterCore, RouterRedbStore, tests::custody_sessions::Driver};
use ed25519_dalek::{Signer, SigningKey};
use ramflux_crypto::{
    CryptoError,
    custody::{
        ProofChannel, VerifiedRecord, branch_exporter_hash, sign_branch_proof_v3,
        sign_proxy_acceptance, verify_branch_proof_v3,
    },
};
use ramflux_protocol::{custody::*, domain, encode_base64url};
use redb::{ReadableDatabase, ReadableTable, TableDefinition};
use serde_json::{Value, json};
use std::collections::BTreeMap;
type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;
const NOW: u64 = 1_760_000_000;
fn vectors() -> Result<Vec<Value>> {
    Ok(serde_json::from_str(include_str!(
        "../../../../ramflux-protocol/fixtures/dm_fs_v3/custody_vectors.json"
    ))?)
}
#[test]
fn dm_fs_v3_custody_proof_grammar_vectors() -> Result {
    let rows = vectors()?;
    assert_eq!(rows.len(), 3);
    for row in &rows {
        let proof: Envelope<BranchProofV3> = serde_json::from_value(row["proof_envelope"].clone())?;
        let seed: Vec<u8> = hex_bytes(row["branch_seed"].as_str().ok_or("seed")?)?;
        let seed: [u8; 32] = seed.try_into().map_err(|_| "seed width")?;
        let branch = ramflux_crypto::DeviceBranch {
            principal_id: "fixture-only".into(),
            device_id: proof.body.device_ref.device_id.clone(),
            device_epoch: proof.body.device_ref.device_epoch,
            signing_key: SigningKey::from_bytes(&seed),
        };
        assert_eq!(sign_branch_proof_v3(&branch, proof.body.clone())?, proof);
        let bytes = signing_bytes(domain::BRANCH_PROOF_V3, &proof.body)?;
        assert_eq!(bytes, hex_bytes(row["proof_transcript"].as_str().ok_or("transcript")?)?);
        // Grammar oracle only: the fixed record/certificate hashes have no authority behind them.
        assert_eq!(
            branch.signing_key.verifying_key().to_bytes().as_slice(),
            hex_bytes(row["branch_public"].as_str().ok_or("public")?)?
        );
        let signature = ed25519_dalek::Signature::from_slice(&ramflux_protocol::decode_base64url(
            &proof.signature,
        )?)?;
        branch.signing_key.verifying_key().verify_strict(&bytes, &signature)?;
        let action: CustodyProofAction = serde_json::from_value(row["action"].clone())?;
        assert_eq!(proof.body.action_hash, custody_action_hash(&action)?);
        let mut wrong = proof.body.clone();
        wrong.action_hash = encode_base64url([0; 32]);
        let verifying = branch.signing_key.verifying_key();
        match verifying.verify_strict(&signing_bytes(domain::BRANCH_PROOF_V3, &wrong)?, &signature)
        {
            Err(error) => assert_eq!(error.to_string(), "signature error"),
            Ok(()) => return Err("mutated action hash verified".into()),
        }
        match verifying
            .verify_strict(&signing_bytes(domain::DM_FS_V3_REQUEST, &proof.body)?, &signature)
        {
            Err(error) => assert_eq!(error.to_string(), "signature error"),
            Ok(()) => return Err("foreign domain verified".into()),
        }
    }
    Ok(())
}
fn hex_bytes(text: &str) -> Result<Vec<u8>> {
    (0..text.len()).step_by(2).map(|i| Ok(u8::from_str_radix(&text[i..i + 2], 16)?)).collect()
}
fn attempt(
    driver: &Driver,
    service: &CustodyService,
    router: &RouterCore,
    store: &RouterRedbStore,
    action: CustodyProofAction,
    proof: Envelope<BranchProofV3>,
) -> Result<CustodyServerFrame> {
    // Build a correctly signed receipt even for deliberately malformed proofs,
    // so node-side negatives cannot be satisfied by the proxy signer's precheck.
    let descriptor = driver.node.envelope().body.proxy_keys.first().ok_or("proxy")?;
    let body = RelayAcceptance {
        schema: domain::CUSTODY_RELAY_ACCEPTANCE.into(),
        version: 1,
        issuer_kind: AcceptanceIssuer::NodeProxy,
        relay_id: descriptor.proxy_id.clone(),
        relay_key_id: descriptor.key_id.clone(),
        node_identity_record_hash: driver.node.hash().into(),
        client_exporter_hash: Some(branch_exporter_hash(&[5; 32])),
        receipt_id: encode_base64url(ramflux_crypto::random_32()?),
        message_hash: object_hash(&proof)?,
        purpose: AcceptancePurpose::BranchProof,
        audience: proof.body.audience.clone(),
        source_device_ref: Some(proof.body.device_ref.clone()),
        branch_certificate_hash: Some(proof.body.certificate_hash.clone()),
        target_anchor: None,
        challenge_nonce: Some(proof.body.challenge_nonce.clone()),
        accepted_at: NOW,
    };
    let receipt = Envelope {
        signature: encode_base64url(
            driver.proxy.sign(&signing_bytes(domain::CUSTODY_RELAY_ACCEPTANCE, &body)?).to_bytes(),
        ),
        body,
    };
    Ok(service.mesh(
        router,
        store,
        CustodyMeshRequest::Prove {
            action,
            proof: Box::new(proof),
            receipt: Some(Box::new(receipt)),
            connection_id: driver.connection.clone(),
        },
        "ramflux-gateway",
        NOW,
    ))
}
fn run(
    driver: &Driver,
    service: &CustodyService,
    router: &RouterCore,
    store: &RouterRedbStore,
    action: CustodyProofAction,
) -> Result<CustodyServerFrame> {
    let challenge = driver.challenge(service, router, store, action.clone())?;
    attempt(driver, service, router, store, action, driver.proof(&challenge)?)
}
fn refused(frame: &CustodyServerFrame, expected: &CustodyRefusal) {
    assert!(
        matches!(frame,CustodyServerFrame::Refused{code,capacity:None,retry:None} if code==expected),
        "wrong dormant admission result: {frame:?}"
    );
}
type Rows = Vec<(String, Vec<u8>)>;
fn snapshot(store: &RouterRedbStore) -> Result<BTreeMap<String, Option<Rows>>> {
    let tx = store.migration_db().begin_read()?;
    let mut snapshot = BTreeMap::new();
    // Authority rows contain the durable certified-range/revision and revocation floors.
    // Challenge/replay bookkeeping deliberately remains outside this contract.
    for name in ["custody_accounts_v3", "custody_prekeys_v3", "foreign_custody_pins_v1"] {
        let rows = match tx.open_table(TableDefinition::<&str, &[u8]>::new(name)) {
            Ok(table) => Some(
                table
                    .iter()?
                    .map(|entry| {
                        let (key, value) = entry?;
                        Ok((key.value().to_owned(), value.value().to_vec()))
                    })
                    .collect::<std::result::Result<Rows, redb::StorageError>>()?,
            ),
            Err(redb::TableError::TableDoesNotExist(_)) => None,
            Err(error) => return Err(error.into()),
        };
        snapshot.insert(name.into(), rows);
    }
    Ok(snapshot)
}
#[test]
fn dm_fs_v3_custody_actions_refused_without_write() -> Result {
    let path = std::env::temp_dir()
        .join(format!("ramflux-dm-fs-v3-{}.redb", encode_base64url(ramflux_crypto::random_32()?)));
    let store = RouterRedbStore::open_without_wal(&path)?;
    let router = RouterCore::new();
    store.bootstrap_router(&router)?;
    let driver = Driver::new("dm-fs-carriers", 10)?;
    let service = CustodyService::new(driver.node.clone(), false, &store, NOW)?;
    assert!(matches!(
        run(&driver, &service, &router, &store, driver.publish())?,
        CustodyServerFrame::Published { .. }
    ));
    assert!(matches!(
        run(
            &driver,
            &service,
            &router,
            &store,
            CustodyProofAction::Register { prekey_bundle: driver.bundle(10)? }
        )?,
        CustodyServerFrame::Registered { .. }
    ));
    let before = snapshot(&store)?;
    let writes = store.custody_publication_write_count();
    let rows = vectors()?;
    for row in &rows[1..] {
        let action: CustodyProofAction = serde_json::from_value(row["action"].clone())?;
        assert_eq!(action.capability(), "register");
        let challenge = driver.challenge(&service, &router, &store, action.clone())?;
        let proof = driver.proof(&challenge)?;
        refused(
            &attempt(
                &driver,
                &service,
                &router,
                &store,
                CustodyProofAction::OpenSession,
                proof.clone(),
            )?,
            &CustodyRefusal::BindingRefused,
        );
        let other: CustodyProofAction = serde_json::from_value(
            rows[if row["action"]["operation"] == "prekey_status" { 2 } else { 1 }]["action"]
                .clone(),
        )?;
        refused(
            &attempt(&driver, &service, &router, &store, other, proof.clone())?,
            &CustodyRefusal::BindingRefused,
        );
        proof_negatives(&driver, &service, &router, &store, &action, &proof)?;
        refused(
            &attempt(&driver, &service, &router, &store, action.clone(), proof.clone())?,
            &CustodyRefusal::Unsupported,
        );
        refused(
            &attempt(&driver, &service, &router, &store, action, proof)?,
            &CustodyRefusal::Replay,
        );
        assert_eq!(snapshot(&store)?, before);
        assert_eq!(store.custody_publication_write_count(), writes);
    }
    drop(service);
    drop(store);
    std::fs::remove_file(path)?;
    Ok(())
}
fn proof_negatives(
    driver: &Driver,
    service: &CustodyService,
    router: &RouterCore,
    store: &RouterRedbStore,
    action: &CustodyProofAction,
    proof: &Envelope<BranchProofV3>,
) -> Result {
    let mutations = [
        ("schema", json!("wrong")),
        ("version", json!(4)),
        ("certificate_hash", json!(encode_base64url([1; 32]))),
        ("record_hash", json!(encode_base64url([1; 32]))),
        ("proof_id", json!("")),
        ("challenge_nonce", json!(encode_base64url([1; 32]))),
        ("action_hash", json!(encode_base64url([1; 32]))),
        ("audience", json!("wrong-node")),
        ("binding_mode", json!("no_channel_binding")),
        ("transport_binding", json!(encode_base64url([1; 32]))),
        ("issued_at", json!(NOW + 301)),
        ("expires_at", json!(NOW + 301)),
    ];
    for (field, value) in mutations {
        let mut body = serde_json::to_value(&proof.body)?;
        body[field] = value;
        let body: BranchProofV3 = serde_json::from_value(body)?;
        let signature = encode_base64url(
            SigningKey::from_bytes(&[12; 32])
                .sign(&signing_bytes(domain::BRANCH_PROOF_V3, &body)?)
                .to_bytes(),
        );
        let bad = Envelope { body, signature };
        let expected = if field == "challenge_nonce" {
            CustodyRefusal::ChallengeUnknown
        } else {
            CustodyRefusal::BindingRefused
        };
        refused(&attempt(driver, service, router, store, action.clone(), bad)?, &expected);
    }
    for field in ["account_anchor", "device_id", "device_epoch"] {
        let mut body = serde_json::to_value(&proof.body)?;
        body["device_ref"][field] = match field {
            "account_anchor" => json!(encode_base64url([1; 32])),
            "device_id" => json!("other"),
            _ => json!(2),
        };
        let mut bad: Envelope<BranchProofV3> = proof.clone();
        bad.body = serde_json::from_value(body)?;
        bad.signature = encode_base64url(
            SigningKey::from_bytes(&[12; 32])
                .sign(&signing_bytes(domain::BRANCH_PROOF_V3, &bad.body)?)
                .to_bytes(),
        );
        refused(
            &attempt(driver, service, router, store, action.clone(), bad)?,
            &CustodyRefusal::BindingRefused,
        );
    }
    let mut bad = proof.clone();
    bad.signature = encode_base64url([0; 64]);
    refused(
        &attempt(driver, service, router, store, action.clone(), bad)?,
        &CustodyRefusal::BindingRefused,
    );
    Ok(())
}

/// Exact production-verifier refusal; `Signature` is the only signature-stage error.
enum Refusal {
    Reason(&'static str),
    Signature,
}
fn exact(error: &CryptoError, expected: &Refusal) -> bool {
    match (error, expected) {
        (CryptoError::IdentityAuthority(actual), Refusal::Reason(reason)) => actual == reason,
        (CryptoError::VerifyFailed, Refusal::Signature) => true,
        _ => false,
    }
}
/// Verify a proof against the live authority through the production verifier.
/// The authority and receipt come from the original proof and are reused for mutated
/// bodies, so a mutated anchor reaches the verifier instead of a lookup miss.
fn live_verify(
    driver: &Driver,
    authority: &VerifiedRecord,
    challenge: &BranchChallenge,
    proof: &Envelope<BranchProofV3>,
    receipt: &Envelope<RelayAcceptance>,
    capability: &str,
) -> std::result::Result<(), CryptoError> {
    verify_branch_proof_v3(
        authority,
        proof,
        challenge,
        capability,
        ProofChannel::HomeRelayReceipt {
            receipt,
            historical_node: &driver.node,
            current_node: &driver.node,
        },
        NOW,
    )
}
#[test]
fn dm_fs_v3_custody_fixed_actions_production_verifier_exact_reasons() -> Result {
    let path = std::env::temp_dir().join(format!(
        "ramflux-dm-fs-v3-verifier-{}.redb",
        encode_base64url(ramflux_crypto::random_32()?)
    ));
    let store = RouterRedbStore::open_without_wal(&path)?;
    let router = RouterCore::new();
    store.bootstrap_router(&router)?;
    let driver = Driver::new("dm-fs-verifier", 11)?;
    let service = CustodyService::new(driver.node.clone(), false, &store, NOW)?;
    assert!(matches!(
        run(&driver, &service, &router, &store, driver.publish())?,
        CustodyServerFrame::Published { .. }
    ));
    for row in &vectors()? {
        let action: CustodyProofAction = serde_json::from_value(row["action"].clone())?;
        let capability = action.capability();
        let challenge = driver.challenge(&service, &router, &store, action.clone())?;
        // The fixed P01 action goldens are the same bytes the live challenge commits to.
        assert_eq!(challenge.action_hash, row["action_hash"].as_str().ok_or("action hash")?);
        let proof = driver.proof(&challenge)?;
        let receipt = sign_proxy_acceptance(
            &driver.proxy,
            &driver.node,
            &proof,
            &branch_exporter_hash(&[5; 32]),
            encode_base64url(ramflux_crypto::random_32()?),
            NOW,
        )?;
        let publication = router
            .custody_record(&proof.body.device_ref.account_anchor, NOW)?
            .ok_or("custody record unavailable")?;
        let authority = router.verify_custody_possession_authority(&publication, NOW, true)?;
        live_verify(&driver, &authority, &challenge, &proof, &receipt, capability)
            .map_err(|error| format!("live proof rejected: {error:?}"))?;
        // Fixture proof bodies bind a fixture audience and dummy record hash: the production
        // verifier refuses them at the audience stage, which is why they stay grammar-only.
        let fixed: Envelope<BranchProofV3> = serde_json::from_value(row["proof_envelope"].clone())?;
        match live_verify(&driver, &authority, &challenge, &fixed, &receipt, capability) {
            Err(error)
                if exact(
                    &error,
                    &Refusal::Reason("branch proof audience differs from receiving node"),
                ) => {}
            other => return Err(format!("fixed fixture proof: {other:?}").into()),
        }
        let mut stale = challenge.clone();
        stale.action_hash = encode_base64url([1; 32]);
        match live_verify(&driver, &authority, &stale, &proof, &receipt, capability) {
            Err(error)
                if exact(
                    &error,
                    &Refusal::Reason("branch proof challenge or current head mismatch"),
                ) => {}
            other => return Err(format!("action substitution: {other:?}").into()),
        }
        let table = mutated_refusals(&proof)?;
        for (bad, expected) in &table {
            match live_verify(&driver, &authority, &challenge, bad, &receipt, capability) {
                Err(error) if exact(&error, expected) => {}
                other => return Err(format!("{}: {other:?}", row["action"]["operation"]).into()),
            }
        }
    }
    drop(service);
    drop(store);
    std::fs::remove_file(path)?;
    Ok(())
}

/// Field mutations that must each reach the production verifier and be refused for
/// one exact stage reason. Mutated bodies are re-signed by a foreign key on purpose.
fn mutated_refusals(
    proof: &Envelope<BranchProofV3>,
) -> Result<Vec<(Envelope<BranchProofV3>, Refusal)>> {
    let signed = |body: &BranchProofV3| -> Result<Envelope<BranchProofV3>> {
        Ok(Envelope {
            body: body.clone(),
            signature: encode_base64url(
                SigningKey::from_bytes(&[12; 32])
                    .sign(&signing_bytes(domain::BRANCH_PROOF_V3, body)?)
                    .to_bytes(),
            ),
        })
    };
    let future = NOW + 301;
    let reason = Refusal::Reason;
    let mut table: Vec<(Envelope<BranchProofV3>, Refusal)> = Vec::new();
    let mutate = |field: &str, value: Value| -> Result<BranchProofV3> {
        let mut body = serde_json::to_value(&proof.body)?;
        body[field] = value;
        Ok(serde_json::from_value(body)?)
    };
    let mutate_device = |field: &str, value: Value| -> Result<BranchProofV3> {
        let mut body = serde_json::to_value(&proof.body)?;
        body["device_ref"][field] = value;
        Ok(serde_json::from_value(body)?)
    };
    table.push((signed(&mutate("schema", json!("wrong"))?)?, reason("unsupported branch proof")));
    table.push((signed(&mutate("version", json!(4))?)?, reason("unsupported branch proof")));
    table.push((
        signed(&mutate("certificate_hash", json!(encode_base64url([1; 32])))?)?,
        reason("branch certificate hash mismatch"),
    ));
    table.push((
        signed(&mutate("record_hash", json!(encode_base64url([1; 32])))?)?,
        reason("branch proof challenge or current head mismatch"),
    ));
    table.push((
        signed(&mutate("proof_id", json!(""))?)?,
        reason("noncanonical custody binary length"),
    ));
    table.push((
        signed(&mutate("challenge_nonce", json!(encode_base64url([1; 32])))?)?,
        reason("branch proof challenge or current head mismatch"),
    ));
    table.push((
        signed(&mutate("action_hash", json!(encode_base64url([1; 32])))?)?,
        reason("branch proof challenge or current head mismatch"),
    ));
    table.push((
        signed(&mutate("audience", json!("wrong-node"))?)?,
        reason("branch proof audience differs from receiving node"),
    ));
    table.push((
        signed(&mutate("binding_mode", json!("no_channel_binding"))?)?,
        reason("branch proof challenge or current head mismatch"),
    ));
    table.push((
        signed(&mutate("transport_binding", json!(encode_base64url([1; 32])))?)?,
        Refusal::Signature,
    ));
    table.push((
        signed(&mutate("issued_at", json!(future))?)?,
        reason("branch proof or challenge expired"),
    ));
    table.push((
        signed(&mutate("expires_at", json!(future))?)?,
        reason("branch proof or challenge expired"),
    ));
    table.push((
        signed(&mutate_device("account_anchor", json!(encode_base64url([1; 32])))?)?,
        reason("custody device anchor or revocation mismatch"),
    ));
    table.push((
        signed(&mutate_device("device_id", json!("other"))?)?,
        reason("custody device unavailable"),
    ));
    table.push((
        signed(&mutate_device("device_epoch", json!(2))?)?,
        reason("custody device unavailable"),
    ));
    table.push((
        Envelope { body: proof.body.clone(), signature: encode_base64url([0; 64]) },
        Refusal::Signature,
    ));
    Ok(table)
}

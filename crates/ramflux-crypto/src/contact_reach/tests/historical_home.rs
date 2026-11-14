// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Real native externally managed tuple and signed genesis, with exact M4 closure controls.
use super::*;
use crate::home_migration::{sign_node, sign_with_keys, verify_home_chain_with_custodians};
use ramflux_protocol::{custody::Publication, home_migration as home};

#[test]
fn cr_retained_external_signer_requires_exact_original_m4_home_closure() -> TestResult {
    let human = account(20, None)?;
    let agent = account(30, Some(&human))?;
    let at = NOW + 100;
    let record = agent.record.envelope();
    let node_key = SigningKey::from_bytes(&[8; 32]);
    let declaration = sign_with_keys(
        home::HomeDeclarationV1 {
            version: 1,
            principal_id: record.body.principal_id.clone(),
            account_anchor: record.body.account_anchor.clone(),
            home_node: "A".into(),
            created_at: at,
            nonce: d(90),
        },
        vec![home::Signer {
            role: home::Role::Management,
            key: home::SignerKey::MasterCertifiedHome {
                account_anchor: record.body.account_anchor.clone(),
                master_certificate_hash: custody::object_hash(&record.body.master_certificate)?,
                public_key: record.body.master_certificate.body.self_signing_public_key.clone(),
            },
        }],
        &[&SigningKey::from_bytes(&agent.key.vault_seed())],
    )?;
    assert!(
        crate::home_migration::verify_home_declaration(&declaration, &agent.record, "A", at)
            .is_err(),
        "historical verifier must not open disabled fresh ExternalHuman registration"
    );
    let vector: serde_json::Value =
        serde_json::from_str(include_str!("../../../tests/fixtures/home_migration_v1.json"))?;
    let mut evidence: home::RecordEvidence =
        serde_json::from_value(vector.get("genesis").ok_or("home genesis")?.clone())?;
    evidence.authority = Publication { record: record.clone(), compacted_ids: None };
    evidence.record = home::HomeRecord::Genesis {
        genesis: Box::new(sign_node(
            home::Genesis {
                version: 1,
                account_anchor: record.body.account_anchor.clone(),
                home_epoch: 0,
                home_node: "A".into(),
                home_node_key: ramflux_protocol::encode_base64url(
                    node_key.verifying_key().to_bytes(),
                ),
                custody_record_hash: custody::object_hash(record)?,
                registered_at: at,
                home_declaration: Box::new(declaration),
            },
            "A",
            &node_key,
        )?),
    };
    let tuple = custody::CustodyAuthority {
        publication: evidence.authority.clone(),
        custodian_publication: Some(Publication {
            record: human.record.envelope().clone(),
            compacted_ids: None,
        }),
    };
    let history = vec![wire::HistoricalCustodian {
        record_hash: custody::object_hash(record)?,
        authority: tuple.clone(),
    }];
    let resolved = home::ResolveResult { home: evidence.clone(), predecessors: vec![] };
    let pinned = verify_home_chain_with_custodians(&resolved, &evidence, &history, at)?;
    let mut body = policy(&agent)?;
    body.home_head_hash = pinned.hash().into();
    body.issued_at = at;
    body.expires_at = at + 300;
    let signed = agent.key.sign_reach_policy(body, &agent.record, at)?;
    let mut proof = wire::ProvenanceAuthority {
        proof_hash: String::new(),
        authority: tuple,
        custodian_history: history,
    };
    proof.proof_hash = proof.content_hash()?;
    verify_historical_policy_with_home(&signed, &proof, Some(&pinned))?;
    encrypted_stage(&signed, &proof, &pinned)?;
    assert!(verify_historical_policy(&signed, &proof).is_err(), "a proof cannot pin its own home");
    let mut missing = proof.clone();
    missing.custodian_history.clear();
    missing.proof_hash = missing.content_hash()?;
    assert!(verify_historical_policy_with_home(&signed, &missing, Some(&pinned)).is_err());
    let mut extra = proof.clone();
    extra.custodian_history.push(extra.custodian_history.first().ok_or("M4 reference")?.clone());
    assert!(verify_historical_policy_with_home(&signed, &extra, Some(&pinned)).is_err());
    Ok(())
}

fn encrypted_stage(
    policy: &Signed<wire::ReachPolicy>,
    proof: &wire::ProvenanceAuthority,
    home: &crate::home_migration::VerifiedHome,
) -> TestResult {
    let records = vec![wire::StateRecord::Policy { revision: 1, update: policy.clone() }];
    let mut references = wire::record_signers(records.first().ok_or("policy")?)?;
    for reference in &mut references {
        reference.proof_hash.clone_from(&proof.proof_hash);
    }
    let mut builder =
        ProvenanceStageBuilder::new(&policy.body.account_anchor, 1, &d(91), references)?;
    builder.push(proof)?;
    let stage = builder.finish()?;
    stage.verify_originals_with_home(&records, Some(home))?;
    assert!(stage.verify_originals(&records).is_err());
    Ok(())
}

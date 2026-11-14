// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Real native sender and federation signatures; network/publication acceptance is separate.
use super::*;
use ramflux_crypto::custody::{GenesisInput, MasterKey, RecoveryPhrase, SelfSigningKey};
use ramflux_protocol::{custody, encode_base64url as d};
type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
const NOW: u64 = 1_700_000_000;

fn submission() -> TestResult<SourceSubmitRequest> {
    let master = MasterKey::from_phrase(&RecoveryPhrase::from_entropy(&[1; 32])?)?;
    let primary = SelfSigningKey::from_vault_seed(&zeroize::Zeroizing::new([2; 32]));
    let branch = ramflux_crypto::create_device_branch("source.example", "primary", 1, [3; 32]);
    let agreement = ramflux_crypto::X25519KeyPair::from_seed([4; 32]);
    let record = ramflux_crypto::custody::create_genesis(
        &master,
        &primary,
        &branch,
        &agreement,
        GenesisInput {
            principal_kind: ramflux_protocol::PrincipalKind::Human,
            display_name: "Source".into(),
            issued_at: NOW,
            master_cert_id: d([5; 32]),
            branch_cert_id: d([6; 32]),
            external_human_primary: None,
        },
    )?;
    let authority = custody::CustodyAuthority {
        publication: custody::Publication { record, compacted_ids: None },
        custodian_publication: None,
    };
    let root = &authority.publication.record.body.account_anchor;
    let recipient = d([9; 32]);
    let ciphertext = d([10; 64]);
    let mut envelope = ramflux_protocol::Envelope {
        schema: "ramflux.envelope.v2".into(),
        version: 2,
        domain: "ramflux.envelope.v2".into(),
        ext: ramflux_protocol::Ext::default(),
        signed: ramflux_protocol::SignedFields {
            signing_key_id: format!("{root}#primary"),
            signature_alg: ramflux_protocol::SignatureAlg::Ed25519,
            signature: String::new(),
        },
        envelope_id: "frozen-native".into(),
        source_principal_id: authority.publication.record.body.principal_id.clone(),
        source_device_id: "primary".into(),
        target_delivery_id: ramflux_protocol::qualified_device_id(&recipient, "phone")?,
        routing_set_id: None,
        delivery_class: ramflux_protocol::DeliveryClass::Message,
        priority: ramflux_protocol::Priority::Normal,
        ttl: 3600,
        created_at: i64::try_from(NOW)?,
        payload_hash: ramflux_protocol::hash_base64url(
            ramflux_protocol::domain::ENVELOPE,
            ciphertext.as_bytes(),
        ),
        encrypted_payload: ciphertext,
        delivery_mode: Some("durable".into()),
        collapse_tag: Some(d([11; 32])),
        report_commitment: Some(d([12; 32])),
    };
    let verified = ramflux_crypto::custody::verify_publication(&authority, NOW)?;
    let actor = custody::DeviceRef {
        account_anchor: root.clone(),
        device_id: "primary".into(),
        device_epoch: 1,
    };
    let certificate = verified.authorize(&actor, "message", NOW)?;
    envelope.ext.ext.insert("source_root_commitment".into(), root.clone().into());
    envelope.ext.ext.insert("source_device_authority".into(), serde_json::json!({
        "custody_authority":authority,"root_public_key":null,"signed_device_set":null,
        "principal_id":envelope.source_principal_id,"device_id":"primary","device_epoch":1,
        "branch_public_key":certificate.branch_signing_public_key,
        "target_delivery_id":ramflux_protocol::qualified_device_id(root,"primary")?,"revoked":false,
    }));
    envelope.signed.signature =
        ramflux_crypto::sign_protocol_object_with_device_branch(&branch, &envelope)?;
    let route = ramflux_crypto::contact_reach::sign_route(
        wire::Route {
            version: 1,
            source: actor,
            recipient_root: recipient.clone(),
            conversation_id: ramflux_protocol::message::dm_scope::derive(root, &recipient)?,
            traffic: wire::Traffic::Dm,
            group: None,
            envelope_hash: custody::framed_hash(wire::ENVELOPE_HASH_DOMAIN, &envelope)?,
            authority_head_hash: custody::object_hash(&authority.publication.record)?,
            issued_at: NOW,
            expires_at: NOW + 3600,
        },
        &branch,
    )?;
    let submission = wire::Submission { route, envelope, cost: None };
    ramflux_crypto::contact_reach::verify_current_source_submission(&submission, &verified, NOW)?;
    Ok(SourceSubmitRequest {
        kind: wire::SourceSubmitKind::Submit,
        request_id: d([13; 32]),
        remaining_ms: 1000,
        target_node_id: "target.example".into(),
        submission,
    })
}

fn node() -> crate::FederationDiscoverySurface {
    crate::FederationDiscoverySurface {
        node_id: "source.example".into(),
        public_endpoint: "https://source.example".into(),
        node_public_key: ramflux_crypto::public_key_base64url_from_seed([14; 32]),
        node_ca_cert_pem: String::new(),
        node_signing_seed: [14; 32],
        protocol_versions: vec![],
        transport_backends: vec![],
        node_capabilities: vec![],
        attachment_authority: None,
    }
}

#[test]
fn cr_submit_signs_the_complete_native_submission_without_resealing() -> TestResult {
    let request = submission()?;
    let node = node();
    let before = ramflux_protocol::canonical_json_bytes(&request.submission)?;
    let forward =
        signed(&request, &node).map_err(|reason| format!("native forward: {reason:?}"))?;
    assert_eq!(
        ramflux_protocol::canonical_json_bytes(&forward.submission)?,
        before,
        "the federation signer must preserve the sender's complete original envelope/route/cost"
    );
    ramflux_crypto::verify_canonical_signature(
        &ramflux_protocol::signed_bytes(&forward)?,
        &forward.signature,
        &node.node_public_key,
    )?;
    assert_eq!(
        forward,
        signed(&request, &node).map_err(|reason| format!("exact retry: {reason:?}"))?,
        "retrying the same frozen submission must preserve the exact deterministic forward bytes"
    );
    let mut changed = forward;
    changed.submission.envelope.encrypted_payload.push('A');
    assert!(
        ramflux_crypto::verify_canonical_signature(
            &ramflux_protocol::signed_bytes(&changed)?,
            &changed.signature,
            &node.node_public_key,
        )
        .is_err(),
        "a changed sealed payload cannot borrow the federation signature"
    );
    let mut wrong = node;
    wrong.node_signing_seed = [15; 32];
    assert!(
        matches!(signed(&request, &wrong), Err(Reason::ForeignUnavailable)),
        "misconfigured node signing material must refuse before dispatch"
    );
    Ok(())
}

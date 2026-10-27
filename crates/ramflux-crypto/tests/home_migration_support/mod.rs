// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use ed25519_dalek::SigningKey;
use ramflux_crypto::{DeviceBranch, custody::*, home_migration::*};
use ramflux_protocol::{custody::*, domain, encode_base64url, home_migration::*};
use zeroize::Zeroizing;
pub type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
pub const NOW: u64 = 1_700_000_100;
pub fn hash(n: u8) -> String {
    encode_base64url([n; 32])
}
pub fn key(n: u8) -> SigningKey {
    SigningKey::from_bytes(&[n; 32])
}
pub fn public(n: u8) -> String {
    encode_base64url(key(n).verifying_key().to_bytes())
}
pub fn authority() -> TestResult<(SelfSigningKey, DeviceBranch, VerifiedRecord)> {
    let vector: serde_json::Value =
        serde_json::from_str(include_str!("../fixtures/custody_v3.json"))?;
    let record: Envelope<DeviceSet> = serde_json::from_value(vector["record"].clone())?;
    Ok((
        SelfSigningKey::from_vault_seed(&Zeroizing::new([2; 32])),
        ramflux_crypto::create_device_branch("vector.example", "primary", 1, [3; 32]),
        verify_record(&record, NOW, None, None)?,
    ))
}
pub fn node(id: &str, n: u8) -> TestResult<Envelope<NodeIdentityRecord>> {
    Ok(sign_node_identity_record(
        &key(n),
        NodeIdentityRecord {
            schema: domain::CUSTODY_NODE_RECORD.into(),
            version: 1,
            node_id: id.into(),
            node_signing_public_key: public(n),
            client_tls_certificate_sha256: Some(hash(n)),
            epoch: 1,
            previous_record_hash: None,
            issued_at: NOW - 100,
            receipt_keys: vec![],
            proxy_keys: vec![],
            revoked_receipt_key_ids: vec![],
            revoked_proxy_key_ids: vec![],
            channel_binding_modes: vec![BindingMode::DirectExporter],
        },
    )?)
}
pub fn genesis(a: &VerifiedRecord) -> TestResult<RecordEvidence> {
    let record = HomeRecord::Genesis {
        genesis: Box::new(sign_node(
            Genesis {
                version: 1,
                account_anchor: a.envelope().body.account_anchor.clone(),
                home_epoch: 0,
                home_node: "A".into(),
                home_node_key: public(8),
                custody_record_hash: object_hash(a.envelope())?,
                registered_at: NOW - 10,
            },
            "A",
            &key(8),
        )?),
    };
    Ok(RecordEvidence {
        authority: Publication { record: a.envelope().clone(), compacted_ids: None },
        record,
        management_certificate_chain: vec![],
        actor_certificate: None,
        node_record: node("A", 8)?,
    })
}
pub fn authorization(
    a: &VerifiedRecord,
    base: &HomeRecord,
    next_node: &str,
    next_key: u8,
    at: u64,
) -> TestResult<Authorization> {
    Ok(Authorization {
        version: 1,
        migration_id: hash(u8::try_from(base.epoch() + 30)?),
        account_anchor: a.envelope().body.account_anchor.clone(),
        actor: DeviceRef {
            account_anchor: a.envelope().body.account_anchor.clone(),
            device_id: "primary".into(),
            device_epoch: 1,
        },
        authority_record_hash: object_hash(a.envelope())?,
        management_certificate_hash: object_hash(&a.envelope().body.master_certificate)?,
        previous_home_hash: record_hash(base)?,
        next_home_epoch: base.epoch() + 1,
        old_node: base.home().0.into(),
        destination_node: next_node.into(),
        destination_key: public(next_key),
        gateway_tcp_addr: "127.0.0.1:9000".into(),
        offer_hash: hash(19),
        delivery_map_hash: hash(20),
        nonce: hash(21),
        issued_at: at,
        seal_until: at + 600,
        max_commit_delay: 600,
        forward_seconds: FORWARD_SECONDS,
    })
}
pub fn transition(
    base: &HomeRecord,
    primary: &SelfSigningKey,
    branch: &DeviceBranch,
    authority: &VerifiedRecord,
    destination: (&str, u8),
    at: u64,
) -> TestResult<RecordEvidence> {
    let authorization = primary.sign_home_authorization(
        authorization(authority, base, destination.0, destination.1, at)?,
        branch,
        authority,
        at,
    )?;
    let a = &authorization.body;
    let old_seed = match base.home().0 {
        "A" => 8,
        "B" => 9,
        "C" => 10,
        _ => 11,
    };
    let proof = sign_node(
        CommitProof {
            version: 1,
            migration_id: a.migration_id.clone(),
            account_anchor: a.account_anchor.clone(),
            old_node: a.old_node.clone(),
            destination_node: a.destination_node.clone(),
            destination_key: a.destination_key.clone(),
            previous_home_hash: a.previous_home_hash.clone(),
            next_home_epoch: a.next_home_epoch,
            authority_record_hash: a.authority_record_hash.clone(),
            authorization_hash: message_hash(&authorization)?,
            offer_hash: a.offer_hash.clone(),
            seal_hash: hash(22),
            commit_deadline: at + 600,
            committed_at: at,
            forward_until: at + FORWARD_SECONDS,
            backlog_manifest_hash: hash(23),
        },
        base.home().0,
        &key(old_seed),
    )?;
    Ok(RecordEvidence {
        authority: Publication { record: authority.envelope().clone(), compacted_ids: None },
        record: HomeRecord::Committed {
            authorization: Box::new(authorization),
            commit_proof: Box::new(proof),
        },
        management_certificate_chain: vec![authority.envelope().body.master_certificate.clone()],
        actor_certificate: authority.envelope().body.devices[0].branch_certificate.clone(),
        node_record: node(base.home().0, old_seed)?,
    })
}

#[cfg(test)]
mod schema_substitution;

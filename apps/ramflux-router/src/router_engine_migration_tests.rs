// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Production submit engines refuse cutover before acceptance, including repeated remote sends.
use super::*;
use ramflux_node_core::{
    DeviceAuthKeyResponse, NodeServiceSigningKey, RouterCore, RouterEnvelopeOrigin, RouterRedbStore,
};
use ramflux_protocol::home_migration::{DeliveryMapEntry, Refusal};
use std::{
    hash::{Hash, Hasher},
    sync::Arc,
};
type TestResult = Result<(), Box<dyn std::error::Error>>;
struct Directory(std::path::PathBuf);
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
fn envelope(
    target: &str,
    id: &str,
) -> Result<ramflux_protocol::Envelope, Box<dyn std::error::Error>> {
    use ramflux_protocol::{DeliveryClass, Envelope, Ext, Priority, SignatureAlg, SignedFields};
    let root = ramflux_crypto::create_identity_root("alice", [0x91; 32]);
    let agreement = ramflux_crypto::X25519KeyPair::from_seed([0x92; 32]);
    let key = ramflux_crypto::fixture_public_key_base64url();
    let commitments = ramflux_crypto::device_key_commitments(
        &key,
        &ramflux_protocol::encode_base64url(agreement.public),
    )?;
    let set = ramflux_crypto::sign_device_set(
        &root,
        ramflux_crypto::DeviceSetSigningInput {
            principal_kind: ramflux_protocol::PrincipalKind::Human,
            device_set_epoch: 1,
            devices: vec![ramflux_protocol::SignedDeviceSetEntry {
                device_id: "sender".into(),
                device_epoch: 1,
                signing_key_commitment: commitments.0,
                agreement_key_commitment: commitments.1,
                status: ramflux_protocol::DeviceSetStatus::Active,
                revoked_at: None,
            }],
        },
    )?;
    let authority = DeviceAuthKeyResponse {
        principal_id: "alice".into(),
        device_id: "sender".into(),
        device_epoch: 1,
        root_public_key: Some(ramflux_protocol::encode_base64url(
            root.signing_key.verifying_key().to_bytes(),
        )),
        signed_device_set: Some(set),
        custody_authority: None,
        branch_public_key: key,
        target_delivery_id: "sender-target".into(),
        revoked: false,
    };
    let source = authority.authenticated_device_identity()?;
    let mut envelope = Envelope {
        schema: ramflux_protocol::domain::ENVELOPE.into(),
        version: 1,
        domain: ramflux_protocol::domain::ENVELOPE.into(),
        ext: Ext::default(),
        signed: SignedFields {
            signing_key_id: "sender".into(),
            signature_alg: SignatureAlg::Ed25519,
            signature: String::new(),
        },
        envelope_id: id.into(),
        source_principal_id: "alice".into(),
        source_device_id: "sender".into(),
        target_delivery_id: target.into(),
        routing_set_id: None,
        delivery_class: DeliveryClass::OpaqueEvent,
        priority: Priority::Normal,
        ttl: 3600,
        created_at: i64::try_from(ramflux_node_core::now_unix_seconds())?,
        encrypted_payload: "opaque".into(),
        payload_hash: ramflux_protocol::encode_base64url([43; 32]),
    };
    envelope
        .ext
        .ext
        .insert("source_root_commitment".into(), serde_json::json!(source.root_commitment()));
    envelope.signed.signature = ramflux_crypto::sign_canonical_bytes(
        &ramflux_protocol::envelope_sender_signed_bytes(&envelope)?,
    );
    envelope.ext.ext.insert("source_device_authority".into(), serde_json::to_value(authority)?);
    Ok(envelope)
}
fn directory() -> Result<Directory, Box<dyn std::error::Error>> {
    let path = std::env::temp_dir().join(format!(
        "rf-cutover-{}",
        ramflux_protocol::encode_base64url(ramflux_crypto::random_32()?)
    ));
    std::fs::create_dir(&path)?;
    Ok(Directory(path))
}
fn stripe(target: &str) -> u64 {
    let mut h = std::collections::hash_map::DefaultHasher::new();
    target.hash(&mut h);
    h.finish() % 64
}
#[test]
fn sync_and_async_submit_refuse_cutover_without_sequence_or_live_push_while_colliding_target_succeeds()
-> TestResult {
    let dir = directory()?;
    let store = RouterRedbStore::open(dir.0.join("router.redb"))?;
    let state = Arc::new(RouterCore::new());
    let unrelated = (0..4096)
        .map(|i| format!("unrelated-{i}"))
        .find(|target| stripe(target) == stripe("moving"))
        .ok_or("stripe collision")?;
    let map = [DeliveryMapEntry {
        device_ref: ramflux_protocol::custody::DeviceRef {
            account_anchor: "anchor".into(),
            device_id: "moving".into(),
            device_epoch: 1,
        },
        target_delivery_id: "moving".into(),
    }];
    let cutover = store.migration_submission_barrier(&map)?;
    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
    let semaphore = Arc::new(tokio::sync::Semaphore::new(1));
    for i in 0..4 {
        let response = submit_envelope(
            &state,
            &store,
            AsyncForwardContext {
                client: None,
                semaphore: &semaphore,
                timeout: std::time::Duration::from_secs(1),
            },
            envelope("moving", &format!("moving-{i}"))?,
            Instant::now(),
            RouterEnvelopeOrigin::Federation,
        )?;
        assert_eq!(response.migration_refusal, Some(Refusal::MigrationInProgress));
        assert_eq!(response.inbox_seq, None);
        let response = runtime.block_on(submit_envelope_async(
            &state,
            &store,
            AsyncForwardContext {
                client: None,
                semaphore: &semaphore,
                timeout: std::time::Duration::from_secs(1),
            },
            envelope("moving", &format!("async-{i}"))?,
            Instant::now(),
            RouterEnvelopeOrigin::Federation,
        ))?;
        assert_eq!(response.migration_refusal, Some(Refusal::MigrationInProgress));
        let response = submit_envelope(
            &state,
            &store,
            AsyncForwardContext {
                client: None,
                semaphore: &semaphore,
                timeout: std::time::Duration::from_secs(1),
            },
            envelope(&unrelated, &format!("other-{i}"))?,
            Instant::now(),
            RouterEnvelopeOrigin::Federation,
        )?;
        assert_eq!(response.outcome, "offline_queued");
        assert_eq!(response.inbox_seq, Some(i + 1));
    }
    assert_eq!(state.resume("moving", 0, 10).len(), 0);
    drop(cutover);
    let response = submit_envelope(
        &state,
        &store,
        AsyncForwardContext {
            client: None,
            semaphore: &semaphore,
            timeout: std::time::Duration::from_secs(1),
        },
        envelope("moving", "retry")?,
        Instant::now(),
        RouterEnvelopeOrigin::Federation,
    )?;
    assert_eq!(response.inbox_seq, Some(1), "refused attempts did not consume sequences");
    Ok(())
}
#[test]
fn repeated_remote_submits_to_committed_home_return_signed_refusal_without_abort() -> TestResult {
    let dir = directory()?;
    let path = dir.0.join("router.redb");
    let home: serde_json::Value = serde_json::from_str(include_str!(
        "../../../crates/ramflux-crypto/tests/fixtures/home_migration_v1.json"
    ))?;
    let head: ramflux_protocol::home_migration::RecordEvidence =
        serde_json::from_value(home["committed_home"].clone())?;
    let ramflux_protocol::home_migration::HomeRecord::Committed { authorization, .. } =
        &head.record
    else {
        return Err("committed fixture".into());
    };
    {
        let db = redb::Database::create(&path)?;
        let tx = db.begin_write()?;
        tx.open_table(redb::TableDefinition::<&str, &[u8]>::new("home_head_v1"))?
            .insert(head.record.account_anchor(), serde_json::to_vec(&head)?.as_slice())?;
        tx.open_table(redb::TableDefinition::<&str, &[u8]>::new("migration_inbox_routes_v1"))?.insert("moving", serde_json::to_vec(&serde_json::json!({"anchor":head.record.account_anchor(),"migration_id":authorization.body.migration_id,"epoch":head.record.epoch(),"active":false}))?.as_slice())?;
        tx.commit()?;
    }
    let store = RouterRedbStore::open(&path)?;
    let state = RouterCore::new();
    state.set_node_service_signer(Some(NodeServiceSigningKey::from_seed([8; 32])));
    let semaphore = Arc::new(tokio::sync::Semaphore::new(1));
    for i in 0..16 {
        let response = submit_envelope(
            &state,
            &store,
            AsyncForwardContext {
                client: None,
                semaphore: &semaphore,
                timeout: std::time::Duration::from_secs(1),
            },
            envelope("moving", &format!("late-{i}"))?,
            Instant::now(),
            RouterEnvelopeOrigin::Federation,
        )?;
        assert_eq!(response.migration_refusal, Some(Refusal::HomeMigrated));
        let nack = response.nack.ok_or("signed migration refusal")?;
        ramflux_crypto::verify_canonical_signature(
            &ramflux_protocol::signed_bytes(&nack)?,
            &nack.signed.signature,
            &head.node_record.body.node_signing_public_key,
        )?;
    }
    assert_eq!(state.resume("moving", 0, 10).len(), 0);
    Ok(())
}

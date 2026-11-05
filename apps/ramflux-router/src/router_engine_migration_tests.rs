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
pub(super) struct Directory(pub(super) std::path::PathBuf);
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
pub(super) fn envelope(
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
pub(super) fn directory() -> Result<Directory, Box<dyn std::error::Error>> {
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
    let store = Arc::new(RouterRedbStore::open(dir.0.join("router.redb"))?);
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
    let store = Arc::new(RouterRedbStore::open(&path)?);
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

#[test]
fn new_source_submission_after_commit_is_forwarded_or_refused_never_spooled() -> TestResult {
    use crate::router_runtime::tests::{current_envelope, test_router};
    let (state, store, path) = test_router("source-cutover")?;
    let message = current_envelope("source-cutover", "remote-target")?;
    let source = state.authenticated_envelope_source_durable(&message, &store)?;
    let semaphore = Arc::new(tokio::sync::Semaphore::new(1));
    let forward = AsyncForwardContext {
        client: None,
        semaphore: &semaphore,
        timeout: std::time::Duration::from_secs(1),
    };
    // Positive arm: an active source can submit to this same unrelated target.
    assert_eq!(
        submit_envelope(
            &state,
            &store,
            forward,
            message.clone(),
            Instant::now(),
            RouterEnvelopeOrigin::Gateway
        )?
        .outcome,
        "offline_queued"
    );
    drop(state);
    drop(store);
    // Install the durable source gate and retained proof independently of target routing.
    let home: serde_json::Value = serde_json::from_str(include_str!(
        "../../../crates/ramflux-crypto/tests/fixtures/home_migration_v1.json"
    ))?;
    {
        let db = redb::Database::create(&path)?;
        let tx = db.begin_write()?;
        tx.open_table(redb::TableDefinition::<&str, &[u8]>::new("home_root_gates_v1"))?.insert(
            source.root_commitment(),
            serde_json::to_vec(&Refusal::HomeMigrated)?.as_slice(),
        )?;
        tx.open_table(redb::TableDefinition::<&str, &[u8]>::new("home_head_v1"))?.insert(
            source.root_commitment(),
            serde_json::to_vec(&home["committed_home"])?.as_slice(),
        )?;
        tx.commit()?;
    }
    let store = Arc::new(RouterRedbStore::open(&path)?);
    let state = Arc::new(store.load_router()?.ok_or("reopened router")?);
    state.set_node_service_signer(Some(NodeServiceSigningKey::from_seed([8; 32])));
    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
    let client = crate::router_runtime::LocalFederationForwardClient {
        url: "http://127.0.0.1:1/forward".into(),
        admin_token: None,
        source_node_id: "A".into(),
    };
    for asynchronous in [false, true] {
        for client in [None, Some(&client)] {
            let forward = AsyncForwardContext { client, ..forward };
            let response = if asynchronous {
                runtime.block_on(submit_envelope_async(
                    &state,
                    &store,
                    forward,
                    current_envelope("after-source-commit", "remote-target")?,
                    Instant::now(),
                    RouterEnvelopeOrigin::Gateway,
                ))?
            } else {
                submit_envelope(
                    &state,
                    &store,
                    forward,
                    current_envelope("after-source-commit", "remote-target")?,
                    Instant::now(),
                    RouterEnvelopeOrigin::Gateway,
                )?
            };
            assert_eq!(response.migration_refusal, Some(Refusal::HomeMigrated));
            assert_eq!(response.inbox_seq, None);
            let nack = response.nack.ok_or("signed source refusal")?;
            ramflux_crypto::verify_canonical_signature(
                &ramflux_protocol::signed_bytes(&nack)?,
                &nack.signed.signature,
                home["committed_home"]["node_record"]["body"]["node_signing_public_key"]
                    .as_str()
                    .ok_or("source key")?,
            )?;
        }
    }
    assert_eq!(
        state.resume("remote-target", 0, 10).len(),
        1,
        "refused submissions allocate no new inbox entries"
    );
    assert_eq!(semaphore.available_permits(), 1);
    Ok(())
}

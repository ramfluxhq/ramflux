// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain
#![allow(clippy::unwrap_used, clippy::too_many_lines)]
use super::*;
use crate::relay::test_support::*;
use crate::*;
use ramflux_protocol::large_attachment::{ContentManifest, ScopedAttachmentGrant};
use redb::ReadableTableMetadata;
use std::{fs, sync::Mutex};
fn bytes(s: &str) -> Vec<u8> {
    s.as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|v| u8::from_str_radix(std::str::from_utf8(v).unwrap(), 16).unwrap())
        .collect()
}
fn fixtures() -> (VerifiedContentManifest, VerifiedScopedGrant) {
    let j: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../../ramflux-protocol/tests/fixtures/large_attachment_v1.json"
    ))
    .unwrap();
    let c = &j["cases"][0];
    let mc = bytes(c["content_manifest_unsigned_hex"].as_str().unwrap());
    let mut signed = u32::try_from(mc.len()).unwrap().to_be_bytes().to_vec();
    signed.extend(mc);
    signed.extend(64_u32.to_be_bytes());
    signed.extend(bytes(c["content_signature_hex"].as_str().unwrap()));
    let g = bytes(c["grant_unsigned_hex"].as_str().unwrap());
    let mut grant = b"RFC1".to_vec();
    grant.extend(u32::try_from(g.len()).unwrap().to_be_bytes());
    grant.extend(g);
    grant.extend(64_u32.to_be_bytes());
    grant.extend(bytes(c["grant_signature_hex"].as_str().unwrap()));
    (
        ContentManifest::decode_signed(&signed).unwrap(),
        ScopedAttachmentGrant::decode_signed(&grant).unwrap(),
    )
}
fn owner_seed() -> [u8; 32] {
    std::array::from_fn(|i| u8::try_from(i).unwrap())
}
struct Auth {
    token: RelayTokenV3,
    proof: OwnerAuthorizationProof,
    pop: RequesterProofOfPossession,
    cache: RelayTrustSnapshotCache,
    body: String,
}
impl Auth {
    fn context(&self) -> ScopedRegistrationAuth<'_> {
        ScopedRegistrationAuth {
            invocation: RelayInvocationV3 {
                token: &self.token,
                issuer_public_key: &self.token.issuer_certificate.attestation_public_key,
                grant: None,
                owner_proof: Some(&self.proof),
                pop: &self.pop,
                expected_audience_node_id: V3_AUDIENCE_NODE,
                expected_body_hash: &self.body,
                capability: ObjectRelayCapability::Put,
                now: self.token.issued_at,
            },
            certificate: &self.token.issuer_certificate,
            pinned_trust: &self.cache,
        }
    }
}
fn authority_token(
    native: &VerifiedContentManifest,
    mut token: RelayTokenV3,
    now: u64,
) -> (RelayTokenV3, RelayTrustSnapshotCache) {
    let owner = &native.manifest().owner;
    let cert = v3_certificate(now, |c| {
        c.node_id = owner.home_node_id.clone();
    })
    .unwrap();
    token.issuer_certificate = cert;
    token.issuer_node_id = owner.home_node_id.clone();
    token.object_id = hex(&native.manifest().object_id);
    token.manifest_hash = hex(&native.manifest().hash().unwrap());
    token.owner_home_node_id = owner.home_node_id.clone();
    token.owner_principal_id = owner.account_anchor.clone();
    token.owner_device_epoch = owner.device_epoch;
    token.owner_signing_key_id = owner.device_id.clone();
    token.owner_public_key = ramflux_protocol::encode_base64url(owner.signing_public_key);
    let mut cache = RelayTrustSnapshotCache::new();
    cache
        .update(
            v3_trust_snapshot(now, |s| {
                s.node_id = owner.home_node_id.clone();
                s.roots[0].node_id = owner.home_node_id.clone();
            }),
            &owner.home_node_id,
            now,
        )
        .unwrap();
    (token, cache)
}
fn auth(native: &VerifiedContentManifest, grant: &VerifiedScopedGrant, now: u64) -> Auth {
    let owner = &native.manifest().owner;
    let body = hex(&grant.grant().hash().unwrap());
    let mut proof = v3_signed_owner_proof(now, ObjectRelayCapability::Put).unwrap();
    proof.object_id = hex(&native.manifest().object_id);
    proof.manifest_hash = Some(hex(&native.manifest().hash().unwrap()));
    proof.owner_home_node_id = owner.home_node_id.clone();
    proof.owner_principal_id = owner.account_anchor.clone();
    proof.owner_device_epoch = owner.device_epoch;
    proof.owner_signing_key_id = owner.device_id.clone();
    proof.owner_public_key = ramflux_protocol::encode_base64url(owner.signing_public_key);
    proof.body_hash = body.clone();
    proof.owner_signature =
        v3_sign(&owner_authorization_proof_signing_bytes(&proof).unwrap(), owner_seed());
    let binding = owner_authorization_proof_binding_hash(&proof).unwrap();
    let (token, cache) = authority_token(
        native,
        v3_owner_session_token(now, ObjectRelayCapability::Put, binding).unwrap(),
        now,
    );
    let mut token = token;
    token.requester_device_id = owner.device_id.clone();
    token.requester_public_key = token.owner_public_key.clone();
    token.requester_device_epoch = owner.device_epoch;
    token.requester_device_hash = ramflux_crypto::blake3_256_base64url(
        "ramflux.object_relay.recipient_device.v1",
        owner.device_id.as_bytes(),
    );
    v3_resign_token(&mut token).unwrap();
    let mut pop = v3_signed_pop(&token, ObjectRelayCapability::Put, owner_seed(), now).unwrap();
    pop.body_hash = body.clone();
    pop.signature = v3_sign(&requester_pop_signing_bytes(&pop).unwrap(), owner_seed());
    Auth { token, proof, pop, cache, body }
}
fn signed(g: &ScopedAttachmentGrant) -> VerifiedScopedGrant {
    let signature =
        SigningKey::from_bytes(&owner_seed()).sign(&g.signing_bytes().unwrap()).to_bytes();
    ScopedAttachmentGrant::decode_signed(&g.signed_bytes(&signature).unwrap()).unwrap()
}
#[test]
fn large_scoped_grants_bind_reference_owner_and_grantee() {
    let now = 1_700_000_001;
    let (native, grant) = fixtures();
    let root = std::env::temp_dir().join(format!(
        "rf-grants-{}-{}",
        std::process::id(),
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
    ));
    fs::create_dir_all(&root).unwrap();
    let path = root.join("db");
    let store = RelayRedbStore::open(&path).unwrap();
    let ledger = store.attachment_ledger(super::super::AttachmentPolicy::default()).unwrap();
    let owner =
        AttachmentOwner::from_authenticated_session(&native.manifest().owner.account_anchor)
            .unwrap();
    let upload = [21; 32];
    ledger
        .reserve(
            &owner,
            super::super::AttachmentReservationRequest {
                upload_id: upload,
                object_id: native.manifest().object_id,
                layout: native.manifest().layout,
            },
            now - 1,
        )
        .unwrap();
    ledger.bind(&owner, &upload, &native, now - 1).unwrap();
    ledger.commit(&owner, &upload, now - 1).unwrap();
    let signer = SigningKey::from_bytes(&[77; 32]);
    let config = AttachmentAuthority {
        source: V3_AUDIENCE_NODE.into(),
        generation: 4,
        signing_public_key: signer.verifying_key().to_bytes(),
    };
    let registry = ledger.scoped_grants(config.clone()).unwrap();
    let proof = auth(&native, &grant, now);
    let registered =
        registry.register(&upload, &native, &grant, &proof.context(), &signer).unwrap();
    assert_eq!(registered.state, ScopedGrantState::Active);
    let capability = ramflux_protocol::decode_base64url(&registered.capability).unwrap();
    let (decoded, receipt) = AttachmentRegistrationReceipt::decode_capability(
        &capability,
        &config.source,
        4,
        &config.signing_public_key,
        now,
    )
    .unwrap();
    assert_eq!(decoded.grant(), grant.grant());
    assert_eq!(receipt.grant_hash, grant.grant().hash().unwrap());
    assert!(
        AttachmentRegistrationReceipt::decode_capability(
            &grant.signed_bytes().unwrap(),
            &config.source,
            4,
            &config.signing_public_key,
            now
        )
        .is_err()
    );
    assert!(
        AttachmentRegistrationReceipt::decode_capability(
            &capability,
            &config.source,
            5,
            &config.signing_public_key,
            now
        )
        .is_err()
    );
    assert_eq!(
        registry.register(&upload, &native, &grant, &proof.context(), &signer).unwrap().capability,
        registered.capability
    );
    for field in 0..3 {
        let mut changed = grant.grant().clone();
        match field {
            0 => changed.reference_id[0] ^= 1,
            1 => changed.grantee.device_id = "substituted-grantee".into(),
            _ => changed.owner.account_anchor = "other-owner".into(),
        }
        let changed = signed(&changed);
        let auth = auth(&native, &changed, now);
        assert!(registry.register(&upload, &native, &changed, &auth.context(), &signer).is_err());
    }
    let mut independent = grant.grant().clone();
    independent.grant_id[0] ^= 1;
    independent.grantee.device_id = "independent-recipient".into();
    let independent = signed(&independent);
    let independent_auth = auth(&native, &independent, now);
    registry
        .register(&upload, &native, &independent, &independent_auth.context(), &signer)
        .unwrap();
    assert!(
        AttachmentRegistrationReceipt::decode_capability(
            &capability,
            &config.source,
            4,
            &config.signing_public_key,
            receipt.expires_at
        )
        .is_err()
    );
    {
        let tx = ledger.db.begin_read().unwrap();
        assert_eq!(tx.open_table(GRANTS).unwrap().len().unwrap(), 2);
        assert_eq!(tx.open_table(REFERENCES).unwrap().len().unwrap(), 2);
    }
    assert!(
        AttachmentRegistrationReceipt::decode_capability(
            &capability,
            &config.source,
            4,
            &config.signing_public_key,
            grant.grant().issued_at - 6
        )
        .is_err()
    );
    let mut bad_epoch = auth(&native, &grant, now);
    bad_epoch.token.owner_device_epoch += 1;
    v3_resign_token(&mut bad_epoch.token).unwrap();
    assert!(registry.register(&upload, &native, &grant, &bad_epoch.context(), &signer).is_err());
    let mut absent = auth(&native, &grant, now);
    absent.cache = RelayTrustSnapshotCache::new();
    assert!(registry.register(&upload, &native, &grant, &absent.context(), &signer).is_err());
    // A valid legacy grant/PoP still cannot dispatch the native payload through Get/Ack.
    let mut shadow = t14d_tombstone_chunk(ramflux_protocol::encode_base64url(
        native.manifest().owner.signing_public_key,
    ));
    shadow.object_id = hex(&native.manifest().object_id);
    shadow.manifest_hash = hex(&native.manifest().hash().unwrap());
    shadow.owner_signing_key_id = native.manifest().owner.device_id.clone();
    shadow.expires_at = now + 100;
    shadow.chunk_cipher_hash = object_relay_chunk_cipher_hash(
        &shadow.manifest_hash,
        shadow.chunk_index,
        &shadow.encrypted_chunk,
    );
    store.record_relay_chunk_entry(&shadow).unwrap();
    let mut cache = RelayCacheState::new();
    cache.put_chunk(shadow.clone()).unwrap();
    let state = Mutex::new(cache);
    let meta = RelayChunkMeta::from(&shadow);
    for capability in [ObjectRelayCapability::Get, ObjectRelayCapability::Ack] {
        let mut legacy = v3_signed_grant(now, vec![capability]).unwrap();
        legacy.object_id = shadow.object_id.clone();
        legacy.manifest_hash = shadow.manifest_hash.clone();
        legacy.owner_signing_key_id = shadow.owner_signing_key_id.clone();
        legacy.owner_public_key = shadow.owner_public_key.clone();
        legacy.owner_signature =
            v3_sign(&object_access_grant_signing_bytes(&legacy).unwrap(), owner_seed());
        let binding = object_access_grant_binding_hash(&legacy).unwrap();
        let (mut token, pins) =
            authority_token(&native, v3_grant_token(now, capability, binding).unwrap(), now);
        v3_resign_token(&mut token).unwrap();
        let pop = v3_signed_pop(&token, capability, V3_REQUESTER_SEED, now).unwrap();
        verify_relay_token_v3_with_trust_snapshot(
            &token,
            &token.issuer_certificate,
            pins.current(&token.issuer_node_id, now).unwrap(),
            capability,
            V3_AUDIENCE_NODE,
            now,
        )
        .unwrap();
        verify_relay_invocation_v3(&RelayInvocationV3 {
            token: &token,
            issuer_public_key: &token.issuer_certificate.attestation_public_key,
            grant: Some(&legacy),
            owner_proof: None,
            pop: &pop,
            expected_audience_node_id: V3_AUDIENCE_NODE,
            expected_body_hash: V3_BODY_HASH,
            capability,
            now,
        })
        .unwrap();
        let refused = if capability == ObjectRelayCapability::Get {
            relay_store_read_through(&store, &state, &meta, now).map(|_| ())
        } else {
            relay_store_ack(&store, &state, |_| Ok(meta.clone())).map(|_| ())
        };
        assert!(matches!(refused, Err(RelayStoreOpError::Unauthorized(_))));
    }
    assert_eq!(
        store.relay_chunk_entry(&shadow.chunk_id).unwrap().unwrap().encrypted_chunk,
        shadow.encrypted_chunk
    );
    assert_eq!(state.lock().unwrap().reserved_bytes(), 0);
    // Existing bound native rows install the format index at normal open, before writes.
    {
        let tx = ledger.db.begin_write().unwrap();
        tx.delete_table(super::super::format::NATIVE).unwrap();
        tx.delete_table(super::super::format::SCHEMA).unwrap();
        tx.commit().unwrap();
    }
    drop(registry);
    drop(ledger);
    drop(store);
    let store = RelayRedbStore::open(&path).unwrap();
    assert!(
        store
            .ensure_generic_attachment_format(&shadow.object_id, Some(&shadow.manifest_hash))
            .is_err()
    );
    assert!(store.ensure_generic_attachment_format(&shadow.object_id, Some("not-a-hash")).is_err());
    assert!(
        store.ensure_generic_attachment_format(&shadow.object_id, Some(&hex(&[0; 32]))).is_err()
    );
    store.ensure_generic_attachment_format("generic-control", Some("generic-manifest")).unwrap();
    let ledger = store.attachment_ledger(super::super::AttachmentPolicy::default()).unwrap();
    let registry = ledger.scoped_grants(config.clone()).unwrap();
    assert_eq!(
        registry.lookup(&grant.grant().grant_id).unwrap().unwrap().capability,
        registered.capability
    );
    assert!(ledger.scoped_grants(AttachmentAuthority { generation: 5, ..config.clone() }).is_err());
    {
        let tx = ledger.db.begin_write().unwrap();
        let mut row = registered;
        row.state = ScopedGrantState::Retired;
        tx.open_table(GRANTS)
            .unwrap()
            .insert(grant.grant().grant_id.as_slice(), serde_json::to_vec(&row).unwrap().as_slice())
            .unwrap();
        tx.commit().unwrap();
    }
    assert!(registry.register(&upload, &native, &grant, &proof.context(), &signer).is_err());
    assert_eq!(
        registry.lookup(&independent.grant().grant_id).unwrap().unwrap().state,
        ScopedGrantState::Active
    );
    assert_eq!(registry.gc_expired(grant.grant().expires_at + 305, 64).unwrap(), 2);
    assert!(registry.lookup(&grant.grant().grant_id).unwrap().is_none());
    assert!(registry.register(&upload, &native, &grant, &proof.context(), &signer).is_err());
    drop(registry);
    drop(ledger);
    drop(store);
    fs::remove_dir_all(root).unwrap();
}

mod admission_tests;

// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain
#![allow(clippy::unwrap_used, clippy::too_many_lines)]
use super::*;
fn native_for(
    original: &VerifiedContentManifest,
    account: &str,
    object: [u8; 32],
) -> VerifiedContentManifest {
    let mut m = original.manifest().clone();
    m.owner.account_anchor = account.into();
    m.object_id = object;
    let signature =
        SigningKey::from_bytes(&owner_seed()).sign(&m.signing_bytes().unwrap()).to_bytes();
    ContentManifest::decode_signed(&m.signed_bytes(&signature).unwrap()).unwrap()
}
fn payload(
    ledger: &AttachmentLedger,
    native: &VerifiedContentManifest,
    upload: [u8; 32],
    now: u64,
) {
    let owner =
        AttachmentOwner::from_authenticated_session(&native.manifest().owner.account_anchor)
            .unwrap();
    ledger
        .reserve(
            &owner,
            super::super::super::AttachmentReservationRequest {
                upload_id: upload,
                object_id: native.manifest().object_id,
                layout: native.manifest().layout,
            },
            now - 1,
        )
        .unwrap();
    ledger.bind(&owner, &upload, native, now - 1).unwrap();
    ledger.commit(&owner, &upload, 1, now - 1).unwrap();
}
fn registration(g: &VerifiedScopedGrant, native: &VerifiedContentManifest) -> VerifiedScopedGrant {
    let mut value = g.grant().clone();
    value.owner = native.manifest().owner.clone();
    value.object_id = native.manifest().object_id;
    value.manifest_hash = native.manifest().hash().unwrap();
    signed(&value)
}
#[test]
fn reference_collision_with_fresh_grant_and_second_upload_is_refused() {
    let now = 1_700_000_001;
    let (native, grant) = fixtures();
    let root = ramflux_test_support::TestPath::new()
        .expect("test: allocate fixture directory")
        .child(format!(
            "rf-ref-binding-{}-{}",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));
    fs::create_dir_all(&root).unwrap();
    let store = RelayRedbStore::open(root.join("db")).unwrap();
    let ledger = store.attachment_ledger(crate::AttachmentPolicy::default()).unwrap();
    let signer = SigningKey::from_bytes(&[77; 32]);
    let registry = ledger
        .scoped_grants(AttachmentAuthority {
            source: V3_AUDIENCE_NODE.into(),
            generation: 4,
            signing_public_key: signer.verifying_key().to_bytes(),
        })
        .unwrap();
    payload(&ledger, &native, [21; 32], now);
    let proof = auth(&native, &grant, now);
    registry.register(&[21; 32], &native, &grant, &proof.context(), &signer).unwrap();
    let second = native_for(&native, &native.manifest().owner.account_anchor, [92; 32]);
    payload(&ledger, &second, [22; 32], now);
    let mut fresh = registration(&grant, &second).grant().clone();
    fresh.grant_id = [93; 32];
    let fresh = signed(&fresh);
    let proof = auth(&second, &fresh, now);
    assert_ne!(fresh.grant().grant_id, grant.grant().grant_id);
    assert_eq!(fresh.grant().reference_id, grant.grant().reference_id);
    assert!(matches!(
        registry.register(&[22; 32], &second, &fresh, &proof.context(), &signer),
        Err(AttachmentLedgerError::Conflict)
    ));
    let tx = ledger.db.begin_read().unwrap();
    assert_eq!(tx.open_table(GRANTS).unwrap().len().unwrap(), 1);
    assert_eq!(tx.open_table(REFERENCES).unwrap().len().unwrap(), 1);
    drop(tx);
    drop(registry);
    drop(ledger);
    drop(store);
    fs::remove_dir_all(root).unwrap();
}
#[test]
fn owner_grant_cap_and_reference_seek_ignore_unrelated_owner_volume() {
    let now = 1_700_000_001;
    let (native, grant) = fixtures();
    let root = ramflux_test_support::TestPath::new()
        .expect("test: allocate fixture directory")
        .child(format!(
            "rf-owner-grants-{}-{}",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));
    fs::create_dir_all(&root).unwrap();
    let path = root.join("db");
    let store = RelayRedbStore::open(&path).unwrap();
    let ledger = store.attachment_ledger(crate::AttachmentPolicy::default()).unwrap();
    let signer = SigningKey::from_bytes(&[77; 32]);
    let authority = AttachmentAuthority {
        source: V3_AUDIENCE_NODE.into(),
        generation: 4,
        signing_public_key: signer.verifying_key().to_bytes(),
    };
    let registry = ledger.scoped_grants(authority.clone()).unwrap();
    payload(&ledger, &native, [21; 32], now);
    let proof = auth(&native, &grant, now);
    let row = registry.register(&[21; 32], &native, &grant, &proof.context(), &signer).unwrap();
    // Seed complete signed records and both indexes: this volume is unrelated to owner B.
    {
        let tx = ledger.db.begin_write().unwrap();
        for nonce in 0..SCOPED_GRANTS_PER_OWNER_MAX - 1 {
            let mut g = grant.grant().clone();
            g.grant_id[..8].copy_from_slice(&nonce.to_be_bytes());
            let g = signed(&g);
            let receipt = AttachmentRegistrationReceipt {
                grant_hash: g.grant().hash().unwrap(),
                grant_epoch: 1,
                source_authority: authority.source.clone(),
                authority_generation: 4,
                expires_at: row.expires_at,
            };
            let sig = signer.sign(&receipt.signing_bytes().unwrap()).to_bytes();
            let mut seeded = row.clone();
            seeded.capability = ramflux_protocol::encode_base64url(
                receipt.capability(&g, &sig, &authority.signing_public_key).unwrap(),
            );
            tx.open_table(GRANTS)
                .unwrap()
                .insert(
                    g.grant().grant_id.as_slice(),
                    serde_json::to_vec(&seeded).unwrap().as_slice(),
                )
                .unwrap();
            let mut r = g.grant().reference_id.to_vec();
            r.extend(g.grant().grant_id);
            tx.open_table(REFERENCES).unwrap().insert(r.as_slice(), ()).unwrap();
            tx.open_table(EXPIRY)
                .unwrap()
                .insert(deadline(g.grant().expires_at + 305, &g.grant().grant_id).as_slice(), ())
                .unwrap();
            admission::record(&tx, &g.grant().grant_id, &g.grant().owner.account_anchor).unwrap();
        }
        tx.commit().unwrap();
    }
    let mut extra = grant.grant().clone();
    extra.grant_id = [94; 32];
    extra.reference_id = [95; 32];
    let extra = signed(&extra);
    let proof = auth(&native, &extra, now);
    assert!(matches!(
        registry.register(&[21; 32], &native, &extra, &proof.context(), &signer),
        Err(AttachmentLedgerError::Capacity)
    ));
    // Same upload/object bytes across accounts isolates the reference-owner condition.
    let other = native_for(&native, "other-owner", native.manifest().object_id);
    payload(&ledger, &other, [21; 32], now);
    let mut collision = registration(&grant, &other).grant().clone();
    collision.grant_id = [96; 32];
    let collision = signed(&collision);
    let proof = auth(&other, &collision, now);
    admission::REFERENCE_VISITS.with(|n| n.set(0));
    assert!(matches!(
        registry.register(&[21; 32], &other, &collision, &proof.context(), &signer),
        Err(AttachmentLedgerError::Conflict)
    ));
    admission::REFERENCE_VISITS.with(|n| assert_eq!(n.get(), 2));
    let mut distinct = collision.grant().clone();
    distinct.reference_id = [250; 32];
    let distinct = signed(&distinct);
    let proof = auth(&other, &distinct, now);
    admission::REFERENCE_VISITS.with(|n| n.set(0));
    registry.register(&[21; 32], &other, &distinct, &proof.context(), &signer).unwrap();
    admission::REFERENCE_VISITS.with(|n| assert!(n.get() <= 2));
    {
        let tx = ledger.db.begin_read().unwrap();
        assert_eq!(tx.open_table(GRANTS).unwrap().len().unwrap(), SCOPED_GRANTS_PER_OWNER_MAX + 1);
    }
    // Rebuild counts from a historical database, before any new admission/write.
    {
        let tx = ledger.db.begin_write().unwrap();
        tx.delete_table(admission::OWNER_COUNTS).unwrap();
        tx.delete_table(admission::GRANT_OWNERS).unwrap();
        tx.delete_table(admission::SCHEMA).unwrap();
        tx.commit().unwrap();
    }
    drop(registry);
    drop(ledger);
    drop(store);
    let store = RelayRedbStore::open(&path).unwrap();
    let ledger = store.attachment_ledger(crate::AttachmentPolicy::default()).unwrap();
    let registry = ledger.scoped_grants(authority).unwrap();
    let proof = auth(&native, &extra, now);
    assert!(matches!(
        registry.register(&[21; 32], &native, &extra, &proof.context(), &signer),
        Err(AttachmentLedgerError::Capacity)
    ));
    {
        let tx = ledger.db.begin_read().unwrap();
        let counts = tx.open_table(admission::OWNER_COUNTS).unwrap();
        assert_eq!(
            counts.get(native.manifest().owner.account_anchor.as_str()).unwrap().unwrap().value(),
            SCOPED_GRANTS_PER_OWNER_MAX
        );
        assert_eq!(counts.get("other-owner").unwrap().unwrap().value(), 1);
    }
    assert_eq!(registry.gc_expired(grant.grant().expires_at + 305, 1).unwrap(), 1);
    {
        let tx = ledger.db.begin_read().unwrap();
        assert_eq!(
            tx.open_table(admission::GRANT_OWNERS).unwrap().len().unwrap(),
            SCOPED_GRANTS_PER_OWNER_MAX
        );
    }
    drop(registry);
    drop(ledger);
    drop(store);
    fs::remove_dir_all(root).unwrap();
}

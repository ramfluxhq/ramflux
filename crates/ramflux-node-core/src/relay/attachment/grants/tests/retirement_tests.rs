// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain
use super::*;
use ramflux_protocol::large_attachment::AttachmentRetirement;
#[test]
fn large_retired_grant_blocks_old_token_renewal_and_late_publish() {
    let now = 1_700_000_001;
    let (native, grant) = fixtures();
    let root = std::env::temp_dir().join(format!(
        "rf-retire-{}-{}",
        std::process::id(),
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
    ));
    fs::create_dir_all(&root).unwrap();
    let path = root.join("db");
    let store = RelayRedbStore::open(&path).unwrap();
    let ledger = store.attachment_ledger(super::super::super::AttachmentPolicy::default()).unwrap();
    let owner =
        AttachmentOwner::from_authenticated_session(&native.manifest().owner.account_anchor)
            .unwrap();
    let upload = [21; 32];
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
    ledger.bind(&owner, &upload, &native, now - 1).unwrap();
    ledger.commit(&owner, &upload, 1, now - 1).unwrap();
    let signer = SigningKey::from_bytes(&[77; 32]);
    let config = AttachmentAuthority {
        source: V3_AUDIENCE_NODE.into(),
        generation: 4,
        signing_public_key: signer.verifying_key().to_bytes(),
    };
    let registry = ledger.scoped_grants(config.clone()).unwrap();
    let proof = auth(&native, &grant, now);
    registry.register(&upload, &native, &grant, &proof.context(), &signer).unwrap();
    let mut other = grant.grant().clone();
    other.grant_id = [43; 32];
    let other = signed(&other);
    registry
        .register(&upload, &native, &other, &auth(&native, &other, now).context(), &signer)
        .unwrap();
    let held = registry.lease_after_operation_admission(&grant, 1, now).unwrap();
    let request = AttachmentRetirement {
        reference_id: grant.grant().reference_id,
        grant_id: grant.grant().grant_id,
        grant_hash: grant.grant().hash().unwrap(),
        grant_epoch: 1,
        source_authority: config.source.clone(),
        authority_generation: 4,
        operation_id: [99; 32],
        issued_at: now,
    };
    let sig =
        SigningKey::from_bytes(&owner_seed()).sign(&request.signing_bytes().unwrap()).to_bytes();
    let retirement = AttachmentRetirement::verify(
        &request.canonical_bytes().unwrap(),
        &sig,
        &grant.grant().owner.signing_public_key,
    )
    .unwrap();
    let body = hex(blake3::hash(&request.signing_bytes().unwrap()).as_bytes());
    let proof = auth_for(&native, now, ObjectRelayCapability::Tombstone, body);
    // A separately opened registry shares the same publication owner.
    let second = ledger.scoped_grants(config.clone()).unwrap();
    assert_eq!(
        second.retire(&retirement, &proof.context()).unwrap(),
        RetirementOutcome::RevocationPending
    );
    assert!(held.cancelled());
    let mut published = false;
    assert!(
        held.publish(now, || {
            published = true;
            Ok(())
        })
        .is_err()
    );
    assert!(!published);
    for right in [1, 2, 4, 8, 16] {
        assert!(registry.lease_after_operation_admission(&grant, right, now).is_err());
    }
    assert_eq!(
        registry.lookup(&grant.grant().grant_id).unwrap().unwrap().state,
        ScopedGrantState::Retiring
    );
    assert_eq!(
        registry.retire(&retirement, &proof.context()).unwrap(),
        RetirementOutcome::RevocationPending
    );
    registry
        .lease_after_operation_admission(&other, 1, now)
        .unwrap()
        .publish(now, || Ok(()))
        .unwrap();
    let (release, blocked) = std::sync::mpsc::channel();
    let worker = std::thread::spawn(move || {
        blocked.recv().unwrap();
        let mut late = false;
        let result = held.publish(now, || {
            late = true;
            Ok(())
        });
        (result, late)
    });
    assert_eq!(
        registry.retire(&retirement, &proof.context()).unwrap(),
        RetirementOutcome::RevocationPending
    );
    release.send(()).unwrap();
    let (result, late) = worker.join().unwrap();
    assert!(result.is_err());
    assert!(!late);
    assert_eq!(second.retire(&retirement, &proof.context()).unwrap(), RetirementOutcome::Retired);
    assert_eq!(
        registry.lookup(&grant.grant().grant_id).unwrap().unwrap().state,
        ScopedGrantState::Retired
    );
    assert!(
        registry
            .register(&upload, &native, &grant, &auth(&native, &grant, now).context(), &signer)
            .is_err()
    );
    drop(second);
    drop(registry);
    drop(ledger);
    drop(store);
    let store = RelayRedbStore::open(&path).unwrap();
    let registry = store
        .attachment_ledger(super::super::super::AttachmentPolicy::default())
        .unwrap()
        .scoped_grants(config)
        .unwrap();
    assert_eq!(
        registry.lookup(&grant.grant().grant_id).unwrap().unwrap().state,
        ScopedGrantState::Retired
    );
    for right in [1, 8] {
        assert!(registry.lease_after_operation_admission(&grant, right, now).is_err());
    }
    assert_eq!(registry.retire(&retirement, &proof.context()).unwrap(), RetirementOutcome::Retired);
    registry
        .lease_after_operation_admission(&other, 1, now)
        .unwrap()
        .publish(now, || Ok(()))
        .unwrap();
    drop(registry);
    drop(store);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn retirement_accepts_current_owner_devices_and_scopes_operation_ids() {
    use super::super::fixture::RetirementFixture;
    let root = std::env::temp_dir().join(format!("rf-current-owner-{}", std::process::id()));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(&root).unwrap();
    let fixture = RetirementFixture::new(&root.join("db"));
    let r = fixture.request();
    // Each single-field mutation is freshly signed; every binding has an exact refusal.
    for field in 0..7 {
        let mut bad = r.clone();
        match field {
            0 => bad.reference_id[0] ^= 1,
            1 => bad.grant_hash[0] ^= 1,
            2 => bad.grant_epoch += 1,
            3 => bad.source_authority = "other".into(),
            4 => bad.authority_generation += 1,
            5 => bad.issued_at += 6,
            _ => bad.grant_id = [17; 32],
        }
        let result = fixture.retire(&bad);
        if field == 6 {
            assert!(matches!(result, Err(AttachmentLedgerError::State)));
        } else {
            assert!(matches!(result, Err(AttachmentLedgerError::Conflict)));
        }
    }
    let foreign = SigningKey::from_bytes(&[88; 32]);
    let sig = foreign.sign(&r.signing_bytes().unwrap()).to_bytes();
    let signed = AttachmentRetirement::verify(
        &r.canonical_bytes().unwrap(),
        &sig,
        &foreign.verifying_key().to_bytes(),
    )
    .unwrap();
    let body = hex(blake3::hash(&r.signing_bytes().unwrap()).as_bytes());
    let proof = auth_for(&fixture.native, fixture.now, ObjectRelayCapability::Tombstone, body);
    assert!(matches!(
        fixture.registry.retire(&signed, &proof.context()),
        Err(AttachmentLedgerError::Conflict)
    ));
    let mut rotated = fixture.owner();
    rotated.device_epoch += 1;
    rotated.signing_public_key = SigningKey::from_bytes(&[65; 32]).verifying_key().to_bytes();
    assert_eq!(fixture.retire_as(&r, &rotated, [65; 32]).unwrap(), RetirementOutcome::Retired);
    let other = fixture.independent(23);
    let mut r2 = r;
    r2.grant_id = other.grant().grant_id;
    r2.grant_hash = other.grant().hash().unwrap();
    let key = SigningKey::from_bytes(&[66; 32]);
    rotated.device_id = "second-current-device".into();
    rotated.signing_public_key = key.verifying_key().to_bytes();
    assert_eq!(fixture.retire_as(&r2, &rotated, [66; 32]).unwrap(), RetirementOutcome::Retired);
    drop(fixture);
    fs::remove_dir_all(root).unwrap();
}

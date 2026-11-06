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
    ledger.commit(&owner, &upload, now - 1).unwrap();
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

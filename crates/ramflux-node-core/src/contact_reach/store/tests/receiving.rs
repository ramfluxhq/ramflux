// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Actual signed snapshot and Native advancement exercise retained ingress source floors.
use super::*;
#[test]
fn cr_ingress_source_floor_refuses_old_verified_snapshot_without_allocating_new_trust() -> TestResult
{
    let dir = tempfile::TempDir::new()?;
    let path = dir.path().join("source-floor.redb");
    let (store, f) = initialize(&path)?;
    let peer = crate::contact_reach::source::tests::verified_source()?;
    let trust_key = key(&f.root, peer.root())?;
    {
        let tx = store.begin_write()?;
        require_ingress_peer(&tx, &f.root, &peer)?;
        assert!(
            tx.open_table(TRUST)?.get(trust_key.as_str())?.is_none(),
            "checking unsolicited evidence must not allocate a permanent source pin"
        );
        adopt_ingress_peer(&tx, &f.root, &peer)?;
        tx.commit()?;
    }
    let mut branch = peer
        .authority()
        .envelope()
        .body
        .devices
        .first()
        .and_then(|device| device.branch_certificate.as_ref())
        .ok_or("current primary branch")?
        .body
        .clone();
    branch.device_id = "new-sibling".into();
    branch.cert_id = digest(90);
    branch.branch_signing_public_key = ramflux_crypto::public_key_base64url_from_seed([91; 32]);
    let next = f.key.enroll_device(peer.authority(), f.key.certify_branch(branch)?, NOW + 1)?;
    let next = ramflux_crypto::custody::verify_record(&next, NOW + 1, None, None)?;
    let saved = {
        let tx = store.begin_write()?;
        let mut previous: AdoptedPeer =
            row(tx.open_table(TRUST)?.get(trust_key.as_str())?.ok_or("adopted source")?.value())?;
        previous.authority_pins.observe(&next)?;
        let saved = encoded(&previous)?;
        tx.open_table(TRUST)?.insert(trust_key.as_str(), saved.as_slice())?;
        tx.commit()?;
        saved
    };
    drop(store);
    let store = RouterRedbStore::open_without_wal(&path)?;
    let tx = store.begin_write()?;
    assert!(
        require_ingress_peer(&tx, &f.root, &peer).is_err(),
        "a still-valid original snapshot cannot bypass a newer independently retained Native head"
    );
    assert_eq!(
        tx.open_table(TRUST)?.get(trust_key.as_str())?.ok_or("retained source")?.value(),
        saved,
        "refusal cannot lower or replace the retained floor"
    );
    Ok(())
}

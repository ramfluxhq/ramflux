// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

#![cfg(test)]

//! Adopted P17 direct-node SDK fixture. Each client owns a separate root/vault/index.
//! Federation TLS/Fedwire continuity is exercised separately in the federation crate.
#[path = "pairing_multi_device/ceremony.rs"]
mod ceremony;
#[path = "pairing_multi_device/device.rs"]
mod device;
#[path = "pairing_multi_device/full.rs"]
mod full;
#[path = "pairing_multi_device/node.rs"]
mod node;
#[path = "pairing_multi_device/relay.rs"]
mod relay;
#[path = "pairing_multi_device/revoke.rs"]
mod revoke;
#[path = "pairing_multi_device/vault.rs"]
mod vault;
type ResultOf<T> = Result<T, Box<dyn std::error::Error>>;

#[tokio::test]
async fn pairing_three_devices_keep_distinct_keys_and_live_sessions() -> ResultOf<()> {
    deadline(Box::pin(three_devices())).await
}
async fn deadline(work: impl std::future::Future<Output = ResultOf<()>>) -> ResultOf<()> {
    tokio::time::timeout(std::time::Duration::from_secs(120), work)
        .await
        .map_err(|_| "test: multi-device native operation exceeded its deadline")?
}

async fn three_devices() -> ResultOf<()> {
    use ramflux_sdk::custody::pairing::PairingAuthorityQuery;
    let node = node::Node::open()?;
    let mut a = Box::pin(device::Device::create(node.clone(), "phone-a", true)).await?;
    let mut b = Box::pin(device::Device::create(node.clone(), "phone-b", false)).await?;
    let mut c = Box::pin(device::Device::create(node.clone(), "web-c", false)).await?;
    for (left, right) in [(&a, &b), (&a, &c), (&b, &c)] {
        assert_ne!(left.root.path(), right.root.path(), "test: SDK devices share a data root");
        assert!(
            !std::sync::Arc::ptr_eq(&left.vault, &right.vault),
            "test: SDK devices share a credential vault"
        );
    }
    Box::pin(ceremony::enroll(&mut a, &mut b, &node)).await?;
    Box::pin(ceremony::enroll(&mut a, &mut c, &node)).await?;
    for device in [&mut a, &mut b, &mut c] {
        device.admit_client(&node).await?;
    }
    let mut signing = std::collections::BTreeSet::new();
    let mut agreement = std::collections::BTreeSet::new();
    let mut references = std::collections::BTreeSet::new();
    let mut sessions = Vec::new();
    for device in [&a, &b, &c] {
        let (branch, dh, reference) = device.endpoint.branch()?;
        signing.insert(ramflux_protocol::encode_base64url(
            branch.signing_key.verifying_key().to_bytes(),
        ));
        agreement.insert(ramflux_protocol::encode_base64url(dh.public));
        references.insert(reference.device_id.clone());
        let session = device.endpoint.open_session()?;
        assert_eq!(
            session.device_ref, reference,
            "test: session admitted another device reference"
        );
        sessions.push(session);
    }
    assert_eq!(signing.len(), 3, "test: paired devices reused a branch signing key");
    assert_eq!(agreement.len(), 3, "test: paired devices reused an agreement identity");
    assert_eq!(references.len(), 3, "test: paired devices reused a device reference");
    let anchor = &sessions.first().ok_or("test: first live session")?.device_ref.account_anchor;
    let current = node.current_authority(anchor)?;
    assert_eq!(
        current.publication.record.body.devices.len(),
        3,
        "test: second enrollment replaced an existing device"
    );
    assert_eq!(
        a.vault.primary_entries()?,
        1,
        "test: approving phone lost its management credential"
    );
    for device in [&b, &c] {
        assert_eq!(
            device.vault.primary_entries()?,
            0,
            "test: enrollment copied primary management authority to a secondary"
        );
    }
    for (device, session) in [&a, &b, &c].into_iter().zip(&sessions) {
        assert!(
            matches!(
                device.endpoint.inbox(session)?,
                ramflux_protocol::custody::CustodyServerFrame::Inbox { .. }
            ),
            "test: one device's session stopped working after another device enrolled"
        );
    }
    a.actor.lock().await?;
    b.actor.lock().await?;
    c.actor.lock().await?;
    Ok(())
}

#[tokio::test]
async fn pairing_receiver_concurrency_and_transfer_acceptance() -> ResultOf<()> {
    deadline(Box::pin(full_acceptance())).await
}
async fn full_acceptance() -> ResultOf<()> {
    let mut fixture = Box::pin(full::Fixture::open()).await?;
    let identities = [&fixture.a, &fixture.b, &fixture.c]
        .into_iter()
        .map(|device| {
            device.endpoint.branch().map(|(sign, dh, reference)| {
                (sign.signing_key.verifying_key().to_bytes(), dh.public, reference)
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    let original =
        ramflux_sdk::custody::load_account(fixture.a.root.path(), &fixture.a.id, node::now()?)?
            .record()
            .body
            .devices
            .clone();
    let wrapping = fixture.b.client.account_index()?.load_wrapped_db_key(&fixture.b.id)?;
    Box::pin(fixture.begin()).await?;
    Box::pin(fixture.data()).await?;
    Box::pin(fixture.publish()).await?;
    for _ in 0..1024 {
        fixture.step().await?;
        let a = fixture.status(true).await?;
        let b = fixture.status(false).await?;
        if a.is_some_and(|value| {
            value.tail_status
                == ramflux_protocol::custody::pairing::local_dto::FullTailStatus::Merged
        }) && b.is_some_and(|value| {
            value.tail_status
                == ramflux_protocol::custody::pairing::local_dto::FullTailStatus::Merged
        }) {
            break;
        }
    }
    for primary in [true, false] {
        assert_eq!(
            fixture.status(primary).await?.ok_or("test: final full status")?.tail_status,
            ramflux_protocol::custody::pairing::local_dto::FullTailStatus::Merged,
            "test: endpoint lacks actual final tail acknowledgement"
        );
    }
    assert_eq!(
        fixture.b.client.account_index()?.load_wrapped_db_key(&fixture.b.id)?,
        wrapping,
        "test: transfer replaced B's original password wrapping"
    );
    for (device, (signing, agreement, reference)) in
        [&fixture.a, &fixture.b, &fixture.c].into_iter().zip(identities)
    {
        let (sign, dh, current) = device.endpoint.branch()?;
        assert_eq!(
            sign.signing_key.verifying_key().to_bytes(),
            signing,
            "test: transfer replaced a branch signer"
        );
        assert_eq!(dh.public, agreement, "test: transfer replaced a device agreement identity");
        assert_eq!(current, reference, "test: transfer replaced a device reference");
    }
    for device in [&fixture.a, &fixture.b] {
        for iteration in [2, 8, 16] {
            assert!(
                matches!(
                    device.client.account_db()?.check_object_identity(
                        &format!("concurrent-{iteration}"),
                        "concurrent-manifest"
                    ),
                    Err(ramflux_storage::StorageError::ObjectErased)
                ),
                "test: concurrent B veto lost in actual union/tail"
            );
        }
    }
    assert_retained_devices(&fixture, &original)?;
    // C reconnects to its own independently queried native authority after the handoff.
    fixture.c.participant.take_client(&mut fixture.c.client)?;
    fixture.c.admit_client(&fixture.node).await?;
    for device in [&fixture.a, &fixture.b, &fixture.c] {
        let session = device.endpoint.open_session()?;
        assert!(
            matches!(
                device.endpoint.inbox(&session)?,
                ramflux_protocol::custody::CustodyServerFrame::Inbox { .. }
            ),
            "test: surviving branch lost live native traffic"
        );
    }
    assert_eq!(fixture.a.vault.primary_entries()?, 0, "test: old primary retained authority");
    assert_eq!(fixture.b.vault.primary_entries()?, 1, "test: B did not become primary");
    assert_eq!(fixture.c.vault.primary_entries()?, 0, "test: C gained primary authority");
    fixture.a.actor.lock().await?;
    fixture.b.actor.lock().await?;
    fixture.c.actor.lock().await?;
    Ok(())
}

fn assert_retained_devices(
    fixture: &full::Fixture,
    original: &[ramflux_protocol::custody::Device],
) -> ResultOf<()> {
    use ramflux_sdk::custody::pairing::PairingAuthorityQuery;
    let (_, _, reference) = fixture.a.endpoint.branch()?;
    let authority = fixture.node.current_authority(&reference.account_anchor)?;
    let current = &authority.publication.record.body;
    assert_eq!(current.devices.len(), 3, "test: full transfer lost another enrolled device");
    assert_eq!(original.len(), 3, "test: pre-transfer three-device oracle was vacuous");
    let (_, _, destination) = fixture.b.endpoint.branch()?;
    assert_eq!(
        current.master_certificate.body.primary_device_ref, destination,
        "test: handoff activated another primary"
    );
    for before in original {
        let after = current
            .devices
            .iter()
            .find(|device| device.device_id == before.device_id)
            .ok_or("test: surviving device absent")?;
        let old = before.branch_certificate.as_ref().ok_or("test: old branch certificate")?;
        let new = after.branch_certificate.as_ref().ok_or("test: new branch certificate")?;
        let mut certificate = new.body.clone();
        certificate.master_certificate_hash.clone_from(&old.body.master_certificate_hash);
        certificate.cert_id.clone_from(&old.body.cert_id);
        assert_eq!(
            certificate, old.body,
            "test: full transfer changed a surviving branch lease or capabilities"
        );
        let mut normalized = after.clone();
        normalized.branch_certificate.clone_from(&before.branch_certificate);
        assert_eq!(normalized, *before, "test: full transfer changed branch status or identity");
    }
    Ok(())
}

// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

#![cfg(test)]

//! Adopted P17 direct-node SDK fixture. Each client owns a separate root/vault/index.
//! Federation TLS/Fedwire continuity is exercised separately in the federation crate.
#[path = "pairing_multi_device/ceremony.rs"]
mod ceremony;
#[path = "pairing_multi_device/device.rs"]
mod device;
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

// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Primary-only single-device revocation through the SDK journal and real custody proof frames.
use super::{ResultOf, ceremony, deadline, device::Device, node};
use ramflux_protocol::custody::*;
use ramflux_sdk::{SdkError, custody::pairing::*};
use std::sync::Mutex;
struct NativePublish(node::Endpoint);
impl NodeHeadPersist for NativePublish {
    fn persist_head(&self, publication: &Publication, _: u64) -> Result<String, SdkError> {
        match self
            .0
            .prove(CustodyProofAction::Publish { publication: Box::new(publication.clone()) })?
        {
            CustodyServerFrame::Published { record_hash } => Ok(record_hash),
            reply => Err(SdkError::LocalBus(format!("test: native revocation refused: {reply:?}"))),
        }
    }
}
fn revoke(source: &Device, target: &str) -> Result<PublishedHead, SdkError> {
    let (_, _, reference) = source.endpoint.branch()?;
    let (branch, primary) = source.vault.owned_references()?;
    let write = HeadWrite {
        account_id: source.id.clone(),
        operation_id: ramflux_protocol::encode_base64url(ramflux_crypto::random_32()?),
        invitation_id: None,
        generation: 1,
        issuer_seq: 0,
        local_seq: 0,
        kind: HeadKind::Revoke,
        publisher_ref: reference.clone(),
        local_ref: reference,
        recipient_ref: None,
        revoked_id: Some(target.into()),
        certificate: None,
        display_name: None,
        now: node::now()?,
        branch_vault_ref: branch,
        data_vault_ref: ramflux_storage::FileVaultSecretSource::owner_ref(&source.id),
        primary_vault_ref: primary,
    };
    let db = Mutex::new(
        source
            .participant
            .db
            .lock()
            .map_err(|_| SdkError::PairingCode("Busy"))?
            .take()
            .ok_or(SdkError::AccountDbNotUnlocked)?,
    );
    let result = publish_head(
        &db,
        source.root.path(),
        source.vault.as_ref(),
        &write,
        &NativePublish(source.endpoint.clone()),
    );
    *source.participant.db.lock().map_err(|_| SdkError::PairingCode("Busy"))? =
        Some(db.into_inner().unwrap_or_else(std::sync::PoisonError::into_inner));
    result
}
#[tokio::test]
async fn pairing_native_revoke_is_single_device_and_primary_only() -> ResultOf<()> {
    deadline(Box::pin(run())).await
}
async fn run() -> ResultOf<()> {
    let node = node::Node::open()?;
    let mut a = Box::pin(Device::create(node.clone(), "revoke-phone", true)).await?;
    let mut b = Box::pin(Device::create(node.clone(), "revoke-secondary", false)).await?;
    let mut c = Box::pin(Device::create(node.clone(), "unaffected-secondary", false)).await?;
    let (_, _, a_ref) = a.endpoint.branch()?;
    let initial = node.current_authority(&a_ref.account_anchor)?;
    assert!(
        revoke(&a, &a_ref.device_id).is_err(),
        "test: single primary revoked its own only device"
    );
    assert_eq!(
        node.current_authority(&a_ref.account_anchor)?,
        initial,
        "test: refused single-device revocation changed native authority"
    );
    assert!(
        a.participant
            .db
            .lock()
            .map_err(|_| "test: refused self-revoke writer")?
            .as_ref()
            .ok_or("test: source writer")?
            .pairing_head()?
            .is_none(),
        "test: self-revocation allocated a submitted head before refusing"
    );
    Box::pin(ceremony::enroll(&mut a, &mut b, &node)).await?;
    Box::pin(ceremony::enroll(&mut a, &mut c, &node)).await?;
    let (_, _, b_ref) = b.endpoint.branch()?;
    let (_, _, c_ref) = c.endpoint.branch()?;
    assert!(
        matches!(revoke(&b, &c_ref.device_id), Err(SdkError::PairingCode("PrimaryRequired"))),
        "test: secondary acquired device-management publication authority"
    );
    for device in [&mut a, &mut b, &mut c] {
        device.admit_client(&node).await?;
    }
    let sessions =
        [a.endpoint.open_session()?, b.endpoint.open_session()?, c.endpoint.open_session()?];
    let before = node.current_authority(&a_ref.account_anchor)?;
    a.participant.take_client(&mut a.client)?;
    let published = revoke(&a, &b_ref.device_id)?;
    let after = node.current_authority(&a_ref.account_anchor)?;
    assert_eq!(
        object_hash(&after.publication.record)?,
        published.record_hash,
        "test: SDK revoke acknowledgement differs from actual node head"
    );
    assert_eq!(
        before.publication.record.body.devices.len(),
        after.publication.record.body.devices.len(),
        "test: revocation dropped roster entries"
    );
    require_one_revoked(&before, &after, &b_ref.device_id)?;
    for (device, session) in [&a, &c].into_iter().zip([sessions.first(), sessions.get(2)]) {
        assert!(
            matches!(
                device.endpoint.inbox(session.ok_or("test: live session")?)?,
                CustodyServerFrame::Inbox { .. }
            ),
            "test: revoking B interrupted another device's signed session"
        );
    }
    assert!(
        matches!(
            b.endpoint.inbox(sessions.get(1).ok_or("test: revoked session")?)?,
            CustodyServerFrame::Refused { .. }
        ),
        "test: revoked device retained signed native session access"
    );
    a.actor.lock().await?;
    b.actor.lock().await?;
    c.actor.lock().await?;
    Ok(())
}
fn require_one_revoked(
    before: &CustodyAuthority,
    after: &CustodyAuthority,
    target: &str,
) -> ResultOf<()> {
    for old in &before.publication.record.body.devices {
        let current = after
            .publication
            .record
            .body
            .devices
            .iter()
            .find(|device| device.device_id == old.device_id)
            .ok_or("test: retained roster entry")?;
        if old.device_id == target {
            assert_eq!(
                current.status,
                ramflux_protocol::DeviceSetStatus::Revoked,
                "test: target device remained active"
            );
            let mut expected = old.clone();
            expected.status = ramflux_protocol::DeviceSetStatus::Revoked;
            expected.migration_state = MigrationState::Revoked;
            expected.revoked_at = Some(after.publication.record.body.issued_at);
            expected.branch_certificate = None;
            expected.message_layer = None;
            assert_eq!(
                current, &expected,
                "test: revocation replaced target's retained key commitments or epoch"
            );
        } else {
            assert_eq!(current, old, "test: revoking one device altered another branch");
        }
    }
    Ok(())
}

// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! First-contact Root hints are lookup context, never an alternative trust anchor.
use super::*;
use crate::client::identity_authority::HeadUse;
type TestResult = Result<(), Box<dyn std::error::Error>>;

#[tokio::test]
async fn first_contact_fetches_only_the_hinted_root_manifest_and_verifies_the_chain() -> TestResult
{
    first_use_discovery().await
}
async fn first_use_discovery() -> TestResult {
    use crate::client::native_test_support::{Fixture as Native, directory::Directory, watchdog};
    watchdog::within(async {
        let sender = Native::with_principal("discovery-source", "alice", "alice").await?;
        let mut receiver = Native::with_principal("discovery-target", "bob", "bob").await?;
        sender.accept_peer(&receiver)?;
        let (entry, exact) = native_discovery_message(&sender, &receiver)?;
        let mut malformed = entry.clone();
        malformed
            .envelope
            .ext
            .ext
            .insert("source_root_commitment".into(), serde_json::json!("../../admin"));
        assert!(
            matches!(receiver.client.ensure_inbound_device(&receiver.config, &malformed).await,
            Err(SdkError::InboundRejected(reason)) if reason.ends_with("invalid sender root hint"))
        );
        assert!(receiver.client.ensure_inbound_device(&receiver.config, &entry).await.is_err());
        assert!(
            receiver
                .client
                .device_identity_for_root(&sender.client.own_account_anchor()?, "alice")
                .is_err()
        );
        receiver.client.establish_friend_link(
            "accepted-root",
            &receiver.client.own_account_anchor()?,
            &sender.client.own_account_anchor()?,
        )?;
        let directory = Directory::new(vec![sender.manifest.clone()]).await?;
        directory.configure(&mut receiver);
        receiver.client.ensure_inbound_device(&receiver.config, &entry).await?;
        assert_eq!(directory.requests(), 1, "first use must fetch exactly the hinted native root");
        assert_eq!(
            receiver.client.authenticated_device_identity(HeadUse::NewAuthorization, &entry)?,
            sender.client.owned_device_identity()?
        );
        let opened = receiver.client.open_routed(&entry, "bob")?;
        assert_eq!(
            opened.body.as_slice(),
            exact,
            "native proof lookup lost the original generated Inner"
        );
        Ok(())
    })
    .await?
}

#[tokio::test(flavor = "current_thread")]
async fn signed_root_hint_cannot_override_an_existing_verified_owner() -> TestResult {
    crate::client::native_test_support::watchdog::within(async {
        let (sender, receiver, mut entry) = Box::pin(native_hint_entry()).await?;
        assert_eq!(
            receiver.client.authenticated_envelope_sender(HeadUse::NewAuthorization, &entry)?,
            "alice"
        );
        entry.envelope.ext.ext.insert(
            "source_root_commitment".into(),
            serde_json::json!(ramflux_protocol::encode_base64url([44; 32])),
        );
        entry.envelope.signed.signature = ramflux_crypto::sign_protocol_object_with_device_branch(
            sender.client.device_branch.as_ref().ok_or("native branch")?,
            &entry.envelope,
        )?;
        ramflux_node_core::check_entry_bound(&entry.envelope)?;
        assert!(
            receiver
                .client
                .authenticated_envelope_sender(HeadUse::NewAuthorization, &entry)
                .is_err(),
            "a valid branch signature cannot replace the pinned account root"
        );
        assert_eq!(
            receiver
                .client
                .account_db()?
                .client_record("identity", "alice")?
                .ok_or("verified root")?["contact_identity_commitment"],
            sender.client.own_account_anchor()?
        );
        Ok(())
    })
    .await?
}

#[tokio::test(flavor = "current_thread")]
async fn a_non_string_signed_root_hint_is_rejected_before_manifest_discovery() -> TestResult {
    crate::client::native_test_support::watchdog::within(async {
        let (_, receiver, mut entry) = Box::pin(native_hint_entry()).await?;
        entry.envelope.ext.ext.insert("source_root_commitment".into(), serde_json::json!(true));
        assert!(matches!(receiver.client.ensure_inbound_device(&receiver.config, &entry).await,
            Err(SdkError::InboundRejected(reason)) if reason.ends_with("invalid sender root hint")));
        Ok(())
    }).await?
}

async fn native_hint_entry() -> crate::client::native_test_support::TestResult<(
    crate::client::native_test_support::Fixture,
    crate::client::native_test_support::Fixture,
    GatewayInboxEntry,
)> {
    use crate::client::native_test_support::Fixture as Native;
    let sender = Native::with_principal("hint-source", "alice", "alice").await?;
    let receiver = Native::with_principal("hint-target", "bob", "bob").await?;
    sender.accept_peer(&receiver)?;
    receiver.accept_peer(&sender)?;
    let (entry, _) = native_discovery_message(&sender, &receiver)?;
    Ok((sender, receiver, entry))
}

fn native_discovery_message(
    sender: &crate::client::native_test_support::Fixture,
    receiver: &crate::client::native_test_support::Fixture,
) -> crate::client::native_test_support::TestResult<(GatewayInboxEntry, Vec<u8>)> {
    use ramflux_protocol::message as g;
    let conversation = g::dm_scope::derive(
        &sender.client.own_account_anchor()?,
        &receiver.client.own_account_anchor()?,
    )?;
    let identity = sender.client.allocate_generated_identity(
        &conversation,
        crate::client::generated_identity::now_ms(),
        false,
    )?;
    let exact = RamfluxClient::encode_generated_inner(
        identity,
        &g::Content {
            value: Some(g::content::Value::Message(g::Message {
                text: "first native root discovery".into(),
                erasure_nonce: ramflux_crypto::random_32()?.to_vec(),
                ..Default::default()
            })),
        },
    )?;
    let envelope = sender.seal_inner_to(receiver, &exact)?;
    Ok((
        GatewayInboxEntry {
            forwarded: false,
            inbox_seq: 1,
            target_delivery_id: receiver.config.target_delivery_id.clone(),
            envelope,
        },
        exact,
    ))
}

// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Native sibling history through production page staging, crypto and receive commits.
use super::*;
use crate::client::generated_history::producer::Outgoing;
use crate::client::routed::{Route, SendMaterial};
use crate::{GatewayDirectMessage, SdkError};
use prost::Message as _;
use ramflux_protocol::message as g;

impl Fixture {
    pub(super) fn seal_inner_to(
        &self,
        target: &Self,
        exact: &[u8],
    ) -> TestResult<ramflux_protocol::Envelope> {
        let inner = g::Inner::decode(exact)?;
        let kind = inner.kind;
        let identity = inner.identity.ok_or("identity")?;
        let route = match (kind, identity.group_id.as_deref()) {
            (8, Some(group)) => Route::group_control(group),
            (8 | 11 | 12, None) => Route::control(),
            (6, _) => Route::receipt(),
            (_, Some(group)) => Route::group_message(group),
            _ => Route::direct(),
        };
        let mut message = GatewayDirectMessage {
            conversation_id: identity.conversation_id,
            message_id: ramflux_protocol::encode_base64url(identity.id),
            envelope_id: ramflux_protocol::encode_base64url(ramflux_crypto::random_32()?),
            source_principal_id: self.config.principal_id.clone(),
            sender_id: self.config.device_id.clone(),
            recipient_device_id: Some(target.config.device_id.clone()),
            recipient_principal_commitment: Some(target.client.own_account_anchor()?),
            target_delivery_id: target.config.target_delivery_id.clone(),
            encrypted_body: Vec::new(),
            created_at: crate::time::now_unix_timestamp(),
            ttl: 300,
        };
        let material = self.material_for(target)?;
        Ok(self.client.account_db()?.write_transaction(|| {
            let sealed = self.client.seal_generated_routed_prepared(
                &self.config,
                &message,
                exact,
                route,
                material,
            )?;
            crate::dm::gateway_generated_envelope_from_sealed(&self.config, &mut message, sealed)
        })?)
    }
}

fn due(client: &RamfluxClient) -> TestResult {
    let db = client.account_db()?;
    db.write_transaction(|| {
        for key in db.actor_state_keys("history-out/transfer/")? {
            let mut row = db.load_actor_state::<Outgoing>(&key)?.ok_or(SdkError::ReplayMismatch)?;
            row.next_at = 0;
            db.persist_actor_state(&key, &row)?;
        }
        Ok::<(), SdkError>(())
    })?;
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn native_sibling_history_preserves_first_hand_origin_resends_and_revokes_captured_pages()
-> TestResult {
    let mut source = Fixture::new("native-history-source").await?;
    let mut sibling = source.enroll_sibling("native-history-sibling", "history-sibling").await?;
    let peer = Fixture::new("native-history-original-peer").await?;
    let _live = ramflux_protocol::schema_profile::SchemaV1LiveGuard::enter();
    let (original, retained, conversation) =
        Box::pin(receive_first_hand(&mut source, &peer)).await?;
    source.client.start_generated_history_transfer(&sibling.config.device_id)?;
    let prepared =
        source.client.prepare_generated_history_delivery(&source.config)?.ok_or("history plan")?;
    let (first_plan, page) = source
        .client
        .seal_generated_history_delivery(&source.config, prepared, source.material_for(&sibling)?)?
        .ok_or("history page")?;
    let mut forged = page.clone();
    forged.report_commitment = Some(ramflux_protocol::encode_base64url([0; 32]));
    assert!(sibling.receive(forged, 1).await.is_err());
    assert_eq!(
        sibling.client.generated_message_view_page(&conversation, None, 10)?.messages.len(),
        0
    );
    sibling
        .receive(page.clone(), 1)
        .await
        .map_err(|error| format!("history page receive: {error}"))?;
    assert_eq!(
        sibling
            .client
            .export_generated_history_item(&original.id)
            .map_err(|error| format!("imported native export: {error:?}"))?,
        retained,
        "forwarding preserves exact original evidence instead of substituting sibling authority"
    );
    let before = sibling.client.generated_message_changes(&conversation, 0, 10)?;
    assert_eq!(before.changes.len(), 1);
    // Submit succeeded, but complete did not run: a resumed plan must use the exact cached page.
    drop(first_plan);
    due(&source.client)?;
    let retry =
        source.client.prepare_generated_history_delivery(&source.config)?.ok_or("resend plan")?;
    let (retry, resent) = source
        .client
        .seal_generated_history_delivery(
            &source.config,
            retry,
            SendMaterial { manifest: None, bundle: None },
        )?
        .ok_or("cached resend")?;
    assert_eq!(resent, page);
    sibling.receive(resent, 2).await?;
    assert_eq!(
        sibling
            .client
            .generated_message_changes(&conversation, before.next_after, 10)?
            .changes
            .len(),
        0
    );
    // An already captured plan loses its authority when any carried owner is erased.
    let id = ramflux_protocol::encode_base64url(&original.id);
    source.client.account_db()?.delete_direct_message(
        &conversation,
        &id,
        "local",
        "erase-history-owner",
    )?;
    source.client.complete_generated_history_delivery(&retry)?;
    assert!(
        source
            .client
            .seal_generated_history_delivery(
                &source.config,
                retry,
                SendMaterial { manifest: None, bundle: None }
            )?
            .is_none()
    );
    assert_eq!(source.client.account_db()?.actor_state_keys("history/page/out/")?.len(), 0);
    Ok(())
}

pub(super) async fn receive_first_hand(
    source: &mut Fixture,
    peer: &Fixture,
) -> TestResult<(g::EventIdentity, g::HistoryItem, String)> {
    source.client.persist_fetched_identity_directory(&peer.manifest)?;
    peer.client.establish_friend_link(
        "native-origin-sender-link",
        &peer.client.own_account_anchor()?,
        &source.client.own_account_anchor()?,
    )?;
    source.client.establish_friend_link(
        "peer-link",
        &source.client.own_account_anchor()?,
        &peer.client.own_account_anchor()?,
    )?;
    let conversation = g::dm_scope::derive(
        &source.client.own_account_anchor()?,
        &peer.client.own_account_anchor()?,
    )?;
    let original = peer.client.allocate_generated_identity(
        &conversation,
        crate::client::generated_identity::now_ms(),
        false,
    )?;
    let exact = RamfluxClient::encode_generated_inner(
        original.clone(),
        &g::Content {
            value: Some(g::content::Value::Message(g::Message {
                text: "native first-hand history".into(),
                ..Default::default()
            })),
        },
    )?;
    let envelope = peer.seal_inner_to(source, &exact)?;
    assert_eq!(
        envelope.schema,
        g::outer::CANDIDATE_ENVELOPE_SCHEMA,
        "first-hand test must use the selected profile"
    );
    source.receive(envelope, 1).await.map_err(|error| format!("first native receive: {error}"))?;
    let id = ramflux_protocol::encode_base64url(&original.id);
    assert!(
        source.client.account_db()?.message_content(&id)?.is_some(),
        "native first receive must store the exact body"
    );
    assert!(
        source.client.account_db()?.actor_state_exists(&format!("routed/origin-evidence/{id}"))?,
        "native first receive must retain independent signed origin"
    );
    let retained = source
        .client
        .export_generated_history_item(&original.id)
        .map_err(|error| format!("first native export: {error:?}"))?;
    assert_eq!(retained.exact_inner, exact);
    Ok((original, retained, conversation))
}

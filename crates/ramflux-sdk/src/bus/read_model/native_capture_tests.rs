// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Post-send presentation capture preserves native authority for the next ordinary revision.
use crate::client::native_test_support::{Fixture, TestResult, watchdog};
use crate::client::routed::Route;
use crate::{GatewayDirectMessage, LocalBusFrame};
use ramflux_protocol::message as g;
use serde_json::json;

#[tokio::test(flavor = "current_thread")]
async fn ordinary_bus_capture_keeps_native_roots_for_the_next_authored_revision() -> TestResult {
    watchdog::within(async {
        let mut source = Fixture::new("capture-source").await?;
        let mut target = Fixture::new("capture-target").await?;
        source.accept_peer(&target)?;
        target.accept_peer(&source)?;
        let conversation = g::dm_scope::derive(
            &source.client.own_account_anchor()?,
            &target.client.own_account_anchor()?,
        )?;
        for text in ["first ordinary revision", "second ordinary revision"] {
            let mut message = GatewayDirectMessage {
                conversation_id: conversation.clone(),
                message_id: text.into(),
                envelope_id: text.into(),
                source_principal_id: source.config.principal_id.clone(),
                sender_id: source.config.device_id.clone(),
                recipient_device_id: Some(target.config.device_id.clone()),
                recipient_principal_commitment: Some(target.client.own_account_anchor()?),
                target_delivery_id: target.config.target_delivery_id.clone(),
                encrypted_body: Vec::new(),
                created_at: crate::time::now_unix_timestamp(),
                ttl: 300,
            };
            let prepared = source.client.prepare_authored_message(
                &mut message,
                None,
                &g::Message { text: text.into(), ..Default::default() },
            )?;
            let db = source.client.account_db()?;
            let mut context = db
                .client_record("conversation", &conversation)?
                .ok_or("test: authored context missing")?;
            context["title"] = json!("Retained title");
            db.persist_client_record("conversation", &conversation, &context)?;
            let envelope = seal(&source, &target, &mut message, &prepared.wire)?;
            source.client.project_authored_message(
                &message,
                &prepared.wire,
                &message.encrypted_body,
            )?;
            target.receive(envelope.clone(), 1).await?;
            capture_route(&mut source, &message, &envelope)?;
            let captured = source
                .client
                .account_db()?
                .client_record("conversation", &conversation)?
                .ok_or("test: captured context")?;
            assert_eq!(captured["participant_roots"], context["participant_roots"]);
            assert_eq!(captured["participants"], context["participants"]);
            assert_eq!(captured["title"], "Retained title");
            assert_eq!(
                captured["direct_route"]["target_delivery_id"],
                target.config.target_delivery_id,
            );
        }
        for client in [&source.client, &target.client] {
            let page = client.generated_message_view_page(&conversation, None, 10)?;
            assert_eq!(page.messages.len(), 2, "both ordinary revisions must survive capture");
        }
        Ok(())
    })
    .await?
}

fn seal(
    source: &Fixture,
    target: &Fixture,
    message: &mut GatewayDirectMessage,
    exact: &[u8],
) -> TestResult<ramflux_protocol::Envelope> {
    let material = source.material_for(target)?;
    Ok(source.client.account_db()?.write_transaction(|| {
        let sealed = source.client.seal_generated_routed_prepared(
            &crate::bus::connection_manager::SessionMetadata::sealing_config_for(&source.config)?,
            message,
            exact,
            Route::direct(),
            material,
        )?;
        crate::dm::gateway_generated_envelope_from_sealed(
            &crate::bus::connection_manager::SessionMetadata::sealing_config_for(&source.config)?,
            message,
            sealed,
        )
    })?)
}

fn capture_route(
    source: &mut Fixture,
    message: &GatewayDirectMessage,
    envelope: &ramflux_protocol::Envelope,
) -> TestResult {
    let root = source.client.own_account_anchor()?;
    let mut account = crate::bus::state::LocalBusAccountState::disconnected(
        std::mem::take(&mut source.client),
        source.config.clone(),
        root,
    );
    let frame = LocalBusFrame::request(
        "capture",
        None,
        "message",
        "message.submit",
        json!({
            "conversation_id": message.conversation_id,
            "recipient_device_id": message.recipient_device_id,
            "recipient_principal_commitment": message.recipient_principal_commitment,
            "target_delivery_id": message.target_delivery_id,
        }),
    );
    let result = super::capture(&account, &frame, &serde_json::to_value(envelope)?);
    source.client = std::mem::take(&mut account.client);
    result?;
    Ok(())
}

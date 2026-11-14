// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Public conversation sends retain generated r4 media and qualified event ids through retry.
use super::*;
use crate::client::native_test_support::{
    TestResult, activation_send::tests::media_pair, directory::Directory, peer_control_send,
    watchdog,
};
use ramflux_protocol::message as g;

#[tokio::test(flavor = "current_thread")]
async fn native_conversation_media_send_returns_real_event_and_replays_exact_packet() -> TestResult
{
    watchdog::within(async {
        let (mut source, mut target, content) = Box::pin(media_pair()).await?;
        let scope = g::dm_scope::derive(&source.client.own_account_anchor()?, &target.client.own_account_anchor()?)?;
        let directory = Directory::new(vec![source.manifest.clone(), target.manifest.clone()]).await?;
        let (mut engine, captured) = peer_control_send::engine_capture(&source, &target, false)?;
        directory.configure_session(&mut engine.config);
        source.client.account_db()?.persist_client_record("conversation", &scope, &json!({
            "id":scope,"kind":"direct","group_id":null,
            "participants":[source.config.principal_id,target.config.principal_id],
            "participant_roots":[source.client.own_account_anchor()?,target.client.own_account_anchor()?],
        }))?;
        let root = source.client.own_account_anchor()?;
        let mut account = LocalBusAccountState::new(std::mem::take(&mut source.client), engine, root);
        account.client.account_db()?.install_receive_ledger_schema()?;
        let before = account.client.account_db()?.durable_rows_for_test()?;
        let retired = LocalBusFrame::request("retired-conversation-attachment", Some("activation-source".into()), "conversation", "conversation.send", json!({
            "conversation_id":scope,"text":"retired input",
            "attachments":[{"mime":0,"relay_endpoint":[],"grant":"invalid"}]
        }));
        assert!(matches!(Box::pin(send_account(&retired, &mut account)).await,
            Err(SdkError::GeneratedRefused { code: crate::GeneratedRefusalCode::Content, .. })),
            "retired input must refuse Content before decoding old metadata or requiring an operation token");
        assert!(account.client.account_db()?.durable_rows_for_test()? == before,
            "retired input allocated or persisted state");
        assert_eq!(captured.lock().map_err(|_| "capture poisoned")?.len(), 0);
        let mut request = LocalBusFrame::request("conversation-media", Some("activation-source".into()), "conversation", "conversation.send", json!({"conversation_id":scope,"text":content.text,"media":content.media}));
        request.operation_id = Some("media-operation".into());
        let first = Box::pin(send_account(&request, &mut account)).await?.response_body;
        let event = first["message_id"].as_str().ok_or("allocated event absent")?.to_owned();
        assert_eq!(first["delivery_state"], "submitted", "{first}");
        assert_ne!(first["message_id"], first["client_message_id"]);
        let retry = Box::pin(send_account(&request, &mut account)).await?.response_body;
        assert_eq!(retry["message_id"], event);
        let packets = captured.lock().map_err(|_| "capture poisoned")?.clone();
        let [original, replay] = packets.as_slice() else { return Err("expected two gateway submissions".into()); };
        assert_eq!(original, replay, "retry changed the exact sealed packet");
        target.receive(original.clone(), 1).await?;
        target.receive(replay.clone(), 1).await?;
        let detail = target.client.generated_message_detail(&scope, &event)?;
        assert_eq!(detail.message.text.as_deref(), Some(content.text.as_str()));
        let exact = target.client.account_db()?.message_content(&event)?.ok_or("stored Inner")?;
        let (_, decoded) = RamfluxClient::decode_generated_inner(&exact)?;
        let Some(g::content::Value::Message(actual)) = decoded.value else { return Err("Message missing".into()); };
        assert_eq!(actual.media, content.media);
        assert_eq!(target.client.direct_messages(&scope)?.len(), 1);
        assert_eq!(account.client.direct_messages(&scope)?.len(), 1);
        Ok(())
    }).await?
}

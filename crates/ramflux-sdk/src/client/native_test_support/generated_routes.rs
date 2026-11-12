// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Native receipt routing and standalone GroupKey receive through real crypto and W1.
use super::*;
use crate::client::routed::Kind;
use ramflux_protocol::message as g;

#[tokio::test(flavor = "current_thread")]
async fn native_generated_receipt_opens_on_receipt_route_with_exact_inner() -> TestResult {
    let source = Fixture::new("native-receipt-source").await?;
    let target = Fixture::new("native-receipt-target").await?;
    let _live = ramflux_protocol::schema_profile::SchemaV1LiveGuard::enter();
    let conversation = g::dm_scope::derive(&source.client.own_account_anchor()?, &target.client.own_account_anchor()?)?;
    let identity = source.client.allocate_generated_identity(&conversation, crate::client::generated_identity::now_ms(), false)?;
    let receiver = identity.author.clone();
    let exact = RamfluxClient::encode_generated_inner(identity, &g::Content { value: Some(g::content::Value::Receipt(g::Receipt {
        targets: vec![g::MessageRef { id: vec![61; 32], conversation_id: conversation, author_anchor: target.client.own_account_anchor()? }],
        state: g::ReceiptState::ReceiptDelivered as i32, at: 1, receiver,
    })) })?;
    let envelope = source.seal_inner_to(&target, &exact)?;
    ramflux_node_core::check_entry_bound(&envelope)?;
    let entry = crate::GatewayInboxEntry { envelope, forwarded: false, inbox_seq: 1, target_delivery_id: target.config.target_delivery_id.clone() };
    let opened = target.client.open_routed(&entry, &target.config.device_id)?;
    assert_eq!(opened.routing.kind, Kind::Receipt);
    assert_eq!(opened.body.as_slice(), exact.as_slice());
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn native_generated_group_key_imports_only_on_its_group_route_and_decrypts_next_message() -> TestResult {
    let source = Fixture::with_device("typed-key-source", "source-device").await?;
    let mut target = Fixture::with_device("typed-key-target", "target-device").await?;
    let _live = ramflux_protocol::schema_profile::SchemaV1LiveGuard::enter();
    source.client.persist_fetched_identity_directory(&target.manifest)?;
    target.client.persist_fetched_identity_directory(&source.manifest)?;
    let primary = source.client.born_v3_account.as_ref().ok_or("native account")?.group_primary(source.vault.as_ref())?;
    source.client.shared_group_create_with_primary("typed-key-group", "typed-key-thread", None, &source.config.target_delivery_id, Some(&primary))?;
    let actor = target.client.owned_group_actor(&target.config.target_delivery_id)?;
    let state = source.client.shared_group_change_with_primary("typed-key-group", &source.config.target_delivery_id, ramflux_protocol::group_state::GroupStateChange::Add { member: actor.identity, role: ramflux_protocol::SharedGroupRole::Member }, Some(&primary))?;
    target.client.accept_shared_group_state(&state, &target.config.target_delivery_id)?;
    let distribution: crate::SdkGroupSenderKeyDistribution = ramflux_protocol::parse_i_json(&source.client.export_group_sender_key_distribution("typed-key-group", &source.config.device_id)?)?;
    assert!(target.client.load_group_sender_key_state("typed-key-group", &source.client.owned_device_identity()?, state.view().epoch, "recv").is_err());
    let exact = source.client.generated_group_key_inner("typed-key-thread", state.view().epoch, &distribution, &target.client.owned_device_identity()?)?;
    target.receive(source.seal_inner_to(&target, &exact)?, 1).await?;
    assert!(target.client.load_group_sender_key_state("typed-key-group", &source.client.owned_device_identity()?, state.view().epoch, "recv").is_ok());
    let identity = source.client.allocate_generated_identity("typed-key-thread", crate::client::generated_identity::now_ms(), false)?;
    let owner = ramflux_protocol::encode_base64url(&identity.id);
    let message = source.client.encrypt_generated_group_inner("typed-key-group", &source.config.device_id, identity, &g::Message { text: "key imported by typed control".into(), ..Default::default() })?;
    target.receive(source.seal_inner_to(&target, &message)?, 2).await?;
    assert_eq!(target.client.generated_message_detail("typed-key-thread", &owner)?.message.text.as_deref(), Some("key imported by typed control"));
    Ok(())
}

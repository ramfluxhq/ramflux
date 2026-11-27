// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Native receipt routing through real crypto and W1.
use super::*;
use crate::client::routed::Kind;
use ramflux_protocol::message as g;

#[tokio::test(flavor = "current_thread")]
async fn native_generated_receipt_opens_on_receipt_route_with_exact_inner() -> TestResult {
    let source = Fixture::new("native-receipt-source").await?;
    let target = Fixture::new("native-receipt-target").await?;
    let conversation = g::dm_scope::derive(
        &source.client.own_account_anchor()?,
        &target.client.own_account_anchor()?,
    )?;
    let identity = source.client.allocate_generated_identity(
        &conversation,
        crate::client::generated_identity::now_ms(),
        false,
    )?;
    let receiver = identity.author.clone();
    let exact = RamfluxClient::encode_generated_inner(
        identity,
        &g::Content {
            value: Some(g::content::Value::Receipt(g::Receipt {
                targets: vec![g::MessageRef {
                    id: vec![61; 32],
                    conversation_id: conversation,
                    author_anchor: target.client.own_account_anchor()?,
                }],
                state: g::ReceiptState::ReceiptDelivered as i32,
                at: 1,
                receiver,
            })),
        },
    )?;
    let envelope = source.seal_inner_to(&target, &exact)?;
    target.client.persist_observed_identity_directory_now(&source.manifest)?;
    ramflux_node_core::check_entry_bound(&envelope)?;
    let entry = crate::GatewayInboxEntry {
        envelope,
        forwarded: false,
        inbox_seq: 1,
        target_delivery_id: target.config.target_delivery_id.clone(),
    };
    let opened = target.client.open_routed(&entry, &target.config.device_id)?;
    assert_eq!(opened.routing.kind, Kind::Receipt);
    assert_eq!(opened.body.as_slice(), exact.as_slice());
    Ok(())
}

// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Private pair controls for task approvals, independent of compacted signed event histories.
use super::task_transport::{Target, direct_targets, own_targets, seal};
use crate::bus::task_delivery::Delivery;
use crate::client::task::invalid;
use crate::prelude::*;

pub(super) async fn send(
    account: &mut LocalBusAccountState,
    conversation: &str,
    recipient: &str,
    body: &[u8],
) -> Result<(), SdkError> {
    crate::client::task::check_delivery_size(body.len())?;
    let mut engine = account.take_live_engine().await?;
    let result = tokio::time::timeout(
        Duration::from_secs(1),
        prepare(account, &mut engine, conversation, recipient, body),
    )
    .await;
    account.put_engine(engine);
    let deliveries = result
        .map_err(|_| SdkError::InboundPending("task approval preparation deferred".into()))??;
    crate::bus::task_delivery::submit_until(
        account,
        deliveries,
        tokio::time::Instant::now() + Duration::from_secs(1),
    )
    .await?;
    Ok(())
}
async fn prepare(
    account: &LocalBusAccountState,
    engine: &mut GatewaySessionEngine,
    conversation: &str,
    recipient: &str,
    body: &[u8],
) -> Result<Vec<Delivery>, SdkError> {
    let client = &account.client;
    let thread = client
        .account_db()?
        .client_record("conversation", conversation)?
        .ok_or_else(|| invalid("task approval conversation missing"))?;
    let group = thread["group_id"].as_str();
    let mut targets = own_targets(account, &engine.config).await?;
    let candidates = if let Some(group) = group {
        super::task_group::plan(
            account,
            conversation,
            &crate::new_surface_message_id()?,
            group,
            &engine.config,
        )
        .await?
        .targets
    } else {
        direct_targets(account, &engine.config, &thread).await?
    };
    let peers = endpoint_targets(client, candidates, recipient)?;
    let local = client.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?;
    if peers.is_empty() && recipient != local.principal_id {
        return Err(invalid("task approval endpoint has no active route"));
    }
    targets.extend(peers);
    if body.len().saturating_add(4096).saturating_mul(targets.len()).saturating_mul(32)
        > 32 * 1024 * 1024
    {
        return Err(invalid("task approval fanout byte budget exceeded"));
    }
    let route = crate::client::routed::Route {
        kind: crate::client::routed::Kind::Control,
        group_id: group.map(str::to_owned),
        attachments: false,
    };
    let mut deliveries = Vec::new();
    for target in targets {
        deliveries.push(seal(account, engine, &target, conversation, body, route.clone()).await?);
    }
    Ok(deliveries)
}
fn endpoint_targets(
    client: &RamfluxClient,
    targets: Vec<Target>,
    recipient: &str,
) -> Result<Vec<Target>, SdkError> {
    let mut result = Vec::new();
    for target in targets {
        let record = client.account_db()?.client_record("device", &target.device)?;
        if record.as_ref().is_some_and(|r| r["principal_id"].as_str() == Some(recipient)) {
            result.push(target);
        }
    }
    Ok(result)
}

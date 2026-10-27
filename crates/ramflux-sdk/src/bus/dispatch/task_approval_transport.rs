// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Private pair controls for task approvals, independent of compacted signed event histories.
use super::task_transport::{
    Preparation, PreparationBudget, Target, await_preparation, direct_targets, own_targets, seal,
};
use crate::bus::task_delivery::Delivery;
use crate::client::task::invalid;
use crate::prelude::*;

pub(super) async fn send(
    account: &mut LocalBusAccountState,
    conversation: &str,
    recipient: &str,
    body: &[u8],
    budget: &PreparationBudget,
) -> Result<Preparation<()>, SdkError> {
    crate::client::task::check_delivery_size(body.len())?;
    let mut engine = account.take_live_engine().await?;
    let result = await_preparation(
        prepare(account, &mut engine, conversation, recipient, body),
        budget,
        "task approval preparation deferred",
    )
    .await;
    account.put_engine(engine);
    let Preparation::Ready(deliveries) = result? else {
        return Ok(Preparation::Deferred);
    };
    crate::bus::task_delivery::submit_until(
        account,
        deliveries,
        tokio::time::Instant::now() + Duration::from_secs(1),
    )
    .await?;
    Ok(Preparation::Ready(()))
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
    diagnostic(account, "own_targets begin");
    let mut targets = own_targets(account, &engine.config).await?;
    diagnostic(account, "own_targets complete");
    diagnostic(account, "peer_targets begin");
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
    diagnostic(account, "peer_targets complete");
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
        diagnostic(account, "seal begin");
        deliveries.push(seal(account, engine, &target, conversation, body, route.clone()).await?);
    }
    diagnostic(account, "seal complete");
    Ok(deliveries)
}
fn diagnostic(account: &LocalBusAccountState, stage: &str) {
    tracing::debug!(device = %account.gateway_config.device_id, stage, "task approval preparation");
}

fn endpoint_targets(
    client: &RamfluxClient,
    targets: Vec<Target>,
    recipient: &str,
) -> Result<Vec<Target>, SdkError> {
    let mut result = Vec::new();
    for target in targets {
        let record = client.account_db()?.client_device_record(&target.identity)?;
        if record.as_ref().is_some_and(|r| r["principal_id"].as_str() == Some(recipient)) {
            result.push(target);
        }
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(start_paused = true)]
    async fn approval_preparation_allows_slow_verified_directory_refresh() {
        let result = tokio::time::timeout(Duration::from_secs(10), async {
            let budget = PreparationBudget::for_sync_cycle();
            await_preparation(
                async {
                    tokio::time::sleep(Duration::from_millis(1_250)).await;
                    Ok::<_, SdkError>(())
                },
                &budget,
                "task approval preparation deferred",
            )
            .await
        })
        .await;
        assert!(
            matches!(result, Ok(Ok(Preparation::Ready(())))),
            "a slow verified directory refresh must remain deliverable"
        );
    }

    #[test]
    fn approval_endpoint_uses_root_qualified_identity_with_ambiguous_literal_names()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = crate::bus::runtime_tests::root("approval-root-lookup");
        let account = crate::bus::runtime_tests::account(
            &root,
            "owner",
            None,
            std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
        )?;
        let db = account.client.account_db()?;
        let mut targets = Vec::new();
        for (principal, seed) in [("bob", 21), ("mallory", 22)] {
            let root = ramflux_crypto::create_identity_root(principal, [seed; 32]);
            let identity =
                ramflux_crypto::RootQualifiedDeviceRef::for_owned_account_device(&root, "shared")?;
            db.persist_client_record("device",identity.storage_key(),&serde_json::json!({
                "device_id":"shared","principal_id":principal,"principal_commitment":identity.root_commitment()}))?;
            targets.push(Target {
                device: "shared".into(),
                identity,
                delivery: principal.into(),
                federation: None,
                own: false,
            });
        }
        let selected = endpoint_targets(&account.client, targets, "bob")?;
        assert_eq!(selected.len(), 1);
        assert_eq!(selected[0].delivery, "bob");
        drop(account);
        std::fs::remove_dir_all(root)?;
        Ok(())
    }
}

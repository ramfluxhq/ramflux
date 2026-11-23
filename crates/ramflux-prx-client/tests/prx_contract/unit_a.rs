// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Unit A rows at pin `f1d430ced`: admission limits, history erase, and purge.
//! Ignored with the rest of `prx_contract`. No wall-clock wait is added here.

use super::{bounded, capabilities, config, list_revision, put_agent, report, rf_message};
use ramflux_prx_client::{
    AgentLimits, AgentName, AgentStatus, ApiCode, ConfigRevision, PURGE_STORES, PrxError, RowBody,
    Target, TurnDisposition,
};
use std::time::Duration;

fn name(raw: &str) -> AgentName {
    AgentName::parse(raw).expect("test: agent name")
}

#[tokio::test]
#[ignore = "needs RAMFLUX_PRX_BIN: a prx binary built at the pinned commit"]
async fn k_ua_limits_round_trip() {
    bounded(async {
        let (mut daemon, stub) = super::paired_rf_daemon("").await;
        let client = daemon.client();
        let caps = capabilities(&client).await;
        assert!(caps.has(ramflux_prx_client::AGENT_LIMITS_V1), "K-UA-limits: token");
        let bounded_name = name("bounded");
        let rev = list_revision(&client, &caps).await;
        let cfg = ramflux_prx_client::AgentConfig {
            limits: Some(AgentLimits {
                max_concurrent_turns: Some(1),
                max_cost_per_day_cents: None,
            }),
            ..config(&stub.provider(), "stub-model", None, ramflux_prx_client::Tools::All, true)
        };
        let put =
            client.put(&caps, &bounded_name, &cfg, &rev, true).await.expect("K-UA-limits: PUT");
        assert_eq!(
            put.readback.config.limits,
            Some(AgentLimits { max_concurrent_turns: Some(1), max_cost_per_day_cents: None }),
            "K-UA-limits: readback echoes the bound"
        );
        put_agent(&client, &caps, "plain", &stub.provider(), true).await;
        let plain = client.get(&caps, &name("plain")).await.expect("K-UA-limits: GET");
        assert_eq!(plain.config.limits, None, "K-UA-limits: unset limits read back as unset");
        report("K-UA-limits");
        daemon.stop();
    })
    .await;
}

#[tokio::test]
#[ignore = "needs RAMFLUX_PRX_BIN: a prx binary built at the pinned commit"]
async fn k_ua_agent_busy() {
    bounded(async {
        let hold = super::ModelStub::start(Duration::from_secs(600)).await;
        let mut daemon =
            super::Daemon::prepare_with_provider(&hold.provider(), "targeted_agents = true\n");
        daemon.start();
        daemon.wait_ready().await;
        daemon.pair().await;
        let client = daemon.client();
        let caps = capabilities(&client).await;
        let agent = name("busy1");
        let rev = list_revision(&client, &caps).await;
        let cfg = ramflux_prx_client::AgentConfig {
            limits: Some(AgentLimits {
                max_concurrent_turns: Some(1),
                max_cost_per_day_cents: None,
            }),
            ..config(&hold.provider(), "stub-model", None, ramflux_prx_client::Tools::All, true)
        };
        client.put(&caps, &agent, &cfg, &rev, true).await.expect("K-UA-busy: PUT");
        let target = Target::Named(agent);
        client.create_session(&caps, "rf-unit-a-busy-0001").await.expect("K-UA-busy: session 1");
        client.create_session(&caps, "rf-unit-a-busy-0002").await.expect("K-UA-busy: session 2");
        let first = client
            .post_turn(
                &caps,
                "rf-unit-a-busy-0001",
                &rf_message("rf-ua-busy-1", target.clone(), "hold"),
            )
            .await
            .expect("K-UA-busy: first turn is admitted");
        assert!(matches!(first.disposition, TurnDisposition::Admitted), "K-UA-busy: {first:?}");
        let second = client
            .post_turn(&caps, "rf-unit-a-busy-0002", &rf_message("rf-ua-busy-2", target, "again"))
            .await;
        assert!(
            matches!(second, Err(PrxError::AgentBusy { retry_after_secs: Some(1) })),
            "K-UA-busy: second turn is agent_busy, got {second:?}"
        );
        report("K-UA-busy");
        daemon.stop();
    })
    .await;
}

#[tokio::test]
#[ignore = "needs RAMFLUX_PRX_BIN: a prx binary built at the pinned commit"]
async fn k_ua_session_erase() {
    bounded(async {
        let fast = super::ModelStub::start(Duration::ZERO).await;
        let mut daemon =
            super::Daemon::prepare_with_provider(&fast.provider(), "targeted_agents = true\n");
        daemon.start();
        daemon.wait_ready().await;
        daemon.pair().await;
        let client = daemon.client();
        let caps = capabilities(&client).await;
        assert!(caps.has(ramflux_prx_client::HISTORY_ERASE_V1), "K-UA-erase: token");
        assert!(caps.has(ramflux_prx_client::MESSAGE_FORGET_WRITES_V1), "K-UA-erase: forget token");
        let session = "rf-unit-a-erase-0001";
        client.create_session(&caps, session).await.expect("K-UA-erase: session");
        put_agent(&client, &caps, "writer", &fast.provider(), true).await;
        let writer = Target::Named(name("writer"));
        client
            .post_context(
                &caps,
                session,
                &rf_message("rf-ua-erase-main", Target::Main, "main context"),
            )
            .await
            .expect("K-UA-erase: main context");
        client
            .post_context(
                &caps,
                session,
                &rf_message("rf-ua-erase-writer", writer.clone(), "writer context"),
            )
            .await
            .expect("K-UA-erase: writer context");
        let before = client.session_messages(&caps, session, None).await.expect("K-UA-erase: read");
        let live = |agent: &Target| {
            before.iter().any(|row| &row.agent == agent && matches!(row.body, RowBody::Text { .. }))
        };
        assert!(live(&Target::Main) && live(&writer), "K-UA-erase: both partitions have a turn");
        let erased = client
            .erase_session_history(&caps, session, "unit-a-erase-key-01")
            .await
            .expect("K-UA-erase");
        let labels: Vec<&str> = erased.iter().map(|row| row.scope.agent.as_str()).collect();
        assert!(labels.contains(&"main") && labels.contains(&"writer"), "K-UA-erase: {labels:?}");
        assert!(
            erased
                .iter()
                .all(|row| row.remaining == 0 && row.generation >= 1 && row.forgotten.is_some()),
            "K-UA-erase: {erased:?}"
        );
        let after = client.session_messages(&caps, session, None).await.expect("K-UA-erase: after");
        assert!(
            after.iter().all(|row| !matches!(row.body, RowBody::Text { .. })),
            "K-UA-erase: no live turn remains: {after:?}"
        );
        report("K-UA-erase");
        daemon.stop();
    })
    .await;
}

#[tokio::test]
#[ignore = "needs RAMFLUX_PRX_BIN: a prx binary built at the pinned commit"]
async fn k_ua_purge_order_and_receipt() {
    bounded(async {
        let (mut daemon, stub) = super::paired_rf_daemon("").await;
        let client = daemon.client();
        let caps = capabilities(&client).await;
        assert!(caps.has(ramflux_prx_client::AGENT_MEMORY_PURGE_V1), "K-UA-purge: token");
        put_agent(&client, &caps, "purge1", &stub.provider(), true).await;
        let agent = name("purge1");
        let rev = list_revision(&client, &caps).await;
        let active = client.purge(&caps, &agent, &rev, "unit-a-purge-active01").await;
        assert!(
            matches!(
                active,
                Err(PrxError::Api { status: 409, code: ApiCode::AgentNotRetired, .. })
            ),
            "K-UA-purge: active agent is refused, got {active:?}"
        );
        let still = client.get(&caps, &agent).await.expect("K-UA-purge: still configured");
        assert_eq!(still.status, AgentStatus::Active, "K-UA-purge: DELETE has not run");
        let receipt = client
            .retire_and_purge(&caps, &agent, &still.revision, "unit-a-purge-retire01")
            .await
            .expect("K-UA-purge: retire then purge");
        assert_eq!(receipt.name, agent);
        assert!(!receipt.incarnations.is_empty(), "K-UA-purge: an incarnation");
        assert!(receipt.completed_at.len() == 20 && receipt.completed_at.ends_with('Z'));
        for store in PURGE_STORES {
            assert!(receipt.counts.contains_key(store), "K-UA-purge: missing {store}");
        }
        let other = ConfigRevision::parse(&"ab".repeat(32)).expect("test: revision");
        let replay = client
            .purge(&caps, &agent, &other, "unit-a-purge-replay01")
            .await
            .expect("K-UA-purge: a later key replays the receipt");
        assert_eq!(replay, receipt, "K-UA-purge: the receipt is permanent");
        let gone = client.get(&caps, &agent).await;
        assert!(
            matches!(gone, Err(PrxError::Api { status: 404, code: ApiCode::AgentUnknown, .. })),
            "K-UA-purge: config is gone, got {gone:?}"
        );
        report("K-UA-purge");
        daemon.stop();
    })
    .await;
}

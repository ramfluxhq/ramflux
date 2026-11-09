// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

#![allow(clippy::expect_used)]

//! Local-first creation and immediate admission-outcome publication.

use super::*;
use tokio::sync::{Notify, Semaphore};

pub(crate) struct NetworkGate {
    pub waiting: Notify,
    pub applied: Notify,
    pub release: Semaphore,
}

pub(super) async fn wait_for_reason(
    socket: &std::path::Path,
    id: &str,
    expected_kind: &str,
) -> Result {
    let mut events = connect(socket).await?;
    events
        .request(
            Some(id.into()),
            "stream",
            "bus.subscribe",
            json!({"topics":["account.networking.changed"],"since_seq":0}),
        )
        .await?;
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let event = events.next_event().await?;
            if event.body["networking_reason"]["kind"] == expected_kind {
                return Ok::<_, crate::SdkError>(());
            }
        }
    })
    .await??;
    Ok(())
}

async fn confirm(socket: &std::path::Path, node: &str) -> Result<crate::LocalBusCreatedAccount> {
    use crate::LocalBusCreationClient;
    use zeroize::Zeroizing;
    let mut ceremony = LocalBusCreationClient::connect(socket).await?;
    ceremony.begin_with_node("Local First", ramflux_protocol::PrincipalKind::Human, node).await?;
    let phrase = ceremony.show_once().await?;
    let answers = words(&phrase, ceremony.hidden_challenge().await?)?;
    let account = tokio::time::timeout(
        Duration::from_secs(10),
        ceremony.confirm(&answers, &Zeroizing::new("local first secret".into())),
    )
    .await??;
    assert_eq!(account.state, crate::LocalBusCreatedAccountState::Unlocked);
    assert_eq!(account.networking, crate::custody::CreationState::NetworkingPending);
    Ok(account)
}

fn configure(root: &Root, gateway: &CauseGateway) -> Result<(LocalBusConfig, String)> {
    let profile =
        node_profile_with_ca("localhost", &gateway.address.to_string(), 8, &gateway.ca_pem);
    let mut nodes = crate::node::NodeStore::default();
    nodes.profiles.insert(profile.node_id.clone(), profile.clone());
    nodes.save(&root.0)?;
    let mut config = LocalBusConfig::new(root.0.join("local-first.sock"), &root.0);
    config.custody_vault = Some(Arc::new(TestVault::default()));
    Ok((config, profile.node_id))
}

#[tokio::test]
async fn creation_confirm_replies_before_first_admission_attempt_completes() -> Result {
    let root = Root::new()?;
    let admission = Arc::new(Semaphore::new(0));
    let gateway =
        CauseGateway::start_held(&root.0, GatewayCause::PoolBusy, Some(admission.clone())).await?;
    let (config, node) = configure(&root, &gateway)?;
    assert!(config.test_retry_budget.is_none());
    let socket = config.socket_path.clone();
    let (stop, receiver) = watch::channel(false);
    let flow = async {
        let _stop = Stop(stop);
        drop(connect(&socket).await?);
        let account = confirm(&socket, &node).await?;
        tokio::time::timeout(Duration::from_secs(10), gateway.admission_entered.notified()).await?;
        assert_eq!(admission.available_permits(), 0);
        let mut bus = connect(&socket).await?;
        let status = tokio::time::timeout(
            Duration::from_secs(10),
            bus.request(Some(account.account_id.clone()), "account", "account.status", json!({})),
        )
        .await??;
        assert_eq!(status["state"], "unlocked");
        assert_eq!(status["networking_snapshot"]["state"], "networking_pending");
        tokio::time::timeout(
            Duration::from_secs(10),
            bus.request(Some(account.account_id.clone()), "contact", "contact.list", json!({})),
        )
        .await??;
        let listed = bus.request(None, "account", "account.list", json!({})).await?;
        assert_eq!(listed["account_details"][0]["state"], "unlocked");
        // No admission response can have been produced while local requests completed.
        assert_eq!(admission.available_permits(), 0);
        Ok::<_, Box<dyn std::error::Error>>(())
    };
    let (server, flow) = tokio::join!(crate::serve_local_bus_until(config, receiver), flow);
    server?;
    flow
}

#[tokio::test]
async fn first_admission_outcome_is_published_without_a_following_command() -> Result {
    for with_network_command in [false, true] {
        publication_case(with_network_command).await?;
    }
    Ok(())
}

async fn publication_case(with_network_command: bool) -> Result {
    let root = Root::new()?;
    let admission = Arc::new(Semaphore::new(0));
    let gateway = CauseGateway::start_held(
        &root.0,
        GatewayCause::Refused(CustodyRefusal::PrincipalIdTaken),
        Some(admission.clone()),
    )
    .await?;
    let (mut config, node) = configure(&root, &gateway)?;
    config.test_suppress_receive_timers = true;
    let gate = Arc::new(NetworkGate {
        waiting: Notify::new(),
        applied: Notify::new(),
        release: Semaphore::new(0),
    });
    if with_network_command {
        config.test_network_command_gate = Some(gate.clone());
    }
    let socket = config.socket_path.clone();
    let (stop, receiver) = watch::channel(false);
    let flow = async {
        let _stop = Stop(stop);
        drop(connect(&socket).await?);
        let account = confirm(&socket, &node).await?;
        let mut events = connect(&socket).await?;
        events
            .request(
                Some(account.account_id.clone()),
                "stream",
                "bus.subscribe",
                json!({"topics":["account.networking.changed"]}),
            )
            .await?;
        let mut bus = connect(&socket).await?;
        let request =
            bus.request(Some(account.account_id), "account", "device.authorize", json!({}));
        tokio::pin!(request);
        if with_network_command {
            tokio::select! {
                result = &mut request => panic!("network command returned before admission: {result:?}"),
                result = tokio::time::timeout(Duration::from_secs(10), gate.waiting.notified()) => { result?; }
            }
        }
        tokio::time::timeout(Duration::from_secs(10), gateway.admission_entered.notified()).await?;
        admission.add_permits(1);
        let event = async {
            loop {
                let event = events.next_event().await?;
                if event.body["networking_reason"]
                    == json!({"kind":"registration_refused","code":"principal_id_taken"})
                {
                    return Ok::<_, crate::SdkError>(event);
                }
            }
        };
        tokio::pin!(event);
        let notification = if with_network_command {
            tokio::select! {
                result = &mut request => panic!("network command escaped its hold: {result:?}"),
                result = tokio::time::timeout(Duration::from_secs(30), &mut event) => {
                    result.expect("admission outcome event hang guard expired")?
                },
            }
        } else {
            tokio::time::timeout(Duration::from_secs(30), &mut event)
                .await
                .expect("admission outcome event hang guard expired")?
        };
        assert_eq!(notification.method, "account.networking.changed");
        if with_network_command {
            tokio::time::timeout(Duration::from_secs(10), gate.applied.notified()).await?;
            gate.release.add_permits(1);
            assert!(tokio::time::timeout(Duration::from_secs(10), &mut request).await?.is_err());
        }
        Ok::<_, Box<dyn std::error::Error>>(())
    };
    let (server, flow) = tokio::join!(crate::serve_local_bus_until(config, receiver), flow);
    server?;
    flow
}

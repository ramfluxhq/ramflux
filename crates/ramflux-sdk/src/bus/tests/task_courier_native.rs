// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Native admission and private unlock keep courier work behind the account's live boundary.
use super::*;
use crate::custody::tests::{Root, TestVault, input, mark_live, words};

#[tokio::test]
async fn courier_native_private_unlock_starts_after_admission_and_preserves_pending_jobs() -> Case {
    LocalSet::new()
        .run_until(Box::pin(async {
            let root = Root::new()?;
            let vault = Arc::new(TestVault::default());
            let now = crate::custody::network_now()?;
            let mut ceremony =
                crate::custody::CreationCeremony::begin(&root.0, input("sender"), now)?;
            let phrase = ceremony.show_once()?;
            let positions = ceremony.hidden_challenge()?;
            ceremony.confirm_with_passphrase(
                &words(&phrase, positions)?,
                vault.as_ref(),
                now,
                b"passphrase",
            )?;
            let (_commands, receiver) = mpsc::channel(1);
            let (_stop, shutdown) = watch::channel(false);
            let (events, mut batches) = mpsc::channel::<EventBatch>(8);
            tokio::task::spawn_local(async move {
                while let Some(batch) = batches.recv().await {
                    let _ = batch.accepted.send(());
                }
            });
            let mut config = LocalBusConfig::new(root.0.join("bus.sock"), &root.0);
            config.custody_vault = Some(vault);
            let mut runtime = AccountRuntime {
                id: "sender".into(),
                state: LocalBusDaemonState {
                    account_index: None,
                    config,
                    nodes: crate::node::NodeStore::default(),
                    accounts: BTreeMap::new(),
                    active_account_id: None,
                    attended_accounts: BTreeSet::new(),
                    subscribers: BTreeMap::new(),
                },
                receiver,
                readers: Arc::new(Mutex::new(None)),
                events,
                shutdown,
                courier: None,
                courier_events: None,
            };
            private_unlock(&mut runtime).await?;
            assert!(runtime.courier.is_none(), "pending native data must not start preparation");
            let account =
                runtime.state.accounts.get_mut("sender").ok_or("native account missing")?;
            account
                .client
                .account_db()?
                .persist_actor_state("task/ack/pending", &json!({"pending":true}))?;
            assert_eq!(task_courier_queue::manifest_requests(account)?.len(), 0);
            assert!(
                account.client.account_db()?.actor_state_exists("task/ack/pending")?,
                "pending restore data must not be quarantined before admission"
            );
            // Model the authoritative admission checkpoint; this test does not impersonate a gateway.
            mark_live(&root.0, "sender", now)?;
            account.client.born_v3_account =
                Some(Box::new(crate::custody::load_account(&root.0, "sender", now)?));
            account.activation_pending = false;
            private_unlock(&mut runtime).await?;
            assert!(
                runtime.courier.is_some(),
                "private native unlock must start admitted courier work"
            );
            assert!(
                runtime
                    .state
                    .accounts
                    .get("sender")
                    .ok_or("account missing")?
                    .task_courier_wake
                    .is_some()
            );
            runtime.stop_courier().await;
            runtime.close_readers().await;
            runtime.state.accounts.clear();
            Ok(())
        }))
        .await
}

async fn private_unlock(runtime: &mut AccountRuntime) -> Case {
    let (reply, response) = oneshot::channel();
    let (outbound, _) = mpsc::channel(1);
    let command = AccountCommand {
        private: Some(crate::bus::actor::PrivateCommand::NativeUnlock {
            passphrase: zeroize::Zeroizing::new("passphrase".into()),
            home_node_id: None,
            reply,
        }),
        request: LocalBusFrame::request(
            "native-unlock",
            Some("sender".into()),
            "account",
            "account.unlock",
            json!({}),
        ),
        connection_id: 1,
        topics: BTreeSet::new(),
        attended: true,
        nodes: None,
        outbound,
        reply: None,
    };
    assert!(!runtime.apply(command).await?);
    response.await??;
    Ok(())
}

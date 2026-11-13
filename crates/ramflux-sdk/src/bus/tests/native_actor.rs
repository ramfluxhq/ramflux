// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Native protocol fixtures start the real account actor without exporting its private mailbox.

use crate::bus::{
    actor::{AccountActor, ActorOptions},
    events::EventBatch,
    runtime_limits::RuntimeTimeouts,
};
use crate::prelude::*;

pub(crate) struct NativeActor {
    actor: AccountActor,
    router: tokio::task::JoinHandle<()>,
}
impl NativeActor {
    pub(crate) async fn start(
        client: RamfluxClient,
        config: GatewaySessionConfig,
        passphrase: Vec<u8>,
        timeouts: RuntimeTimeouts,
    ) -> Result<Self, SdkError> {
        let native = config.custody.as_ref().ok_or(SdkError::CustodySetupInvalid)?;
        let root = native.account_root.clone();
        let id = native.account_id.clone();
        let initial_id = id.clone();
        let own = client.own_account_anchor()?;
        let branch = client.device_branch.clone().ok_or(SdkError::IdentityRootMissing)?;
        let index = client.account_index()?.clone();
        // This is an in-process actor handoff: keep actual observation timestamps,
        // rather than recreating freshness from the durable directory cache.
        let freshness = client.native_head_freshness.take();
        drop(client);
        let passphrase = zeroize::Zeroizing::new(passphrase);
        let (events, mut batches) = mpsc::channel::<EventBatch>(64);
        let router = tokio::task::spawn_local(async move {
            while let Some(batch) = batches.recv().await {
                let _ = batch.accepted.send(());
            }
        });
        let actor = AccountActor::start_local(
            id,
            LocalBusConfig::new(root.join("bus.sock"), &root),
            crate::node::NodeStore::default(),
            index,
            events,
            ActorOptions {
                timeouts,
                initial: Some(Box::new(move |index| {
                    let mut client = RamfluxClient::new();
                    client.open_account_index(index.root())?;
                    client.unlock_account(&initial_id, &passphrase)?;
                    *client.native_head_freshness.borrow_mut() = freshness;
                    client.device_branch = Some(branch.clone());
                    client
                        .active_account_db
                        .as_mut()
                        .ok_or(SdkError::AccountDbNotUnlocked)?
                        .set_device_signer(branch);
                    Ok(LocalBusAccountState::disconnected(client, config, own))
                })),
            },
        )
        .await?;
        Ok(Self { actor, router })
    }
    pub(crate) fn connection(
        &self,
    ) -> Result<crate::bus::connection_manager::ConnectionHandle, SdkError> {
        self.actor.connection_for_test().ok_or(SdkError::GatewaySessionNotEstablished)
    }
    pub(crate) fn request(
        &self,
        request: LocalBusFrame,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<serde_json::Value, SdkError>>>>
    {
        let actor = self.actor.clone();
        Box::pin(async move {
            let (outbound, _) = mpsc::channel(1);
            actor
                .request(crate::bus::actor::AccountCommand {
                    admission: None,
                    private: None,
                    request,
                    connection_id: 1,
                    topics: BTreeSet::new(),
                    attended: true,
                    nodes: None,
                    outbound: outbound.into(),
                    reply: None,
                })
                .await
                .map(|response| response.body)
        })
    }
    pub(crate) async fn stop(self) -> Result<(), SdkError> {
        self.actor.stop().await?;
        drop(self.actor);
        self.router
            .await
            .map_err(|error| SdkError::LocalBus(format!("fixture event router failed: {error}")))
    }
}

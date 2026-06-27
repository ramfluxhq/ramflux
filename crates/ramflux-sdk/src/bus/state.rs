// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

#![allow(clippy::missing_errors_doc)]
#![allow(clippy::wildcard_imports)]
use crate::prelude::*;

pub(crate) struct LocalBusDaemonState {
    pub(crate) config: LocalBusConfig,
    pub(crate) accounts: BTreeMap<String, LocalBusAccountState>,
    pub(crate) active_account_id: Option<String>,
    pub(crate) attended_accounts: BTreeSet<String>,
    pub(crate) subscribers: BTreeMap<u64, LocalBusSubscriber>,
}

pub(crate) struct LocalBusSubscriber {
    pub(crate) account_id: String,
    pub(crate) topics: BTreeSet<String>,
    pub(crate) outbound: mpsc::Sender<LocalBusFrame>,
}

pub(crate) struct LocalBusAccountState {
    pub(crate) client: RamfluxClient,
    pub(crate) engine: Option<GatewaySessionEngine>,
    pub(crate) gateway_config: GatewaySessionConfig,
    pub(crate) principal_commitment: String,
    pub(crate) target_delivery_id: String,
    pub(crate) pending_deliveries: Vec<GatewayInboxEntry>,
    pub(crate) acked_envelope_ids: BTreeSet<String>,
    pub(crate) calls: BTreeMap<String, LocalCallRecord>,
    pub(crate) bots: BTreeMap<String, LocalBotRecord>,
    pub(crate) pending_a2i: BTreeMap<String, A2iControlEvent>,
    pub(crate) mcp_registry: McpRegistry,
    pub(crate) mcp_grants: BTreeMap<String, LocalMcpGrantRecord>,
    pub(crate) mcp_standing_approvals: BTreeMap<String, LocalMcpStandingApprovalRecord>,
    pub(crate) mcp_pending_approvals: BTreeMap<String, LocalMcpApprovalRecord>,
    pub(crate) mcp_audit_log: Vec<LocalMcpAuditRecord>,
}

impl LocalBusAccountState {
    pub(crate) fn new(
        client: RamfluxClient,
        engine: GatewaySessionEngine,
        principal_commitment: String,
    ) -> Self {
        let gateway_config = engine.config.clone();
        let target_delivery_id = engine.target_delivery_id().to_owned();
        Self {
            client,
            engine: Some(engine),
            gateway_config,
            principal_commitment,
            target_delivery_id,
            pending_deliveries: Vec::new(),
            acked_envelope_ids: BTreeSet::new(),
            calls: BTreeMap::new(),
            bots: BTreeMap::new(),
            pending_a2i: BTreeMap::new(),
            mcp_registry: McpRegistry::new(),
            mcp_grants: BTreeMap::new(),
            mcp_standing_approvals: BTreeMap::new(),
            mcp_pending_approvals: BTreeMap::new(),
            mcp_audit_log: Vec::new(),
        }
    }

    pub(crate) fn disconnected(
        client: RamfluxClient,
        gateway_config: GatewaySessionConfig,
        principal_commitment: String,
    ) -> Self {
        let target_delivery_id = gateway_config.target_delivery_id.clone();
        Self {
            client,
            engine: None,
            gateway_config,
            principal_commitment,
            target_delivery_id,
            pending_deliveries: Vec::new(),
            acked_envelope_ids: BTreeSet::new(),
            calls: BTreeMap::new(),
            bots: BTreeMap::new(),
            pending_a2i: BTreeMap::new(),
            mcp_registry: McpRegistry::new(),
            mcp_grants: BTreeMap::new(),
            mcp_standing_approvals: BTreeMap::new(),
            mcp_pending_approvals: BTreeMap::new(),
            mcp_audit_log: Vec::new(),
        }
    }

    pub(crate) fn merge_deliveries(
        &mut self,
        entries: Vec<GatewayInboxEntry>,
    ) -> Vec<GatewayInboxEntry> {
        let mut fresh = Vec::new();
        for entry in entries {
            let envelope_id = &entry.envelope.envelope_id;
            if self.acked_envelope_ids.contains(envelope_id)
                || self
                    .pending_deliveries
                    .iter()
                    .any(|pending| pending.envelope.envelope_id == *envelope_id)
            {
                continue;
            }
            self.pending_deliveries.push(entry.clone());
            fresh.push(entry);
        }
        fresh
    }

    pub(crate) fn pending_page(&self, limit: usize) -> Vec<GatewayInboxEntry> {
        self.pending_deliveries.iter().take(limit).cloned().collect()
    }

    pub(crate) fn mark_acked(&mut self, envelope_id: &str) {
        self.acked_envelope_ids.insert(envelope_id.to_owned());
        self.pending_deliveries.retain(|entry| entry.envelope.envelope_id != envelope_id);
    }

    pub(crate) async fn ensure_gateway_live(&mut self) -> Result<(), SdkError> {
        let target_delivery_id = self.target_delivery_id.clone();
        let last_seen_inbox_seq = self
            .client
            .gateway_cursor(&target_delivery_id)?
            .max(self.client.gateway_receive_cursor(&target_delivery_id)?);
        if let Some(engine) = self.engine.as_mut() {
            gateway_session_timeout("gateway ensure live", engine.ensure_live(last_seen_inbox_seq))
                .await
        } else {
            let mut config = self.gateway_config.clone();
            config.last_seen_inbox_seq = last_seen_inbox_seq;
            if config.device_branch.is_none()
                && let Some(branch) = self.client.device_branch.as_ref()
                && branch.principal_id == config.principal_id
                && branch.device_id == config.device_id
                && branch.device_epoch == config.device_epoch
            {
                config.device_branch = Some(std::sync::Arc::new(branch.clone()));
            }
            self.engine = Some(
                gateway_session_timeout("gateway connect", GatewaySessionEngine::connect(config))
                    .await?,
            );
            Ok(())
        }
    }

    pub(crate) async fn take_live_engine(&mut self) -> Result<GatewaySessionEngine, SdkError> {
        self.ensure_gateway_live().await?;
        self.engine.take().ok_or(SdkError::GatewaySessionNotEstablished)
    }

    pub(crate) fn put_engine(&mut self, engine: GatewaySessionEngine) {
        self.gateway_config = engine.config.clone();
        engine.target_delivery_id().clone_into(&mut self.target_delivery_id);
        self.engine = Some(engine);
    }
}
pub(crate) struct LocalBusConnectionState {
    pub(crate) connection_id: u64,
    pub(crate) outbound: mpsc::Sender<LocalBusFrame>,
    pub(crate) topics: BTreeSet<String>,
    pub(crate) attended_account_id: Option<String>,
    pub(crate) pending_events: Vec<LocalBusFrame>,
}

impl LocalBusConnectionState {
    pub(crate) fn new(connection_id: u64, outbound: mpsc::Sender<LocalBusFrame>) -> Self {
        Self {
            connection_id,
            outbound,
            topics: BTreeSet::new(),
            attended_account_id: None,
            pending_events: Vec::new(),
        }
    }

    pub(crate) fn push_event(&mut self, event: LocalBusFrame) {
        self.pending_events.push(event);
    }

    pub(crate) fn drain_events(&mut self) -> Vec<LocalBusFrame> {
        std::mem::take(&mut self.pending_events)
    }
}

impl LocalBusDaemonState {
    pub(crate) fn register_subscription(
        &mut self,
        connection: &LocalBusConnectionState,
        account_id: String,
    ) {
        self.subscribers.insert(
            connection.connection_id,
            LocalBusSubscriber {
                account_id,
                topics: connection.topics.clone(),
                outbound: connection.outbound.clone(),
            },
        );
    }

    pub(crate) fn unregister_connection(&mut self, connection_id: u64) {
        self.subscribers.remove(&connection_id);
    }

    pub(crate) fn broadcast_events(&mut self, events: &[LocalBusFrame]) {
        let mut stale_connections = BTreeSet::new();
        for event in events {
            let Some(account_id) = event.account_id.as_deref() else {
                continue;
            };
            for (connection_id, subscriber) in &self.subscribers {
                if subscriber.account_id != account_id || !subscriber.topics.contains(&event.method)
                {
                    continue;
                }
                match subscriber.outbound.try_send(event.clone()) {
                    Ok(()) => {}
                    Err(
                        mpsc::error::TrySendError::Full(_) | mpsc::error::TrySendError::Closed(_),
                    ) => {
                        stale_connections.insert(*connection_id);
                    }
                }
            }
        }
        for connection_id in stale_connections {
            self.subscribers.remove(&connection_id);
        }
    }
}

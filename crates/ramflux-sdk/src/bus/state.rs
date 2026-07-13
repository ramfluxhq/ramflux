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

/// T25-A3 (CTRL-102 / OBJ-IPC-01): an in-flight bounded UPLOAD spool for one large `object.put`,
/// keyed by `operation_id` on the owning account. `object.put.begin` binds the content-and-intent
/// and opens the private (0600, `create_new`) spool file; each `object.put.chunk` appends bounded
/// plaintext at the verified `written` offset; `object.put.finish` reads the whole (<= 16 MiB)
/// plaintext back, verifies hash + len, then reuses the A2 durable commit. Any failure — and every
/// finish — removes the spool file AND its journal.
///
/// T25-A5 (OBJ-IPC-01): a durable crash-resume journal is now maintained alongside the spool. Each
/// chunk records `written` + `prefix_hash` (the BLAKE3 of the durably-written spool prefix) into a
/// fsync'd sidecar AFTER the spool bytes are fsync'd, so a mid-upload rfd `SIGKILL`/abort resumes
/// from the durable offset on restart instead of re-uploading from zero. `prefix_hasher` is the
/// incremental hasher whose current finalize is recorded into the journal each chunk.
pub(crate) struct ObjectPutSpoolSession {
    pub(crate) account_id: String,
    pub(crate) operation_id: String,
    pub(crate) object_id: String,
    pub(crate) total_len: usize,
    pub(crate) plaintext_hash: String,
    pub(crate) chunk_size: usize,
    pub(crate) relay_endpoint: Option<String>,
    pub(crate) relay_service_key_base64: Option<String>,
    pub(crate) relay_interrupt_after_chunks: Option<u32>,
    pub(crate) path: PathBuf,
    pub(crate) journal_path: PathBuf,
    pub(crate) file: std::fs::File,
    pub(crate) written: usize,
    pub(crate) prefix_hasher: ramflux_crypto::Blake3DomainHasher,
}

/// T25-A4 (CTRL-104 / OBJ-IPC-01): an in-flight bounded DOWNLOAD spool for one large `object.get`,
/// keyed by `operation_id` on the owning account. `object.get.begin` decrypts the whole (<= 16 MiB)
/// plaintext, spools it to a private (0600, `create_new`) temp file, and records `total_len` +
/// `plaintext_hash`; each `object.get.read` serves a bounded slice at the verified sequential
/// `read_offset`; `object.get.finish` (or a begin re-entry / the daemon-startup sweep) removes it. It
/// is in-memory only (no crash-resume journal: that is A5) so an rfd restart drops it and the orphan
/// file is swept on the next startup. Never echoes ciphertext.
pub(crate) struct ObjectGetSpoolSession {
    pub(crate) object_id: String,
    pub(crate) total_len: usize,
    pub(crate) plaintext_hash: String,
    pub(crate) path: PathBuf,
    pub(crate) file: std::fs::File,
    pub(crate) read_offset: usize,
}

pub(crate) struct LocalBusAccountState {
    pub(crate) client: RamfluxClient,
    pub(crate) engine: Option<GatewaySessionEngine>,
    /// Per-account relay QUIC connection pool (T24-A2), shared via `Arc`. Lazily built on first
    /// relay transfer and then owned by the account for its whole lifetime; each relay request
    /// takes only an `Arc::clone` (never moving the instance out), so a cancelled or failing
    /// request cannot leave the account without its pool. It persists across engine take/return and
    /// gateway reconnect, is a distinct instance per account (no process-global pool, and it is
    /// deliberately not stored inside the `GatewaySessionEngine`). `None` until first use; an rfd
    /// restart cold-rebuilds it.
    pub(crate) relay_quic_pool: Option<std::sync::Arc<ramflux_transport::RelayQuicPool>>,
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
    /// T25-A3 (OBJ-IPC-01): in-flight bounded UPLOAD spools, keyed by `operation_id`.
    pub(crate) object_put_spools: BTreeMap<String, ObjectPutSpoolSession>,
    /// T25-A4 (OBJ-IPC-01): in-flight bounded DOWNLOAD spools, keyed by `operation_id`.
    pub(crate) object_get_spools: BTreeMap<String, ObjectGetSpoolSession>,
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
            relay_quic_pool: None,
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
            object_put_spools: BTreeMap::new(),
            object_get_spools: BTreeMap::new(),
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
            relay_quic_pool: None,
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
            object_put_spools: BTreeMap::new(),
            object_get_spools: BTreeMap::new(),
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

    /// Returns a shared handle to the account's relay QUIC pool, installing it (with the current
    /// safe functional defaults) on first use. The pool **instance lives on the account** for the
    /// account's whole lifetime; callers hold only an `Arc::clone` for the duration of their
    /// request, so a cancelled or failing request drops only the clone and can never leave the
    /// account without its pool. This is genuine persistent per-account ownership — an `Arc`, not a
    /// process-global, and it needs no lock across `.await`. Different accounts lazily build
    /// distinct `Arc`s. On config-creation failure the account is left unchanged and a clear error
    /// is returned.
    pub(crate) fn relay_quic_pool(
        &mut self,
    ) -> Result<std::sync::Arc<ramflux_transport::RelayQuicPool>, SdkError> {
        if let Some(pool) = self.relay_quic_pool.as_ref() {
            return Ok(std::sync::Arc::clone(pool));
        }
        let config =
            ramflux_transport::RelayQuicPoolConfig::functional_default().map_err(|error| {
                SdkError::Transport(ramflux_transport::TransportError::Quic(format!(
                    "relay QUIC pool config: {error}"
                )))
            })?;
        let pool = std::sync::Arc::new(ramflux_transport::RelayQuicPool::new(config));
        self.relay_quic_pool = Some(std::sync::Arc::clone(&pool));
        Ok(pool)
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

#[cfg(test)]
mod t24a2_pool_ownership_tests {
    //! T24-A2 pool ownership: each account owns its own `RelayQuicPool` via `Arc` for its whole
    //! lifetime (never a process-global). Requests hold only an `Arc::clone`, so a cancelled or
    //! failing request drops only the clone and never the account's pool. The
    //! engine-reconnect-keeps-pool property is structural — `take_live_engine`/`put_engine` only
    //! touch `self.engine`, a distinct field from `self.relay_quic_pool` — and is additionally
    //! exercised end-to-end by the s55/s56 realnet regression.
    use super::LocalBusAccountState;
    use crate::gateway::{GatewayQuicEndpointConfig, GatewaySessionConfig};
    use crate::prelude::RamfluxClient;
    use std::net::{Ipv4Addr, SocketAddr};
    use std::path::PathBuf;
    use std::sync::Arc;

    fn test_account() -> LocalBusAccountState {
        let gateway = GatewaySessionConfig::quic(GatewayQuicEndpointConfig {
            bind_addr: SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
            gateway_addr: SocketAddr::from((Ipv4Addr::LOCALHOST, 1)),
            server_name: "ramflux-gateway".to_owned(),
            ca_cert: PathBuf::from("ca.pem"),
            principal_id: "principal_pool_test".to_owned(),
            device_id: "device_pool_test".to_owned(),
            target_delivery_id: "target_pool_test".to_owned(),
            prekey_http_url: None,
        });
        LocalBusAccountState::disconnected(
            RamfluxClient::new(),
            gateway,
            "principal_pool_test".to_owned(),
        )
    }

    #[test]
    fn accessor_installs_once_and_returns_the_same_arc_per_account() -> Result<(), crate::SdkError>
    {
        let mut account = test_account();
        assert!(account.relay_quic_pool.is_none(), "no pool until first relay transfer");
        let first = account.relay_quic_pool()?;
        assert!(
            account.relay_quic_pool.is_some(),
            "pool is installed on the account, not moved out"
        );
        let second = account.relay_quic_pool()?;
        assert!(Arc::ptr_eq(&first, &second), "same account returns the same pool instance");
        Ok(())
    }

    #[test]
    fn different_accounts_get_distinct_pool_instances() -> Result<(), crate::SdkError> {
        let mut account_a = test_account();
        let mut account_b = test_account();
        let pool_a = account_a.relay_quic_pool()?;
        let pool_b = account_b.relay_quic_pool()?;
        assert!(!Arc::ptr_eq(&pool_a, &pool_b), "each account owns a distinct pool (no global)");
        Ok(())
    }

    #[test]
    fn dropping_a_request_clone_leaves_the_account_pool_intact() -> Result<(), crate::SdkError> {
        // Models a request (or an aborted future) that acquired the pool clone and then ended: the
        // clone is dropped, but the account's own Arc must remain, so a later request sees the very
        // same instance rather than a silent cold rebuild.
        let mut account = test_account();
        let original = account.relay_quic_pool()?;
        {
            let request_clone = account.relay_quic_pool()?;
            // ... future cancelled / dropped here ...
            drop(request_clone);
        }
        assert!(
            account.relay_quic_pool.is_some(),
            "account keeps its pool after a clone is dropped"
        );
        let after = account.relay_quic_pool()?;
        assert!(Arc::ptr_eq(&original, &after), "no cold rebuild after a dropped request clone");
        Ok(())
    }

    #[test]
    fn account_retains_pool_across_simulated_pre_business_and_relay_errors()
    -> Result<(), crate::SdkError> {
        let mut account = test_account();
        let original = account.relay_quic_pool()?;
        // A pre-business validation error path: acquire the clone, then bail with an error before
        // the relay send. The `?`-propagated early return drops only the clone.
        let pre_business: Result<(), crate::SdkError> = (|| {
            let _clone = account.relay_quic_pool()?;
            Err(crate::SdkError::LocalBus("simulated pre-business rejection".to_owned()))
        })();
        assert!(pre_business.is_err());
        // A relay error path: acquire the clone, then the relay attempt fails.
        let relay_failure: Result<(), crate::SdkError> = (|| {
            let _clone = account.relay_quic_pool()?;
            Err(crate::SdkError::Transport(ramflux_transport::TransportError::Quic(
                "simulated relay failure".to_owned(),
            )))
        })();
        assert!(relay_failure.is_err());
        // After both error paths the account still owns the original pool instance.
        let after = account.relay_quic_pool()?;
        assert!(
            Arc::ptr_eq(&original, &after),
            "pool survives pre-business and relay error paths (persistent ownership)"
        );
        Ok(())
    }

    #[test]
    fn pool_is_dropped_with_its_account_no_global_leak() -> Result<(), crate::SdkError> {
        for _index in 0..8 {
            let mut account = test_account();
            assert!(account.relay_quic_pool.is_none());
            let _pool = account.relay_quic_pool()?;
            assert!(account.relay_quic_pool.is_some());
            drop(account);
        }
        assert!(test_account().relay_quic_pool.is_none(), "no global pool leaks across accounts");
        Ok(())
    }
}

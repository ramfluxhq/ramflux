// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Supervisor-level advance of agent creations (controller decision r10 item 1). The human account's
//! runtime performs the store steps; the supervisor activates the agent account through the normal
//! activation path. Every step is idempotent, so a repeated advance only finishes what is missing.
use super::supervisor::Supervisor;
use crate::SdkError;
use crate::custody::agent_creation::{
    AgentCreationRecord, AgentCreationState, AgentCreationStore, AgentStep, AgentSteps,
    RebindBinding, advance_all, advance_primary, advance_reassociation, agent_account_id,
    fresh_plan_ready, is_retired_agent_account, observe_primary, paused_agent_binding,
    plan_reassociation, rebind_awaits_owner, release_completed_sources,
};
use crate::custody::{CustodyConnection, CustodyNetworkConfig};
use crate::gateway::GatewayQuicEndpointConfig;
use crate::node::NodeProfile;
use ramflux_protocol::custody::{BindingMode, RegisterPlan, decode_register_plan};
use ramflux_protocol::message as g;
use std::path::Path;
use std::time::Duration;
use zeroize::Zeroizing;

/// Outcome of one advanced request: its id and its state, or the step failure.
pub(super) type AdvanceOutcome = (String, Result<AgentCreationState, SdkError>);

struct SupervisorSteps<'a> {
    supervisor: &'a Supervisor,
    human: String,
    store: AgentCreationStore,
}

impl SupervisorSteps<'_> {
    fn human_actor(&self) -> Result<super::actor::AccountActor, SdkError> {
        self.supervisor
            .account_actor(&self.human)
            .filter(super::actor::AccountActor::is_open)
            .ok_or(SdkError::NetworkingPending)
    }

    /// The human account's home node. The agent is homed on it (controller decision r11 item 2).
    /// A human account without one refuses with the same typed reason as missing networking.
    async fn home_node(&self) -> Result<String, SdkError> {
        self.human_actor()?.agent_home_node().await?.ok_or(SdkError::NoNodeSelected)
    }
}

/// The provisioning secret of an agent: the one its creation record names. A rebind names none of its
/// own, so the creation record of the same agent account holds it.
fn provisioning_reference(
    store: &AgentCreationStore,
    record: &AgentCreationRecord,
) -> Result<String, SdkError> {
    if let Some(reference) =
        record.vault_refs.iter().find(|reference| reference.starts_with("agent-provisioning:"))
    {
        return Ok(reference.clone());
    }
    let account = record.account_id.as_deref().ok_or(SdkError::CustodySetupInvalid)?;
    store
        .records()?
        .iter()
        .filter(|candidate| candidate.account_id.as_deref() == Some(account))
        .find_map(|candidate| {
            candidate
                .vault_refs
                .iter()
                .find(|reference| reference.starts_with("agent-provisioning:"))
                .cloned()
        })
        .ok_or(SdkError::CustodySetupInvalid)
}

impl AgentSteps for SupervisorSteps<'_> {
    async fn commit(
        &mut self,
        request_id: &str,
        now: u64,
    ) -> Result<AgentCreationRecord, SdkError> {
        let home = self.home_node().await?;
        let capabilities = self.supervisor.node_capabilities(&home)?;
        self.human_actor()?
            .agent_creation_step(AgentStep::Commit {
                request_id: request_id.to_owned(),
                capabilities,
                now,
            })
            .await
    }

    fn is_live(&self, account_id: &str) -> bool {
        self.supervisor.account_is_open(account_id)
    }

    async fn activate(&mut self, record: &AgentCreationRecord) -> Result<(), SdkError> {
        let account_id = record.account_id.clone().ok_or(SdkError::CustodySetupInvalid)?;
        let reference = provisioning_reference(&self.store, record)?;
        let vault = super::custody_setup::primary_provider(&self.supervisor.config);
        let secret = vault.load_provisioning_secret(&reference)?;
        let passphrase = Zeroizing::new(
            std::str::from_utf8(&secret).map_err(|_| SdkError::CustodySetupInvalid)?.to_owned(),
        );
        let home = self.home_node().await?;
        self.supervisor.activate_native(&account_id, passphrase, Some(home)).await?;
        Ok(())
    }

    async fn commit_rebind(
        &mut self,
        request_id: &str,
        now: u64,
    ) -> Result<AgentCreationRecord, SdkError> {
        let home = self.home_node().await?;
        let capabilities = self.supervisor.node_capabilities(&home)?;
        self.human_actor()?
            .agent_creation_step(AgentStep::CommitRebind {
                request_id: request_id.to_owned(),
                capabilities,
                now,
            })
            .await
    }

    /// Stage E0: the rebind publication of a committed agent through a proof-only connection to the
    /// human's home node. The connection is dropped at once: no session, no registration.
    async fn publish_rebind(&mut self, request_id: &str) -> Result<AgentCreationRecord, SdkError> {
        let record = self.store.load(request_id)?.ok_or(SdkError::CustodySetupInvalid)?;
        let plan: RegisterPlan = decode_register_plan(&record.plan_bytes()?)
            .map_err(|_| SdkError::CustodySetupInvalid)?;
        let account_id = record.account_id.clone().ok_or(SdkError::CustodySetupInvalid)?;
        let home = self.home_node().await?;
        let profile = self.supervisor.node_profile(&home)?;
        // Production reaches the custody service through the gateway, which proves the channel with
        // `HomeRelayReceipt` (`gateway/custody.rs` `proof_network_config`). The test node is a direct
        // custody endpoint and sets its own mode through `LocalBusConfig::rebind_binding_mode`.
        #[cfg(test)]
        let binding =
            self.supervisor.config.rebind_binding_mode.unwrap_or(BindingMode::HomeRelayReceipt);
        #[cfg(not(test))]
        let binding = BindingMode::HomeRelayReceipt;
        let config = rebind_network(
            &self.supervisor.config.data_root,
            &profile,
            &account_id,
            &plan,
            binding,
        )
        .await?;
        let vault = super::custody_setup::primary_provider(&self.supervisor.config);
        // Boxed like the other connect futures (`custody/network.rs`): the connection state machine
        // is large and the advance future is awaited from the unlock path.
        drop(Box::pin(CustodyConnection::publish_rebind(config, vault)).await?);
        self.store.load(request_id)?.ok_or(SdkError::CustodySetupInvalid)
    }

    async fn complete(&mut self, request_id: &str) -> Result<AgentCreationRecord, SdkError> {
        self.human_actor()?
            .agent_creation_step(AgentStep::Complete { request_id: request_id.to_owned() })
            .await
    }
}

/// The custody connection settings of a paused agent, built from the home node's stored profile
/// the way `configure_pending` builds the gateway settings of an account (`bus/native_account.rs`).
/// The agent device is the one the rebind plan names.
async fn rebind_network(
    root: &Path,
    profile: &NodeProfile,
    account_id: &str,
    plan: &RegisterPlan,
    binding_mode: BindingMode,
) -> Result<CustodyNetworkConfig, SdkError> {
    let unset = std::net::SocketAddr::from(([0, 0, 0, 0], 0));
    let endpoint = profile
        .gateway_config(
            root,
            GatewayQuicEndpointConfig {
                bind_addr: unset,
                gateway_addr: unset,
                server_name: String::new(),
                ca_cert: std::path::PathBuf::new(),
                principal_id: String::new(),
                device_id: plan.agent_device.device_id.clone(),
                target_delivery_id: String::new(),
                prekey_http_url: None,
            },
        )
        .await?;
    Ok(CustodyNetworkConfig {
        pairing_admission: None,
        account_root: root.to_path_buf(),
        account_id: account_id.to_owned(),
        device_id: plan.agent_device.device_id.clone(),
        gateway_address: crate::node::resolve_node_addr(&profile.gateway.tcp_addr).await?,
        server_name: endpoint.server_name,
        ca_certificate: endpoint.ca_cert,
        node_id: profile.node_id.clone(),
        node_public_key: profile.node_public_key.clone(),
        audience: profile.node_id.clone(),
        binding_mode,
        allow_no_channel_binding: false,
        timeout: Duration::from_secs(10),
    })
}

enum Settle {
    Continue,
    Follow(String),
    Hold,
}

fn refused(human: &str, error: SdkError) -> SdkError {
    tracing::warn!(account = %human, reason = %error, "agent reassociation refused");
    error
}

impl Supervisor {
    /// Refuses an agent account that must not be unlocked or activated. Stage E0 (decision r20): an
    /// agent whose rebind is pending (R) or committed (C) is refused with the typed reason
    /// `rebind_pending`. Stage F1 (decision r23): an agent that was deleted (`agent.delete`,
    /// lifecycle `X`) is refused with `agent_retired`, before its missing directory can be reported
    /// as an unknown account. An account with no inventory entry and no retired record passes.
    pub(super) fn refuse_unusable_agent(&self, account_id: &str) -> Result<(), SdkError> {
        if matches!(
            paused_agent_binding(&self.config.data_root, account_id)?,
            Some(RebindBinding::RebindPending | RebindBinding::Committed)
        ) {
            return Err(SdkError::AgentCreationRefused("rebind_pending"));
        }
        if is_retired_agent_account(&self.config.data_root, account_id)? {
            return Err(SdkError::AgentCreationRefused("agent_retired"));
        }
        Ok(())
    }

    /// Stage F1 (decision r23): before `agent.delete` removes the local state of an agent in state
    /// `U`, the agent's running session is closed through the account lock path
    /// (`lock_account_session`). Nothing is closed unless the delete would proceed (confirmed, a
    /// stored record in `U`, a local account for the agent), so a refused delete leaves the session
    /// alone; the delete itself repeats the checks and reports the typed refusal.
    pub(super) async fn close_agent_before_delete(
        &self,
        human: &str,
        mutation: &g::AgentMutation,
    ) -> Result<(), SdkError> {
        if mutation.confirmed != Some(true) {
            return Ok(());
        }
        let directory = self.config.data_root.join("custody_accounts").join(human);
        if !directory.join("agent_creation").is_dir() {
            return Ok(());
        }
        let store = AgentCreationStore::open(self.config.data_root.clone(), human)?;
        let records = crate::agent_record::AgentRecordStore::at(store.agent_record_dir());
        let Some(record) = records.load(&mutation.agent_anchor)? else {
            return Ok(());
        };
        if record.lifecycle != crate::agent_record::LIFECYCLE_ACTIVE {
            return Ok(());
        }
        match agent_account_id(&store, &mutation.agent_anchor)? {
            Some(account_id) => self.lock_account_session(&account_id).await,
            None => Ok(()),
        }
    }

    /// Advances every pending agent creation of one open human account. Returns no outcomes when the
    /// account is not open.
    ///
    /// # Errors
    /// Refuses a store that cannot be opened or listed; per-request failures are in the outcomes.
    pub(super) async fn advance_agent_creations(
        &self,
        human: &str,
        now: u64,
    ) -> Result<Vec<AdvanceOutcome>, SdkError> {
        if !self.account_is_open(human) {
            return Ok(Vec::new());
        }
        match self.settle_reassociation(human, now).await? {
            Settle::Hold => return Ok(Vec::new()),
            Settle::Follow(destination) => {
                return Box::pin(self.advance_agent_creations(&destination, now)).await;
            }
            Settle::Continue => {}
        }
        // Opening the store creates its directory, which must not happen for an account that has
        // never created an agent: the directory is what makes an account look present on disk.
        let root = self.config.data_root.clone();
        let directory = root.join("custody_accounts").join(human).join("agent_creation");
        if !directory.is_dir() {
            return Ok(Vec::new());
        }
        let store = AgentCreationStore::open(root.clone(), human)?;
        // Stage D2: observe the human's current primary first, so the rebind inventory is current
        // before any step runs. Complete agents are not advanced (advance only handles pending
        // requests), so the pause is recorded in the inventory and read by stage D3.
        let primary = advance_primary(&root, human, now)?;
        // Stage D3: an agent whose binding moved to a new primary is paused. Its open session is
        // closed through the account.lock path, and the advance below never activates it.
        for entry in observe_primary(&store, &primary)? {
            if matches!(entry.binding, RebindBinding::RebindPending | RebindBinding::Committed) {
                self.lock_account_session(&entry.agent_account_id).await?;
            }
            // Stage D R1: a paused agent whose request is not frozen yet sends its rebind plan to
            // the new primary. A refusal (the desktop left the human) keeps the agent paused, and the
            // next advance tries again.
            if entry.binding == RebindBinding::RebindPending
                && fresh_plan_ready(&root, &store, &entry.agent_account_id)?
                && rebind_awaits_owner(&store, &entry)?
                && let Some(actor) =
                    self.account_actor(human).filter(super::actor::AccountActor::is_open)
            {
                let _ = actor
                    .agent_creation_step(AgentStep::SendRebind {
                        agent_account_id: entry.agent_account_id.clone(),
                        now,
                    })
                    .await;
            }
        }
        self.lock_retired_agent_sessions(&store).await?;
        let mut steps =
            SupervisorSteps { supervisor: self, human: human.to_owned(), store: store.clone() };
        advance_all(&mut steps, &store, now).await
    }

    /// Close an open session of an agent whose stored lifecycle is retired (`X`). The next
    /// `agent.operation.get` or unlock runs this. A record page past the cap refuses.
    async fn lock_retired_agent_sessions(
        &self,
        store: &AgentCreationStore,
    ) -> Result<(), SdkError> {
        let records = crate::agent_record::AgentRecordStore::at(store.agent_record_dir());
        let mut after = None;
        for _ in 0..256 {
            let (page, next) = records.page(after.as_deref(), 50)?;
            for record in &page {
                if record.lifecycle != crate::agent_record::LIFECYCLE_RETIRED {
                    continue;
                }
                if let Some(account_id) = agent_account_id(store, &record.agent_anchor)? {
                    self.lock_account_session(&account_id).await?;
                }
            }
            match next {
                Some(cursor) => after = Some(cursor),
                None => return Ok(()),
            }
        }
        Err(SdkError::CustodySetupInvalid)
    }

    /// Move one human's agent inventory onto the account created by a fresh pairing, or resume
    /// that journal. The source and each agent are drained first. The destination is not locked.
    ///
    /// `Hold` means the journal is still open, so this account must not activate or publish.
    /// `Follow` is the destination, whose own advance sends the fresh plans.
    async fn settle_reassociation(&self, human: &str, now: u64) -> Result<Settle, SdkError> {
        let root = self.config.data_root.clone();
        release_completed_sources(&root, human).map_err(|error| refused(human, error))?;
        let index = self.index.clone();
        let source_unlocked =
            move |id: &str| index.account(id).is_ok_and(|row| row.account_state == "active");
        let Some(planned) = plan_reassociation(&root, human, &source_unlocked)
            .map_err(|error| refused(human, error))?
        else {
            return Ok(Settle::Continue);
        };
        self.lock_account_session(&planned.source).await.map_err(|error| refused(human, error))?;
        for agent in &planned.agents {
            self.lock_account_session(agent).await.map_err(|error| refused(human, error))?;
        }
        if !advance_reassociation(&root, human, now).map_err(|error| refused(human, error))? {
            return Ok(Settle::Hold);
        }
        if planned.destination != human {
            return Ok(Settle::Follow(planned.destination));
        }
        Ok(Settle::Continue)
    }

    /// Resume durable approved repairs without another read or unlock from the user.
    pub(super) async fn maintain_agent_repairs(&self) {
        let humans: Vec<String> = self
            .accounts
            .borrow()
            .iter()
            .filter(|(_, actor)| actor.is_open())
            .map(|(id, _)| id.clone())
            .collect();
        for human in humans {
            match ready_repair(&self.config.data_root, &human) {
                Ok(true) => {
                    let Ok(now) = super::custody_setup::now() else { continue };
                    match self.advance_agent_creations(&human, now).await {
                        Ok(outcomes) => {
                            for (_, result) in outcomes {
                                if let Err(error) = result {
                                    tracing::warn!(%error, "agent repair advance deferred");
                                }
                            }
                        }
                        Err(error) => tracing::warn!(%error, "agent repair scan deferred"),
                    }
                }
                Ok(false) => {}
                Err(error) => tracing::warn!(%error, "agent repair readiness deferred"),
            }
        }
    }

    /// Trigger (b) of decision r10: after a human account unlocks, finish what its pending agent
    /// creations still need. A failure leaves the requests pending for the next trigger.
    pub(super) async fn advance_after_unlock(&self, human: &str) {
        if let Ok(now) = super::custody_setup::now() {
            let _ = self.advance_agent_creations(human, now).await;
        }
    }
}

fn ready_repair(root: &Path, human: &str) -> Result<bool, SdkError> {
    if !root.join("custody_accounts").join(human).join("agent_creation").is_dir() {
        return Ok(false);
    }
    let store = AgentCreationStore::open(root.to_path_buf(), human)?;
    for entry in store.rebind_entries()? {
        if !matches!(entry.binding, RebindBinding::RebindPending | RebindBinding::Committed) {
            continue;
        }
        let Some(request) = entry.request_id else { continue };
        let Some(record) = store.load(&request)? else { continue };
        if matches!(
            record.state,
            AgentCreationState::Authorized
                | AgentCreationState::PublicationPending
                | AgentCreationState::PublicationUnknown
        ) {
            return Ok(true);
        }
    }
    Ok(false)
}

#[cfg(test)]
mod tests;

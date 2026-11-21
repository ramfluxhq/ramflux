// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Supervisor-level advance of agent creations (controller decision r10 item 1). The human account's
//! runtime performs the store steps; the supervisor activates the agent account through the normal
//! activation path. Every step is idempotent, so a repeated advance only finishes what is missing.
use super::supervisor::Supervisor;
use crate::SdkError;
use crate::custody::agent_creation::{
    AgentCreationRecord, AgentCreationState, AgentCreationStore, AgentStep, AgentSteps,
    advance_all,
};
use zeroize::Zeroizing;

/// Outcome of one advanced request: its id and its state, or the step failure.
pub(super) type AdvanceOutcome = (String, Result<AgentCreationState, SdkError>);

struct SupervisorSteps<'a> {
    supervisor: &'a Supervisor,
    human: String,
}

impl SupervisorSteps<'_> {
    fn human_actor(&self) -> Result<super::actor::AccountActor, SdkError> {
        self.supervisor
            .account_actor(&self.human)
            .filter(super::actor::AccountActor::is_open)
            .ok_or(SdkError::NetworkingPending)
    }
}

impl AgentSteps for SupervisorSteps<'_> {
    async fn commit(&mut self, request_id: &str, now: u64) -> Result<AgentCreationRecord, SdkError> {
        let capabilities = self.supervisor.selected_node_capabilities()?;
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
        let reference = record
            .vault_refs
            .iter()
            .find(|reference| reference.starts_with("agent-provisioning:"))
            .ok_or(SdkError::CustodySetupInvalid)?;
        let vault = super::custody_setup::primary_provider(&self.supervisor.config);
        let secret = vault.load_provisioning_secret(reference)?;
        let passphrase =
            Zeroizing::new(std::str::from_utf8(&secret).map_err(|_| SdkError::CustodySetupInvalid)?.to_owned());
        self.supervisor.activate_native(&account_id, passphrase, None).await?;
        Ok(())
    }

    async fn complete(&mut self, request_id: &str) -> Result<AgentCreationRecord, SdkError> {
        self.human_actor()?
            .agent_creation_step(AgentStep::Complete { request_id: request_id.to_owned() })
            .await
    }
}

impl Supervisor {
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
        // Opening the store creates its directory, which must not happen for an account that has
        // never created an agent: the directory is what makes an account look present on disk.
        let root = self.config.data_root.clone();
        let directory = root.join("custody_accounts").join(human).join("agent_creation");
        if !directory.is_dir() {
            return Ok(Vec::new());
        }
        let store = AgentCreationStore::open(root, human)?;
        let mut steps = SupervisorSteps { supervisor: self, human: human.to_owned() };
        advance_all(&mut steps, &store, now).await
    }

    /// Trigger (b) of decision r10: after a human account unlocks, finish what its pending agent
    /// creations still need. A failure leaves the requests pending for the next trigger.
    pub(super) async fn advance_after_unlock(&self, human: &str) {
        if let Ok(now) = super::custody_setup::now() {
            let _ = self.advance_agent_creations(human, now).await;
        }
    }
}

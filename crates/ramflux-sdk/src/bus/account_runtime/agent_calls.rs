// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Store steps of one agent creation, run by the human account's runtime (controller decision r10).
//! The supervisor sequences them and performs activation; nothing here touches the agent account.
use super::AccountRuntime;
use crate::SdkError;
use crate::custody::agent_creation::{
    AgentCreationRecord, AgentCreationStore, AgentStep, commit_approved,
};

impl AccountRuntime {
    pub(super) fn agent_creation_step(
        &self,
        step: AgentStep,
    ) -> Result<AgentCreationRecord, SdkError> {
        let store = AgentCreationStore::open(self.state.config.data_root.clone(), &self.id)?;
        match step {
            AgentStep::Commit { request_id, capabilities, now } => {
                let vault = super::super::custody_setup::primary_provider(&self.state.config);
                commit_approved(&store, vault.as_ref(), &self.id, &request_id, &capabilities, now)
            }
            AgentStep::Complete { request_id } => {
                crate::custody::agent_creation::complete_with_receipt(&store, &request_id)
            }
        }
    }

    /// The home node of this human account: the value `native_account::unlock` persists as
    /// `account/node-id`. `None` when the account has none yet.
    pub(super) fn agent_home_node(&self) -> Result<Option<String>, SdkError> {
        let account = self.state.accounts.get(&self.id).ok_or(SdkError::AccountDbNotUnlocked)?;
        Ok(account.client.account_db()?.load_actor_state::<String>("account/node-id")?)
    }
}

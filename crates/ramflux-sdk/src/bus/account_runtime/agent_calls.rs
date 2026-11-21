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

    /// Answer one agent creation call by private command; a closed reply channel skips the work.
    pub(super) fn reply_agent_call(
        &self,
        call: super::super::agent_methods::AgentCall,
        reply: tokio::sync::oneshot::Sender<
            Result<ramflux_protocol::message::AgentCustodyStatus, SdkError>,
        >,
    ) {
        if !reply.is_closed() {
            let _ = reply.send(self.agent_call(call));
        }
    }

    /// Answer the home-node read by private command; a closed reply channel skips the read.
    pub(super) fn reply_agent_home_node(
        &self,
        reply: tokio::sync::oneshot::Sender<Result<Option<String>, SdkError>>,
    ) {
        if !reply.is_closed() {
            let _ = reply.send(self.agent_home_node());
        }
    }

    /// One account-scoped call of the agent creation methods on this human account.
    pub(super) fn agent_call(
        &self,
        call: super::super::agent_methods::AgentCall,
    ) -> Result<ramflux_protocol::message::AgentCustodyStatus, SdkError> {
        use super::super::agent_methods::AgentCall;
        let account = self.state.accounts.get(&self.id).ok_or(SdkError::AccountDbNotUnlocked)?;
        let vault = super::super::custody_setup::primary_provider(&self.state.config);
        match call {
            AgentCall::Create(body) => account.client.agent_create(
                vault.as_ref(),
                &body,
                super::super::custody_setup::now()?,
            ),
            AgentCall::Decide(body) => account.client.agent_creation_decide(
                vault.as_ref(),
                &body,
                super::super::custody_setup::now()?,
            ),
            AgentCall::Get(operation_id) => account.client.agent_operation_status(&operation_id),
        }
    }

    /// The home node of this human account: the value `native_account::unlock` persists as
    /// `account/node-id`. `None` when the account has none yet.
    pub(super) fn agent_home_node(&self) -> Result<Option<String>, SdkError> {
        let account = self.state.accounts.get(&self.id).ok_or(SdkError::AccountDbNotUnlocked)?;
        Ok(account.client.account_db()?.load_actor_state::<String>("account/node-id")?)
    }
}

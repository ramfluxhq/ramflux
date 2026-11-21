// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Store steps of one agent creation, run by the human account's runtime (controller decision r10).
//! The supervisor sequences them and performs activation; nothing here touches the agent account.
use super::AccountRuntime;
use crate::SdkError;
use crate::custody::agent_creation::{
    AgentCreationRecord, AgentCreationStore, AgentStep, commit_approved,
};

/// `AgentRecord.cleanup` of a deleted agent: the published custody record stays on the node.
const NODE_RECORD_RETAINED: &str = "node_record_retained";

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
            AgentStep::CommitRebind { request_id, capabilities, now } => {
                let vault = super::super::custody_setup::primary_provider(&self.state.config);
                let account =
                    self.state.accounts.get(&self.id).ok_or(SdkError::AccountDbNotUnlocked)?;
                account.client.agent_rebind_commit(vault.as_ref(), &request_id, &capabilities, now)
            }
            AgentStep::Complete { request_id } => {
                crate::custody::agent_creation::complete_with_receipt(&store, &request_id)
            }
            AgentStep::SendRebind { agent_account_id, now } => {
                let account =
                    self.state.accounts.get(&self.id).ok_or(SdkError::AccountDbNotUnlocked)?;
                account.client.agent_rebind_send(&agent_account_id, now)?;
                let request_id = store
                    .load_rebind(&agent_account_id)?
                    .and_then(|entry| entry.request_id)
                    .ok_or(SdkError::CustodySetupInvalid)?;
                store.load(&request_id)?.ok_or(SdkError::CustodySetupInvalid)
            }
        }
    }

    /// Answer one agent creation call by private command; a closed reply channel skips the work.
    pub(super) fn reply_agent_call(
        &self,
        call: super::super::agent_methods::AgentCall,
        reply: tokio::sync::oneshot::Sender<
            Result<ramflux_protocol::message::AgentConfigResult, SdkError>,
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
    ) -> Result<ramflux_protocol::message::AgentConfigResult, SdkError> {
        use super::super::agent_methods::AgentCall;
        use ramflux_protocol::message as g;
        let account = self.state.accounts.get(&self.id).ok_or(SdkError::AccountDbNotUnlocked)?;
        let vault = super::super::custody_setup::primary_provider(&self.state.config);
        let custody = |status: g::AgentCustodyStatus| g::AgentConfigResult {
            value: Some(g::agent_config_result::Value::Custody(status)),
        };
        let now = super::super::custody_setup::now()?;
        let result = match call {
            AgentCall::Create(body) => {
                custody(account.client.agent_create(vault.as_ref(), &body, now)?)
            }
            AgentCall::Decide(body) => {
                custody(account.client.agent_creation_decide(vault.as_ref(), &body, now)?)
            }
            AgentCall::Get(operation_id) => {
                custody(account.client.agent_operation_status(&operation_id)?)
            }
            AgentCall::List(list) => {
                let (records, next) =
                    account.client.agent_record_page(list.cursor.as_deref(), list.limit)?;
                let head = account.client.agent_record_head()?;
                g::AgentConfigResult {
                    value: Some(g::agent_config_result::Value::Page(g::AgentPage {
                        records: records.iter().map(crate::agent_record::to_wire).collect(),
                        next,
                        journal_cursor: head.to_string(),
                    })),
                }
            }
            AgentCall::Delete(mutation) => {
                let record = account.client.agent_delete(
                    vault.as_ref(),
                    &mutation.agent_anchor,
                    mutation.confirmed,
                    now,
                )?;
                let mut wire = crate::agent_record::to_wire(&record);
                // The custody record published on the home node is not retired by this module.
                wire.cleanup = NODE_RECORD_RETAINED.into();
                g::AgentConfigResult { value: Some(g::agent_config_result::Value::Record(wire)) }
            }
            AgentCall::Watch(watch) => {
                let changes = account.client.agent_record_changes(&watch.journal_cursor)?;
                let cursor = changes.cursor.to_string();
                g::AgentConfigResult {
                    value: Some(g::agent_config_result::Value::Page(g::AgentPage {
                        records: changes.records.iter().map(crate::agent_record::to_wire).collect(),
                        next: changes.more.then(|| cursor.clone()),
                        journal_cursor: cursor,
                    })),
                }
            }
            AgentCall::Record(agent) => g::AgentConfigResult {
                value: Some(g::agent_config_result::Value::Record(crate::agent_record::to_wire(
                    &account.client.agent_record_get(&agent)?,
                ))),
            },
            AgentCall::PersonaEdit(edit) => {
                let persona =
                    edit.persona.ok_or(SdkError::AgentCreationRefused("persona_invalid"))?;
                // The contract's persona edit carries no base: the stored identity is the base.
                let current = account.client.agent_record_get(&edit.agent_anchor)?;
                let record = account.client.agent_persona_edit(
                    &edit.agent_anchor,
                    &current.identity,
                    persona,
                    edit.confirmed,
                    now,
                )?;
                g::AgentConfigResult {
                    value: Some(g::agent_config_result::Value::Record(
                        crate::agent_record::to_wire(&record),
                    )),
                }
            }
            AgentCall::AccessSet(set) => {
                let access =
                    set.access.ok_or(SdkError::AgentCreationRefused("access_policy_invalid"))?;
                let base = set.base.ok_or(SdkError::AgentCreationRefused("stale_base"))?;
                let record = account.client.agent_access_set(
                    &set.agent_anchor,
                    &base,
                    access,
                    set.confirmed,
                    now,
                )?;
                g::AgentConfigResult {
                    value: Some(g::agent_config_result::Value::Record(
                        crate::agent_record::to_wire(&record),
                    )),
                }
            }
        };
        Ok(result)
    }

    /// The home node of this human account: the value `native_account::unlock` persists as
    /// `account/node-id`. `None` when the account has none yet.
    pub(super) fn agent_home_node(&self) -> Result<Option<String>, SdkError> {
        let account = self.state.accounts.get(&self.id).ok_or(SdkError::AccountDbNotUnlocked)?;
        Ok(account.client.account_db()?.load_actor_state::<String>("account/node-id")?)
    }
}

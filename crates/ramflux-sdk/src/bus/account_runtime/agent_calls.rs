// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Store steps of one agent creation, run by the human account's runtime (controller decision r10).
//! The supervisor sequences them and performs activation; nothing here touches the agent account.
use super::AccountRuntime;
use crate::SdkError;
use crate::custody::agent_creation::{
    AgentCreationRecord, AgentCreationStore, AgentStep, commit_approved,
};

/// `AgentRecord.cleanup` after this call's node retirement succeeded.
const NODE_RETIRED: &str = "node_retired";

impl AccountRuntime {
    /// Carries the agent records this device wrote to the owner's other devices. The record
    /// directory exists only after an agent was created; an account without one is left alone.
    pub(super) fn maintain_agent_record_broadcast(&self) {
        let dir = self
            .state
            .config
            .data_root
            .join("custody_accounts")
            .join(&self.id)
            .join("agent_record");
        if !dir.is_dir() {
            return;
        }
        let Some(account) = self.state.accounts.get(&self.id) else { return };
        let Ok(now) = super::super::custody_setup::now() else { return };
        if let Err(error) = account.client.broadcast_own_agent_records(dir, now) {
            tracing::debug!(%error, "agent record broadcast deferred");
        }
    }
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

    /// Runs one agent command of this runtime; a closed reply channel skips the work.
    pub(super) fn apply_agent(&self, command: super::super::actor::AgentPrivate) {
        use super::super::actor::AgentPrivate;
        match command {
            AgentPrivate::Creation { step, reply } => {
                if !reply.is_closed() {
                    let _ = reply.send(self.agent_creation_step(step));
                }
            }
            AgentPrivate::Call { call, reply } => self.reply_agent_call(call, reply),
            AgentPrivate::HomeNode { reply } => self.reply_agent_home_node(reply),
            AgentPrivate::Gateway { reply } => {
                if !reply.is_closed() {
                    let _ = reply.send(self.agent_gateway());
                }
            }
            AgentPrivate::Admission { reply } => self.reply_pairing_admission(reply),
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
                deleted_record(&account.client, vault.as_ref(), &mutation, now)?
            }
            AgentCall::Retire(mutation) => retired_record(&account.client, &mutation, now)?,
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

    /// Gateway config of this unlocked account. `None` before a native account is loaded.
    fn agent_gateway(&self) -> Result<Option<crate::gateway::GatewaySessionConfig>, SdkError> {
        let account = self.state.accounts.get(&self.id).ok_or(SdkError::AccountDbNotUnlocked)?;
        if account.client.born_v3_account.is_none() {
            return Ok(None);
        }
        Ok(Some(account.gateway_config.clone()))
    }

    /// The home node of this human account: the value `native_account::unlock` persists as
    /// `account/node-id`. `None` when the account has none yet.
    pub(super) fn agent_home_node(&self) -> Result<Option<String>, SdkError> {
        let account = self.state.accounts.get(&self.id).ok_or(SdkError::AccountDbNotUnlocked)?;
        Ok(account.client.account_db()?.load_actor_state::<String>("account/node-id")?)
    }

    /// Answer the admission-reader read by private command; a closed reply channel skips it.
    pub(super) fn reply_pairing_admission(
        &self,
        reply: tokio::sync::oneshot::Sender<
            Result<Option<std::sync::Arc<ramflux_storage::PairingAdmissionReader>>, SdkError>,
        >,
    ) {
        if !reply.is_closed() {
            let _ = reply.send(self.pairing_admission());
        }
    }

    /// The still-open reader of this account's unlocked DB. A closed reader is `None`.
    pub(super) fn pairing_admission(
        &self,
    ) -> Result<Option<std::sync::Arc<ramflux_storage::PairingAdmissionReader>>, SdkError> {
        let account = self.state.accounts.get(&self.id).ok_or(SdkError::AccountDbNotUnlocked)?;
        if let Some(reader) = account.gateway_config.pairing_admission.clone()
            && reader.is_open()
        {
            return Ok(Some(reader));
        }
        let Some(db) = account.client.active_account_db.as_ref() else {
            return Ok(None);
        };
        let reader = std::sync::Arc::new(db.pairing_admission_reader());
        Ok(reader.is_open().then_some(reader))
    }
}

fn deleted_record(
    client: &crate::RamfluxClient,
    vault: &dyn crate::custody::PrimaryVault,
    mutation: &ramflux_protocol::message::AgentMutation,
    now: u64,
) -> Result<ramflux_protocol::message::AgentConfigResult, SdkError> {
    let record = client.agent_delete(vault, &mutation.agent_anchor, mutation.confirmed, now)?;
    Ok(record_result(&record))
}

/// Local half of `agent.retire`: lifecycle `X` and the broadcast. The phone keeps the agent's
/// vault items; the desktop that receives the metadata destroys them.
fn retired_record(
    client: &crate::RamfluxClient,
    mutation: &ramflux_protocol::message::AgentMutation,
    now: u64,
) -> Result<ramflux_protocol::message::AgentConfigResult, SdkError> {
    match client.agent_record_get(&mutation.agent_anchor) {
        Ok(current) => {
            let record = client.agent_retire(
                &mutation.agent_anchor,
                &current.identity,
                mutation.confirmed,
                now,
            )?;
            Ok(record_result(&record))
        }
        Err(SdkError::AgentCreationRefused("agent_not_found")) => {
            node_only_retired(client, mutation)
        }
        Err(error) => Err(error),
    }
}

/// The node already accepted retirement and this phone has no local file to rewrite.
fn node_only_retired(
    client: &crate::RamfluxClient,
    mutation: &ramflux_protocol::message::AgentMutation,
) -> Result<ramflux_protocol::message::AgentConfigResult, SdkError> {
    use ramflux_protocol::message as g;
    if mutation.confirmed != Some(true) {
        return Err(SdkError::AgentCreationRefused("agent_not_found"));
    }
    let record = g::AgentRecord {
        agent_anchor: mutation.agent_anchor.clone(),
        custodian_anchor: client.own_account_anchor()?,
        persona: None,
        host: None,
        config: None,
        revision: None,
        lifecycle: crate::agent_record::LIFECYCLE_RETIRED.to_owned(),
        observation: String::new(),
        cleanup: NODE_RETIRED.to_owned(),
        access: None,
        role: String::new(),
    };
    Ok(g::AgentConfigResult { value: Some(g::agent_config_result::Value::Record(record)) })
}

fn record_result(
    record: &crate::agent_record::StoredAgentRecord,
) -> ramflux_protocol::message::AgentConfigResult {
    use ramflux_protocol::message as g;
    let mut wire = crate::agent_record::to_wire(record);
    wire.cleanup = NODE_RETIRED.into();
    g::AgentConfigResult { value: Some(g::agent_config_result::Value::Record(wire)) }
}

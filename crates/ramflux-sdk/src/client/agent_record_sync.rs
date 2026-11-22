// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Own-device replication of the agent record (AGENT-IDENTITY-01 E3, contract 4 and D8). A change
//! made on this device is broadcast to the other devices of the owner root as
//! `AgentHostPacket.metadata` on the `AgentSync` control. A receiver applies it through
//! `agent_record::apply_metadata`, after `client/agent_custody.rs` authorized the sender.
use crate::agent_record::{
    AgentRecordStore, Changes, LIFECYCLE_ACTIVE, StoredAgentRecord, apply_metadata, edit_record,
    metadata_of, parse_cursor, retire,
};
use crate::bus::own_device_copy;
use crate::client::generated_control::control_from_payload;
use crate::client::own_device_copy::{OwnMessageInput, OwnPayloadKind};
use crate::custody::PrimaryVault;
use crate::custody::agent_creation::expected_scope;
use crate::custody::agent_creation::retire_agent_material;
use crate::{RamfluxClient, SdkError};
use prost::Message as _;
use ramflux_protocol::custody::DeviceRef;
use ramflux_protocol::message as g;
use ramflux_protocol::message::{AgentAccessPolicy, AgentPersona, EventIdentity};

/// Domain of the local message id of one metadata packet.
const SEND_DOMAIN: &str = "ramflux.sdk.agent_metadata_packet.v1";

/// Refuses an edit that the owner did not confirm on this device (contract 2: `confirmed` must be
/// present and true).
fn require_confirmed(confirmed: Option<bool>) -> Result<(), SdkError> {
    if confirmed == Some(true) {
        Ok(())
    } else {
        Err(SdkError::AgentCreationRefused("confirmation_required"))
    }
}

fn qualified(device: &DeviceRef) -> g::QualifiedDevice {
    g::QualifiedDevice {
        account_anchor: device.account_anchor.clone(),
        device_id: device.device_id.clone(),
        device_epoch: device.device_epoch,
    }
}

impl RamfluxClient {
    /// The agent record store of the unlocked human account of this client.
    /// # Errors
    /// Refuses a client without an unlocked human account.
    pub(crate) fn agent_record_store(&self) -> Result<AgentRecordStore, SdkError> {
        Ok(AgentRecordStore::at(self.agent_creation_store()?.agent_record_dir()))
    }

    /// This device as a record author: its root, device id and current epoch.
    pub(crate) fn own_device_ref(&self) -> Result<DeviceRef, SdkError> {
        let own = self.owned_device_identity()?;
        Ok(DeviceRef {
            account_anchor: own.root_commitment().into(),
            device_id: own.device_id().into(),
            device_epoch: self.device_epoch_of(&own)?,
        })
    }

    /// Persona edit on this device (contract 2 `AgentPersonaEdit`). `base` must be the stored
    /// identity; the change is broadcast to the other owner devices.
    /// # Errors
    /// `confirmation_required` without `confirmed`, `stale_base`, `agent_not_found`,
    /// `agent_retired`, and the persona refusals of `check_persona`.
    pub(crate) fn agent_persona_edit(
        &self,
        agent: &str,
        base: &EventIdentity,
        persona: AgentPersona,
        confirmed: Option<bool>,
        now: u64,
    ) -> Result<StoredAgentRecord, SdkError> {
        require_confirmed(confirmed)?;
        let author = self.own_device_ref()?;
        let record =
            edit_record(&self.agent_record_store()?, agent, base, &author, now, |record| {
                record.persona = persona;
            })?;
        self.stage_agent_metadata(&record, now)?;
        Ok(record)
    }

    /// Access edit on this device (contract 2 `AgentAccessSet`), broadcast like the persona edit.
    /// # Errors
    /// As `agent_persona_edit`, with `access_policy_invalid` for a policy outside the closed shapes.
    pub(crate) fn agent_access_set(
        &self,
        agent: &str,
        base: &EventIdentity,
        access: AgentAccessPolicy,
        confirmed: Option<bool>,
        now: u64,
    ) -> Result<StoredAgentRecord, SdkError> {
        require_confirmed(confirmed)?;
        let author = self.own_device_ref()?;
        let record =
            edit_record(&self.agent_record_store()?, agent, base, &author, now, |record| {
                record.access = access;
            })?;
        self.stage_agent_metadata(&record, now)?;
        Ok(record)
    }

    /// `agent.delete` (contract 2 `AgentMutation`, decision r22 item 2): only a record in state `U`
    /// can be deleted. The agent's vault items and local account go first (repeatable), then the
    /// retirement is written and broadcast (`identity_retired`).
    /// # Errors
    /// `confirmation_required` without `confirmed`; `unsupported` for any state but `U`;
    /// `agent_not_found`; the vault and store refusals.
    pub(crate) fn agent_delete(
        &self,
        vault: &dyn PrimaryVault,
        agent: &str,
        confirmed: Option<bool>,
        now: u64,
    ) -> Result<StoredAgentRecord, SdkError> {
        require_confirmed(confirmed)?;
        let current = self.agent_record_get(agent)?;
        if current.lifecycle != LIFECYCLE_ACTIVE {
            return Err(SdkError::AgentCreationRefused("unsupported"));
        }
        retire_agent_material(&self.agent_creation_store()?, vault, agent)?;
        self.agent_retire(agent, &current.identity, Some(true), now)
    }

    /// Retires the record on this device and broadcasts the retirement (`identity_retired`).
    /// # Errors
    /// As `agent_persona_edit`.
    pub(crate) fn agent_retire(
        &self,
        agent: &str,
        base: &EventIdentity,
        confirmed: Option<bool>,
        now: u64,
    ) -> Result<StoredAgentRecord, SdkError> {
        require_confirmed(confirmed)?;
        let author = self.own_device_ref()?;
        let record = retire(&self.agent_record_store()?, agent, base, &author, now)?;
        self.stage_agent_metadata(&record, now)?;
        Ok(record)
    }

    /// Broadcasts the whole record to the other devices of this root as one `AgentHostPacket`
    /// (`metadata`, the own-device `stage`). The recipient names this root only.
    /// # Errors
    /// Refuses a clock outside `i64`, a missing owner, or a failed stage.
    pub(crate) fn stage_agent_metadata(
        &self,
        record: &StoredAgentRecord,
        now: u64,
    ) -> Result<(), SdkError> {
        let owner = self.own_account_anchor()?;
        let device = self.own_device_ref()?;
        let scope = expected_scope(&owner, &record.agent_anchor)?;
        let packet = g::AgentHostPacket {
            owner_anchor: owner.clone(),
            source: Some(qualified(&device)),
            recipient: Some(g::QualifiedDevice {
                account_anchor: owner,
                device_id: device.device_id.clone(),
                device_epoch: device.device_epoch,
            }),
            correlation_id: format!("agent-metadata:{}", record.agent_anchor),
            body: Some(g::agent_host_packet::Body::Metadata(metadata_of(record))),
        };
        let body = control_from_payload(g::control::Payload::AgentSync(packet))?.encode_to_vec();
        let id = ramflux_protocol::hash_base64url(SEND_DOMAIN, &body);
        let created_at =
            i64::try_from(now).map_err(|_| SdkError::AgentCreationRefused("clock_range"))?;
        own_device_copy::stage(
            self,
            OwnMessageInput {
                payload_kind: OwnPayloadKind::Control,
                id: &id,
                created_at,
                conversation: &scope,
                group: None,
                body: &body,
            },
            None,
        )
    }

    /// Sends the records this device wrote (the author is this device) to the other devices of
    /// the root once per stored change. A new agent's record is written where its creation
    /// completes, which is the account going live and not an edit, so nothing else would carry it
    /// to the owner's other devices. Records that arrived from a sibling are not echoed back.
    /// # Errors
    /// The store's and the stage's refusals; a root without a sibling sends nothing yet.
    pub(crate) fn broadcast_own_agent_records(
        &self,
        dir: std::path::PathBuf,
        now: u64,
    ) -> Result<(), SdkError> {
        let store = crate::agent_record::AgentRecordStore::at(dir);
        let own = self.own_device_ref()?;
        let mut cursor: Option<String> = None;
        loop {
            let (records, next) = store.page(cursor.as_deref(), 100)?;
            for record in records {
                let ours = record
                    .identity
                    .author
                    .as_ref()
                    .is_some_and(|author| author.device_id == own.device_id);
                let key = format!("agent-record/broadcast/{}", record.agent_anchor);
                let db = self.account_db()?;
                if !ours || db.load_actor_state::<u64>(&key)? == Some(record.change_seq) {
                    continue;
                }
                if !self.own_sent_has_siblings()? {
                    return Ok(());
                }
                self.stage_agent_metadata(&record, now)?;
                db.persist_actor_state(&key, &record.change_seq)?;
            }
            match next {
                Some(after) => cursor = Some(after),
                None => return Ok(()),
            }
        }
    }

    /// One page of the agent records of this root (contract 2 `AgentList`).
    /// # Errors
    /// The store's listing and record refusals.
    pub(crate) fn agent_record_page(
        &self,
        cursor: Option<&str>,
        limit: u32,
    ) -> Result<(Vec<StoredAgentRecord>, Option<String>), SdkError> {
        self.agent_record_store()?.page(cursor, usize::try_from(limit).unwrap_or(usize::MAX))
    }

    /// The changes of this root after `cursor` (contract 2 `AgentWatch`, decision r22 item 1).
    /// # Errors
    /// `journal_cursor_invalid` for a malformed or future cursor, and the store's refusals.
    pub(crate) fn agent_record_changes(&self, cursor: &str) -> Result<Changes, SdkError> {
        self.agent_record_store()?.changes(parse_cursor(cursor)?)
    }

    /// The current change cursor of this root (the head); the value `agent.list` returns so that a
    /// watch can start where the list ends.
    /// # Errors
    /// The store's listing refusals.
    pub(crate) fn agent_record_head(&self) -> Result<u64, SdkError> {
        self.agent_record_store()?.head()
    }

    /// One stored agent record (contract 2 `AgentGet`).
    /// # Errors
    /// `agent_not_found` for no record of that agent on this root.
    pub(crate) fn agent_record_get(&self, agent: &str) -> Result<StoredAgentRecord, SdkError> {
        self.agent_record_store()?
            .load(agent)?
            .ok_or(SdkError::AgentCreationRefused("agent_not_found"))
    }

    /// Applies one authorized metadata body to this device's store (`EventOrder`, see
    /// `agent_record::apply_metadata`). Returns whether the stored record changed.
    /// # Errors
    /// The refusals of `apply_metadata` and the store.
    pub(crate) fn receive_agent_metadata(
        &self,
        metadata: &g::AgentMetadata,
    ) -> Result<bool, SdkError> {
        let owner = self.own_account_anchor()?;
        apply_metadata(&self.agent_record_store()?, &owner, metadata)
    }
}

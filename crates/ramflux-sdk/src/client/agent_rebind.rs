// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Stage D R1, client side: the desktop sends the frozen rebind plan to the new primary over the
//! custody transport (point-to-point). Nothing is sent when this desktop is no longer a paired
//! device of the human; the preparation refuses first and the agent stays in R.
use crate::client::agent_custody::AgentCustodySend;
use crate::custody::agent_creation::prepare_rebind_request;
use ramflux_crypto::RootQualifiedDeviceRef;
use crate::{RamfluxClient, SdkError};
use ramflux_protocol::custody::DeviceRef;
use ramflux_protocol::message as g;

impl RamfluxClient {
    /// Freeze the rebind plan of one paused agent and send it to the current primary of this human.
    /// # Errors
    /// The preparation refusals of `prepare_rebind_request` (nothing is sent), then the staging
    /// failure of the custody transport.
    pub(crate) fn agent_rebind_send(&self, agent_account_id: &str, now: u64) -> Result<(), SdkError> {
        let account = self.born_v3_account.as_deref().ok_or(SdkError::AccountDbNotUnlocked)?;
        let store = account.agent_creation_store()?;
        let own = self.owned_device_identity()?;
        let desktop = DeviceRef {
            account_anchor: own.root_commitment().into(),
            device_id: own.device_id().into(),
            device_epoch: self.device_epoch_of(&own)?,
        };
        let human = account.record();
        let prepared = prepare_rebind_request(&store, human, &desktop, agent_account_id, now)?;
        let target =
            RootQualifiedDeviceRef::from_custody_record(account.verified(), &prepared.primary.device_id)?;
        self.stage_agent_custody(AgentCustodySend {
            target: &target,
            owner_anchor: &human.body.account_anchor,
            agent_anchor: &prepared.agent_anchor,
            correlation_id: &prepared.request_id,
            custody: g::AgentCustodyPacket {
                value: Some(g::agent_custody_packet::Value::RequestJson(prepared.plan_bytes)),
            },
            now,
        })
    }
}

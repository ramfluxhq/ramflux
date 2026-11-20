// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Agent creation custody packets on the paired Human's own-device channel (AGENT-IDENTITY-01,
//! P5 and D8). Sending is point-to-point to one sibling. Receive authorization (sender, endpoints,
//! epochs, plan and scope) runs before any store, UI or signature effect. The durable apply stays
//! refused until stage C3 opens the creation store for this client.
use crate::bus::own_device_copy;
use crate::client::identity_authority::HeadUse;
use crate::client::own_device_copy::{OwnMessageInput, OwnPayloadKind};
use crate::client::routed::Opened;
use crate::custody::agent_creation::{check_received_request, expected_scope};
use crate::error::GeneratedRefusalCode;
use crate::{GatewayInboxEntry, RamfluxClient, SdkError};
use prost::Message as _;
use ramflux_crypto::RootQualifiedDeviceRef;
use ramflux_protocol::message as g;

/// Domain of the local message id of one custody control.
const SEND_DOMAIN: &str = "ramflux.sdk.agent_custody_packet.v1";

/// Inputs of one custody send to the paired primary device.
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) struct AgentCustodySend<'a> {
    /// Sibling device that must be the current primary of the owner root.
    pub target: &'a RootQualifiedDeviceRef,
    /// Owner anchor; must equal this device's root.
    pub owner_anchor: &'a str,
    /// Pending agent anchor, which fixes the conversation scope.
    pub agent_anchor: &'a str,
    /// Correlation id copied into the packet.
    pub correlation_id: &'a str,
    /// The custody body (request, decision, cancel or receipt).
    pub custody: g::AgentCustodyPacket,
    /// Wall-clock unix seconds from the caller.
    pub now: u64,
}

fn refused(reason: &str) -> SdkError {
    SdkError::GeneratedRefused { code: GeneratedRefusalCode::Content, reason: reason.into() }
}

impl RamfluxClient {
    fn device_epoch_of(&self, device: &RootQualifiedDeviceRef) -> Result<u64, SdkError> {
        self.account_db()?
            .client_device_record(device)?
            .and_then(|record| record["device_epoch"].as_u64())
            .filter(|epoch| *epoch != 0)
            .ok_or_else(|| refused("agent custody device epoch missing"))
    }

    /// Receive authorization of one `AgentHostPacket`. Refuses before any effect.
    /// # Errors
    /// Refuses endpoint, epoch, body, plan or scope mismatches.
    pub(crate) fn authorize_generated_agent_sync(
        &self,
        opened: &Opened,
        entry: &GatewayInboxEntry,
        packet: &g::AgentHostPacket,
    ) -> Result<(), SdkError> {
        let source = self.authenticated_device_identity(HeadUse::NewAuthorization, entry)?;
        let local = self.owned_device_identity()?;
        let own_root = self.own_account_anchor()?;
        let declared_source =
            packet.source.as_ref().ok_or_else(|| refused("agent custody source missing"))?;
        let declared_recipient =
            packet.recipient.as_ref().ok_or_else(|| refused("agent custody recipient missing"))?;
        if packet.owner_anchor != own_root
            || declared_source.account_anchor != source.root_commitment()
            || declared_source.device_id != source.device_id()
            || declared_recipient.account_anchor != own_root
            || declared_recipient.device_id != local.device_id()
        {
            return Err(refused("agent custody endpoints do not match the authenticated devices"));
        }
        if self.device_epoch_of(&source)? != declared_source.device_epoch
            || self.device_epoch_of(&local)? != declared_recipient.device_epoch
        {
            return Err(refused("agent custody device epoch is not current"));
        }
        let Some(g::agent_host_packet::Body::Custody(custody)) = packet.body.as_ref() else {
            return Err(refused("agent custody body missing"));
        };
        let Some(g::agent_custody_packet::Value::RequestJson(plan_bytes)) = custody.value.as_ref()
        else {
            return Err(refused(
                "agent custody packet needs its stored plan; admitted from stage C3",
            ));
        };
        check_received_request(
            plan_bytes,
            &opened.routing.conversation_id,
            &own_root,
            source.root_commitment(),
            source.device_id(),
            local.device_id(),
        )?;
        Ok(())
    }

    /// Durable apply of an authorized custody packet. Until stage C3 opens the creation store, an
    /// authorized packet is refused with no store, UI or signature effect.
    /// # Errors
    /// Every authorization refusal, then the typed unavailability of the creation store.
    pub(crate) fn apply_generated_agent_sync(
        &self,
        opened: &Opened,
        entry: &GatewayInboxEntry,
        packet: &g::AgentHostPacket,
    ) -> Result<(), SdkError> {
        self.authorize_generated_agent_sync(opened, entry, packet)?;
        Err(refused("agent creation custody is unavailable until the creation store is opened"))
    }

    /// Send one custody packet point-to-point to a sibling of this root (the paired primary).
    /// The conversation scope is `dm_scope::derive(owner, agent)`, never a fixed string.
    /// # Errors
    /// Refuses a foreign owner, a non-sibling target, an out-of-range clock, or a failed stage.
    // The bus caller arrives in stage C3; until then only the test calls this.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn stage_agent_custody(&self, send: AgentCustodySend<'_>) -> Result<(), SdkError> {
        let AgentCustodySend { target, owner_anchor, agent_anchor, correlation_id, custody, now } =
            send;
        let own = self.owned_device_identity()?;
        if owner_anchor != self.own_account_anchor()? {
            return Err(refused("agent custody owner is not this root"));
        }
        let scope = expected_scope(owner_anchor, agent_anchor)?;
        let packet = g::AgentHostPacket {
            owner_anchor: owner_anchor.into(),
            source: Some(g::QualifiedDevice {
                account_anchor: own.root_commitment().into(),
                device_id: own.device_id().into(),
                device_epoch: self.device_epoch_of(&own)?,
            }),
            recipient: Some(g::QualifiedDevice {
                account_anchor: target.root_commitment().into(),
                device_id: target.device_id().into(),
                device_epoch: self.device_epoch_of(target)?,
            }),
            correlation_id: correlation_id.into(),
            body: Some(g::agent_host_packet::Body::Custody(custody)),
        };
        let body = crate::client::generated_control::control_from_payload(
            g::control::Payload::AgentSync(packet),
        )?
        .encode_to_vec();
        let id = ramflux_protocol::hash_base64url(SEND_DOMAIN, &body);
        let created_at = i64::try_from(now).map_err(|_| refused("agent custody clock range"))?;
        own_device_copy::stage_to(
            self,
            OwnMessageInput {
                payload_kind: OwnPayloadKind::Control,
                id: &id,
                created_at,
                conversation: &scope,
                group: None,
                body: &body,
            },
            target,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::shared_group::tests::{
        install_native_directories, native_person, native_sibling,
    };
    use crate::prelude::now_unix_timestamp;
    use ramflux_protocol::encode_base64url;

    fn send<'a>(
        owner_anchor: &'a str,
        target: &'a RootQualifiedDeviceRef,
        agent: &'a str,
        custody: &g::AgentCustodyPacket,
        now: u64,
    ) -> AgentCustodySend<'a> {
        AgentCustodySend {
            target,
            owner_anchor,
            agent_anchor: agent,
            correlation_id: "agent-create-test",
            custody: custody.clone(),
            now,
        }
    }

    #[test]
    fn custody_send_reaches_only_a_sibling_of_the_same_root() -> Result<(), SdkError> {
        let mut phone = native_person("owner", "phone")?;
        let laptop = native_sibling(&mut phone, "owner-laptop", "laptop")?;
        let stranger = native_person("stranger", "stranger")?;
        install_native_directories(&[&phone, &laptop, &stranger])?;
        let owner = phone.client.own_account_anchor()?;
        let agent = encode_base64url([8_u8; 32]);
        let sibling = laptop.client.owned_device_identity()?;
        let foreign = stranger.client.owned_device_identity()?;
        let custody = g::AgentCustodyPacket {
            value: Some(g::agent_custody_packet::Value::RequestJson(b"{}".to_vec())),
        };
        let now = u64::try_from(now_unix_timestamp()).expect("test: clock is after the epoch");

        assert!(
            phone
                .client
                .stage_agent_custody(send(&agent, &sibling, &agent, &custody, now))
                .is_err(),
            "a foreign owner anchor must refuse before any stage"
        );
        assert!(
            phone
                .client
                .stage_agent_custody(send(&owner, &foreign, &agent, &custody, now))
                .is_err(),
            "a target in another root must refuse"
        );
        phone.client.stage_agent_custody(send(&owner, &sibling, &agent, &custody, now))?;
        Ok(())
    }
}

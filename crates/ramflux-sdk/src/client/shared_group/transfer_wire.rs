// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Signed, short-lived creator-head probes and transferee acknowledgements.
use crate::prelude::*;
use ramflux_protocol::{GroupStateActor, GroupStateSnapshot, GroupTransferAcceptance};
use serde::{Deserialize, Serialize};
const DOMAIN: &str = "ramflux.group.transfer_sync.v1";
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct TransferDevice {
    pub root: String,
    pub device: String,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct TransferProbe {
    pub id: String,
    pub actor: GroupStateActor,
    pub creator: GroupStateActor,
    pub base: GroupStateSnapshot,
    pub required: Vec<TransferDevice>,
    pub issued_at: i64,
    pub expires_at: i64,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct TransferHead {
    pub proposal: String,
    pub actor: GroupStateActor,
    pub requested_hash: String,
    pub head: GroupStateSnapshot,
    pub acceptance: Option<Box<GroupTransferAcceptance>>,
    pub requires_sync: bool,
    pub target: TransferDevice,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub additional_targets: Vec<TransferDevice>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub cancelled: bool,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub cancel_ack: bool,
    pub issued_at: i64,
    pub expires_at: i64,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum TransferBody {
    Probe { probe: Box<TransferProbe> },
    Head { reply: Box<TransferHead> },
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct TransferControl {
    pub body: TransferBody,
    pub signature: String,
}
impl TransferControl {
    pub(crate) fn actor(&self) -> &GroupStateActor {
        match &self.body {
            TransferBody::Probe { probe } => &probe.actor,
            TransferBody::Head { reply } => &reply.actor,
        }
    }
    pub(crate) fn group(&self) -> &str {
        match &self.body {
            TransferBody::Probe { probe } => &probe.base.group_id,
            TransferBody::Head { reply } => &reply.head.group_id,
        }
    }
    pub(crate) fn proposal(&self) -> &str {
        match &self.body {
            TransferBody::Probe { probe } => &probe.id,
            TransferBody::Head { reply } => &reply.proposal,
        }
    }
    pub(crate) fn expires_at(&self) -> i64 {
        match &self.body {
            TransferBody::Probe { probe } => probe.expires_at,
            TransferBody::Head { reply } => reply.expires_at,
        }
    }
    pub(crate) fn targets(&self) -> Vec<TransferDevice> {
        match &self.body {
            TransferBody::Probe { probe } => probe.required.clone(),
            TransferBody::Head { reply } => std::iter::once(reply.target.clone())
                .chain(reply.additional_targets.iter().cloned())
                .collect(),
        }
    }
    pub(crate) fn signing(&self) -> serde_json::Value {
        serde_json::json!({"domain":DOMAIN,"body":self.body})
    }
    pub(crate) fn sign(client: &RamfluxClient, body: TransferBody) -> Result<Self, SdkError> {
        let mut wire = Self { body, signature: String::new() };
        wire.signature = ramflux_crypto::sign_with_device_branch(
            client.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?,
            &wire.signing(),
        )?;
        Ok(wire)
    }
    pub(crate) fn verify(&self, now: i64) -> Result<(), SdkError> {
        let (at, until) = match &self.body {
            TransferBody::Probe { probe } => (probe.issued_at, probe.expires_at),
            TransferBody::Head { reply } => (reply.issued_at, reply.expires_at),
        };
        if matches!(&self.body,TransferBody::Head{reply} if reply.cancelled &&
            (reply.actor.identity.root_commitment != reply.head.creator.identity.root_commitment
                || reply.requested_hash != reply.head.state_hash || !reply.requires_sync || reply.acceptance.is_some()))
        {
            return Err(super::invalid("transfer cancellation authority or base mismatch"));
        }
        let cancelled = matches!(&self.body, TransferBody::Head { reply } if reply.cancelled);
        let lifetime = if cancelled { 7 * 86400 } else { 60 };
        if matches!(&self.body,TransferBody::Head{reply} if reply.cancel_ack && (reply.cancelled || reply.requires_sync || reply.acceptance.is_some() || !reply.additional_targets.is_empty()))
            || self.targets().len() > ramflux_protocol::group_state::MAX_GROUP_DEVICES_PER_ROOT + 1
            || matches!(&self.body, TransferBody::Head { reply } if (!reply.requires_sync || reply.acceptance.is_some()) && !reply.additional_targets.is_empty())
            || at < 0
            || at > now.saturating_add(300)
            || until < now.saturating_sub(300)
            || until <= at
            || until > at.saturating_add(lifetime)
        {
            return Err(super::transfer::requires_sync_reason("clock_skew_or_expired_control"));
        }
        ramflux_crypto::verify_group_state_actor(self.actor())?;
        ramflux_crypto::verify_device_branch_signature(
            &self.actor().identity.signing_public_key,
            &self.signing(),
            &self.signature,
        )?;
        let snapshot = match &self.body {
            TransferBody::Probe { probe } => &probe.base,
            TransferBody::Head { reply } => &reply.head,
        };
        ramflux_crypto::verify_group_state_snapshot(snapshot.clone())?;
        let nonce = ramflux_protocol::decode_base64url(self.proposal())
            .map_err(|_| super::invalid("transfer nonce encoding"))?;
        if nonce.len() != 32 || ramflux_protocol::encode_base64url(nonce) != self.proposal() {
            return Err(super::invalid("transfer nonce"));
        }
        Ok(())
    }
}

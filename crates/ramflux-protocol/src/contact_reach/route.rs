// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Complete signed-envelope binding for durable and volatile reach traffic.
use super::{actor, digest, invalid, lifetime, node, safe, text};
use crate::{
    ProtocolError,
    custody::{DeviceRef, Envelope as Signed},
};
use serde::{Deserialize, Serialize};

pub const COST_DOMAIN: &str = "ramflux.contact.sender_cost.v1";
pub const COST_CONTEXT_DOMAIN: &str = "ramflux.contact.sender_cost_context.v1";
pub const EPHEMERAL_HASH_DOMAIN: &str = "ramflux.contact.reach_ephemeral_frame.v1";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Traffic {
    Dm,
    Group,
    GroupInvite,
    ReceiptDelivered,
    ReceiptRead,
    Typing,
    OwnCopy,
    SelfSync,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GroupRoute {
    pub group_id: String,
    pub group_epoch: u64,
    pub membership_hash: String,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Route {
    pub version: u32,
    pub source: DeviceRef,
    pub recipient_root: String,
    pub conversation_id: String,
    pub traffic: Traffic,
    pub group: Option<GroupRoute>,
    pub envelope_hash: String,
    pub authority_head_hash: String,
    pub issued_at: u64,
    pub expires_at: u64,
}
impl Route {
    /// Validate route shape; recipient-owned authority is checked separately.
    /// # Errors
    /// Refuses malformed names/hashes, unsafe times and nonpositive lifetimes.
    pub fn validate(&self) -> Result<(), ProtocolError> {
        actor(&self.source)?;
        digest(&self.recipient_root)?;
        digest(&self.envelope_hash)?;
        digest(&self.authority_head_hash)?;
        text(&self.conversation_id)?;
        if matches!(
            self.traffic,
            Traffic::Dm | Traffic::ReceiptDelivered | Traffic::ReceiptRead | Traffic::Typing
        ) {
            let expected =
                crate::message::dm_scope::derive(&self.source.account_anchor, &self.recipient_root)
                    .map_err(|_| invalid("invalid route DM root pair"))?;
            if self.conversation_id != expected {
                return Err(invalid("route conversation/root binding mismatch"));
            }
        }
        if (self.traffic == Traffic::Group) != self.group.is_some() {
            return Err(invalid("group route null rule"));
        }
        if let Some(group) = &self.group {
            super::group_profile::validate_group_id(&group.group_id)?;
            crate::message::dm_scope::validate_group(&self.conversation_id)
                .map_err(|_| invalid("invalid group conversation"))?;
            digest(&group.membership_hash)?;
            safe(group.group_epoch)?;
            if group.group_epoch == 0 {
                return Err(invalid("zero route group epoch"));
            }
        }
        safe(self.issued_at)?;
        safe(self.expires_at)?;
        if self.version != 1 || self.expires_at <= self.issued_at {
            return Err(invalid("route version or lifetime"));
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CostPurpose {
    Stranger,
    NameClaim,
    NameRename,
}
impl CostPurpose {
    #[must_use]
    pub const fn difficulty(self) -> u32 {
        match self {
            Self::Stranger => 20,
            Self::NameClaim => 24,
            Self::NameRename => 22,
        }
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChallengeRequest {
    pub purpose: CostPurpose,
    pub source_root: String,
    pub recipient_root: Option<String>,
    pub operation_hash: String,
}
impl ChallengeRequest {
    /// Validate purpose/target correlation without creating a challenge.
    /// # Errors
    /// Refuses malformed digests and a missing or extraneous recipient.
    pub fn validate(&self) -> Result<(), ProtocolError> {
        digest(&self.source_root)?;
        digest(&self.operation_hash)?;
        if (self.purpose == CostPurpose::Stranger) != self.recipient_root.is_some() {
            return Err(invalid("cost purpose recipient mismatch"));
        }
        if let Some(root) = &self.recipient_root {
            digest(root)?;
        }
        Ok(())
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Challenge {
    pub version: u32,
    pub issuer: String,
    pub purpose: CostPurpose,
    pub source_root: String,
    pub recipient_root: Option<String>,
    pub operation_hash: String,
    pub nonce: String,
    pub difficulty: u64,
    pub issued_at: u64,
    pub expires_at: u64,
}
impl Challenge {
    /// Validate the fixed work parameters and exact submission window.
    /// # Errors
    /// Refuses malformed audience, purpose, difficulty or time.
    pub fn validate(&self) -> Result<(), ProtocolError> {
        ChallengeRequest {
            purpose: self.purpose,
            source_root: self.source_root.clone(),
            recipient_root: self.recipient_root.clone(),
            operation_hash: self.operation_hash.clone(),
        }
        .validate()?;
        node(&self.issuer)?;
        digest(&self.nonce)?;
        if self.version != 1 || self.difficulty != u64::from(self.purpose.difficulty()) {
            return Err(invalid("cost version or difficulty"));
        }
        lifetime(self.issued_at, self.expires_at, super::COMMAND_LIFETIME)
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Cost {
    pub challenge: Signed<Challenge>,
    pub work_nonce: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Submission {
    pub route: Signed<Route>,
    pub envelope: crate::Envelope,
    pub cost: Option<Cost>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeliveryReach {
    pub route: Signed<Route>,
    pub cost: Option<Cost>,
    pub node_report_receipt: Option<crate::NodeReportReceipt>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EphemeralFrameKind {
    Ephemeral,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EphemeralFrame {
    pub frame_type: EphemeralFrameKind,
    pub envelope: crate::Envelope,
    pub expires_at_ms: u64,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReachEphemeral {
    pub route: Signed<Route>,
    pub frame: EphemeralFrame,
}
impl ReachEphemeral {
    /// Validate exact volatile frame/route size, clock units and original five-second lifetime.
    /// # Errors
    /// Refuses durable input, a renewed deadline and a substituted complete frame hash.
    pub fn validate(&self, now_ms: u64) -> Result<(), ProtocolError> {
        let b = &self.route.body;
        b.validate()?;
        safe(self.frame.expires_at_ms)?;
        let deadline = crate::ephemeral::deadline(&self.frame.envelope, now_ms)
            .map_err(|_| invalid("invalid reach ephemeral lifetime"))?;
        let created = u64::try_from(self.frame.envelope.created_at)
            .map_err(|_| invalid("negative ephemeral start"))?;
        if b.traffic != Traffic::Typing
            || b.issued_at != created
            || created.checked_add(u64::from(self.frame.envelope.ttl)) != Some(b.expires_at)
            || b.expires_at.checked_mul(1000).is_none_or(|limit| self.frame.expires_at_ms > limit)
            || self.frame.expires_at_ms > deadline
            || now_ms >= self.frame.expires_at_ms
            || b.envelope_hash != crate::custody::framed_hash(EPHEMERAL_HASH_DOMAIN, &self.frame)?
            || crate::canonical_json_bytes(&self.frame)?.len() > 32_768
            || crate::canonical_json_bytes(&self.route)?.len() > 4096
            || crate::canonical_json_bytes(self)?.len() > 40_960
        {
            return Err(invalid("reach ephemeral route or frame mismatch"));
        }
        Ok(())
    }
}

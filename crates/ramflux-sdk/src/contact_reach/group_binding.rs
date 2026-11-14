// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Bind every group subtype to an adopted head, or a purely verified snapshot before preparation.
use super::{SavedReachState, refused};
use crate::{RamfluxClient, SdkError};
use prost::Message as _;
use ramflux_protocol::{
    contact_reach::{self as wire, Reason, Route, StateRecord, Subject},
    message as g,
};
fn invalid() -> SdkError {
    refused(Reason::ReachRouteInvalid)
}
fn native<T: serde::Serialize + serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T, SdkError> {
    Ok(ramflux_protocol::custody::decode(
        bytes,
        ramflux_protocol::group_state::MAX_GROUP_STATE_BYTES,
    )?)
}
fn control_head(
    control: &g::Control,
    identity: &g::EventIdentity,
) -> Result<(u64, Option<String>), SdkError> {
    match control.payload.as_ref() {
        Some(g::control::Payload::GroupKeyControl(key)) if control.operation == 5 => {
            let distribution = key.distribution.as_ref().ok_or_else(invalid)?;
            if Some(&distribution.group_id) != identity.group_id.as_ref() {
                return Err(invalid());
            }
            Ok((
                distribution.group_key_epoch,
                Some(distribution.group_state_hash.clone().ok_or_else(invalid)?),
            ))
        }
        Some(g::control::Payload::GroupState(state)) if control.operation == 4 => {
            match state.body.as_ref().and_then(|body| body.value.as_ref()) {
                Some(g::group_control_body::Value::Request(value)) => {
                    let request: ramflux_protocol::group_state::GroupChangeRequest =
                        native(&value.request.as_ref().ok_or_else(invalid)?.canonical)?;
                    if Some(&request.group_id) != identity.group_id.as_ref() {
                        return Err(invalid());
                    }
                    Ok((request.base_epoch, None))
                }
                Some(g::group_control_body::Value::Result(value)) => {
                    let result: ramflux_protocol::group_state::GroupChangeResult =
                        native(&value.result.as_ref().ok_or_else(invalid)?.canonical)?;
                    if Some(&result.group_id) != identity.group_id.as_ref() {
                        return Err(invalid());
                    }
                    Ok((result.epoch, Some(result.state_hash)))
                }
                Some(
                    g::group_control_body::Value::DeviceSet(_)
                    | g::group_control_body::Value::Transfer(_),
                ) => Ok((identity.group_epoch.ok_or_else(invalid)?, None)),
                _ => Err(invalid()),
            }
        }
        _ => Err(invalid()),
    }
}
impl RamfluxClient {
    pub(crate) fn require_reach_group_invite_binding(
        &self,
        route: &Route,
        inner: &g::Inner,
        body: &[u8],
    ) -> Result<(), SdkError> {
        let candidate = crate::client::shared_group::decode_packet(body)?.ok_or_else(invalid)?;
        let identity = inner.identity.as_ref().ok_or_else(invalid)?;
        if identity.group_id.as_deref() != Some(candidate.view().group_id.as_str())
            || identity.group_epoch != Some(candidate.view().epoch)
            || identity.conversation_id != candidate.view().conversation_id
            || route.conversation_id != candidate.view().conversation_id
        {
            return Err(invalid());
        }
        wire::group_profile::check(identity, inner.kind, Some(4), true)
            .map_err(SdkError::ReachRefused)?;
        let genesis = candidate.genesis_hash()?;
        let state: SavedReachState = serde_json::from_value(
            self.account_db()?.client_record("reach", "state")?.ok_or_else(|| {
                SdkError::InboundPending("verified recipient reach state unavailable".into())
            })?,
        )?;
        if state.root != route.recipient_root || state.conflict {
            return Err(refused(Reason::HomeFork));
        }
        for record in state.records.iter().chain(state.restrictions.values()) {
            let (subject, denied) = match record {
                StateRecord::Grant { subject, .. } => (subject, false),
                StateRecord::Block { subject, .. } => (subject, true),
                StateRecord::Floor { subject, denied, .. } => (subject, *denied),
                StateRecord::Retirement { subject, group_floor, .. } => {
                    (subject, group_floor.as_ref().is_some_and(|floor| floor.blocked()))
                }
                _ => continue,
            };
            let Subject::Group { group_id, conversation_id, genesis_hash, .. } = subject else {
                continue;
            };
            if group_id == &candidate.view().group_id
                || conversation_id == &candidate.view().conversation_id
                || genesis_hash == &genesis
            {
                if group_id != &candidate.view().group_id
                    || conversation_id != &candidate.view().conversation_id
                    || genesis_hash != &genesis
                {
                    return Err(invalid());
                }
                if denied {
                    return Err(SdkError::GeneratedRefused {
                        code: crate::error::GeneratedRefusalCode::Authority,
                        reason: "recipient group is blocked".into(),
                    });
                }
            }
        }
        Ok(())
    }

    pub(crate) fn require_reach_group_binding(
        &self,
        route: &Route,
        inner: &g::Inner,
        body: &[u8],
    ) -> Result<(), SdkError> {
        let identity = inner.identity.as_ref().ok_or_else(invalid)?;
        let group = route.group.as_ref().ok_or_else(invalid)?;
        self.require_reach_group_roster_unforked(&group.group_id)?;
        let candidate =
            if inner.kind == 8 { crate::client::shared_group::decode_packet(body)? } else { None };
        let comparison = candidate
            .as_ref()
            .map(|candidate| {
                self.account_db()?
                    .shared_group_state(&candidate.view().group_id)
                    .map_err(SdkError::from)
            })
            .transpose()?
            .flatten();
        // Compute the relation without effects; handle a fork only after all W/identity bindings.
        let relation = candidate
            .as_ref()
            .zip(comparison.as_ref())
            .map(|(candidate, current)| candidate.relation_to(current));
        if identity.group_id.as_deref() != Some(group.group_id.as_str())
            || identity.group_epoch != Some(group.group_epoch)
            || identity.conversation_id != route.conversation_id
        {
            return Err(invalid());
        }
        let operation = if inner.kind == 8 {
            Some(g::Control::decode(inner.body.as_slice()).map_err(|_| invalid())?.operation)
        } else {
            None
        };
        wire::group_profile::check(
            identity,
            inner.kind,
            operation,
            self.reach_signed_group_present(body)?,
        )
        .map_err(SdkError::ReachRefused)?;
        if let Some(candidate) = candidate {
            if candidate.view().group_id != group.group_id
                || candidate.view().conversation_id != route.conversation_id
                || candidate.view().epoch != group.group_epoch
                || candidate.snapshot().state_hash != group.membership_hash
            {
                return Err(invalid());
            }
            self.require_reach_group_relation(route, &candidate, comparison.as_ref(), relation)?;
            self.require_reach_group_grant(route, &candidate.genesis_hash()?)?;
            return Ok(());
        }
        let (epoch, hash) = referenced_head(inner)?;
        let adopted =
            self.account_db()?.shared_group_state_at_epoch(&group.group_id, epoch)?.ok_or_else(
                || SdkError::InboundPending("group route names an unadopted head".into()),
            )?;
        if epoch != group.group_epoch
            || adopted.view().conversation_id != route.conversation_id
            || adopted.snapshot().state_hash != group.membership_hash
            || hash.as_deref().is_some_and(|hash| hash != group.membership_hash)
        {
            return Err(invalid());
        }
        self.require_reach_group_grant(route, &adopted.genesis_hash()?)
    }
    fn require_reach_group_relation(
        &self,
        route: &Route,
        candidate: &ramflux_crypto::VerifiedGroupState,
        current: Option<&ramflux_crypto::VerifiedGroupState>,
        relation: Option<Result<ramflux_crypto::GroupStateRelation, ramflux_crypto::CryptoError>>,
    ) -> Result<(), SdkError> {
        use ramflux_crypto::{CryptoError, GroupStateRelation};
        let fork = match relation {
            Some(
                Ok(GroupStateRelation::RemovalConflict | GroupStateRelation::Unrelated)
                | Err(CryptoError::Protocol(
                    ramflux_protocol::ProtocolError::GroupTransferRequiresSync,
                )),
            ) => true,
            Some(Err(error)) => return Err(error.into()),
            _ => false,
        };
        if fork {
            let current = current.ok_or_else(invalid)?;
            self.require_reach_group_grant(route, &current.genesis_hash()?)?;
            self.group_conflict_event(candidate, "pending_fork")?;
            return Err(SdkError::InboundPending("group roster is pending_fork".into()));
        }
        Ok(())
    }
    fn require_reach_group_grant(&self, route: &Route, genesis: &str) -> Result<(), SdkError> {
        let state: SavedReachState = serde_json::from_value(
            self.account_db()?
                .client_record("reach", "state")?
                .ok_or_else(|| refused(Reason::ReachPolicyRequired))?,
        )?;
        state.require_positive_ready()?;
        if state.root != route.recipient_root || state.conflict {
            return Err(refused(Reason::HomeFork));
        }
        self.require_reach_authority_head(
            &state.root,
            &state.authority_head_hash,
            crate::custody::network_now()?,
        )?;
        let group = route.group.as_ref().ok_or_else(invalid)?;
        let now = crate::custody::network_now()?;
        for record in state.records.iter().chain(state.restrictions.values()) {
            match record {
                StateRecord::Block { subject: Subject::Friendship { root }, .. }
                | StateRecord::Floor {
                    subject: Subject::Friendship { root }, denied: true, ..
                } if root == &route.source.account_anchor => {
                    return Err(refused(Reason::ForeignReadRefused));
                }
                StateRecord::Decline { root, until, .. }
                    if root == &route.source.account_anchor && *until > now =>
                {
                    return Err(refused(Reason::ForeignReadRefused));
                }
                StateRecord::Block { subject: Subject::Node { .. }, .. }
                | StateRecord::Floor { subject: Subject::Node { .. }, denied: true, .. } => {
                    return Err(SdkError::InboundPending(
                        "source-home evidence is required for node-denial enforcement".into(),
                    ));
                }
                StateRecord::Retirement {
                    subject: Subject::Group { group_id, .. },
                    group_floor: Some(floor),
                    ..
                } if group_id == &group.group_id && floor.blocked() => {
                    return Err(refused(Reason::ForeignReadRefused));
                }
                _ => {}
            }
        }
        let grant = state
            .records
            .iter()
            .find_map(|record| match record {
                StateRecord::Grant {
                    subject:
                        Subject::Group { group_id, conversation_id, genesis_hash, group_epoch, .. },
                    ..
                } if group_id == &group.group_id
                    && conversation_id == &route.conversation_id
                    && genesis_hash == genesis =>
                {
                    Some(*group_epoch)
                }
                _ => None,
            })
            .ok_or_else(|| refused(Reason::ForeignReadRefused))?;
        if group.group_epoch < grant {
            return Err(refused(Reason::GroupEpochStale));
        }
        for record in state.records.iter().chain(state.restrictions.values()) {
            if let StateRecord::Retirement {
                subject: Subject::Group { group_id, .. },
                group_floor: Some(floor),
                ..
            } = record
                && group_id == &group.group_id
                && grant <= floor.floor_epoch
            {
                return Err(refused(Reason::GroupEpochStale));
            }
        }
        Ok(())
    }
}

pub(super) fn referenced_head(inner: &g::Inner) -> Result<(u64, Option<String>), SdkError> {
    let identity = inner.identity.as_ref().ok_or_else(invalid)?;
    let group_id = identity.group_id.as_deref().ok_or_else(invalid)?;
    Ok(match inner.kind {
        1 => {
            let message = g::Message::decode(inner.body.as_slice()).map_err(|_| invalid())?;
            let sealed = message.sealed_group.ok_or_else(invalid)?;
            if sealed.group_id != group_id {
                return Err(invalid());
            }
            (sealed.key_epoch, Some(ramflux_protocol::encode_base64url(&sealed.group_state_hash)))
        }
        8 => control_head(
            &g::Control::decode(inner.body.as_slice()).map_err(|_| invalid())?,
            identity,
        )?,
        2..=5 | 9 | 10 => (identity.group_epoch.ok_or_else(invalid)?, None),
        _ => return Err(invalid()),
    })
}

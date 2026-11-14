// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Independently retained recipient decisions precede every decrypted application effect.
use super::SavedReachState;
use crate::{RamfluxClient, SdkError};
use ramflux_protocol::contact_reach::{Route, StateRecord, Subject, Traffic};

fn pending() -> SdkError {
    SdkError::InboundPending("verified recipient reach state unavailable".into())
}
fn denied() -> SdkError {
    SdkError::GeneratedRefused {
        code: crate::error::GeneratedRefusalCode::Authority,
        reason: "recipient reach permission denied".into(),
    }
}

impl SavedReachState {
    fn peer_denials(
        &self,
        owner: &str,
        peer: &str,
        conversation: &str,
        now: u64,
    ) -> Result<(), SdkError> {
        if self.root != owner || self.conflict {
            return Err(pending());
        }
        let mut node_evidence_needed = false;
        for record in self.records.iter().chain(self.restrictions.values()) {
            let subject = match record {
                StateRecord::Block { subject, .. }
                | StateRecord::Floor { subject, denied: true, .. } => Some(subject),
                StateRecord::Decline { root, until, .. } if root == peer && *until > now => {
                    return Err(denied());
                }
                StateRecord::Placement { conversation_id, tombstone: true, .. }
                    if conversation_id == conversation =>
                {
                    return Err(denied());
                }
                StateRecord::Conflict { .. } => return Err(pending()),
                _ => None,
            };
            match subject {
                Some(Subject::Friendship { root }) if root == peer => {
                    return Err(denied());
                }
                Some(Subject::Conversation { root, conversation_id })
                    if root == peer && conversation_id == conversation =>
                {
                    return Err(denied());
                }
                Some(Subject::Node { .. }) => node_evidence_needed = true,
                _ => {}
            }
        }
        if node_evidence_needed {
            return Err(SdkError::InboundPending(
                "authenticated source-home evidence required for node-denial enforcement".into(),
            ));
        }
        Ok(())
    }
}

impl RamfluxClient {
    fn reach_policy_state(
        &self,
        owner: &str,
        peer: &str,
        conversation: &str,
        now: u64,
    ) -> Result<SavedReachState, SdkError> {
        let state: SavedReachState = serde_json::from_value(
            self.account_db()?.client_record("reach", "state")?.ok_or_else(pending)?,
        )
        .map_err(|_| pending())?;
        state.peer_denials(owner, peer, conversation, now)?;
        state.require_positive_ready()?;
        self.require_reach_authority_head(
            &state.root,
            &state.authority_head_hash,
            state.custodian_head_hash.as_deref(),
            now,
        )?;
        Ok(state)
    }
    fn require_reach_signal(
        &self,
        state: &SavedReachState,
        peer: &str,
        conversation: &str,
        traffic: Traffic,
        now: u64,
    ) -> Result<(), SdkError> {
        // All node denials were checked before this projection. The empty selector supplies
        // no node identity or permission; authenticated source-home evidence is separate.
        let permission = state.conversation(peer, "", conversation, now)?;
        let settings = self.reach_signal_settings()?;
        let allowed = match traffic {
            Traffic::ReceiptDelivered => {
                permission.permissions.user_delivered && settings.user_delivered
            }
            Traffic::ReceiptRead => permission.permissions.read && settings.read,
            Traffic::Typing => permission.permissions.typing && settings.typing,
            _ => false,
        };
        if allowed { Ok(()) } else { Err(denied()) }
    }
    /// Apply the installed original recipient signatures after source authentication.
    pub(super) fn require_reach_receive_policy(
        &self,
        route: &Route,
        now: u64,
    ) -> Result<(), SdkError> {
        let state = self.reach_policy_state(
            &route.recipient_root,
            &route.source.account_anchor,
            &route.conversation_id,
            now,
        )?;
        if matches!(
            route.traffic,
            Traffic::ReceiptDelivered | Traffic::ReceiptRead | Traffic::Typing
        ) {
            self.require_reach_signal(
                &state,
                &route.source.account_anchor,
                &route.conversation_id,
                route.traffic,
                now,
            )?;
        }
        Ok(())
    }
    /// An outgoing signal needs this device's filter and its own original phone-signed grant.
    /// The receiving home independently enforces the other endpoint's grant.
    pub(super) fn require_reach_outgoing_signal(
        &self,
        peer: &str,
        conversation: &str,
        traffic: Traffic,
        now: u64,
    ) -> Result<(), SdkError> {
        let own = self.own_account_anchor()?;
        let state = self.reach_policy_state(&own, peer, conversation, now)?;
        self.require_reach_signal(&state, peer, conversation, traffic, now)
    }
}

#[cfg(test)]
mod tests;

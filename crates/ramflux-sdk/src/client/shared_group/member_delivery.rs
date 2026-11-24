// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Local participation evidence is separate from the creator's signed membership grant.
use super::{RamfluxClient, SdkError};
use ramflux_crypto::VerifiedGroupState;
use ramflux_protocol::group_state::{GroupMemberIdentity, SharedGroupMember};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

pub(crate) const PREFIX: &str = "group-member-confirmation/";

#[derive(Deserialize, Serialize)]
struct Confirmation {
    genesis_hash: String,
    root: String,
    device: String,
    joined_epoch: u64,
}

fn key(group: &str) -> String {
    format!("{PREFIX}{}", ramflux_protocol::encode_base64url(group))
}

fn matches(row: &Confirmation, genesis_hash: &str, member: &SharedGroupMember) -> bool {
    row.genesis_hash == genesis_hash
        && row.root == member.identity.root_commitment
        && row.device == member.identity.device_id
        && row.joined_epoch == member.joined_epoch
}

impl RamfluxClient {
    pub(super) fn confirm_group_member_beacon(
        &self,
        group: &str,
        actor: &GroupMemberIdentity,
        group_epoch: u64,
    ) -> Result<(), SdkError> {
        let db = self.account_db()?;
        let state = db.shared_group_state(group)?.ok_or(super::invalid("group absent"))?;
        let Some(member) = state.view().members.iter().find(|member| {
            member.identity == *actor
                && member.joined_epoch <= group_epoch
                && group_epoch <= state.view().epoch
                && state.view().effective_role(&actor.root_commitment, &actor.device_id).is_some()
        }) else {
            // A delayed beacon from before removal/re-admission cannot confirm the new grant.
            return Ok(());
        };
        let id = key(group);
        let genesis_hash = state.genesis_hash()?;
        let mut rows: Vec<Confirmation> = db.load_actor_state(&id)?.unwrap_or_default();
        rows.retain(|row| {
            state.view().members.iter().any(|member| matches(row, &genesis_hash, member))
        });
        if rows.iter().any(|row| matches(row, &genesis_hash, member)) {
            return Ok(());
        }
        rows.push(Confirmation {
            genesis_hash,
            root: actor.root_commitment.clone(),
            device: actor.device_id.clone(),
            joined_epoch: member.joined_epoch,
        });
        db.persist_actor_state(&id, &rows)?;
        Ok(())
    }

    pub(crate) fn group_member_delivery_outcomes(
        &self,
        state: &VerifiedGroupState,
    ) -> Result<Vec<Value>, SdkError> {
        let own = self.owned_device_identity()?;
        let genesis_hash = state.genesis_hash()?;
        let rows: Vec<Confirmation> =
            self.account_db()?.load_actor_state(&key(&state.view().group_id))?.unwrap_or_default();
        Ok(state
            .view()
            .members
            .iter()
            .map(|member| {
                let identity = &member.identity;
                let joined = (identity.root_commitment == own.root_commitment()
                    && identity.device_id == own.device_id())
                    || *identity == state.creator().identity
                    || rows.iter().any(|row| matches(row, &genesis_hash, member));
                json!({
                    "root_commitment": identity.root_commitment,
                    "principal_id": identity.principal_id,
                    "device_id": identity.device_id,
                    "joined_epoch": member.joined_epoch,
                    "state": if joined { "joined" } else { "pending" },
                    "reason": if joined { Value::Null } else { json!("delivery_unconfirmed") },
                    "status_text": if joined { "Joined" } else { "Delivery unconfirmed" },
                })
            })
            .collect())
    }
}

// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Same-root contact restrictions are sticky against delayed sibling acceptance copies.
use super::{
    OwnContactReceiveMode, OwnContactReceiveOutcome, RamfluxClient, SdkError, contact_peer,
};
use serde::{Deserialize, Serialize};
const PREFIX: &[u8] = b"ramflux.own_contact_tombstone.v1\n";
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Tombstone {
    link: ramflux_storage::FriendLinkRecord,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    decided_at: Option<i64>,
}
pub(super) fn is_packet(body: &[u8]) -> bool {
    body.starts_with(PREFIX)
}
pub(super) fn is_restricted(link: &ramflux_storage::FriendLinkRecord) -> bool {
    link.state == "removed" || link.blocked || link.capability_revoked_at.is_some()
}
pub(super) fn encode(
    client: &RamfluxClient,
    link: &ramflux_storage::FriendLinkRecord,
) -> Result<Vec<u8>, SdkError> {
    let db = client.account_db()?;
    let decided_at = db
        .contact_link_decision(&link.link_id)?
        .filter(|decision| {
            (is_restricted(link) && decision.state == "blocked")
                || (link.state == "rejected" && decision.state == "declined")
        })
        .map_or_else(
            || db.friend_link_updated_at_millis(&link.link_id),
            |decision| Ok(decision.decided_at),
        )?;
    let mut bytes = PREFIX.to_vec();
    bytes.extend(serde_json::to_vec(&Tombstone {
        link: link.clone(),
        decided_at: Some(decided_at),
    })?);
    Ok(bytes)
}
impl RamfluxClient {
    pub(super) fn receive_own_contact_tombstone(
        &self,
        body: &[u8],
        mode: OwnContactReceiveMode,
    ) -> Result<Option<OwnContactReceiveOutcome>, SdkError> {
        let Some(raw) = body.strip_prefix(PREFIX) else {
            return Ok(None);
        };
        let Tombstone { link, decided_at } = ramflux_protocol::parse_i_json(raw)?;
        let own = self.owned_device_identity()?;
        let peer = contact_peer(&link, own.root_commitment()).ok_or_else(|| {
            SdkError::InboundRejected("own contact tombstone ownership mismatch".into())
        })?;
        if !is_restricted(&link)
            || peer == own.root_commitment()
            || ramflux_protocol::decode_base64url(peer).map_or(true, |v| v.len() != 32)
        {
            return Err(SdkError::InboundRejected("invalid own contact tombstone".into()));
        }
        let db = self.account_db()?;
        let existing = db.find_friend_link(&link.link_id)?;
        if let Some(existing) = &existing
            && (existing.requester_id != link.requester_id || existing.target_id != link.target_id)
        {
            return Err(SdkError::InboundRejected("own contact tombstone link collision".into()));
        }
        if mode == OwnContactReceiveMode::BackupRestore
            && db
                .contact_link_decision(&link.link_id)?
                .is_some_and(|local| decided_at.is_none_or(|source| source < local.decided_at))
        {
            return Ok(Some(OwnContactReceiveOutcome::TombstoneSkippedOlder));
        }
        if existing.as_ref().is_some_and(|existing| {
            existing.blocked == link.blocked
                && (link.blocked || existing.state == "removed" && link.state == "removed")
        }) {
            return Ok(Some(OwnContactReceiveOutcome::AlreadyPresent));
        }
        if existing.is_none() {
            db.establish_friend_link(&link.link_id, &link.requester_id, &link.target_id)?;
        }
        if link.blocked {
            self.block_friend_link(&link.link_id)?;
        } else {
            self.remove_friend_link(
                &link.link_id,
                link.remove_scope.as_deref().unwrap_or("own_devices"),
            )?;
        }
        Ok(Some(OwnContactReceiveOutcome::TombstoneApplied))
    }
}

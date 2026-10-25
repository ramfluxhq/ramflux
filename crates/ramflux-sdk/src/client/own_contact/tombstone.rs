// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Same-root contact restrictions are sticky against delayed sibling acceptance copies.
use super::{RamfluxClient, SdkError, contact_peer};
use serde::{Deserialize, Serialize};
const PREFIX: &[u8] = b"ramflux.own_contact_tombstone.v1\n";
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Tombstone {
    link: ramflux_storage::FriendLinkRecord,
}
pub(super) fn is_packet(body: &[u8]) -> bool {
    body.starts_with(PREFIX)
}
pub(super) fn is_restricted(link: &ramflux_storage::FriendLinkRecord) -> bool {
    link.state == "removed" || link.blocked || link.capability_revoked_at.is_some()
}
pub(super) fn encode(link: &ramflux_storage::FriendLinkRecord) -> Result<Vec<u8>, SdkError> {
    let mut bytes = PREFIX.to_vec();
    bytes.extend(serde_json::to_vec(&Tombstone { link: link.clone() })?);
    Ok(bytes)
}
impl RamfluxClient {
    pub(super) fn receive_own_contact_tombstone(&self, body: &[u8]) -> Result<bool, SdkError> {
        let Some(raw) = body.strip_prefix(PREFIX) else {
            return Ok(false);
        };
        let Tombstone { link } = ramflux_protocol::parse_i_json(raw)?;
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
        if let Some(existing) = db.find_friend_link(&link.link_id)? {
            if existing.requester_id != link.requester_id || existing.target_id != link.target_id {
                return Err(SdkError::InboundRejected(
                    "own contact tombstone link collision".into(),
                ));
            }
            if existing.blocked || (existing.state == "removed" && !link.blocked) {
                return Ok(true);
            }
        } else {
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
        Ok(true)
    }
}

// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Generated Friend controls enter the existing contact state machine.
use super::{g, validate_friend};
use crate::client::identity_authority::HeadUse;
use crate::{GatewayInboxEntry, RamfluxClient, SdkError};

fn fingerprint(source: &str, bytes: &[u8]) -> Result<[u8; 32], SdkError> {
    let mut transcript = Vec::new();
    for field in
        [ramflux_protocol::domain::MESSAGE_FRIEND_APPLIED.as_bytes(), source.as_bytes(), bytes]
    {
        let len = u32::try_from(field.len())
            .map_err(|_| SdkError::InboundRejected("Friend replay input too large".into()))?;
        transcript.extend_from_slice(&len.to_be_bytes());
        transcript.extend_from_slice(field);
    }
    Ok(*blake3::hash(&transcript).as_bytes())
}
impl RamfluxClient {
    pub(crate) fn authorize_generated_friend_control(
        &self,
        source: &ramflux_crypto::RootQualifiedDeviceRef,
        friend: &g::FriendControl,
    ) -> Result<(), SdkError> {
        validate_friend(friend)?;
        let own = self.own_account_anchor()?;
        let (sender, local) = if friend.action == 2 {
            (&friend.target, &friend.requester)
        } else {
            (&friend.requester, &friend.target)
        };
        if sender != source.root_commitment() || local != &own || sender == local {
            return Err(SdkError::InboundRejected(
                "Friend actor differs from authenticated endpoint roles".into(),
            ));
        }
        if let Some(link) = self.account_db()?.find_friend_link(&friend.link_id)? {
            if link.requester_id != friend.requester || link.target_id != friend.target {
                return Err(SdkError::InboundRejected(
                    "Friend link belongs to different roots".into(),
                ));
            }
            if friend.action == 2 && !matches!(link.state.as_str(), "pending" | "accepted") {
                return Err(SdkError::InboundRejected(
                    "Friend accept has no live local request".into(),
                ));
            }
        } else if friend.action == 2 {
            return Err(SdkError::InboundRejected("Friend accept requires a local request".into()));
        } else if friend.action >= 3 {
            return Err(SdkError::InboundRejected("Friend link missing".into()));
        }
        if self.friend_rejection_reason(source.root_commitment())?.is_some() {
            return Err(SdkError::InboundRejected(
                "blocked or removed peer cannot mutate Friend controls".into(),
            ));
        }
        Ok(())
    }

    pub(crate) fn apply_generated_friend_control(
        &self,
        entry: &GatewayInboxEntry,
        identity: &g::EventIdentity,
        friend: &g::FriendControl,
        exact_inner: &[u8],
    ) -> Result<bool, SdkError> {
        let source = self.authenticated_device_identity(HeadUse::NewAuthorization, entry)?;
        self.authorize_generated_friend_control(&source, friend)?;
        let key = format!(
            "routed/friend-applied/{}/{}",
            source.storage_key(),
            ramflux_protocol::encode_base64url(&identity.id)
        );
        let digest = fingerprint(source.storage_key(), exact_inner)?;
        let db = self.account_db()?;
        if let Some(old) = db.load_actor_state::<[u8; 32]>(&key)? {
            return if old == digest { Ok(false) } else { Err(SdkError::ReplayMismatch) };
        }
        match friend.action {
            1 => {
                self.record_pending_friend_link(
                    &friend.link_id,
                    &friend.requester,
                    &friend.target,
                )?;
            }
            2 => {
                self.establish_friend_link(&friend.link_id, &friend.requester, &friend.target)?;
            }
            3 => {
                self.remove_friend_link(
                    &friend.link_id,
                    friend.remove_scope.as_deref().unwrap_or("both"),
                )?;
            }
            4 => {
                self.block_friend_link(&friend.link_id)?;
            }
            5 => {
                self.unblock_friend_link(&friend.link_id)?;
            }
            _ => return Err(SdkError::InboundRejected("unknown Friend action".into())),
        }
        db.persist_message_actor_state(
            &ramflux_protocol::encode_base64url(&identity.id),
            &key,
            &digest,
        )?;
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn friend_replay_fingerprint_has_independent_framed_golden_vector() -> Result<(), SdkError> {
        assert_eq!(
            ramflux_protocol::encode_base64url(fingerprint("root/device", &[8, 2, 16, 8])?),
            "zIRMS3Hkqt3CWK94eJEP3RB_rN7UuU8unDa8L-vBIdw"
        );
        assert_ne!(fingerprint("ab", b"c")?, fingerprint("a", b"bc")?);
        Ok(())
    }
}

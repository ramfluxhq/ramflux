// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Named same-root Sync adapters reuse native contact import and sticky restrictions.
use super::{Contact, OwnContactReceiveMode};
use crate::{RamfluxClient, SdkError};
use ramflux_protocol::message as g;

fn invalid(message: &str) -> SdkError {
    SdkError::InboundRejected(message.into())
}

pub(super) fn link(
    value: Option<&g::FriendLinkRecord>,
) -> Result<ramflux_storage::FriendLinkRecord, SdkError> {
    let value = value.ok_or_else(|| invalid("own contact link missing"))?;
    if value.link_id.is_empty()
        || value.requester_id.is_empty()
        || value.target_id.is_empty()
        || value
            .remove_scope
            .as_deref()
            .is_some_and(|scope| !matches!(scope, "me" | "own_devices" | "both"))
    {
        return Err(invalid("own contact link fields invalid"));
    }
    Ok(ramflux_storage::FriendLinkRecord {
        link_id: value.link_id.clone(),
        requester_id: value.requester_id.clone(),
        target_id: value.target_id.clone(),
        state: value.state.clone(),
        remove_scope: value.remove_scope.clone(),
        blocked: value.blocked,
        capability_revoked_at: value.capability_revoked_at,
    })
}

pub(super) fn generated_link(value: &ramflux_storage::FriendLinkRecord) -> g::FriendLinkRecord {
    g::FriendLinkRecord {
        link_id: value.link_id.clone(),
        requester_id: value.requester_id.clone(),
        target_id: value.target_id.clone(),
        state: value.state.clone(),
        remove_scope: value.remove_scope.clone(),
        blocked: value.blocked,
        capability_revoked_at: value.capability_revoked_at,
    }
}
impl Contact {
    pub(super) fn bytes(&self) -> Result<Vec<u8>, SdkError> {
        use prost::Message as _;
        Ok(crate::client::generated_control::control_from_payload(
            g::control::Payload::OwnContactSync(g::OwnContactSync {
                manifest: Some(g::NativeDeviceManifest::try_from(&self.manifest)?),
                link: Some(generated_link(&self.link)),
                ..Default::default()
            }),
        )?
        .encode_to_vec())
    }
    pub(super) fn decode(body: &[u8]) -> Result<Option<Self>, SdkError> {
        use prost::Message as _;
        if g::validation::scan_message("Control", body, g::registry::COMPILED_LAYER).is_err() {
            return Ok(None);
        }
        let control = g::Control::decode(body).map_err(|_| invalid("invalid own Control"))?;
        crate::client::generated_control::validate_control_operation(&control)?;
        let Some(g::control::Payload::OwnContactSync(value)) = control.payload else {
            return Ok(None);
        };
        let manifest = crate::client::task::generated::manifest::generated_manifest_fields(
            value.manifest.as_ref().ok_or_else(|| invalid("own contact manifest missing"))?,
        )?;
        Ok(Some(Self { manifest, link: link(value.link.as_ref())? }))
    }
}

impl RamfluxClient {
    fn generated_own_contact(&self, value: &g::OwnContactSync) -> Result<Contact, SdkError> {
        let link = link(value.link.as_ref())?;
        let own = self.own_account_anchor()?;
        let peer = super::contact_peer(&link, &own)
            .filter(|peer| *peer != own.as_str())
            .ok_or_else(|| invalid("own contact relationship root mismatch"))?;
        let manifest = Self::decode_generated_own_contact_manifest(
            value.manifest.as_ref().ok_or_else(|| invalid("own contact manifest missing"))?,
            peer,
        )?;
        Ok(Contact { manifest, link })
    }

    pub(crate) fn authorize_generated_own_contact(
        &self,
        value: &g::OwnContactSync,
    ) -> Result<(), SdkError> {
        self.validate_own_contact(&self.generated_own_contact(value)?)?;
        Ok(())
    }

    pub(crate) fn receive_generated_own_contact(
        &self,
        value: &g::OwnContactSync,
    ) -> Result<(), SdkError> {
        let contact = self.generated_own_contact(value)?;
        self.account_db()?.join_write(|| {
            self.apply_own_contact(&contact)?;
            self.ensure_direct_conversation(
                &contact.manifest.principal_commitment,
                &contact.manifest.principal_id,
            )
            .map(drop)
        })
    }

    pub(crate) fn receive_generated_own_contact_with_origin(
        &self,
        value: &g::OwnContactSync,
        source: &ramflux_crypto::RootQualifiedDeviceRef,
        identity: &g::EventIdentity,
        exact_inner: &[u8],
    ) -> Result<(), SdkError> {
        self.receive_generated_own_contact(value)?;
        self.account_db()?.join_write(|| {
            super::super::contact_verification_cas::install_sibling_confirmation_from(
                self,
                source,
                value,
                identity,
                exact_inner,
            )
        })
    }

    pub(crate) fn authorize_generated_contact_tombstone(
        &self,
        value: &g::OwnContactTombstone,
    ) -> Result<(), SdkError> {
        if value.decided_at.is_none_or(|at| at < 0) {
            return Err(invalid("own contact decision time missing or invalid"));
        }
        self.validate_own_contact_tombstone(&link(value.link.as_ref())?)?;
        Ok(())
    }

    pub(crate) fn receive_generated_contact_tombstone(
        &self,
        value: &g::OwnContactTombstone,
    ) -> Result<(), SdkError> {
        self.authorize_generated_contact_tombstone(value)?;
        self.apply_own_contact_tombstone(
            &link(value.link.as_ref())?,
            value.decided_at,
            OwnContactReceiveMode::Sibling,
        )?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::native_test_support::{Fixture, TestResult};
    use prost::Message as _;

    fn manifest(peer: &Fixture) -> TestResult<g::NativeDeviceManifest> {
        Ok(g::NativeDeviceManifest::decode(
            peer.client.encode_generated_task_manifest(&peer.manifest)?.as_slice(),
        )?)
    }

    #[tokio::test]
    async fn generated_own_contact_import_and_tombstone_use_native_sticky_rules() -> TestResult {
        let own = Box::pin(Fixture::new("typed-own-contact")).await?;
        let peer = Box::pin(Fixture::new("typed-own-contact-peer")).await?;
        let foreign = Box::pin(Fixture::new("typed-own-contact-foreign")).await?;
        let link = g::FriendLinkRecord {
            link_id: "typed-contact-link".into(),
            requester_id: own.client.own_account_anchor()?,
            target_id: peer.client.own_account_anchor()?,
            state: "accepted".into(),
            ..Default::default()
        };
        let value = g::OwnContactSync {
            manifest: Some(manifest(&peer)?),
            link: Some(link.clone()),
            ..Default::default()
        };
        let db = own.client.account_db()?;
        assert!(db.client_record("identity", &peer.manifest.principal_id)?.is_none());
        own.client.authorize_generated_own_contact(&value)?;
        assert!(
            db.client_record("identity", &peer.manifest.principal_id)?.is_none(),
            "validation imported keys"
        );
        assert!(db.find_friend_link(&link.link_id)?.is_none());
        own.client.receive_generated_own_contact(&value)?;
        assert!(db.client_record("identity", &peer.manifest.principal_id)?.is_some());
        assert_eq!(db.friend_link(&link.link_id)?.state, "accepted");
        let collision = g::OwnContactSync {
            manifest: Some(manifest(&foreign)?),
            link: Some(g::FriendLinkRecord {
                target_id: foreign.client.own_account_anchor()?,
                ..link.clone()
            }),
            ..Default::default()
        };
        assert!(
            own.client.authorize_generated_own_contact(&collision).is_err(),
            "existing link changed peer roots"
        );
        assert!(db.client_record("identity", &foreign.manifest.principal_id)?.is_none());
        let tombstone = g::OwnContactTombstone {
            decided_at: Some(crate::time::now_unix_timestamp().saturating_mul(1000)),
            link: Some(g::FriendLinkRecord {
                state: "removed".into(),
                remove_scope: Some("own_devices".into()),
                ..link
            }),
        };
        own.client.authorize_generated_contact_tombstone(&tombstone)?;
        own.client.receive_generated_contact_tombstone(&tombstone)?;
        assert_eq!(db.friend_link("typed-contact-link")?.state, "removed");
        own.client.receive_generated_own_contact(&value)?;
        assert_eq!(
            db.friend_link("typed-contact-link")?.state,
            "removed",
            "delayed accepted contact resurrected a restriction"
        );
        let mut invalid = tombstone;
        invalid.link.as_mut().ok_or("link")?.remove_scope = Some("local".into());
        assert!(own.client.authorize_generated_contact_tombstone(&invalid).is_err());
        Ok(())
    }
}

// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Accepted root relationships replicated only inside authenticated own-device packets.
use crate::prekey::SdkDeviceManifestResponse;
use crate::{RamfluxClient, SdkError};
use serde::{Deserialize, Serialize};
const PREFIX: &[u8] = b"ramflux.own_contact.v1\n";
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Contact {
    manifest: SdkDeviceManifestResponse,
    link: ramflux_storage::FriendLinkRecord,
}
impl RamfluxClient {
    pub(crate) fn stage_own_contact(
        &self,
        manifest: &SdkDeviceManifestResponse,
        link: &str,
    ) -> Result<(), SdkError> {
        let own = self.owned_device_identity()?;
        if self.observed_device_set(own.root_commitment())?.is_none_or(|r| {
            r.devices
                .iter()
                .filter(|d| d.status == ramflux_protocol::DeviceSetStatus::Active)
                .count()
                < 2
        }) {
            return Ok(());
        }
        let link = self.account_db()?.friend_link(link)?;
        let mut body = PREFIX.to_vec();
        body.extend(serde_json::to_vec(&Contact { manifest: manifest.clone(), link })?);
        let id = ramflux_protocol::hash_base64url("ramflux.sdk.own_contact.copy.v1", &body);
        crate::bus::own_device_copy::stage(
            self,
            crate::client::own_device_copy::OwnMessageInput {
                id: &id,
                created_at: crate::prelude::now_unix_timestamp(),
                conversation: "own-contact",
                group: None,
                body: &body,
            },
            None,
        )
    }
    /// The caller must first verify the packet's active sibling signature and owned root.
    pub(super) fn receive_own_contact(&self, body: &[u8]) -> Result<bool, SdkError> {
        let Some(raw) = body.strip_prefix(PREFIX) else {
            return Ok(false);
        };
        let contact: Contact = ramflux_protocol::parse_i_json(raw)?;
        let own = self.owned_device_identity()?;
        let peer = &contact.manifest.principal_commitment;
        let link = &contact.link;
        if peer == own.root_commitment()
            || link.state != "accepted"
            || link.blocked
            || link.capability_revoked_at.is_some()
            || !((link.requester_id == own.root_commitment() && link.target_id == *peer)
                || (link.target_id == own.root_commitment() && link.requester_id == *peer))
        {
            return Err(SdkError::InboundRejected("own contact relationship root mismatch".into()));
        }
        crate::client::contact::verify_device_manifest(&contact.manifest, peer)?;
        let existing = self
            .account_db()?
            .friend_link_for_peer(peer)?
            .or(self.account_db()?.friend_link_for_peer(&contact.manifest.principal_id)?);
        if existing.is_some_and(|link| {
            link.state != "accepted" || link.blocked || link.capability_revoked_at.is_some()
        }) {
            return Ok(true);
        }
        self.persist_identity_directory(&contact.manifest)?;
        // An existing local block/revocation always wins over a delayed sibling acceptance.
        if self.friend_rejection_reason(&contact.manifest.principal_id)?.is_none() {
            self.establish_friend_link(&link.link_id, &link.requester_id, &link.target_id)?;
        }
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    type TestResult = Result<(), Box<dyn std::error::Error>>;
    fn client(
        path: &std::path::Path,
        principal: &str,
        root_seed: u8,
    ) -> Result<RamfluxClient, SdkError> {
        let mut client = RamfluxClient::new();
        client.create_identity_root(principal, [root_seed; 32]);
        client.create_device_branch(principal, "shared", 1, [root_seed + 1; 32]);
        client.open_account_index(path)?;
        client.create_account(principal, principal)?;
        client.unlock_account(principal, b"own-contact-test")?;
        Ok(client)
    }
    #[test]
    fn sibling_acceptance_supplies_the_pinned_root_but_never_replaces_a_pin_or_local_block()
    -> TestResult {
        let path = std::env::temp_dir().join(format!(
            "rf-own-contact-{}-{}",
            std::process::id(),
            ramflux_protocol::encode_base64url(&ramflux_crypto::random_32()?[..8])
        ));
        let own = client(&path.join("own"), "bob", 1)?;
        let peer = client(&path.join("peer"), "alice", 3)?;
        let impostor = client(&path.join("impostor"), "alice", 5)?;
        let manifest = crate::client::identity_authority::test_support::public_manifest(&peer)?;
        let own_root = own.owned_device_identity()?.root_commitment().to_owned();
        own.establish_friend_link("accepted", &own_root, &manifest.principal_commitment)?;
        let link = own.account_db()?.friend_link("accepted")?;
        let packet = |manifest: SdkDeviceManifestResponse,
                      link: ramflux_storage::FriendLinkRecord|
         -> Result<Vec<u8>, SdkError> {
            let mut bytes = PREFIX.to_vec();
            bytes.extend(serde_json::to_vec(&Contact { manifest, link })?);
            Ok(bytes)
        };
        assert!(own.account_db()?.client_record("identity", "alice")?.is_none());
        assert!(own.receive_own_contact(&packet(manifest.clone(), link.clone())?)?);
        assert_eq!(own.trusted_recipient_root("shared")?, manifest.principal_commitment);
        assert!(own.inbound_relationship_names_root(
            "alice",
            &manifest.principal_commitment,
            "shared"
        )?);
        let forged_manifest =
            crate::client::identity_authority::test_support::public_manifest(&impostor)?;
        let mut forged_link = link.clone();
        forged_link.target_id.clone_from(&forged_manifest.principal_commitment);
        assert!(own.receive_own_contact(&packet(forged_manifest, forged_link)?).is_err());
        assert_eq!(own.trusted_recipient_root("shared")?, manifest.principal_commitment);
        own.block_friend_link("accepted")?;
        own.receive_own_contact(&packet(manifest, link)?)?;
        assert!(own.account_db()?.friend_link("accepted")?.blocked);
        drop((own, peer, impostor));
        std::fs::remove_dir_all(path)?;
        Ok(())
    }
}

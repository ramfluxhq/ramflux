// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Accepted root relationships replicated only inside authenticated own-device packets.
use crate::prekey::SdkDeviceManifestResponse;
use crate::{RamfluxClient, SdkError};
use serde::{Deserialize, Serialize};
mod tombstone;
const PREFIX: &[u8] = b"ramflux.own_contact.v1\n";
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Contact {
    manifest: SdkDeviceManifestResponse,
    link: ramflux_storage::FriendLinkRecord,
}
#[derive(Default, Serialize, Deserialize)]
struct Backfill {
    #[serde(default)]
    schema_version: u32,
    epoch: u64,
    cursor: String,
    complete: bool,
    #[serde(default)]
    restrictions_done: bool,
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
        self.stage_own_contact_body(&body)
    }
    fn stage_own_contact_body(&self, body: &[u8]) -> Result<(), SdkError> {
        let own = self.owned_device_identity()?;
        let set = self.observed_device_set(own.root_commitment())?;
        let id = ramflux_protocol::hash_base64url(
            "ramflux.sdk.own_contact.copy.v2",
            &ramflux_protocol::canonical_json_bytes(&(body, set))?,
        );
        crate::bus::own_device_copy::stage(
            self,
            crate::client::own_device_copy::OwnMessageInput {
                id: &id,
                created_at: crate::prelude::now_unix_timestamp(),
                conversation: "own-contact",
                group: None,
                body,
            },
            None,
        )
    }
    pub(super) fn own_history_contacts(&self) -> Result<Vec<String>, SdkError> {
        let own = self.owned_device_identity()?;
        let db = self.account_db()?;
        let mut result = Vec::new();
        let mut bytes = 0;
        // Restrictions precede acceptances both in history and in the ordered own-device queue.
        for restrictions in [true, false] {
            let mut after = String::new();
            loop {
                let page = db.friend_link_page(&after, 64)?;
                for link in &page {
                    after.clone_from(&link.link_id);
                    let Some(peer) = contact_peer(link, own.root_commitment()) else {
                        continue;
                    };
                    if tombstone::is_restricted(link) != restrictions {
                        continue;
                    }
                    let body = if restrictions {
                        tombstone::encode(link)?
                    } else if link.state == "accepted" {
                        let Some(manifest) = db.load_actor_state::<SdkDeviceManifestResponse>(
                            &format!("identity/manifest-root/{peer}"),
                        )?
                        else {
                            continue;
                        };
                        let mut body = PREFIX.to_vec();
                        body.extend(serde_json::to_vec(&Contact { manifest, link: link.clone() })?);
                        body
                    } else {
                        continue;
                    };
                    let encoded = ramflux_protocol::encode_base64url(body);
                    if result.len() >= 512 || bytes + encoded.len() > 3 * 1024 * 1024 {
                        return Ok(result);
                    }
                    bytes += encoded.len();
                    result.push(encoded);
                }
                if page.len() < 64 {
                    break;
                }
            }
        }
        Ok(result)
    }
    pub(crate) fn stage_contact_backfill_batch(&self) -> Result<usize, SdkError> {
        let own = self.owned_device_identity()?;
        let Some(set) = self.observed_device_set(own.root_commitment())? else {
            return Ok(0);
        };
        if set
            .devices
            .iter()
            .filter(|d| d.status == ramflux_protocol::DeviceSetStatus::Active)
            .count()
            < 2
        {
            return Ok(0);
        }
        let db = self.account_db()?;
        let mut progress =
            db.load_actor_state::<Backfill>("own-contact/backfill")?.unwrap_or_default();
        if progress.epoch != set.device_set_epoch || progress.schema_version != 1 {
            progress =
                Backfill { schema_version: 1, epoch: set.device_set_epoch, ..Backfill::default() };
        }
        if progress.complete {
            return Ok(0);
        }
        let links = db.friend_link_page(&progress.cursor, 4)?;
        let mut count = 0;
        for link in &links {
            if let Some(peer) = contact_peer(link, own.root_commitment()) {
                if !progress.restrictions_done && tombstone::is_restricted(link) {
                    self.stage_own_contact_body(&tombstone::encode(link)?)?;
                    count += 1;
                } else if progress.restrictions_done
                    && link.state == "accepted"
                    && !tombstone::is_restricted(link)
                {
                    let Some(manifest) = db.load_actor_state::<SdkDeviceManifestResponse>(
                        &format!("identity/manifest-root/{peer}"),
                    )?
                    else {
                        // Leave the cursor immediately before this link; refresh its manifest next tick.
                        db.persist_actor_state("own-contact/backfill", &progress)?;
                        return Ok(count);
                    };
                    self.stage_own_contact(&manifest, &link.link_id)?;
                    count += 1;
                }
            }
            progress.cursor.clone_from(&link.link_id);
            db.persist_actor_state("own-contact/backfill", &progress)?;
        }
        if links.len() < 4 {
            if progress.restrictions_done {
                progress.complete = true;
            } else {
                progress.restrictions_done = true;
                progress.cursor.clear();
            }
            db.persist_actor_state("own-contact/backfill", &progress)?;
        }
        Ok(count)
    }
    pub(crate) fn pending_contact_backfill_root(&self) -> Result<Option<String>, SdkError> {
        let db = self.account_db()?;
        let progress = db.load_actor_state::<Backfill>("own-contact/backfill")?.unwrap_or_default();
        if !progress.restrictions_done || progress.complete {
            return Ok(None);
        }
        let own = self.owned_device_identity()?;
        let links = db.friend_link_page(&progress.cursor, 4)?;
        for link in links {
            if link.state == "accepted"
                && !tombstone::is_restricted(&link)
                && let Some(peer) = contact_peer(&link, own.root_commitment())
                && !db.actor_state_exists(&format!("identity/manifest-root/{peer}"))?
            {
                return Ok(Some(peer.into()));
            }
        }
        Ok(None)
    }
    /// The caller must first verify the packet's active sibling signature and owned root.
    pub(super) fn receive_own_contact(&self, body: &[u8]) -> Result<bool, SdkError> {
        if self.receive_own_contact_tombstone(body)? {
            return Ok(true);
        }
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
        if self.account_db()?.find_friend_link(&link.link_id)?.is_some_and(|existing| {
            existing.requester_id != link.requester_id || existing.target_id != link.target_id
        }) {
            return Err(SdkError::InboundRejected(
                "own contact link id belongs to another relationship".into(),
            ));
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

pub(super) fn is_tombstone_packet(body: &[u8]) -> bool {
    tombstone::is_packet(body)
}

fn contact_peer<'a>(link: &'a ramflux_storage::FriendLinkRecord, own: &str) -> Option<&'a str> {
    if link.requester_id == own {
        Some(&link.target_id)
    } else if link.target_id == own {
        Some(&link.requester_id)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    type TestResult = Result<(), Box<dyn std::error::Error>>;
    pub(super) fn client(
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
    #[test]
    fn sibling_link_id_collision_cannot_replace_a_different_blocked_relationship() -> TestResult {
        let path = std::env::temp_dir().join(format!(
            "rf-contact-collision-{}",
            ramflux_protocol::encode_base64url(&ramflux_crypto::random_32()?[..8])
        ));
        let own = client(&path.join("own"), "bob", 1)?;
        let peer = client(&path.join("peer"), "alice", 3)?;
        let other = client(&path.join("other"), "carol", 5)?;
        let manifest = crate::client::identity_authority::test_support::public_manifest(&peer)?;
        let other_manifest =
            crate::client::identity_authority::test_support::public_manifest(&other)?;
        let own_root = own.owned_device_identity()?.root_commitment().to_owned();
        own.establish_friend_link("collision", &own_root, &other_manifest.principal_commitment)?;
        own.block_friend_link("collision")?;
        let before = own.account_db()?.friend_link("collision")?;
        let mut link = before.clone();
        link.target_id.clone_from(&manifest.principal_commitment);
        link.blocked = false;
        link.state = "accepted".into();
        link.capability_revoked_at = None;
        let mut packet = PREFIX.to_vec();
        packet.extend(serde_json::to_vec(&Contact { manifest, link })?);
        assert!(own.receive_own_contact(&packet).is_err());
        assert_eq!(own.account_db()?.friend_link("collision")?, before);
        drop((own, peer, other));
        std::fs::remove_dir_all(path)?;
        Ok(())
    }
    #[test]
    fn contacts_accepted_before_activation_are_backfilled_once_per_own_set() -> TestResult {
        let path = std::env::temp_dir().join(format!(
            "rf-contact-backfill-{}",
            ramflux_protocol::encode_base64url(&ramflux_crypto::random_32()?[..8])
        ));
        let own = client(&path.join("own"), "bob", 1)?;
        let peer = client(&path.join("peer"), "alice", 3)?;
        let mut sibling = client(&path.join("sibling"), "bob", 1)?;
        sibling.create_device_branch("bob", "second", 1, [8; 32]);
        let manifest = crate::client::identity_authority::test_support::public_manifest(&peer)?;
        let mut set = crate::client::identity_authority::test_support::public_manifest(&own)?;
        own.persist_identity_directory(&set)?;
        own.persist_identity_directory(&manifest)?;
        let own_root = own.owned_device_identity()?.root_commitment().to_owned();
        own.establish_friend_link("before-activation", &own_root, &manifest.principal_commitment)?;
        own.stage_own_contact(&manifest, "before-activation")?;
        assert_eq!(own.account_db()?.actor_state_usage("own-device/send/")?.0, 0);
        // A second signed active entry becomes visible after the contact was accepted.
        let second = crate::client::identity_authority::test_support::public_manifest(&sibling)?
            .devices
            .remove(0);
        set.devices.push(second);
        crate::client::identity_authority::test_support::sign_manifest(
            own.identity_root.as_ref().ok_or("root")?,
            &mut set,
            2,
        )?;
        own.persist_identity_directory(&set)?;
        assert_eq!(own.stage_contact_backfill_batch()?, 0); // Restriction pass precedes acceptances.
        assert_eq!(own.stage_contact_backfill_batch()?, 1);
        assert_eq!(own.stage_contact_backfill_batch()?, 0);
        assert_eq!(own.account_db()?.actor_state_usage("own-device/send/")?.0, 1);
        drop((own, peer, sibling));
        std::fs::remove_dir_all(path)?;
        Ok(())
    }
}

#[cfg(test)]
#[path = "own_contact/review_r9_tests.rs"]
mod review_r9_tests;

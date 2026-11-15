// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Idempotent direct-conversation projection for accepted contacts.
//!
//! Becoming friends creates the canonical root-pair direct conversation on both sides. The empty
//! thread is presentation only: it grants nothing, and the first outbound message still goes
//! through the normal send path and its authorization.
use super::RamfluxClient;
use crate::SdkError;
use ramflux_protocol::message as g;
use std::collections::BTreeSet;

/// Contacts examined per page while backfilling on account open.
const BACKFILL_PAGE: u32 = 64;

fn invalid(message: &str) -> SdkError {
    SdkError::InboundRejected(message.into())
}

impl RamfluxClient {
    /// Ensure the canonical direct conversation with an accepted contact exists.
    ///
    /// Returns the conversation id, or `None` when the contact is not an accepted, unblocked
    /// friend (pending, declined, blocked and revoked contacts never get a row). An existing row
    /// keeps its history and title. Runs in one transaction.
    ///
    /// # Errors
    /// Returns an error when the principal is not bound to the root, an existing row conflicts
    /// with the canonical kind or roots, or storage fails.
    pub(crate) fn ensure_direct_conversation(
        &self,
        peer_root: &str,
        peer_principal: &str,
    ) -> Result<Option<String>, SdkError> {
        let own = self.own_account_anchor()?;
        if peer_root == own || !self.friend_link_peer_is_accepted(peer_root)? {
            return Ok(None);
        }
        let db = self.account_db()?;
        let bound = db
            .client_record("identity", peer_principal)?
            .is_some_and(|row| row["contact_identity_commitment"] == peer_root);
        if !bound {
            return Err(invalid("direct conversation principal is not bound to the contact root"));
        }
        let local = self.direct_local_principal()?;
        let conversation =
            g::dm_scope::derive(&own, peer_root).map_err(|_| invalid("direct DM scope"))?;
        let roots = BTreeSet::from([own, peer_root.to_owned()]);
        db.write_transaction(|| -> Result<(), SdkError> {
            if let Some(old) = db.client_record("conversation", &conversation)? {
                let bound = old["participant_roots"].as_array().map(|values| {
                    values
                        .iter()
                        .filter_map(serde_json::Value::as_str)
                        .map(str::to_owned)
                        .collect::<BTreeSet<_>>()
                });
                if old["kind"] != "direct" || !old["group_id"].is_null() || bound != Some(roots) {
                    return Err(invalid("direct conversation conflicts with bound roots"));
                }
                return Ok(());
            }
            db.persist_client_record(
                "conversation",
                &conversation,
                &serde_json::json!({
                    "id": conversation, "kind": "direct", "group_id": null, "title": null,
                    "direct_route": null,
                    "participants": [local, peer_principal],
                    "participant_roots": roots,
                }),
            )?;
            Ok(())
        })?;
        Ok(Some(conversation))
    }

    fn direct_local_principal(&self) -> Result<String, SdkError> {
        if let Some(branch) = &self.device_branch {
            return Ok(branch.principal_id.clone());
        }
        let account = self.born_v3_account.as_ref().ok_or(SdkError::IdentityRootMissing)?;
        Ok(account.record().body.principal_id.clone())
    }

    /// Project the direct conversation for every already-accepted contact.
    ///
    /// Each contact is repaired independently: a failure warns and leaves that contact unchanged.
    /// Link enumeration errors are fatal because the remaining contacts cannot be listed.
    ///
    /// # Errors
    /// Returns an error when the friend links cannot be listed.
    pub(crate) fn backfill_direct_conversations(&self) -> Result<(), SdkError> {
        let own = self.own_account_anchor()?;
        let db = self.account_db()?;
        let mut after = String::new();
        loop {
            let page = db.friend_link_backfill_page(&after, BACKFILL_PAGE, false)?;
            let Some(last) = page.last() else { return Ok(()) };
            let next = last.link_id.clone();
            for link in &page {
                let Some(peer) = super::own_contact::contact_peer(link, &own) else { continue };
                let result = db
                    .load_actor_state::<crate::prekey::SdkDeviceManifestResponse>(&format!(
                        "identity/manifest-root/{peer}"
                    ))
                    .map_err(SdkError::from)
                    .and_then(|manifest| {
                        manifest.map_or(Ok(None), |manifest| {
                            self.ensure_direct_conversation(peer, &manifest.principal_id)
                        })
                    });
                if let Err(error) = result {
                    tracing::warn!(%error, "direct conversation backfill skipped one contact");
                }
            }
            after = next;
        }
    }
}

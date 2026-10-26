// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Root provenance, explicit provisional replacement, and stale-session retirement.
use crate::prelude::*;
use crate::{ContactReason, ContactRootChange, ContactRootSource};
use serde_json::{Value, json};
impl RamfluxClient {
    pub(crate) fn contact_own_commitment(&self) -> Result<String, SdkError> {
        let root = self.identity_root.as_ref().ok_or(SdkError::IdentityRootMissing)?;
        identity_root_public_key_commitment(&ramflux_protocol::encode_base64url(
            root.signing_key.verifying_key().to_bytes(),
        ))
    }

    pub(crate) fn decorate_contact_identity(
        &self,
        old: &Value,
        identity: &mut Value,
        card: Option<&crate::ContactCardBody>,
        replaced: bool,
    ) -> Result<(), SdkError> {
        if let Some(card) = card {
            for (field, value) in [
                ("display_name", json!(card.display_name)),
                ("kind_asserted", json!(card.kind_asserted)),
            ] {
                if identity["kind_verified"] != true {
                    identity[field] =
                        old.get(field).filter(|v| !v.is_null()).cloned().unwrap_or(value);
                }
            }
            identity["node"] = json!(card.node);
        }
        let source = if replaced || old["contact_identity_commitment"].is_null() {
            if card.is_some() { ContactRootSource::Card } else { ContactRootSource::Lookup }
        } else {
            let old_source = self.contact_root_source(old)?;
            if card.is_some() && old_source == ContactRootSource::Lookup {
                ContactRootSource::Card
            } else {
                old_source
            }
        };
        identity["root_source"] = json!(source);
        Ok(())
    }

    pub(crate) fn contact_root_source(
        &self,
        identity: &Value,
    ) -> Result<ContactRootSource, SdkError> {
        let db = self.account_db()?;
        if let Some(root) = identity["contact_identity_commitment"].as_str()
            && db
                .contact_verification(root)?
                .is_some_and(|v| matches!(v.verification_state.as_str(), "verified" | "changed"))
        {
            return Ok(ContactRootSource::Verified);
        }
        if let Some(source) = identity.get("root_source").filter(|v| !v.is_null()) {
            return serde_json::from_value(source.clone()).map_err(SdkError::from);
        }
        // Prior card imports always retained their signed home-node locator. Unknown older
        // anchors remain immutable; only explicit lookup provenance is migrated as provisional.
        if identity.get("node").is_some_and(|node| !node.is_null()) {
            return Ok(ContactRootSource::Card);
        }
        if let Some(devices) = identity["devices"].as_array() {
            for device in devices {
                if let Some(id) = device["device_id"].as_str()
                    && self.account_db()?.device_directory_entry(id)?.is_some_and(|record| {
                        matches!(record.source.as_str(), "contact_lookup" | "contact.safety_number")
                    })
                {
                    return Ok(ContactRootSource::Lookup);
                }
            }
        }
        Ok(ContactRootSource::Card)
    }
    pub(crate) fn contact_replacement(
        &self,
        identity: &Value,
        principal: &str,
        new_root: &str,
        confirmed: Option<&str>,
    ) -> Result<Option<ContactRootChange>, SdkError> {
        let Some(old_root) = identity["contact_identity_commitment"].as_str() else {
            if confirmed.is_some() {
                return Err(ContactReason::RootConflict.into());
            }
            return Ok(None);
        };
        if old_root == new_root {
            if confirmed.is_some_and(|root| root != old_root) {
                return Err(ContactReason::RootConflict.into());
            }
            return Ok(None);
        }
        if self.contact_root_source(identity)? != ContactRootSource::Lookup {
            return Err(ContactReason::RootConflict.into());
        }
        let change = ContactRootChange {
            principal_id: principal.into(),
            previous_root_commitment: old_root.into(),
            proposed_root_commitment: new_root.into(),
        };
        match confirmed {
            None => Err(SdkError::ContactConfirmationRequired(Box::new(change))),
            Some(root) if root != old_root => Err(ContactReason::RootConflict.into()),
            Some(_) => Ok(Some(change)),
        }
    }
    pub(crate) fn clear_provisional_contact(
        &self,
        old: &Value,
        change: &ContactRootChange,
        own_root: &str,
    ) -> Result<(), SdkError> {
        let db = self.account_db()?;
        if let Some(devices) = old["devices"].as_array() {
            for device in devices {
                let Some(id) = device["device_id"].as_str() else { continue };
                let identity =
                    self.device_identity_for_root(&change.previous_root_commitment, id)?;
                if let Some(record) = db.client_record("device", identity.storage_key())?
                    && record["principal_commitment"].as_str()
                        == Some(&change.previous_root_commitment)
                {
                    self.remove_device_pair(&identity, "provisional_root_replaced")?;
                    db.remove_actor_state(&format!("directory/device/{}", identity.storage_key()))?;
                    db.remove_device_directory_root(&identity)?;
                }
            }
        }
        db.remove_actor_state(&format!("directory/identity/{}", change.principal_id))?;
        db.remove_actor_state(&format!(
            "directory/commitment/{}",
            change.previous_root_commitment
        ))?;
        let own = &self.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?.principal_id;
        db.replace_contact_link_root(
            own,
            own_root,
            &change.previous_root_commitment,
            &change.proposed_root_commitment,
        )?;
        let id = ramflux_protocol::hash_base64url(
            "ramflux.contact.root-change.v1",
            &ramflux_protocol::canonical_json_bytes(change)?,
        );
        db.append_journal(&format!("contact-root-change:{id}"),"safety.changed",&json!({"principal_id":change.principal_id,"reason":"provisional_root_replaced","previous_root_commitment":change.previous_root_commitment,"root_commitment":change.proposed_root_commitment}),now_unix_timestamp(),Some(&change.principal_id))?;
        Ok(())
    }
}
pub(crate) fn contact_link_id(left: &str, right: &str) -> Result<String, SdkError> {
    let pair = if left <= right { (left, right) } else { (right, left) };
    Ok(format!(
        "contact:{}",
        ramflux_protocol::hash_hex(
            "ramflux.contact.link.v2",
            &ramflux_protocol::canonical_json_bytes(&pair)?
        )
    ))
}

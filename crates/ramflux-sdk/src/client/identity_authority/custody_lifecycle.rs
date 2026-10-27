// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Native denial and key-change retirement precedes optional directory prekey material.
use crate::{RamfluxClient, SdkError};
use ramflux_crypto::{RootQualifiedDeviceRef, custody::VerifiedRecord};
use ramflux_protocol::custody::Device;
use serde_json::{Value, json};
use std::collections::BTreeSet;

impl RamfluxClient {
    pub(super) fn apply_custody_retirements(
        &self,
        current: &VerifiedRecord,
        previous_devices: &[String],
    ) -> Result<(), SdkError> {
        let body = &current.envelope().body;
        let names = previous_devices
            .iter()
            .map(String::as_str)
            .chain(body.devices.iter().map(|entry| entry.device_id.as_str()))
            .collect::<BTreeSet<_>>();
        let db = self.account_db()?;
        for name in names {
            let identity = RootQualifiedDeviceRef::from_custody_record(current, name)?;
            let old = db.client_record("device", identity.storage_key())?;
            let revoked = current.revoked_ids().contains(name);
            let changed = body
                .devices
                .iter()
                .find(|entry| entry.device_id == name)
                .is_some_and(|entry| old.as_ref().is_some_and(|row| keys_differ(row, entry)));
            let messaging_removed =
                body.devices.iter().find(|entry| entry.device_id == name).is_some_and(|entry| {
                    entry.branch_certificate.as_ref().is_none_or(|certificate| {
                        !certificate.body.capabilities.iter().any(|scope| scope == "message")
                    })
                });
            if revoked || changed || messaging_removed {
                let reason = if revoked {
                    "native_device_revoked"
                } else if changed {
                    "native_device_key_changed"
                } else {
                    "native_message_capability_removed"
                };
                let already_revoked = db
                    .load_actor_state::<bool>(&Self::device_revocation_key(&identity))?
                    .unwrap_or(false);
                // Retained denial pins do not make restored private state safe to keep.
                let retired =
                    db.retire_device_pairs(&identity, crate::time::now_unix_timestamp(), reason)?;
                if !already_revoked || retired > 0 {
                    db.append_journal(&format!("native-device-retired:{}:{}",identity.storage_key(),body.device_set_epoch),
                        "session.reset", &json!({"device_id":identity.storage_key(),"reason":reason,"retired_sessions":retired}),
                        crate::time::now_unix_timestamp(), None)?;
                }
                if revoked {
                    db.persist_actor_state(&Self::device_revocation_key(&identity), &true)?;
                    let mut row = old.unwrap_or_else(||json!({"device_id":name,"principal_id":body.principal_id,"principal_commitment":body.account_anchor}));
                    row["revoked"] = json!(true);
                    row["authority_epoch"] = json!(body.device_set_epoch);
                    row["custody_v3_observed"] = json!(true);
                    db.persist_client_record("device", identity.storage_key(), &row)?;
                }
            }
        }
        self.refresh_existing_custody_stamp(current)
    }

    fn refresh_existing_custody_stamp(&self, current: &VerifiedRecord) -> Result<(), SdkError> {
        let body = &current.envelope().body;
        let db = self.account_db()?;
        let Some(mut row) = db.client_record("identity", &body.principal_id)? else {
            return Ok(());
        };
        if row["contact_identity_commitment"] != body.account_anchor {
            return Ok(());
        }
        let hash = super::custody_directory::native_fingerprint(current)?;
        let previous = row["device_set_hash"].as_str();
        if previous.is_some_and(|old| old != hash) {
            db.append_journal(&format!("identity-safety:{}:{}",body.account_anchor,body.device_set_epoch), "safety.changed",
                &json!({"principal_id":body.principal_id,"device_set_epoch":body.device_set_epoch,"reason":"native_device_authority_changed"}),
                crate::time::now_unix_timestamp(), None)?;
        }
        row["device_set_hash"] = json!(hash);
        row["device_set_epoch"] = json!(body.device_set_epoch);
        db.persist_client_record("identity", &body.principal_id, &row)?;
        Ok(())
    }
}

fn keys_differ(row: &Value, entry: &Device) -> bool {
    let signing = row["signing_public_key"]
        .as_str()
        .and_then(|key| ramflux_protocol::decode_base64url(key).ok());
    let agreement = serde_json::from_value::<[u8; 32]>(row["x25519_identity_public"].clone()).ok();
    signing.is_none_or(|key| {
        ramflux_crypto::blake3_256_base64url(
            ramflux_protocol::domain::DEVICE_SIGNING_KEY_COMMITMENT,
            &key,
        ) != entry.signing_key_commitment
    }) || agreement.is_none_or(|key| {
        ramflux_crypto::blake3_256_base64url(
            ramflux_protocol::domain::DEVICE_AGREEMENT_KEY_COMMITMENT,
            &key,
        ) != entry.agreement_key_commitment
    })
}

// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Atomic highest-record persistence, root-authorized rotation and peer retirement.
use super::{invalid, record_key, verify_manifest};
use crate::{RamfluxClient, SdkError, prekey::SdkDeviceManifestResponse};
use ramflux_protocol::{DeviceSetStatus, SignedDeviceSetRecord};
use serde_json::{Value, json};
impl RamfluxClient {
    pub(crate) fn persist_root_verified_directory(
        &self,
        manifest: &SdkDeviceManifestResponse,
    ) -> Result<(), SdkError> {
        verify_manifest(manifest, &manifest.principal_commitment)?;
        let db = self.account_db()?;
        let record =
            manifest.signed_device_set.as_ref().ok_or_else(|| invalid("missing signed set"))?;
        // Preserve the existing bounded pinned-owner safety observation, even for ownership
        // conflicts, but only after the new record and its exact keys authenticate.
        db.write_transaction(|| self.record_pinned_group_key_changes(manifest))?;
        db.write_transaction(|| {
            self.check_observed_set(record)?;
            self.check_directory_ownership(manifest)?;
            db.persist_actor_state(&record_key(&record.principal_commitment), record)?;
            if db.client_record("identity",&record.principal_id)?.is_none() {db.persist_client_record("identity",&record.principal_id,&json!({"principal_id":record.principal_id,"contact_identity_commitment":record.principal_commitment}))?;}
            self.apply_record_retirements(record)?;
            self.write_directory_metadata(manifest)?;
            db.persist_actor_state(
                &format!("identity/manifest/{}", manifest.principal_id),
                manifest,
            )?;
            Ok::<_, SdkError>(())
        })?;
        self.finish_pair_retirement()
    }
    pub(crate) fn check_observed_set(&self, next: &SignedDeviceSetRecord) -> Result<(), SdkError> {
        if let Some(old) = self
            .account_db()?
            .load_actor_state::<SignedDeviceSetRecord>(&record_key(&next.principal_commitment))?
        {
            ramflux_crypto::validate_device_set_transition(&old, next)?;
        }
        Ok(())
    }
    fn check_directory_ownership(
        &self,
        manifest: &SdkDeviceManifestResponse,
    ) -> Result<(), SdkError> {
        let db = self.account_db()?;
        if db.client_record("identity", &manifest.principal_id)?.is_some_and(|old| {
            old["contact_identity_commitment"]
                .as_str()
                .is_some_and(|c| c != manifest.principal_commitment)
        }) {
            return Err(invalid("principal root changed"));
        }
        for entry in
            &manifest.signed_device_set.as_ref().ok_or_else(|| invalid("set absent"))?.devices
        {
            if let Some(old) = db.client_record("device", &entry.device_id)? {
                if old["principal_commitment"]
                    .as_str()
                    .is_some_and(|c| c != manifest.principal_commitment)
                    || old["principal_id"].as_str().is_some_and(|p| p != manifest.principal_id)
                {
                    return Err(invalid("device owner changed"));
                }
            }
        }
        Ok(())
    }
    pub(super) fn apply_record_retirements(
        &self,
        record: &SignedDeviceSetRecord,
    ) -> Result<(), SdkError> {
        let db = self.account_db()?;
        for entry in &record.devices {
            let old = db.client_record("device", &entry.device_id)?;
            if entry.status == DeviceSetStatus::Revoked {
                self.apply_verified_device_revocation(&entry.device_id, &record.principal_id)?;
                let mut row=old.unwrap_or_else(||json!({"principal_id":record.principal_id,"principal_commitment":record.principal_commitment}));
                row["revoked"] = json!(true);
                db.persist_client_record("device", &entry.device_id, &row)?;
            } else if old.as_ref().is_some_and(|old| old.get("signing_public_key").is_some()) {
                let old = old.ok_or_else(|| invalid("device disappeared"))?;
                let signing =
                    old["signing_public_key"].as_str().ok_or_else(|| invalid("old key missing"))?;
                let agreement = old
                    .get("x25519_identity_public")
                    .cloned()
                    .map(serde_json::from_value::<[u8; 32]>)
                    .transpose()?;
                let changed = ramflux_crypto::blake3_256_base64url(
                    ramflux_protocol::domain::DEVICE_SIGNING_KEY_COMMITMENT,
                    &ramflux_protocol::decode_base64url(signing)
                        .map_err(|_| invalid("old signing key invalid"))?,
                ) != entry.signing_key_commitment
                    || agreement.is_some_and(|key| {
                        ramflux_crypto::blake3_256_base64url(
                            ramflux_protocol::domain::DEVICE_AGREEMENT_KEY_COMMITMENT,
                            &key,
                        ) != entry.agreement_key_commitment
                    });
                if changed {
                    self.remove_device_pair(&entry.device_id, "root_authorized_key_rotation")?;
                }
            }
        }
        Ok(())
    }
    fn write_directory_metadata(
        &self,
        manifest: &SdkDeviceManifestResponse,
    ) -> Result<(), SdkError> {
        let db = self.account_db()?;
        let record = manifest.signed_device_set.as_ref().ok_or_else(|| invalid("set absent"))?;
        let old = db.client_record("identity", &manifest.principal_id)?.unwrap_or(Value::Null);
        let material = crate::client::contact::contact_safety_material_from_manifest(manifest)?;
        let hash =
            ramflux_protocol::encode_base64url(ramflux_crypto::device_set_hash(&material.devices));
        let changed = old["device_set_hash"].as_str().is_some_and(|old| old != hash);
        let devices=manifest.devices.iter().map(|d|json!({"id":d.device_id,"device_id":d.device_id,"target_delivery_id":d.target_delivery_id,"signing_public_key":d.branch_public_key,"device_epoch":d.device_epoch})).collect::<Vec<_>>();
        db.persist_client_record("identity",&manifest.principal_id,&json!({"id":manifest.principal_id,"principal_id":manifest.principal_id,"display_name":old.get("display_name"),"kind":record.principal_kind,"kind_verified":true,"device_set_epoch":record.device_set_epoch,"is_self":self.device_branch.as_ref().is_some_and(|b|b.principal_id==manifest.principal_id),"contact_identity_commitment":manifest.principal_commitment,"devices":devices,"device_set_hash":hash,"safety_number":if changed {Value::Null} else {old["safety_number"].clone()}}))?;
        db.persist_client_record(
            "commitment",
            &manifest.principal_commitment,
            &json!({"principal_id":manifest.principal_id}),
        )?;
        for device in &manifest.devices {
            self.rotate_verified_group_pins(manifest, device)?;
            db.persist_client_record("device",&device.device_id,&json!({"principal_id":manifest.principal_id,"principal_commitment":manifest.principal_commitment,"signing_public_key":device.branch_public_key,"x25519_identity_public":device.prekey_bundle.identity_key,"target_delivery_id":device.target_delivery_id,"device_epoch":device.device_epoch,"revoked":false,"authority_epoch":record.device_set_epoch}))?;
        }
        if changed {
            db.append_journal(&format!("identity-safety:{}:{}",manifest.principal_commitment,record.device_set_epoch),"safety.changed",&json!({"principal_id":manifest.principal_id,"device_set_epoch":record.device_set_epoch,"reason":"root_signed_device_set_changed"}),crate::prelude::now_unix_timestamp(),None)?;
        }
        Ok(())
    }
    fn rotate_verified_group_pins(
        &self,
        manifest: &SdkDeviceManifestResponse,
        device: &crate::prekey::SdkDeviceManifestEntry,
    ) -> Result<(), SdkError> {
        let db = self.account_db()?;
        let old = db.client_record("device", &device.device_id)?;
        for (group, pin) in db.pinned_group_device_keys(&device.device_id)? {
            if pin == device.branch_public_key {
                db.bind_group_member_key_identity(
                    &group,
                    &device.device_id,
                    &manifest.principal_id,
                    &manifest.principal_commitment,
                    &pin,
                )?;
                continue;
            }
            let bound = db
                .group_member_key_binding(&group, &device.device_id)?
                .ok_or_else(|| invalid("pin absent"))?;
            if bound.principal_id.is_none() {
                let old = old.as_ref().ok_or_else(|| invalid("legacy pin owner is unverified"))?;
                if old["signing_public_key"] != pin
                    || old["principal_commitment"] != manifest.principal_commitment
                {
                    return Err(invalid("legacy pin owner is unverified"));
                }
                db.bind_group_member_key_identity(
                    &group,
                    &device.device_id,
                    &manifest.principal_id,
                    &manifest.principal_commitment,
                    &pin,
                )?;
            }
            db.rotate_root_authorized_group_device_key(
                &group,
                &device.device_id,
                &manifest.principal_id,
                &manifest.principal_commitment,
                &pin,
                &device.branch_public_key,
            )?;
        }
        Ok(())
    }
}

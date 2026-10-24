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
        super::verify::verify_manifest_authority(manifest, &manifest.principal_commitment)?;
        let material = verify_manifest(manifest, &manifest.principal_commitment);
        let db = self.account_db()?;
        let record =
            manifest.signed_device_set.as_ref().ok_or_else(|| invalid("missing signed set"))?;
        // Preserve the existing bounded pinned-owner safety observation, even for ownership
        // conflicts, but only after the new record and its exact keys authenticate.
        if material.is_ok() {
            db.write_transaction(|| self.record_pinned_group_key_changes(manifest))?;
        }
        if let Err(error) =
            self.check_observed_set(record).and_then(|()| self.check_directory_ownership(manifest))
        {
            self.record_authority_rejection(record)?;
            return Err(error);
        }
        let previous = self.observed_device_set(&record.principal_commitment)?;
        let authority_changed = previous.as_ref().is_some_and(|r| r.devices != record.devices);
        db.write_transaction(|| {
            self.check_observed_set(record)?;
            self.check_directory_ownership(manifest)?;
            db.persist_actor_state(&record_key(&record.principal_commitment), record)?;
            if db.client_record("identity",&record.principal_id)?.is_none() {db.persist_client_record("identity",&record.principal_id,&json!({"principal_id":record.principal_id,"contact_identity_commitment":record.principal_commitment}))?;}
            self.apply_record_retirements(record)?;
            Ok::<_, SdkError>(())
        })?;
        self.finish_pair_retirement()?;
        material?;
        db.write_transaction(|| {
            self.write_directory_metadata(manifest, authority_changed)?;
            db.persist_actor_state(
                &format!("identity/manifest/{}", manifest.principal_id),
                manifest,
            )?;
            db.persist_actor_state(
                &format!("identity/manifest-root/{}", manifest.principal_commitment),
                manifest,
            )?;

            Ok::<_, SdkError>(())
        })?;
        self.finish_pair_retirement()
    }
    fn record_authority_rejection(&self, record: &SignedDeviceSetRecord) -> Result<(), SdkError> {
        let known = self.observed_device_set(&record.principal_commitment)?.is_some()
            || self.account_db()?.client_record("identity", &record.principal_id)?.is_some();
        if !known {
            return Ok(());
        } // Existing bounded group-owner observations cover unknown claimants.
        let key = ramflux_protocol::hash_base64url(
            "ramflux.sdk.authority_rejection.v1",
            record.principal_id.as_bytes(),
        );
        self.account_db()?.persist_actor_state(&format!("identity/rejected_set/{key}"), record)?;
        self.account_db()?.append_journal(&format!("identity-authority-rejected:{key}"),"safety.changed",&json!({"principal_id":record.principal_id,"principal_commitment":record.principal_commitment,"device_set_epoch":record.device_set_epoch,"reason":"root_authority_rollback_equivocation_or_owner_conflict"}),crate::prelude::now_unix_timestamp(),None)?;
        Ok(())
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
        Ok(())
    }
    pub(super) fn apply_record_retirements(
        &self,
        record: &SignedDeviceSetRecord,
    ) -> Result<(), SdkError> {
        let db = self.account_db()?;
        for entry in &record.devices {
            let reference = ramflux_protocol::qualified_device_id(
                &record.principal_commitment,
                &entry.device_id,
            )?;
            let old = db.client_record("device", &reference)?;
            if entry.status == DeviceSetStatus::Revoked {
                self.apply_verified_device_revocation(&reference, &record.principal_id)?;
                let mut row=old.unwrap_or_else(||json!({"device_id":entry.device_id,"principal_id":record.principal_id,"principal_commitment":record.principal_commitment}));
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
                    if let Some(local) = &self.device_branch
                        && local.device_id == entry.device_id
                        && self.identity_root.as_ref().is_some_and(|root| {
                            ramflux_crypto::identity_root_commitment(
                                &root.signing_key.verifying_key(),
                            ) == record.principal_commitment
                        })
                    {
                        for peer in db.pair_peer_devices(&self.owned_device_identity()?)? {
                            self.remove_device_pair(
                                &self.device_identity(&peer)?,
                                "root_authorized_local_key_rotation",
                            )?;
                        }
                    } else {
                        self.remove_device_pair(
                            &self.device_identity(&reference)?,
                            "root_authorized_key_rotation",
                        )?;
                    }
                }
            }
        }
        Ok(())
    }
    fn write_directory_metadata(
        &self,
        manifest: &SdkDeviceManifestResponse,
        authority_changed: bool,
    ) -> Result<(), SdkError> {
        let db = self.account_db()?;
        let record = manifest.signed_device_set.as_ref().ok_or_else(|| invalid("set absent"))?;
        let old = db.client_record("identity", &manifest.principal_id)?.unwrap_or(Value::Null);
        let material = crate::client::contact::contact_safety_material_from_manifest(manifest)?;
        let hash =
            ramflux_protocol::encode_base64url(ramflux_crypto::device_set_hash(&material.devices));
        let changed =
            authority_changed || old["device_set_hash"].as_str().is_some_and(|old| old != hash);
        let devices=manifest.devices.iter().map(|d|json!({"id":d.device_id,"device_id":d.device_id,"target_delivery_id":d.target_delivery_id,"signing_public_key":d.branch_public_key,"device_epoch":d.device_epoch})).collect::<Vec<_>>();
        db.persist_client_record("identity",&manifest.principal_id,&json!({"id":manifest.principal_id,"principal_id":manifest.principal_id,"display_name":old.get("display_name"),"kind":record.principal_kind,"kind_asserted":true,"kind_verified":false,"device_set_epoch":record.device_set_epoch,"is_self":self.device_branch.as_ref().is_some_and(|b|b.principal_id==manifest.principal_id),"contact_identity_commitment":manifest.principal_commitment,"devices":devices,"device_set_hash":hash,"safety_number":if changed {Value::Null} else {old["safety_number"].clone()}}))?;
        db.persist_client_record(
            "commitment",
            &manifest.principal_commitment,
            &json!({"principal_id":manifest.principal_id}),
        )?;
        for device in &manifest.devices {
            self.rotate_verified_group_pins(manifest, device)?;
            db.persist_client_record("device",&device.device_id,&json!({"device_id":device.device_id,"principal_id":manifest.principal_id,"principal_commitment":manifest.principal_commitment,"signing_public_key":device.branch_public_key,"x25519_identity_public":device.prekey_bundle.identity_key,"target_delivery_id":device.target_delivery_id,"device_epoch":device.device_epoch,"revoked":false,"authority_epoch":record.device_set_epoch,"proof_expires_at":device.branch_proof.expires_at}))?;
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
        let identity = Self::device_identity_from_manifest(manifest, &device.device_id)?;
        let reference = identity.storage_key();
        let old = db.client_record("device", reference)?;
        for (group, pin) in db.pinned_group_device_keys(&identity)? {
            if pin == device.branch_public_key {
                db.bind_group_member_key_identity(
                    &group,
                    &identity,
                    &manifest.principal_id,
                    &manifest.principal_commitment,
                    &pin,
                )?;
                continue;
            }
            let bound = db
                .group_member_key_binding(&group, &identity)?
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
                    &identity,
                    &manifest.principal_id,
                    &manifest.principal_commitment,
                    &pin,
                )?;
            }
            db.rotate_root_authorized_group_device_key(
                ramflux_storage::RootAuthorizedGroupKeyRotation {
                    group_id: &group,
                    device_id: &identity,
                    principal_id: &manifest.principal_id,
                    principal_commitment: &manifest.principal_commitment,
                    previous_key: &pin,
                    next_key: &device.branch_public_key,
                },
            )?;
        }
        Ok(())
    }
}

// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Verified v3 directory state for the ordinary account database and feature paths.
use super::invalid;
use crate::{RamfluxClient, SdkError};
use ramflux_crypto::{
    RootQualifiedDeviceRef,
    custody::{AuthorityPins, PinOutcome, VerifiedRecord},
};
use ramflux_protocol::custody::{CustodyManifest, DeviceRef, Publication};
use serde::{Deserialize, Serialize};
use serde_json::json;

#[derive(Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RetainedAuthority {
    pins: AuthorityPins,
    publication: Option<Publication>,
    custodian: Option<Publication>,
}
fn key(anchor: &str) -> Result<String, SdkError> {
    let bytes = ramflux_protocol::decode_base64url(anchor)
        .map_err(|_| invalid("invalid custody anchor encoding"))?;
    if bytes.len() != 32 || ramflux_protocol::encode_base64url(bytes) != anchor {
        return Err(invalid("invalid custody account anchor"));
    }
    Ok(format!("identity/custody/{anchor}"))
}
impl RamfluxClient {
    /// Authenticate complete v3 authority and branch prekeys before recording directory facts.
    /// # Errors
    /// Rejects malformed evidence, wrong roots/keys, rollback, equivocation and storage errors.
    pub fn observe_custody_manifest(
        &self,
        manifest: &CustodyManifest,
        expected: &str,
        now: u64,
    ) -> Result<(), SdkError> {
        let verified = verify_native_authority(manifest, expected, now)?;
        if let Some(human) = &manifest.custodian_publication {
            self.observe_custody_manifest(
                &CustodyManifest {
                    publication: human.clone(),
                    custodian_publication: None,
                    devices: Vec::new(),
                },
                &human.record.body.account_anchor,
                now,
            )?;
        }
        let db = self.account_db()?;
        let state_key = key(expected)?;
        // Persist a detected fence even though the caller receives a refusal.
        let outcome = db.write_transaction(|| -> Result<PinOutcome, SdkError> {
            let mut state =
                db.load_actor_state::<RetainedAuthority>(&state_key)?.unwrap_or_default();
            let outcome = state.pins.observe(&verified)?;
            if outcome == PinOutcome::Advanced {
                state.publication = Some(manifest.publication.clone());
                state.custodian.clone_from(&manifest.custodian_publication);
            }
            db.persist_actor_state(&state_key, &state)?;
            Ok(outcome)
        })?;
        if outcome == PinOutcome::Fenced {
            return Err(invalid("custody authority equivocation fenced"));
        }
        self.current_custody_authority(expected, now)?
            .ok_or_else(|| invalid("custody authority absent"))?;
        verify_native_material(manifest, expected, now)?;
        db.write_transaction(|| -> Result<(), SdkError> {
            let current = db.load_actor_state::<RetainedAuthority>(&state_key)?
                .ok_or_else(|| invalid("custody authority absent"))?;
            current.pins.require_current(&verified)?;
            let body = &verified.envelope().body;
            let old = db.client_record("identity", &body.principal_id)?;
            if old.as_ref().and_then(|row| row["contact_identity_commitment"].as_str())
                .is_some_and(|anchor| anchor != expected)
            { return Err(invalid("principal root changed")); }
            let previous_name = old.as_ref().and_then(|row| row["display_name"].as_str()).map(str::to_owned);
            let previous_fingerprint = old.as_ref().and_then(|row| row["device_set_hash"].as_str()).map(str::to_owned);
            let fingerprint = native_fingerprint(&verified)?;
            let mut row = old.unwrap_or_else(|| json!({"id":body.principal_id,"principal_id":body.principal_id}));
            row["contact_identity_commitment"] = json!(expected);
            row["root_public_key"] = json!(body.master_certificate.body.master_public_key);
            row["device_set_epoch"] = json!(body.device_set_epoch);
            row["device_set_hash"] = json!(fingerprint);
            row["principal_kind"] = json!(body.principal_kind);
            row["public_display_name"] = json!(body.profile.display_name);
            row["custody_v3_observed"] = json!(true);
            row["kind"] = json!(body.principal_kind);
            row["kind_asserted"] = json!(body.principal_kind);
            row["kind_verified"] = json!(true);
            row["display_name"] = json!(body.profile.display_name);
            row["is_self"] = json!(self.born_v3_account.as_ref().is_some_and(|account| account.record().body.account_anchor == expected));
            row["devices"] = json!(manifest.devices.iter().map(|device| {
                let cert = verified.authorize(&device.device_ref, "message", now)?;
                Ok(json!({"id":device.device_ref.device_id,"device_id":device.device_ref.device_id,"device_epoch":device.device_ref.device_epoch,"target_delivery_id":device.target_delivery_id,"signing_public_key":cert.branch_signing_public_key}))
            }).collect::<Result<Vec<_>, SdkError>>()?);
            if previous_name.as_deref().is_some_and(|name| name != body.profile.display_name) {
                db.append_journal(&format!("identity-public-name:{expected}:{}", body.device_set_epoch), "contact.changed",
                    &json!({"principal_id":body.principal_id,"reason":"public_profile_renamed","old_display_name":previous_name,"new_display_name":body.profile.display_name}),
                    crate::time::now_unix_timestamp(), None)?;
            }
            if previous_fingerprint.as_ref().is_some_and(|old| old != &fingerprint) {
                db.append_journal(&format!("identity-safety:{expected}:{}", body.device_set_epoch), "safety.changed",
                    &json!({"principal_id":body.principal_id,"device_set_epoch":body.device_set_epoch,"reason":"native_device_authority_changed"}),
                    crate::time::now_unix_timestamp(), None)?;
            }
            db.persist_client_record("commitment", expected, &json!({"principal_id":body.principal_id}))?;
            db.persist_client_record("identity", &body.principal_id, &row)?;
            for device in &manifest.devices {
                let cert = verified.authorize(&device.device_ref, "message", now)?;
                let identity = RootQualifiedDeviceRef::from_custody_record(&verified, &device.device_ref.device_id)?;
                let agreement = ramflux_protocol::decode_base64url(&cert.agreement_identity_public_key).map_err(|_| invalid("invalid custody agreement encoding"))?;
                db.persist_client_record("device", identity.storage_key(), &json!({
                    "device_id": device.device_ref.device_id, "device_epoch": device.device_ref.device_epoch,
                    "principal_id": verified.envelope().body.principal_id, "principal_commitment": expected,
                    "signing_public_key": cert.branch_signing_public_key,
                    "x25519_identity_public": agreement, "target_delivery_id": device.target_delivery_id,
                    "custody_v3_observed": true, "revoked": false, "authority_epoch": body.device_set_epoch,
                }))?;
            }
            Ok(())
        })
    }

    pub(super) fn custody_mode_observed(&self, anchor: &str) -> Result<bool, SdkError> {
        Ok(self
            .born_v3_account
            .as_ref()
            .is_some_and(|account| account.record().body.account_anchor == anchor)
            || self.account_db()?.actor_state_exists(&key(anchor)?)?)
    }

    pub(crate) fn current_custody_authority(
        &self,
        anchor: &str,
        now: u64,
    ) -> Result<Option<VerifiedRecord>, SdkError> {
        self.load_current_custody_authority(anchor, now, true)
    }

    fn load_current_custody_authority(
        &self,
        anchor: &str,
        now: u64,
        allow_external: bool,
    ) -> Result<Option<VerifiedRecord>, SdkError> {
        let Some(state) =
            self.account_db()?.load_actor_state::<RetainedAuthority>(&key(anchor)?)?
        else {
            return Ok(None);
        };
        let publication =
            state.publication.as_ref().ok_or_else(|| invalid("custody publication absent"))?;
        if publication.record.body.account_anchor != anchor {
            return Err(invalid("custody cache namespace mismatch"));
        }
        let master = &publication.record.body.master_certificate.body;
        let human = if master.custody_kind == ramflux_protocol::custody::CustodyKind::ExternalHuman
        {
            if !allow_external {
                return Err(invalid("human custodian cannot be externally chained"));
            }
            Some(
                self.load_current_custody_authority(
                    &master.primary_device_ref.account_anchor,
                    now,
                    false,
                )?
                .ok_or_else(|| invalid("current human custodian authority absent"))?,
            )
        } else {
            None
        };
        let verified = ramflux_crypto::custody::verify_record(
            &publication.record,
            now,
            publication.compacted_ids.as_deref(),
            human.as_ref(),
        )?;
        state.pins.require_current(&verified)?;
        Ok(Some(verified))
    }

    pub(super) fn require_custody_device(
        &self,
        identity: &RootQualifiedDeviceRef,
        now: u64,
    ) -> Result<bool, SdkError> {
        let Some(verified) = self.current_custody_authority(identity.root_commitment(), now)?
        else {
            return Ok(false);
        };
        let row = self
            .account_db()?
            .client_record("device", identity.storage_key())?
            .ok_or_else(|| invalid("custody device metadata absent"))?;
        let reference = DeviceRef {
            account_anchor: identity.root_commitment().into(),
            device_id: identity.device_id().into(),
            device_epoch: row["device_epoch"]
                .as_u64()
                .ok_or_else(|| invalid("custody device epoch absent"))?,
        };
        let cert = verified.authorize(&reference, "message", now)?;
        let agreement: Vec<u8> = serde_json::from_value(row["x25519_identity_public"].clone())?;
        if row["custody_v3_observed"] != true
            || row["target_delivery_id"] != identity.storage_key()
            || row["principal_id"] != verified.envelope().body.principal_id
            || row["principal_commitment"] != reference.account_anchor
            || row["signing_public_key"] != cert.branch_signing_public_key
            || ramflux_protocol::encode_base64url(agreement) != cert.agreement_identity_public_key
        {
            return Err(invalid("custody directory differs from signed authority"));
        }
        Ok(true)
    }
}

pub(super) fn verify_native_authority(
    manifest: &CustodyManifest,
    expected: &str,
    now: u64,
) -> Result<VerifiedRecord, SdkError> {
    if manifest.devices.len() > ramflux_protocol::custody::MAX_ROSTER
        || ramflux_protocol::canonical_json_bytes(manifest)?.len() > 5 * 1024 * 1024
        || manifest.publication.record.body.account_anchor != expected
    {
        return Err(invalid("custody manifest root or budget mismatch"));
    }
    crate::custody::verify_public_authority(
        &manifest.publication,
        manifest.custodian_publication.as_ref(),
        now,
    )
}
pub(super) fn verify_native_material(
    manifest: &CustodyManifest,
    expected: &str,
    now: u64,
) -> Result<(), SdkError> {
    let verified = verify_native_authority(manifest, expected, now)?;
    let mut seen = std::collections::BTreeSet::new();
    for device in &manifest.devices {
        let identity =
            RootQualifiedDeviceRef::from_custody_record(&verified, &device.device_ref.device_id)?;
        let cert = verified.authorize(&device.device_ref, "message", now)?;
        let bundle: ramflux_crypto::PrekeyBundle = ramflux_protocol::custody::decode(
            &ramflux_protocol::canonical_json_bytes(&device.prekey_bundle)?,
            64 * 1024,
        )?;
        if !seen.insert(identity.storage_key().to_owned())
            || bundle.device_id != device.device_ref.device_id
            || bundle.device_epoch != device.device_ref.device_epoch
            || bundle.identity_commitment != verified.envelope().body.principal_id
            || bundle.device_identity_ed25519_public != cert.branch_signing_public_key
            || ramflux_protocol::encode_base64url(bundle.identity_key)
                != cert.agreement_identity_public_key
            || bundle.device_agreement_x25519_public != bundle.identity_key
            || device.target_delivery_id
                != ramflux_protocol::qualified_device_id(expected, &device.device_ref.device_id)?
        {
            return Err(invalid("custody prekey or delivery binding mismatch"));
        }
        ramflux_crypto::verify_prekey_bundle(
            &ramflux_crypto::verifying_key_from_base64url(&cert.branch_signing_public_key)?,
            &bundle,
        )?;
    }
    Ok(())
}

pub(crate) fn native_fingerprint(authority: &VerifiedRecord) -> Result<String, SdkError> {
    let body = &authority.envelope().body;
    let devices: Vec<_> = body
        .devices
        .iter()
        .map(|entry| {
            (
                &entry.device_id,
                entry.device_epoch,
                &entry.signing_key_commitment,
                &entry.agreement_key_commitment,
                entry.status,
                entry.branch_certificate.as_ref().map(|certificate| &certificate.body.capabilities),
            )
        })
        .collect();
    Ok(ramflux_protocol::hash_base64url(
        "ramflux.sdk.verified_device_authority.v3",
        &ramflux_protocol::canonical_json_bytes(&(
            &body.account_anchor,
            body.principal_kind,
            ramflux_protocol::custody::object_hash(&body.master_certificate)?,
            devices,
            &body.delegations,
        ))?,
    ))
}

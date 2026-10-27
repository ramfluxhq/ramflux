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
        if manifest.devices.len() > ramflux_protocol::custody::MAX_ROSTER
            || ramflux_protocol::canonical_json_bytes(manifest)?.len() > 5 * 1024 * 1024
            || manifest.publication.record.body.account_anchor != expected
        {
            return Err(invalid("custody manifest root or budget mismatch"));
        }
        let verified = crate::custody::verify_public_authority(
            &manifest.publication,
            manifest.custodian_publication.as_ref(),
            now,
        )?;
        let mut seen = std::collections::BTreeSet::new();
        for device in &manifest.devices {
            let cert = verified.authorize(&device.device_ref, "message", now)?;
            let bundle: ramflux_crypto::PrekeyBundle = ramflux_protocol::custody::decode(
                &ramflux_protocol::canonical_json_bytes(&device.prekey_bundle)?,
                64 * 1024,
            )?;
            if !seen.insert(device.device_ref.device_id.clone())
                || bundle.device_id != device.device_ref.device_id
                || bundle.device_epoch != device.device_ref.device_epoch
                || bundle.identity_commitment != verified.envelope().body.principal_id
                || bundle.device_identity_ed25519_public != cert.branch_signing_public_key
                || ramflux_protocol::encode_base64url(bundle.identity_key)
                    != cert.agreement_identity_public_key
                || bundle.device_agreement_x25519_public != bundle.identity_key
                || device.target_delivery_id
                    != ramflux_protocol::qualified_device_id(
                        expected,
                        &device.device_ref.device_id,
                    )?
            {
                return Err(invalid("custody prekey or delivery binding mismatch"));
            }
            ramflux_crypto::verify_prekey_bundle(
                &ramflux_crypto::verifying_key_from_base64url(&cert.branch_signing_public_key)?,
                &bundle,
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
        db.write_transaction(|| -> Result<(), SdkError> {
            for device in &manifest.devices {
                let cert = verified.authorize(&device.device_ref, "message", now)?;
                let identity = RootQualifiedDeviceRef::from_custody_record(&verified, &device.device_ref.device_id)?;
                let agreement = ramflux_protocol::decode_base64url(&cert.agreement_identity_public_key).map_err(|_| invalid("invalid custody agreement encoding"))?;
                db.persist_client_record("device", identity.storage_key(), &json!({
                    "device_id": device.device_ref.device_id, "device_epoch": device.device_ref.device_epoch,
                    "principal_id": verified.envelope().body.principal_id, "principal_commitment": expected,
                    "signing_public_key": cert.branch_signing_public_key,
                    "x25519_identity_public": agreement, "target_delivery_id": device.target_delivery_id,
                    "custody_v3_observed": true,
                }))?;
            }
            Ok(())
        })
    }

    pub(crate) fn current_custody_authority(
        &self,
        anchor: &str,
        now: u64,
    ) -> Result<Option<VerifiedRecord>, SdkError> {
        let Some(state) =
            self.account_db()?.load_actor_state::<RetainedAuthority>(&key(anchor)?)?
        else {
            return Ok(None);
        };
        let publication =
            state.publication.as_ref().ok_or_else(|| invalid("custody publication absent"))?;
        let verified =
            crate::custody::verify_public_authority(publication, state.custodian.as_ref(), now)?;
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
        if row["principal_id"] != verified.envelope().body.principal_id
            || row["principal_commitment"] != reference.account_anchor
            || row["signing_public_key"] != cert.branch_signing_public_key
            || ramflux_protocol::encode_base64url(agreement) != cert.agreement_identity_public_key
        {
            return Err(invalid("custody directory differs from signed authority"));
        }
        Ok(true)
    }
}

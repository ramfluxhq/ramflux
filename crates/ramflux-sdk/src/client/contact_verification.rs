// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! One-time legacy safety baselining and read-only current-authority verification.
use crate::SdkError;
use ramflux_protocol::SignedDeviceSetRecord;
use ramflux_storage::AccountDb;

pub(crate) const MIGRATION_MARKER: &str = "identity/safety-verification-migration/v1";

/// Baselines only the legacy records present when this account first opens after upgrade.
pub(crate) fn migrate_legacy_contact_verifications(db: &AccountDb) -> Result<(), SdkError> {
    if db.load_actor_state::<bool>(MIGRATION_MARKER)? == Some(true) {
        return Ok(());
    }
    db.write_transaction(|| {
        if db.load_actor_state::<bool>(MIGRATION_MARKER)? == Some(true) {
            return Ok(());
        }
        let mut after = String::new();
        loop {
            let ids = db.client_directory_ids("identity", &after, 100)?;
            for id in &ids {
                let Some(identity) = db.client_record("identity", id)? else { continue };
                let Some(root) = identity["contact_identity_commitment"].as_str() else { continue };
                let Some(verification) = db.contact_verification(root)? else { continue };
                if verification.verification_state != "verified"
                    || identity["device_set_hash"].as_str()
                        != Some(verification.verified_device_set_hash.as_str())
                {
                    continue;
                }
                let stamp_key = format!("identity/safety_verified_set/{root}");
                if db.load_actor_state::<String>(&stamp_key)?.is_some() {
                    continue;
                }
                if let Some(observed) = db.load_actor_state::<SignedDeviceSetRecord>(
                    &super::identity_authority::record_key(root),
                )? {
                    db.persist_actor_state(
                        &stamp_key,
                        &super::identity_authority::set_fingerprint(&observed)?,
                    )?;
                }
            }
            if ids.len() < 100 {
                break;
            }
            after.clone_from(
                ids.last().ok_or_else(|| SdkError::LocalBus("missing identity cursor".into()))?,
            );
        }
        // The stamps and completion marker commit together; a failed scan can be retried safely.
        db.persist_actor_state(MIGRATION_MARKER, &true)?;
        Ok(())
    })
}

pub(crate) fn verification_state(
    db: &AccountDb,
    commitment: &str,
    device_set_hash: Option<&str>,
) -> Result<String, SdkError> {
    let check = || -> Result<String, SdkError> {
        let Some(verification) = db.contact_verification(commitment)? else {
            return Ok("unverified".into());
        };
        if verification.verification_state != "verified" {
            return Ok(verification.verification_state);
        }
        let observed = db.load_actor_state::<SignedDeviceSetRecord>(
            &super::identity_authority::record_key(commitment),
        )?;
        let current_hash = if observed.is_none() {
            // Cached synthetic verification never authenticates a signed kind or the card's
            // historical device hash. Every view compares the same synthetic safety material.
            Some(ramflux_protocol::encode_base64url(ramflux_crypto::device_set_hash(
                &super::contact::contact_safety_material_for(commitment).devices,
            )))
        } else {
            device_set_hash.map(str::to_owned)
        };
        if current_hash.as_deref() != Some(verification.verified_device_set_hash.as_str()) {
            return Ok("verification_stale".into());
        }
        let stamp =
            db.load_actor_state::<String>(&format!("identity/safety_verified_set/{commitment}"))?;
        let Some(observed) = observed else {
            return Ok(if stamp.is_none() { "verified" } else { "verification_stale" }.into());
        };
        let current = super::identity_authority::set_fingerprint(&observed)?;
        Ok(if stamp.as_deref() == Some(current.as_str()) {
            "verified"
        } else {
            "verification_stale"
        }
        .into())
    };
    // Account reader requests already own a read snapshot. Standalone writer-side queries also
    // keep verification, observed authority and stamp reads in one snapshot, without any writes.
    if db.is_query_only()? { check() } else { db.read_snapshot(check) }
}

// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! One-time legacy safety baselining and read-only current-authority verification.
use crate::SdkError;
use ramflux_protocol::SignedDeviceSetRecord;
use ramflux_storage::AccountDb;

pub(crate) const MIGRATION_MARKER: &str = ramflux_storage::LEGACY_SAFETY_VERIFICATION_MARKER;

/// Baselines only eligible legacy rows present when the account first opens after upgrade.
pub(crate) fn migrate_legacy_contact_verifications(db: &AccountDb) -> Result<(), SdkError> {
    if db.load_actor_state::<bool>(MIGRATION_MARKER)? == Some(true) {
        return Ok(());
    }
    Ok(db.migrate_legacy_contact_verifications()?)
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

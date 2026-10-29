// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Anchor-based identity comparison and independent native roster verification stamps.
use crate::{RamfluxClient, SdkContactSafetyNumber, SdkError};

impl RamfluxClient {
    pub(super) fn persist_native_accepted_contact_safety(
        &self,
        principal: &str,
        root: &str,
    ) -> Result<(), SdkError> {
        if self.born_v3_account.is_none() {
            return Ok(());
        }
        let db = self.account_db()?;
        let mut identity = db
            .client_record("identity", principal)?
            .ok_or_else(|| SdkError::LocalBus("accepted native contact identity missing".into()))?;
        let safety = self.contact_safety_number(root)?;
        identity["safety_number"] = serde_json::json!(safety.safety_number);
        identity["safety_number_algorithm_version"] = serde_json::json!(safety.algorithm_version);
        db.persist_client_record("identity", principal, &identity)?;
        Ok(())
    }

    pub(super) fn require_native_safety_link(&self, peer: &str) -> Result<(), SdkError> {
        let own = self.own_account_anchor()?;
        if self.friend_links()?.iter().any(|link| {
            link.state == "accepted"
                && ((link.requester_id == own && link.target_id == peer)
                    || (link.target_id == own && link.requester_id == peer))
        }) {
            return Ok(());
        }
        Err(SdkError::LocalBus("contact is not linked to this account".into()))
    }

    pub(super) fn native_safety_number(
        &self,
        peer: &str,
    ) -> Result<SdkContactSafetyNumber, SdkError> {
        let now = crate::custody::network_now()?;
        let own = self.born_v3_account.as_ref().ok_or(SdkError::CustodySetupInvalid)?;
        let authority =
            self.current_custody_authority(peer, now)?.ok_or(SdkError::NetworkingPending)?;
        safety_from_native(
            own.verified(),
            &authority,
            self.native_safety_verification_state(peer)?.unwrap_or_else(|| "unverified".into()),
        )
    }

    pub(super) fn native_safety_verification_state(
        &self,
        peer: &str,
    ) -> Result<Option<String>, SdkError> {
        let Some(authority) =
            self.current_custody_authority(peer, crate::custody::network_now()?)?
        else {
            return Ok(None);
        };
        let db = self.account_db()?;
        let Some(verification) = db.contact_verification(peer)? else {
            return Ok(Some("unverified".into()));
        };
        if verification.verification_state != "verified" {
            return Ok(Some(verification.verification_state));
        }
        let current = super::identity_authority::native_authority_fingerprint(&authority)?;
        let saved =
            db.load_actor_state::<String>(&format!("identity/safety_verified_set/{peer}"))?;
        let state = if saved.as_deref() == Some(current.as_str())
            && verification.verified_device_set_hash == current
        {
            "verified"
        } else {
            "verification_stale"
        };
        Ok(Some(state.into()))
    }
}

pub(super) fn safety_from_native(
    own: &ramflux_crypto::custody::VerifiedRecord,
    peer: &ramflux_crypto::custody::VerifiedRecord,
    verification_state: String,
) -> Result<SdkContactSafetyNumber, SdkError> {
    let own_anchor = &own.envelope().body.account_anchor;
    let peer_anchor = &peer.envelope().body.account_anchor;
    let fingerprint = ramflux_crypto::custody::safety_fingerprint(own_anchor, peer_anchor)?;
    Ok(SdkContactSafetyNumber {
        algorithm_version: 2,
        contact_identity_commitment: peer_anchor.clone(),
        self_identity_commitment: own_anchor.clone(),
        safety_number: ramflux_crypto::custody::safety_number(own_anchor, peer_anchor)?,
        fingerprint_hex: super::contact::bytes_to_hex(&fingerprint),
        safety_number_hash: ramflux_protocol::encode_base64url(fingerprint),
        self_device_count: own
            .envelope()
            .body
            .devices
            .iter()
            .filter(|d| d.status == ramflux_protocol::DeviceSetStatus::Active)
            .count(),
        contact_device_count: peer
            .envelope()
            .body
            .devices
            .iter()
            .filter(|d| d.status == ramflux_protocol::DeviceSetStatus::Active)
            .count(),
        contact_device_set_hash: super::identity_authority::native_authority_fingerprint(peer)?,
        contact_lineage_head: ramflux_protocol::custody::object_hash(
            &peer.envelope().body.master_certificate,
        )?,
        verification_state,
    })
}

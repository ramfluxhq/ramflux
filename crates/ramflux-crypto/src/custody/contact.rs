// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Exact primary signatures and the narrow historical-authority exception for delayed consent.
use super::{
    VerifiedRecord,
    validate::{key, reject, signature},
};
use crate::CryptoError;
use ramflux_protocol::{
    custody::{self, ContactConsentV2, DeviceRef, Envelope},
    domain,
};

/// Verify consent against its exact historical record and fresh current account authority.
/// The transport source must already have proved possession of its current certified branch key.
/// Callers enforce the recipient endpoint, routing, fresh current-head pins and replay rules.
/// # Errors
/// Rejects changed ranges/keys, substituted historical heads, expired consent and revoked branches.
pub fn verify_contact_consent(
    consent: &Envelope<ContactConsentV2>,
    historical: &VerifiedRecord,
    current: &VerifiedRecord,
    source: &DeviceRef,
    now: u64,
) -> Result<(), CryptoError> {
    validate_authority(&consent.body, historical, current, source, now)?;
    signature(
        &key(&historical.envelope().body.master_certificate.body.self_signing_public_key)?,
        domain::CONTACT_REQUEST_V2,
        consent,
    )
}

pub(super) fn validate_authority(
    body: &ContactConsentV2,
    historical: &VerifiedRecord,
    current: &VerifiedRecord,
    source: &DeviceRef,
    now: u64,
) -> Result<(), CryptoError> {
    custody::validate_contact_consent(body)?;
    let old = &historical.envelope().body;
    let head = &current.envelope().body;
    if now > ramflux_protocol::MAX_SAFE_JSON_INTEGER
        || body.expires_at <= now
        || body.issued_at > now.saturating_add(custody::CLOCK_SKEW_SECONDS)
        || body.issued_at < old.issued_at
        || old.account_anchor != body.actor_root
        || head.account_anchor != body.actor_root
        || old.principal_id != head.principal_id
        || old.principal_kind != head.principal_kind
        || old.device_set_epoch > head.device_set_epoch
        || old.master_certificate != head.master_certificate
        || custody::object_hash(historical.envelope())? != body.actor_record_hash
        || custody::object_hash(&old.master_certificate)? != body.master_certificate_hash
        || source != &body.sending_device_ref
    {
        return Err(reject("contact consent authority or lifetime mismatch"));
    }
    let issuing = historical.authorize(source, "message", body.issued_at)?;
    let receiving = current.authorize(source, "message", now)?;
    if issuing.not_before > body.issued_at
        || issuing.expires_at <= body.issued_at
        || issuing.branch_signing_public_key != receiving.branch_signing_public_key
        || issuing.agreement_identity_public_key != receiving.agreement_identity_public_key
    {
        return Err(reject("contact consent sending branch changed"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::custody::{MasterKey, RecoveryPhrase, SelfSigningKey, verify_record};
    use ramflux_protocol::custody::{ContactDecision, encode_epoch, object_hash};
    type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;
    const NOW: u64 = 1_700_000_000;

    fn body(authority: &VerifiedRecord) -> Result<ContactConsentV2> {
        let anchor = authority.envelope().body.account_anchor.clone();
        let nonce = ramflux_protocol::encode_base64url([29; 32]);
        Ok(ContactConsentV2 {
            schema: domain::CONTACT_REQUEST_V2.into(),
            version: 2,
            kind: ContactDecision::Request,
            request_id: ramflux_protocol::hash_base64url(
                "ramflux.contact_request.id.v1",
                &ramflux_protocol::canonical_json_bytes(&(&anchor, &nonce))?,
            ),
            nonce,
            requester_root: anchor.clone(),
            target_root: ramflux_protocol::encode_base64url([30; 32]),
            actor_root: anchor,
            sending_device_ref: authority
                .envelope()
                .body
                .master_certificate
                .body
                .primary_device_ref
                .clone(),
            issued_at: NOW,
            expires_at: NOW + custody::CONTACT_CONSENT_TTL_SECONDS,
            note: None,
            actor_record_hash: object_hash(authority.envelope())?,
            master_certificate_hash: object_hash(&authority.envelope().body.master_certificate)?,
        })
    }

    #[test]
    fn native_contact_consent_accepts_exact_delayed_revision_but_refuses_revocation_or_substitution()
    -> Result {
        let (_, primary, genesis) = super::super::tests::fixture()?;
        let old = verify_record(&genesis, NOW, None, None)?;
        let intent = body(&old)?;
        let source = intent.sending_device_ref.clone();
        let signed = primary.sign_contact_consent(&old, intent, NOW)?;
        let vector: serde_json::Value =
            serde_json::from_str(include_str!("../../tests/fixtures/contact_consent_v2.json"))?;
        assert_eq!(serde_json::to_value(&signed)?, vector["consent"]);
        assert_eq!(
            hex::encode(custody::signing_bytes(domain::CONTACT_REQUEST_V2, &signed.body)?),
            vector["signing_bytes_hex"]
        );
        assert_eq!(
            hex::encode(ramflux_protocol::canonical_json_bytes(&signed)?),
            vector["canonical_hex"]
        );
        verify_contact_consent(&signed, &old, &old, &source, NOW)?;
        let mut changed = genesis.body.clone();
        changed.profile.display_name = "Renamed Human".into();
        changed.device_set_epoch += 1;
        changed.previous_record_hash = Some(object_hash(&genesis)?);
        changed.issued_at += 1;
        let renamed = primary.sign_record(changed)?;
        let current = verify_record(&renamed, NOW + 2, None, None)?;
        verify_contact_consent(&signed, &old, &current, &source, NOW + 2)?;
        assert!(verify_contact_consent(&signed, &current, &current, &source, NOW + 2).is_err());
        let mut wrong_source = source.clone();
        wrong_source.device_epoch += 1;
        assert!(verify_contact_consent(&signed, &old, &current, &wrong_source, NOW + 2).is_err());
        let mut tampered = signed.clone();
        tampered.body.note = Some("substituted intent".into());
        assert!(verify_contact_consent(&tampered, &old, &current, &source, NOW + 2).is_err());
        let revoked = primary.revoke_device(&current, &source.device_id, NOW + 2)?;
        let revoked = verify_record(&revoked, NOW + 2, None, None)?;
        assert!(verify_contact_consent(&signed, &old, &revoked, &source, NOW + 2).is_err());
        assert!(
            verify_contact_consent(&signed, &old, &current, &source, signed.body.expires_at)
                .is_err()
        );
        let other = SelfSigningKey::from_vault_seed(&zeroize::Zeroizing::new([31; 32]));
        assert!(other.sign_contact_consent(&old, signed.body.clone(), NOW).is_err());
        let wire = ramflux_protocol::canonical_json_bytes(&signed)?;
        let decoded: Envelope<ContactConsentV2> = custody::decode(&wire, 16 * 1024)?;
        assert_eq!(decoded, signed);
        let mut missing = serde_json::to_value(&signed)?;
        missing["body"].as_object_mut().ok_or("body")?.remove("note");
        assert!(
            custody::decode::<Envelope<ContactConsentV2>>(
                &serde_json::to_vec(&missing)?,
                16 * 1024
            )
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn native_contact_consent_does_not_cross_a_master_certified_range() -> Result {
        let (_, primary, genesis) = super::super::tests::fixture()?;
        let old = verify_record(&genesis, NOW, None, None)?;
        let signed = primary.sign_contact_consent(&old, body(&old)?, NOW)?;
        let master = MasterKey::from_phrase(&RecoveryPhrase::from_entropy(&[0; 32])?)?;
        let next = SelfSigningKey::from_vault_seed(&zeroize::Zeroizing::new([32; 32]));
        let mut replacement = genesis.body.clone();
        let mut cert = replacement.master_certificate.body;
        cert.range_index += 1;
        cert.previous_certificate_hash = Some(object_hash(&genesis.body.master_certificate)?);
        cert.self_signing_public_key = next.public_key();
        cert.cert_id = ramflux_protocol::encode_base64url([33; 32]);
        replacement.master_certificate = master.certify(cert)?;
        let mut branch = replacement.devices[0].branch_certificate.take().ok_or("branch")?.body;
        branch.master_certificate_hash = object_hash(&replacement.master_certificate)?;
        branch.cert_id = ramflux_protocol::encode_base64url([34; 32]);
        replacement.devices[0].branch_certificate = Some(next.certify_branch(branch)?);
        replacement.device_set_epoch = encode_epoch(2, 1)?;
        replacement.previous_record_hash = Some(object_hash(&genesis)?);
        replacement.issued_at += 1;
        let replacement = next.sign_record(replacement)?;
        let current = verify_record(&replacement, NOW + 2, None, None)?;
        assert!(
            verify_contact_consent(
                &signed,
                &old,
                &current,
                &signed.body.sending_device_ref,
                NOW + 2
            )
            .is_err()
        );
        Ok(())
    }
}

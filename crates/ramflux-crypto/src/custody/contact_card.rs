// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Native cards authenticate management authority without a legacy root signer.
use super::{SelfSigningKey, VerifiedRecord, validate};
use crate::CryptoError;
use ramflux_protocol::{
    custody::{
        CONTACT_CARD_V3_DOMAIN, ContactCardV3, Envelope, MAX_CONTACT_CARD_V3_BYTES, object_hash,
    },
    domain,
};

/// Verify the master certificate and exact domain-separated self-signing signature.
/// Current revocation/head checks still require independently refreshed directory authority.
/// # Errors
/// Rejects malformed, expired, substituted, oversized or incorrectly signed cards.
pub fn verify_contact_card_v3(card: &Envelope<ContactCardV3>, now: u64) -> Result<(), CryptoError> {
    let body = &card.body;
    let certificate = &body.master_certificate;
    validate::master_body(&certificate.body)?;
    validate::signature(
        &validate::key(&certificate.body.master_public_key)?,
        domain::CUSTODY_MASTER_CERTIFICATE,
        certificate,
    )?;
    validate::bytes(&body.authority_head_hash, 32)?;
    validate::time(body.issued_at)?;
    validate::time(body.expires_at)?;
    if body.version != 3
        || body.account_anchor != certificate.body.account_anchor
        || body.principal_id != certificate.body.principal_id
        || body.master_public_key != certificate.body.master_public_key
        || body.issued_at < certificate.body.issued_at
        || body.issued_at > now.saturating_add(60)
        || body.expires_at <= now
        || body.expires_at <= body.issued_at
        || body.expires_at.saturating_sub(body.issued_at) > 30 * 24 * 60 * 60
        || body.devices.len() > ramflux_protocol::custody::MAX_ROSTER
        || ramflux_protocol::normalize_profile_display_name(&body.display_name)?
            != body.display_name
        || ramflux_protocol::canonical_json_bytes(card)?.len() > MAX_CONTACT_CARD_V3_BYTES
    {
        return Err(validate::reject("invalid native contact card"));
    }
    validate::signature(
        &validate::key(&certificate.body.self_signing_public_key)?,
        CONTACT_CARD_V3_DOMAIN,
        card,
    )
}

impl SelfSigningKey {
    /// Sign only a card for the exact verified current authority and roster.
    /// # Errors
    /// Rejects a substituted head, certificate, profile, roster or unavailable signer.
    pub fn sign_contact_card_v3(
        &self,
        current: &VerifiedRecord,
        body: ContactCardV3,
        now: u64,
    ) -> Result<Envelope<ContactCardV3>, CryptoError> {
        let record = current.envelope();
        if body.master_certificate != record.body.master_certificate
            || body.authority_head_hash != object_hash(record)?
            || body.devices != record.body.devices
            || body.display_name != record.body.profile.display_name
            || self.public_key() != body.master_certificate.body.self_signing_public_key
        {
            return Err(validate::reject("native contact card authority mismatch"));
        }
        let card = Envelope {
            signature: crate::sign_canonical_bytes_with_seed(
                &ramflux_protocol::custody::signing_bytes(CONTACT_CARD_V3_DOMAIN, &body)?,
                *self.vault_seed(),
            ),
            body,
        };
        verify_contact_card_v3(&card, now)?;
        Ok(card)
    }
}

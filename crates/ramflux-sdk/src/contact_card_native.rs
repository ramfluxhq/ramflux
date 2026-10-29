// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Native portable cards retain the master anchor and certified primary provenance.
use crate::{ContactCardBody, ContactNode, ContactReason, SdkError};
use ramflux_protocol::custody::{ContactCardV3, Envelope, MAX_CONTACT_CARD_V3_BYTES};

pub(crate) fn is_native(input: &str) -> bool {
    input.starts_with("ramflux-card:v3:") || input.starts_with("ramflux://contact/v3/")
}
pub(crate) fn encode(
    card: &Envelope<ContactCardV3>,
    now: i64,
) -> Result<(String, String), SdkError> {
    let encoded = ramflux_protocol::encode_base64url(ramflux_protocol::canonical_json_bytes(card)?);
    let text = format!("ramflux-card:v3:{encoded}");
    let link = format!("ramflux://contact/v3/{encoded}");
    parse(&text, now)?;
    Ok((text, link))
}
pub(crate) fn parse(input: &str, now: i64) -> Result<ContactCardBody, SdkError> {
    if input.len() > MAX_CONTACT_CARD_V3_BYTES {
        return Err(ContactReason::InvalidCard.into());
    }
    let encoded = input
        .strip_prefix("ramflux-card:v3:")
        .or_else(|| input.strip_prefix("ramflux://contact/v3/"))
        .ok_or(ContactReason::InvalidCard)?;
    let bytes =
        ramflux_protocol::decode_base64url(encoded).map_err(|_| ContactReason::InvalidCard)?;
    let card: Envelope<ContactCardV3> =
        ramflux_protocol::custody::decode(&bytes, MAX_CONTACT_CARD_V3_BYTES)
            .map_err(|_| ContactReason::InvalidCard)?;
    if ramflux_protocol::canonical_json_bytes(&card)? != bytes {
        return Err(ContactReason::InvalidCard.into());
    }
    let clock = u64::try_from(now).map_err(|_| ContactReason::InvalidCard)?;
    if card.body.expires_at <= clock {
        return Err(ContactReason::CardExpired.into());
    }
    ramflux_crypto::custody::verify_contact_card_v3(&card, clock)
        .map_err(|_| ContactReason::CardSignatureInvalid)?;
    let mut body = ContactCardBody {
        version: 1,
        principal_id: card.body.principal_id,
        root_commitment: card.body.account_anchor,
        root_public_key: card.body.master_public_key,
        node: ContactNode {
            url: card.body.node_url,
            key_fingerprint: card.body.node_key_fingerprint,
        },
        display_name: Some(card.body.display_name),
        kind_asserted: Some(
            serde_json::to_value(card.body.master_certificate.body.principal_kind)?
                .as_str()
                .ok_or(ContactReason::InvalidCard)?
                .into(),
        ),
        issued_at: i64::try_from(card.body.issued_at).map_err(|_| ContactReason::InvalidCard)?,
        expires_at: i64::try_from(card.body.expires_at).map_err(|_| ContactReason::InvalidCard)?,
        native_authority: None,
    };
    crate::contact_card::validate(&body, now)?;
    body.version = 3;
    body.native_authority = Some(crate::contact_card::ContactCardAuthority {
        head_hash: card.body.authority_head_hash,
        master_certificate_hash: ramflux_protocol::custody::object_hash(
            &card.body.master_certificate,
        )?,
    });
    Ok(body)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::contact_resolution::verify_native_card_head;
    use crate::custody::{
        BornAccount, RecoveryCeremony,
        tests::{Root, TestVault, create_with_phrase},
    };
    type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
    fn card(
        account: &BornAccount,
        vault: &TestVault,
        now: u64,
    ) -> TestResult<Envelope<ContactCardV3>> {
        Ok(account.sign_contact_card(
            vault,
            ContactCardV3 {
                version: 3,
                principal_id: account.record().body.principal_id.clone(),
                account_anchor: account.record().body.account_anchor.clone(),
                master_public_key: account
                    .record()
                    .body
                    .master_certificate
                    .body
                    .master_public_key
                    .clone(),
                master_certificate: account.record().body.master_certificate.clone(),
                authority_head_hash: ramflux_protocol::custody::object_hash(account.record())?,
                devices: account.record().body.devices.clone(),
                node_url: "https://node.example".into(),
                node_key_fingerprint: crate::contact_node_fingerprint(
                    &ramflux_crypto::fixture_public_key_base64url(),
                )?,
                display_name: account.record().body.profile.display_name.clone(),
                issued_at: now,
                expires_at: now + 3600,
            },
            now,
        )?)
    }
    fn manifest(account: &BornAccount) -> TestResult<crate::prekey::SdkDeviceManifestResponse> {
        Ok(crate::prekey::SdkDeviceManifestResponse::from_native(
            ramflux_protocol::custody::CustodyManifest {
                publication: account.publication(),
                custodian_publication: None,
                devices: Vec::new(),
            },
        )?)
    }
    #[test]
    fn native_cards_verify_master_chain_and_cannot_reuse_a_revoked_self_signing_key() -> TestResult
    {
        let root = Root::new()?;
        let vault = TestVault::default();
        let now = crate::custody::network_now()?;
        let (prior, phrase) = create_with_phrase(&root.0, "card", &vault, now)?;
        let old_key = vault.primary_for_public_key(
            &prior.record().body.master_certificate.body.self_signing_public_key,
        )?;
        let original = card(&prior, &vault, now)?;
        let (text, link) = encode(&original, i64::try_from(now)?)?;
        for input in [&text, &link] {
            let parsed = crate::parse_contact_card(input, i64::try_from(now)?)?;
            assert_eq!(parsed.version, 3);
            assert_eq!(parsed.root_commitment, prior.record().body.account_anchor);
            verify_native_card_head(Some(&parsed), &manifest(&prior)?)?;
        }
        let pending = RecoveryCeremony::begin(&root.0, "card", now)?;
        let replacement =
            pending.confirm(&phrase, &prior.record().body.account_anchor, &vault, now)?;
        let updated = manifest(&replacement)?;
        let parsed = crate::parse_contact_card(&text, i64::try_from(now)?)?;
        assert!(verify_native_card_head(Some(&parsed), &updated).is_err());
        let mut forged = original;
        // A stolen old primary can name the public new head, but cannot replace its certificate.
        forged.body.authority_head_hash =
            ramflux_protocol::custody::object_hash(replacement.record())?;
        forged.signature = ramflux_crypto::sign_canonical_bytes_with_seed(
            &ramflux_protocol::custody::signing_bytes(
                ramflux_protocol::custody::CONTACT_CARD_V3_DOMAIN,
                &forged.body,
            )?,
            *old_key.vault_seed(),
        );
        let (text, _) = encode(&forged, i64::try_from(now)?)?;
        let parsed = crate::parse_contact_card(&text, i64::try_from(now)?)?;
        assert!(verify_native_card_head(Some(&parsed), &updated).is_err());
        let (fresh, _) = encode(&card(&replacement, &vault, now)?, i64::try_from(now)?)?;
        verify_native_card_head(
            Some(&crate::parse_contact_card(&fresh, i64::try_from(now)?)?),
            &updated,
        )?;
        let mut substituted = card(&replacement, &vault, now)?;
        substituted.body.master_certificate.signature =
            prior.record().body.master_certificate.signature.clone();
        assert!(encode(&substituted, i64::try_from(now)?).is_err());
        Ok(())
    }
}

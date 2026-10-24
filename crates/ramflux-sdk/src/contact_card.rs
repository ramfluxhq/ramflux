// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Portable root-signed contact cards; display metadata never grants safety verification.
use crate::{SdkError, identity_root_public_key_commitment};
use serde::{Deserialize, Serialize};

const DOMAIN: &str = "ramflux.contact.card.v1";
const PREFIX: &str = "ramflux-card:v1:";
const LINK_PREFIX: &str = "ramflux://contact/v1/";
const MAX_CARD_BYTES: usize = 4096;

/// Machine-readable failures for contact input and identity resolution.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, thiserror::Error)]
#[serde(rename_all = "snake_case")]
pub enum ContactReason {
    #[error("principal_id_taken")]
    PrincipalIdTaken,
    #[error("principal_id_ambiguous")]
    PrincipalIdAmbiguous,
    #[error("rate_limited")]
    LookupRateLimited,
    #[error("root_conflict")]
    RootConflict,
    #[error("manifest_invalid")]
    ManifestInvalid,
    /// The directory has no unambiguous active identity for this principal.
    #[error("unknown_principal")]
    UnknownPrincipal,
    /// The input does not conform to the bounded versioned card or selector contract.
    #[error("invalid_card")]
    InvalidCard,
    /// The root signature or root commitment does not authenticate the card.
    #[error("card_signature_invalid")]
    CardSignatureInvalid,
    /// The card's validity window has ended.
    #[error("card_expired")]
    CardExpired,
    /// The requested contact is the current account.
    #[error("self_contact")]
    SelfContact,
    /// An accepted contact already exists.
    #[error("already_contact")]
    AlreadyContact,
}

/// A home-node locator authenticated by the card's root signature.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ContactNode {
    pub url: String,
    pub key_fingerprint: String,
}

/// Public identity and expiry bound into the card's root signature.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ContactCardBody {
    pub version: u32,
    pub principal_id: String,
    pub root_commitment: String,
    pub root_public_key: String,
    pub node: ContactNode,
    pub display_name: Option<String>,
    pub kind_asserted: Option<String>,
    pub issued_at: i64,
    pub expires_at: i64,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct SignedCard {
    body: ContactCardBody,
    signature: String,
}

fn signing_bytes(body: &impl Serialize) -> Result<Vec<u8>, SdkError> {
    Ok(ramflux_protocol::canonical_json_bytes(&serde_json::json!({"domain":DOMAIN,"body":body}))?)
}

/// Fingerprint of the node's Ed25519 public key, independent of certificate renewal.
/// # Errors
/// Returns an error for an invalid node public key.
pub fn contact_node_fingerprint(public_key: &str) -> Result<String, SdkError> {
    let bytes =
        ramflux_protocol::decode_base64url(public_key).map_err(|_| ContactReason::InvalidCard)?;
    if bytes.len() != 32 {
        return Err(ContactReason::InvalidCard.into());
    }
    Ok(ramflux_protocol::hash_hex("ramflux.contact.node-key.v1", &bytes))
}

pub(crate) fn valid_principal(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 256
        && id.bytes().all(|b| b.is_ascii_alphanumeric() || b"_.:@~-".contains(&b))
}

fn validate(body: &ContactCardBody, now: i64) -> Result<(), SdkError> {
    if body.version != 1
        || !valid_principal(&body.principal_id)
        || body.issued_at > now.saturating_add(60)
        || body.expires_at <= body.issued_at
        || body.expires_at.saturating_sub(body.issued_at) > 30 * 24 * 60 * 60
        || body.node.key_fingerprint.len() != 64
        || !body.node.key_fingerprint.bytes().all(|b| b.is_ascii_hexdigit())
        || body.display_name.as_ref().is_some_and(|name| {
            name.len() > 256 || !ramflux_protocol::text_safety::single_line_is_safe(name)
        })
        || body
            .kind_asserted
            .as_deref()
            .is_some_and(|kind| !matches!(kind, "human" | "headless_ai" | "bot" | "workflow"))
    {
        return Err(ContactReason::InvalidCard.into());
    }
    let url = reqwest::Url::parse(&body.node.url).map_err(|_| ContactReason::InvalidCard)?;
    if !matches!(url.scheme(), "http" | "https")
        || (url.scheme() == "http"
            && !matches!(url.host_str(), Some("127.0.0.1" | "[::1]" | "localhost")))
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
    {
        return Err(ContactReason::InvalidCard.into());
    }
    if body.expires_at <= now {
        return Err(ContactReason::CardExpired.into());
    }
    if identity_root_public_key_commitment(&body.root_public_key).ok().as_deref()
        != Some(body.root_commitment.as_str())
    {
        return Err(ContactReason::CardSignatureInvalid.into());
    }
    Ok(())
}

/// Verifies either a text card or its link form without trusting display metadata.
/// # Errors
/// Returns typed contact errors for size, schema, expiry or signature failures.
pub fn parse_contact_card(input: &str, now: i64) -> Result<ContactCardBody, SdkError> {
    if input.len() > MAX_CARD_BYTES {
        return Err(ContactReason::InvalidCard.into());
    }
    let encoded = input
        .strip_prefix(PREFIX)
        .or_else(|| input.strip_prefix(LINK_PREFIX))
        .ok_or(ContactReason::InvalidCard)?;
    let bytes =
        ramflux_protocol::decode_base64url(encoded).map_err(|_| ContactReason::InvalidCard)?;
    let raw: serde_json::Value =
        serde_json::from_slice(&bytes).map_err(|_| ContactReason::InvalidCard)?;
    if ramflux_protocol::canonical_json_bytes(&raw)? != bytes {
        return Err(ContactReason::InvalidCard.into());
    }
    let card: SignedCard =
        serde_json::from_value(raw.clone()).map_err(|_| ContactReason::InvalidCard)?;
    validate(&card.body, now)?;
    ramflux_crypto::verify_canonical_signature(
        &signing_bytes(&raw["body"])?,
        &card.signature,
        &card.body.root_public_key,
    )
    .map_err(|_| ContactReason::CardSignatureInvalid)?;
    Ok(card.body)
}

pub(crate) fn encode_contact_card(
    body: ContactCardBody,
    seed: [u8; 32],
    now: i64,
) -> Result<(String, String), SdkError> {
    validate(&body, now)?;
    let signature = ramflux_crypto::sign_canonical_bytes_with_seed(&signing_bytes(&body)?, seed);
    let encoded =
        ramflux_protocol::encode_base64url(ramflux_protocol::canonical_json_bytes(&SignedCard {
            body,
            signature,
        })?);
    let card = format!("{PREFIX}{encoded}");
    let link = format!("{LINK_PREFIX}{encoded}");
    if card.len().max(link.len()) > MAX_CARD_BYTES {
        return Err(ContactReason::InvalidCard.into());
    }
    Ok((card, link))
}

#[cfg(test)]
mod tests {
    use super::*;
    fn body() -> Result<ContactCardBody, SdkError> {
        let public = ramflux_crypto::public_key_base64url_from_seed([7; 32]);
        Ok(ContactCardBody {
            version: 1,
            principal_id: "alice".into(),
            root_commitment: identity_root_public_key_commitment(&public)?,
            root_public_key: public,
            node: ContactNode {
                url: "https://node.example".into(),
                key_fingerprint: contact_node_fingerprint(
                    &ramflux_crypto::public_key_base64url_from_seed([8; 32]),
                )?,
            },
            display_name: Some("Alice".into()),
            kind_asserted: Some("human".into()),
            issued_at: 1000,
            expires_at: 2000,
        })
    }
    #[test]
    fn plaintext_card_discovery_is_restricted_to_loopback_development_origins()
    -> Result<(), SdkError> {
        for url in ["http://example.com", "http://192.168.1.1", "http://127.0.0.2"] {
            let mut card = body()?;
            card.node.url = url.into();
            assert!(matches!(
                encode_contact_card(card, [7; 32], 1000),
                Err(SdkError::ContactInput(ContactReason::InvalidCard))
            ));
        }
        for url in ["http://127.0.0.1:8080", "http://[::1]:8080", "https://example.com"] {
            let mut card = body()?;
            card.node.url = url.into();
            encode_contact_card(card, [7; 32], 1000)?;
        }
        Ok(())
    }
    #[test]
    fn text_and_link_contact_cards_authenticate_the_same_root_and_metadata() -> Result<(), SdkError>
    {
        let (card, link) = encode_contact_card(body()?, [7; 32], 1000)?;
        for input in [&card, &link] {
            let parsed = parse_contact_card(input, 1001)?;
            assert_eq!(parsed.principal_id, "alice");
            assert_eq!(parsed.root_commitment, body()?.root_commitment);
            assert_eq!(parsed.kind_asserted.as_deref(), Some("human"));
        }
        Ok(())
    }
    #[test]
    fn modified_contact_card_identity_is_rejected_by_the_root_signature() -> Result<(), SdkError> {
        let (card, _) = encode_contact_card(body()?, [7; 32], 1000)?;
        let mut signed: SignedCard = serde_json::from_slice(
            &ramflux_protocol::decode_base64url(
                card.strip_prefix(PREFIX).ok_or(ContactReason::InvalidCard)?,
            )
            .map_err(|_| ContactReason::InvalidCard)?,
        )?;
        signed.body.principal_id = "mallory".into();
        let tampered = format!(
            "{PREFIX}{}",
            ramflux_protocol::encode_base64url(ramflux_protocol::canonical_json_bytes(&signed)?)
        );
        assert!(matches!(
            parse_contact_card(&tampered, 1001),
            Err(SdkError::ContactInput(ContactReason::CardSignatureInvalid))
        ));
        Ok(())
    }
    #[test]
    fn expired_oversized_and_unsafe_display_cards_have_typed_input_errors() -> Result<(), SdkError>
    {
        let (card, _) = encode_contact_card(body()?, [7; 32], 1000)?;
        assert!(matches!(
            parse_contact_card(&card, 2000),
            Err(SdkError::ContactInput(ContactReason::CardExpired))
        ));
        assert!(matches!(
            parse_contact_card(&"x".repeat(4097), 1000),
            Err(SdkError::ContactInput(ContactReason::InvalidCard))
        ));
        for name in ["Alice\nBob", "Alice\u{202e}Bob", "Alice\u{2028}Bob"] {
            let mut unsafe_body = body()?;
            unsafe_body.display_name = Some(name.into());
            assert!(encode_contact_card(unsafe_body, [7; 32], 1000).is_err());
        }
        Ok(())
    }
    #[test]
    fn altered_root_commitments_and_noncanonical_cards_fail_closed() -> Result<(), SdkError> {
        let mut invalid = body()?;
        invalid.root_commitment = "wrong".into();
        assert!(matches!(
            encode_contact_card(invalid, [7; 32], 1000),
            Err(SdkError::ContactInput(ContactReason::CardSignatureInvalid))
        ));
        let signed = SignedCard { body: body()?, signature: "fake".into() };
        let input = format!(
            "{PREFIX}{}",
            ramflux_protocol::encode_base64url(serde_json::to_vec_pretty(&signed)?)
        );
        assert!(matches!(
            parse_contact_card(&input, 1000),
            Err(SdkError::ContactInput(ContactReason::InvalidCard))
        ));
        Ok(())
    }
    #[test]
    fn omitted_optional_card_metadata_verifies_the_exact_signed_body() -> Result<(), SdkError> {
        let mut raw = serde_json::to_value(body()?)?;
        let fields = raw.as_object_mut().ok_or(ContactReason::InvalidCard)?;
        fields.remove("display_name");
        fields.remove("kind_asserted");
        let signature =
            ramflux_crypto::sign_canonical_bytes_with_seed(&signing_bytes(&raw)?, [7; 32]);
        let card = format!(
            "{PREFIX}{}",
            ramflux_protocol::encode_base64url(ramflux_protocol::canonical_json_bytes(
                &serde_json::json!({"body":raw,"signature":signature})
            )?)
        );
        let parsed = parse_contact_card(&card, 1000)?;
        assert!(parsed.display_name.is_none());
        assert!(parsed.kind_asserted.is_none());
        raw["display_name"] = serde_json::json!("forged label");
        let tampered = format!(
            "{PREFIX}{}",
            ramflux_protocol::encode_base64url(ramflux_protocol::canonical_json_bytes(
                &serde_json::json!({"body":raw,"signature":signature})
            )?)
        );
        assert!(matches!(
            parse_contact_card(&tampered, 1000),
            Err(SdkError::ContactInput(ContactReason::CardSignatureInvalid))
        ));
        Ok(())
    }
}

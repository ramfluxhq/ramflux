// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Offline-root provider keyrings and signed trust snapshot verification.

use super::{
    BTreeSet, Deserialize, FederatedIssuerTrustSnapshot, NodeCoreError,
    OBJECT_RELAY_CLOCK_SKEW_LEEWAY_SECONDS, Serialize, require_non_empty, within_ttl,
};

/// T23-A2b2: the out-of-band, offline-root-signed provider keyring document (independent of any
/// snapshot; never self-certified by a provider/snapshot key).
pub const PROVIDER_KEYRING_SCHEMA: &str = "ramflux.federation_provider_keyring.v1";
pub const PROVIDER_KEYRING_VERSION: u32 = 1;
pub(super) const PROVIDER_KEYRING_FINGERPRINT_DOMAIN: &str =
    "ramflux.federation_provider_keyring.fingerprint.v1";
/// T23-A2b2: the versioned provider-signed trust-snapshot envelope carrying `provider_epoch`. This is
/// the production keyring-era envelope; the legacy single-pin `..._envelope.v3` schema is hard-rejected
/// by the keyring verifier and only parsed by the compile-gated `itest-provider-single-key` path.
pub const PROVIDER_SIGNED_TRUST_SNAPSHOT_ENVELOPE_SCHEMA: &str =
    "ramflux.federated_issuer_trust_snapshot_envelope.v4";
pub const PROVIDER_SIGNED_TRUST_SNAPSHOT_ENVELOPE_VERSION: u32 = 4;

// ─── T23-A2b2: provider signing-key keyring rotation (production keyring era) ──────────────────────

/// One provider signing key in the out-of-band keyring. `authorized_provider_epoch` is the EXACT
/// provider epoch this key may sign — a key can never advance the provider epoch beyond its own, so a
/// compromised overlapping key cannot forge a higher-epoch (seizing) envelope. `retired_at` is the
/// absolute unix second (offline-root-attested, not a locally-observed time) from which the key may no
/// longer sign or authorize.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ProviderKeyEntry {
    pub key_id: String,
    pub public_key: String,
    pub not_before: u64,
    pub not_after: u64,
    pub retired_at: Option<u64>,
    pub authorized_provider_epoch: u64,
}

/// The out-of-band provider keyring, authorized by a single independent offline signing root whose
/// public key the relay pins separately (never by the provider/snapshot/node-root key). `keyring_epoch`
/// is monotonic and anchors file-level anti-rollback. This is the wire/at-rest form; only a
/// [`ValidatedProviderKeyring`] (produced by [`verify_provider_keyring`]) may select a signing key.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ProviderKeyring {
    pub schema: String,
    pub version: u32,
    pub issuer_node_id: String,
    pub keyring_epoch: u64,
    pub keys: Vec<ProviderKeyEntry>,
    pub keyring_signature: String,
}

/// A [`ProviderKeyring`] that has passed offline-root signature + structural validation. It cannot be
/// deserialized directly — only [`verify_provider_keyring`] constructs it — so an unvalidated keyring
/// can never select a provider key. `fingerprint` is a canonical content hash used to reject a
/// same-`keyring_epoch` content replacement (only a higher epoch may change content).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedProviderKeyring {
    inner: ProviderKeyring,
    fingerprint: String,
}

impl ValidatedProviderKeyring {
    #[must_use]
    pub fn keyring_epoch(&self) -> u64 {
        self.inner.keyring_epoch
    }

    #[must_use]
    pub fn issuer_node_id(&self) -> &str {
        &self.inner.issuer_node_id
    }

    /// The canonical content fingerprint (blake3 over the signing bytes) — same content re-signed
    /// yields the same fingerprint; any content change yields a different one.
    #[must_use]
    pub fn fingerprint(&self) -> &str {
        &self.fingerprint
    }

    /// Selects the unique keyring entry for `key_id` (uniqueness is enforced at validation).
    #[must_use]
    pub fn select(&self, key_id: &str) -> Option<&ProviderKeyEntry> {
        self.inner.keys.iter().find(|entry| entry.key_id == key_id)
    }
}

/// # Errors
/// Returns an error when the keyring cannot be canonicalized.
pub fn provider_keyring_signing_bytes(keyring: &ProviderKeyring) -> Result<Vec<u8>, NodeCoreError> {
    let mut canonical = keyring.clone();
    canonical.keyring_signature.clear();
    ramflux_protocol::canonical_json_bytes(&canonical)
        .map_err(|source| NodeCoreError::ItestJson(source.to_string()))
}

/// Validates a provider keyring against the pinned offline-root public key and structural rules, then
/// returns a [`ValidatedProviderKeyring`]. Checks schema/version, node identity, non-empty fields, per
/// entry validity window (`not_before < not_after`), `key_id` uniqueness, `authorized_provider_epoch`
/// uniqueness (no two keys share an exact epoch — exact-epoch authorization would otherwise be
/// ambiguous), and the offline-root signature over the canonical keyring. The offline root is an
/// anchor independent of every provider key.
///
/// # Errors
/// Returns an error when any structural rule or the offline-root signature fails.
pub fn verify_provider_keyring(
    keyring: &ProviderKeyring,
    offline_root_public_key: &str,
    expected_node_id: &str,
) -> Result<ValidatedProviderKeyring, NodeCoreError> {
    if keyring.schema != PROVIDER_KEYRING_SCHEMA {
        return Err(NodeCoreError::ItestJson("provider keyring schema rejected".to_owned()));
    }
    if keyring.version != PROVIDER_KEYRING_VERSION {
        return Err(NodeCoreError::ItestJson("provider keyring version rejected".to_owned()));
    }
    require_non_empty(&keyring.issuer_node_id, "keyring issuer_node_id")?;
    if keyring.issuer_node_id != expected_node_id {
        return Err(NodeCoreError::Unauthorized(
            "provider keyring issuer node mismatch".to_owned(),
        ));
    }
    require_non_empty(&keyring.keyring_signature, "keyring signature")?;
    if keyring.keys.is_empty() {
        return Err(NodeCoreError::Unauthorized("provider keyring has no keys".to_owned()));
    }
    let mut seen_key_ids = std::collections::BTreeSet::new();
    let mut seen_epochs = std::collections::BTreeSet::new();
    for entry in &keyring.keys {
        require_non_empty(&entry.key_id, "keyring entry key_id")?;
        require_non_empty(&entry.public_key, "keyring entry public_key")?;
        if entry.not_before >= entry.not_after {
            return Err(NodeCoreError::Unauthorized(
                "keyring entry validity window is empty".to_owned(),
            ));
        }
        if !seen_key_ids.insert(entry.key_id.clone()) {
            return Err(NodeCoreError::Unauthorized("keyring has a duplicate key_id".to_owned()));
        }
        if !seen_epochs.insert(entry.authorized_provider_epoch) {
            return Err(NodeCoreError::Unauthorized(
                "keyring has a duplicate authorized_provider_epoch".to_owned(),
            ));
        }
    }
    let signing_bytes = provider_keyring_signing_bytes(keyring)?;
    ramflux_crypto::verify_canonical_signature(
        &signing_bytes,
        &keyring.keyring_signature,
        offline_root_public_key,
    )
    .map_err(|source| NodeCoreError::Unauthorized(source.to_string()))?;
    let fingerprint =
        ramflux_crypto::blake3_256_base64url(PROVIDER_KEYRING_FINGERPRINT_DOMAIN, &signing_bytes);
    Ok(ValidatedProviderKeyring { inner: keyring.clone(), fingerprint })
}

/// The versioned provider-signed trust-snapshot envelope (keyring era). Adds `provider_epoch` (bound
/// by the signature via the canonical bytes) so the relay can enforce that only the key authorized for
/// that exact epoch may sign it. `provider_public_key` is retained only as a redundant field that MUST
/// equal the selected keyring entry's public key — it is never a self-declared trust input.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ProviderSignedTrustSnapshot {
    pub schema: String,
    pub version: u32,
    pub snapshot: FederatedIssuerTrustSnapshot,
    pub provider_signing_key_id: String,
    pub provider_public_key: String,
    pub provider_epoch: u64,
    pub issued_at: u64,
    pub expires_at: u64,
    pub signature: String,
}

/// # Errors
/// Returns an error when the envelope cannot be canonicalized.
pub fn provider_signed_trust_snapshot_signing_bytes(
    envelope: &ProviderSignedTrustSnapshot,
) -> Result<Vec<u8>, NodeCoreError> {
    let mut canonical = envelope.clone();
    canonical.signature.clear();
    ramflux_protocol::canonical_json_bytes(&canonical)
        .map_err(|source| NodeCoreError::ItestJson(source.to_string()))
}

/// Verifies a versioned provider-signed trust-snapshot envelope against a validated keyring and
/// returns the selected keyring entry. Hard-rejects the legacy `..._envelope.v3` schema (only the
/// keyring-era `..._envelope.v4` is accepted in production). Selects the unique entry by
/// `provider_signing_key_id`; rejects a retired key, a key outside its validity window (with clock
/// skew), an envelope whose `provider_epoch` is not the entry's exact `authorized_provider_epoch`, or
/// an envelope whose `provider_public_key` differs from the entry's key; then verifies the provider
/// signature over the canonical envelope with the entry's key.
///
/// # Errors
/// Returns an error when any of the above checks fail.
pub fn verify_provider_signed_trust_snapshot<'a>(
    envelope: &ProviderSignedTrustSnapshot,
    keyring: &'a ValidatedProviderKeyring,
    now: u64,
) -> Result<&'a ProviderKeyEntry, NodeCoreError> {
    if envelope.schema != PROVIDER_SIGNED_TRUST_SNAPSHOT_ENVELOPE_SCHEMA {
        return Err(NodeCoreError::ItestJson(
            "provider trust snapshot envelope schema rejected".to_owned(),
        ));
    }
    if envelope.version != PROVIDER_SIGNED_TRUST_SNAPSHOT_ENVELOPE_VERSION {
        return Err(NodeCoreError::ItestJson(
            "provider trust snapshot envelope version rejected".to_owned(),
        ));
    }
    require_non_empty(&envelope.provider_signing_key_id, "envelope provider_signing_key_id")?;
    require_non_empty(&envelope.provider_public_key, "envelope provider_public_key")?;
    require_non_empty(&envelope.signature, "envelope signature")?;
    let entry = keyring.select(&envelope.provider_signing_key_id).ok_or_else(|| {
        NodeCoreError::Unauthorized(
            "envelope provider_signing_key_id is not in the pinned keyring".to_owned(),
        )
    })?;
    if let Some(retired_at) = entry.retired_at
        && now >= retired_at
    {
        return Err(NodeCoreError::Unauthorized("envelope provider key is retired".to_owned()));
    }
    if now.saturating_add(OBJECT_RELAY_CLOCK_SKEW_LEEWAY_SECONDS) < entry.not_before
        || now >= entry.not_after
    {
        return Err(NodeCoreError::TtlExpired { envelope_id: entry.key_id.clone() });
    }
    if envelope.provider_epoch != entry.authorized_provider_epoch {
        return Err(NodeCoreError::Unauthorized(
            "envelope provider_epoch is not authorized for this provider key".to_owned(),
        ));
    }
    if envelope.provider_public_key != entry.public_key {
        return Err(NodeCoreError::Unauthorized(
            "envelope provider public key does not match the keyring entry".to_owned(),
        ));
    }
    within_ttl(envelope.issued_at, envelope.expires_at, now, &entry.key_id)?;
    ramflux_crypto::verify_canonical_signature(
        &provider_signed_trust_snapshot_signing_bytes(envelope)?,
        &envelope.signature,
        &entry.public_key,
    )
    .map_err(|source| NodeCoreError::Unauthorized(source.to_string()))?;
    Ok(entry)
}
#[cfg(test)]
#[path = "tests/provider.rs"]
mod tests;

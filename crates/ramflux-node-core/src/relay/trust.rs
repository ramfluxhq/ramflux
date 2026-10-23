// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Federated trust admission, root selection, and snapshot high-water cache.

use super::{
    BTreeSet, Deserialize, GatewayIssuerCertificate, NodeCoreError,
    OBJECT_RELAY_CLOCK_SKEW_LEEWAY_SECONDS, OBJECT_RELAY_V3_PROOF_VERSION, ObjectRelayCapability,
    ProviderSignedTrustSnapshot, RelayTokenV3, Serialize, ValidatedProviderKeyring,
    require_non_empty, verify_provider_signed_trust_snapshot,
    verify_relay_token_v3_with_certificate, within_ttl,
};

pub const FEDERATED_ISSUER_TRUST_SNAPSHOT_SCHEMA: &str =
    "ramflux.federated_issuer_trust_snapshot.v3";
/// T23-A2b2b: legacy single-pinned-key envelope schema — gated to the legacy compatibility path.
#[cfg(any(test, feature = "itest-provider-single-key"))]
pub const FEDERATED_ISSUER_TRUST_SNAPSHOT_ENVELOPE_SCHEMA: &str =
    "ramflux.federated_issuer_trust_snapshot_envelope.v3";

/// Trust status of a federated issuer node, mirroring the federation trust directory. Only `Active`
/// nodes may back new relay tokens.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FederatedIssuerTrustStatus {
    Invited,
    Active,
    Suspended,
    Revoked,
    Migrated,
}

/// One pinned node-root public key for a federated issuer node, with its own validity window and
/// pin generation. During a root rotation the snapshot carries both the current and the previous
/// (overlapping) root so in-flight certificates signed by either remain verifiable until the older
/// root's window ends or it is retired.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TrustedNodeRootKey {
    pub node_id: String,
    pub key_id: String,
    pub public_key: String,
    pub not_before: u64,
    pub not_after: u64,
    pub pin_epoch: u64,
    pub retired_at: Option<u64>,
}

/// A relay's federated trust snapshot for a single issuer node: the pinned node-root key(s), trust
/// status, revoked certificate ids, and a hard staleness deadline after which the snapshot must not
/// be used. This is the only source of node-root trust for v3 token verification — there is no bare
/// key or HMAC fallback. Keyring distribution, live rotation, and CRL propagation are runtime/
/// provider concerns; this type is the pure, already-fetched snapshot the relay verifies against.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FederatedIssuerTrustSnapshot {
    pub schema: String,
    pub version: u32,
    pub node_id: String,
    pub generation: u64,
    pub pin_epoch: u64,
    pub trust_status: FederatedIssuerTrustStatus,
    pub roots: Vec<TrustedNodeRootKey>,
    pub revoked_cert_ids: BTreeSet<String>,
    pub hard_stale_at: u64,
}

pub const FEDERATED_TRUST_SNAPSHOT_ENVELOPE_SCHEMA: &str =
    "ramflux.federated_trust_snapshot_envelope.v3";

/// Signed transport envelope for a federated trust snapshot. The cache must only receive an
/// envelope after [`verify_federated_trust_snapshot_envelope`] succeeds.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FederatedTrustSnapshotEnvelope {
    pub schema: String,
    pub version: u32,
    pub snapshot: FederatedIssuerTrustSnapshot,
    pub signer_key_id: String,
    pub signer_public_key: String,
    pub issued_at: u64,
    pub expires_at: u64,
    pub signature: String,
}

/// Returns the canonical bytes signed by the federation trust provider.
///
/// # Errors
/// Returns an error when the envelope cannot be canonicalized.
pub fn federated_trust_snapshot_envelope_signing_bytes(
    envelope: &FederatedTrustSnapshotEnvelope,
) -> Result<Vec<u8>, NodeCoreError> {
    let mut unsigned = envelope.clone();
    unsigned.signature.clear();
    ramflux_protocol::canonical_json_bytes(&unsigned)
        .map_err(|source| NodeCoreError::ItestJson(source.to_string()))
}

/// Verifies a signed trust snapshot envelope before it enters the runtime cache.
///
/// # Errors
/// Returns an error when schema/version, signer binding, validity, signature, or snapshot
/// freshness is invalid.
pub fn verify_federated_trust_snapshot_envelope(
    envelope: &FederatedTrustSnapshotEnvelope,
    expected_node_id: &str,
    expected_signer_key_id: &str,
    expected_signer_public_key: &str,
    now: u64,
) -> Result<(), NodeCoreError> {
    if envelope.schema != FEDERATED_TRUST_SNAPSHOT_ENVELOPE_SCHEMA
        || envelope.version != OBJECT_RELAY_V3_PROOF_VERSION
    {
        return Err(NodeCoreError::ItestJson(
            "federated trust snapshot envelope schema/version rejected".to_owned(),
        ));
    }
    if envelope.signer_key_id != expected_signer_key_id
        || envelope.signer_public_key != expected_signer_public_key
    {
        return Err(NodeCoreError::Unauthorized(
            "federated trust snapshot signer binding mismatch".to_owned(),
        ));
    }
    if envelope.issued_at >= envelope.expires_at
        || now < envelope.issued_at
        || now >= envelope.expires_at
    {
        return Err(NodeCoreError::TtlExpired { envelope_id: envelope.snapshot.node_id.clone() });
    }
    let signing_bytes = federated_trust_snapshot_envelope_signing_bytes(envelope)?;
    ramflux_crypto::verify_canonical_signature(
        &signing_bytes,
        &envelope.signature,
        &envelope.signer_public_key,
    )
    .map_err(|source| NodeCoreError::Unauthorized(source.to_string()))?;
    verify_federated_issuer_trust_snapshot(&envelope.snapshot, expected_node_id, now)
}

/// Returns `true` when a pinned root key is usable at `now`: within its validity window and not yet
/// retired. A `retired_at` in the future still permits use until then (rotation grace).
#[must_use]
pub fn trusted_node_root_key_is_valid(root: &TrustedNodeRootKey, now: u64) -> bool {
    root.not_before <= now
        && now < root.not_after
        && root.retired_at.is_none_or(|retired_at| now < retired_at)
}

/// Verifies a federated issuer trust snapshot's structural validity and that it currently permits
/// backing new relay tokens.
///
/// Checks schema/version, that it is for the expected issuer node, a non-zero generation, that it is
/// not past its hard staleness deadline, and the trust status. Only `Active` permits new tokens.
/// `Invited`/`Suspended`/`Revoked` fail closed. `Migrated` also fails closed here; the grace period
/// for already-issued tokens from a migrated node is a runtime/integration concern not modeled by
/// this pure snapshot.
///
/// # Errors
/// Returns an error when any of the above checks fail.
pub fn verify_federated_issuer_trust_snapshot(
    snapshot: &FederatedIssuerTrustSnapshot,
    expected_node_id: &str,
    now: u64,
) -> Result<(), NodeCoreError> {
    // Admission (structural + freshness) is a strict prerequisite of authorization, but not
    // sufficient: a structurally-valid non-Active snapshot is admissible to the cache yet must not
    // authorize requests.
    verify_federated_issuer_trust_snapshot_admission(snapshot, expected_node_id, now)?;
    match snapshot.trust_status {
        FederatedIssuerTrustStatus::Active => Ok(()),
        FederatedIssuerTrustStatus::Migrated => Err(NodeCoreError::Unauthorized(
            "trust snapshot node is migrated; new tokens fail closed (old-token grace is deferred to integration)"
                .to_owned(),
        )),
        FederatedIssuerTrustStatus::Invited
        | FederatedIssuerTrustStatus::Suspended
        | FederatedIssuerTrustStatus::Revoked => Err(NodeCoreError::Unauthorized(
            "trust snapshot node is not active".to_owned(),
        )),
    }
}

/// Admission check for a federated issuer trust snapshot: structural validity (schema/version/node
/// identity/non-zero generation) and freshness (`now < hard_stale_at`). This is the check a snapshot
/// must pass to *enter the relay's trust cache*, and it is deliberately independent of
/// `trust_status`: a validly-signed `Suspended`/`Revoked`/`Invited`/`Migrated` snapshot is admissible
/// so that a node-status transition propagates to the relay and replaces a stale `Active` snapshot.
///
/// Admission is NOT authorization. Every v3 request re-checks the cached snapshot with the Active-only
/// [`verify_federated_issuer_trust_snapshot`], so an admitted non-Active snapshot fails requests
/// closed. A hard-stale snapshot is rejected here too and can neither be installed nor authorize.
///
/// # Errors
/// Returns an error when the snapshot is structurally invalid, for the wrong node, has a zero
/// generation, or is past its hard staleness deadline.
pub fn verify_federated_issuer_trust_snapshot_admission(
    snapshot: &FederatedIssuerTrustSnapshot,
    expected_node_id: &str,
    now: u64,
) -> Result<(), NodeCoreError> {
    if snapshot.schema != FEDERATED_ISSUER_TRUST_SNAPSHOT_SCHEMA {
        return Err(NodeCoreError::ItestJson(
            "federated issuer trust snapshot schema rejected".to_owned(),
        ));
    }
    if snapshot.version != OBJECT_RELAY_V3_PROOF_VERSION {
        return Err(NodeCoreError::ItestJson(
            "federated issuer trust snapshot version rejected".to_owned(),
        ));
    }
    require_non_empty(&snapshot.node_id, "trust snapshot node_id")?;
    if snapshot.node_id != expected_node_id {
        return Err(NodeCoreError::Unauthorized("trust snapshot node id mismatch".to_owned()));
    }
    if snapshot.generation == 0 {
        return Err(NodeCoreError::Unauthorized("trust snapshot generation is zero".to_owned()));
    }
    if now >= snapshot.hard_stale_at {
        return Err(NodeCoreError::TtlExpired { envelope_id: snapshot.node_id.clone() });
    }
    Ok(())
}

/// Selects the pinned root key for `key_id` from a snapshot, requiring it to belong to the
/// snapshot's node and to be currently valid (window + not retired). This is where current/previous
/// rotation overlap is resolved: whichever root matches the certificate's signing key id and is
/// still valid is returned.
///
/// # Errors
/// Returns an error when no matching, currently-valid root exists.
pub fn select_trusted_node_root_key<'a>(
    snapshot: &'a FederatedIssuerTrustSnapshot,
    key_id: &str,
    now: u64,
) -> Result<&'a TrustedNodeRootKey, NodeCoreError> {
    snapshot
        .roots
        .iter()
        .find(|root| {
            root.key_id == key_id
                && root.node_id == snapshot.node_id
                && trusted_node_root_key_is_valid(root, now)
        })
        .ok_or_else(|| {
            NodeCoreError::Unauthorized(
                "no valid trusted node root key for the certificate signer".to_owned(),
            )
        })
}

/// Verifies a v3 relay token using a federated trust snapshot as the only source of node-root trust.
///
/// The snapshot is verified first (it must be `Active`, fresh, and for the token's issuer node), the
/// embedded certificate must not be listed as revoked, the pinned root is selected by the embedded
/// certificate's `node_root_signing_key_id` (resolving rotation overlap), and finally the token is
/// verified against that root via [`verify_relay_token_v3_with_certificate`] (which also enforces the
/// frame/expected certificate match and the token issuer signature). There is no bare-key or HMAC
/// fallback.
///
/// # Errors
/// Returns an error when the snapshot, revocation, root selection, or certificate/token chain fails.
pub fn verify_relay_token_v3_with_trust_snapshot(
    token: &RelayTokenV3,
    certificate: &GatewayIssuerCertificate,
    snapshot: &FederatedIssuerTrustSnapshot,
    capability: ObjectRelayCapability,
    expected_audience_node_id: &str,
    now: u64,
) -> Result<(), NodeCoreError> {
    verify_federated_issuer_trust_snapshot(snapshot, &token.issuer_node_id, now)?;
    if snapshot.revoked_cert_ids.contains(&token.issuer_certificate.cert_id)
        || snapshot.revoked_cert_ids.contains(&certificate.cert_id)
    {
        return Err(NodeCoreError::Unauthorized(
            "issuer certificate is revoked by the trust snapshot".to_owned(),
        ));
    }
    let root = select_trusted_node_root_key(
        snapshot,
        &token.issuer_certificate.node_root_signing_key_id,
        now,
    )?;
    verify_relay_token_v3_with_certificate(
        token,
        certificate,
        &root.public_key,
        capability,
        expected_audience_node_id,
        now,
    )
}

/// Enforces that a successor snapshot does not roll back trust: it must be for the same node and its
/// `generation` and `pin_epoch` must be monotonically non-decreasing. A decrease is a rollback and is
/// rejected.
///
/// # Errors
/// Returns an error when the successor is for a different node or rolls back the generation or
/// `pin_epoch`.
pub fn verify_federated_issuer_trust_snapshot_successor(
    previous: &FederatedIssuerTrustSnapshot,
    next: &FederatedIssuerTrustSnapshot,
) -> Result<(), NodeCoreError> {
    if next.node_id != previous.node_id {
        return Err(NodeCoreError::Unauthorized(
            "trust snapshot successor is for a different node".to_owned(),
        ));
    }
    if next.generation < previous.generation || next.pin_epoch < previous.pin_epoch {
        return Err(NodeCoreError::Unauthorized(
            "trust snapshot successor rolls back generation or pin epoch".to_owned(),
        ));
    }
    if next.generation == previous.generation
        && next.pin_epoch == previous.pin_epoch
        && next != previous
    {
        return Err(NodeCoreError::Unauthorized(
            "trust snapshot successor changed at the same generation and pin epoch".to_owned(),
        ));
    }
    // The certificate revocation list is monotonic: a successor may add revocations but must not drop
    // any. Without a signed revocation-withdrawal protocol, silently shrinking the CRL (even at a
    // higher generation) would resurrect a revoked issuer certificate; recovery of a revoked
    // certificate requires a new certificate / rotation (deferred to a later card).
    if !next.revoked_cert_ids.is_superset(&previous.revoked_cert_ids) {
        return Err(NodeCoreError::Unauthorized(
            "trust snapshot successor shrinks the certificate revocation list".to_owned(),
        ));
    }
    Ok(())
}

/// A provider-signed envelope carrying a `FederatedIssuerTrustSnapshot`. The signing key is the
/// trusted provider / node-root key that distributes trust snapshots to relays; the relay pins that
/// public key out of band. The envelope binds the snapshot plus an issuance/expiry window, so an
/// unsigned or tampered snapshot cannot enter the relay's trust cache.
///
/// T23-A2b2b: this is the LEGACY single-pinned-key envelope. It is gated to the
/// `itest-provider-single-key` compatibility path; the production/default relay uses only the
/// offline-root-signed keyring envelope [`ProviderSignedTrustSnapshot`].
#[cfg(any(test, feature = "itest-provider-single-key"))]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SignedFederatedIssuerTrustSnapshot {
    pub schema: String,
    pub version: u32,
    pub snapshot: FederatedIssuerTrustSnapshot,
    pub provider_signing_key_id: String,
    pub provider_public_key: String,
    pub issued_at: u64,
    pub expires_at: u64,
    pub signature: String,
}

/// # Errors
/// Returns an error when the envelope cannot be canonicalized.
#[cfg(any(test, feature = "itest-provider-single-key"))]
pub fn signed_federated_issuer_trust_snapshot_signing_bytes(
    envelope: &SignedFederatedIssuerTrustSnapshot,
) -> Result<Vec<u8>, NodeCoreError> {
    let mut canonical = envelope.clone();
    canonical.signature.clear();
    ramflux_protocol::canonical_json_bytes(&canonical)
        .map_err(|source| NodeCoreError::ItestJson(source.to_string()))
}

/// Verifies a signed trust-snapshot envelope against a pinned provider/node-root public key.
///
/// Checks schema/version, required non-empty fields, that the envelope names the expected pinned
/// provider key, a fresh issuance/expiry window, and the provider signature over the canonical
/// envelope (which covers the inner snapshot, so tampering breaks the signature). This authenticates
/// the snapshot's source; the inner snapshot's structural validity and successor rules are enforced
/// separately when it is installed via [`RelayTrustSnapshotCache::update_from_signed`].
///
/// # Errors
/// Returns an error when any of the above checks fail.
#[cfg(any(test, feature = "itest-provider-single-key"))]
pub fn verify_signed_federated_issuer_trust_snapshot(
    envelope: &SignedFederatedIssuerTrustSnapshot,
    expected_provider_public_key: &str,
    now: u64,
) -> Result<(), NodeCoreError> {
    if envelope.schema != FEDERATED_ISSUER_TRUST_SNAPSHOT_ENVELOPE_SCHEMA {
        return Err(NodeCoreError::ItestJson("trust snapshot envelope schema rejected".to_owned()));
    }
    if envelope.version != OBJECT_RELAY_V3_PROOF_VERSION {
        return Err(NodeCoreError::ItestJson(
            "trust snapshot envelope version rejected".to_owned(),
        ));
    }
    require_non_empty(&envelope.provider_signing_key_id, "envelope provider_signing_key_id")?;
    require_non_empty(&envelope.provider_public_key, "envelope provider_public_key")?;
    require_non_empty(&envelope.signature, "envelope signature")?;
    if envelope.provider_public_key != expected_provider_public_key {
        return Err(NodeCoreError::Unauthorized(
            "trust snapshot envelope provider key is not the pinned provider".to_owned(),
        ));
    }
    within_ttl(envelope.issued_at, envelope.expires_at, now, &envelope.provider_signing_key_id)?;
    ramflux_crypto::verify_canonical_signature(
        &signed_federated_issuer_trust_snapshot_signing_bytes(envelope)?,
        &envelope.signature,
        &envelope.provider_public_key,
    )
    .map_err(|source| NodeCoreError::Unauthorized(source.to_string()))
}

/// A pure, cloneable in-memory holder for the relay's current federated issuer trust snapshot.
///
/// It has no interior mutability (no lock): callers own the cache and clone it for sharing, so
/// concurrency is the caller's responsibility. Admission (entering the cache) is deliberately
/// separated from authorization (Active-only, enforced at read time), so a node-status transition
/// (e.g. Active -> Suspended) propagates instead of leaving a stale Active in force:
/// - [`RelayTrustSnapshotCache::update`] admits a snapshot that is structurally valid and fresh
///   ([`verify_federated_issuer_trust_snapshot_admission`], which does NOT check `trust_status`) and
///   that does not roll back the cached generation/pin epoch, switch node, or shrink the certificate
///   revocation list ([`verify_federated_issuer_trust_snapshot_successor`]). A validly-signed
///   non-`Active` snapshot is therefore admissible.
/// - [`RelayTrustSnapshotCache::current`] performs authorization at read time with the Active-only
///   [`verify_federated_issuer_trust_snapshot`] and errors when the cache is empty or the cached
///   snapshot is not currently usable (past its hard staleness deadline, non-`Active`, ...). So an
///   admitted non-`Active` snapshot fails requests closed rather than being silently ignored.
///
/// This is a runtime skeleton only. It does NOT authenticate a snapshot's origin (that is the future
/// federation provider's job) and it never authorizes a relay token by itself — token verification is
/// done separately by [`verify_relay_token_v3_with_trust_snapshot`], which re-validates the snapshot.
/// There is no v2/HMAC path here.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct RelayTrustSnapshotCache {
    current: Option<FederatedIssuerTrustSnapshot>,
    /// T23-A2b2: the keyring `key_id` that signed the currently-cached snapshot. Used to fail the
    /// cache closed when a later keyring retires/removes that signer.
    accepted_signer_key_id: Option<String>,
    /// T23-A2b2: monotonic high-water of the accepted `provider_epoch`. A compromised overlapping key
    /// authorized for an older epoch can never re-take or advance past this.
    provider_epoch_high_water: u64,
    /// T23-A2b2: monotonic high-water of the adopted `keyring_epoch` (file-level anti-rollback). This
    /// defends only against replacing the keyring *file* with an older one; whole-persist-volume
    /// rollback is out of scope for v1 (its trust boundary is the persisted volume's integrity).
    keyring_epoch_high_water: u64,
    /// T23-A2b2: canonical fingerprint of the adopted keyring at `keyring_epoch_high_water`. A keyring
    /// presenting the same epoch but a different fingerprint is a content replacement and is rejected;
    /// only a strictly higher epoch may change content.
    keyring_fingerprint_high_water: Option<String>,
}

impl RelayTrustSnapshotCache {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns the cached snapshot's generation, or `None` when the cache is empty. Does not imply
    /// the snapshot is still usable — use [`RelayTrustSnapshotCache::current`] for a fail-closed read.
    #[must_use]
    pub fn generation(&self) -> Option<u64> {
        self.current.as_ref().map(|snapshot| snapshot.generation)
    }

    /// Admits `snapshot` as the current trust snapshot for `expected_node_id` at `now`.
    ///
    /// This is admission, not authorization: it rejects a snapshot that is not structurally valid or
    /// is hard-stale ([`verify_federated_issuer_trust_snapshot_admission`], which does NOT check
    /// `trust_status`) and — when a snapshot is already cached — one for a different node, one that
    /// rolls back the generation or pin epoch, or one that shrinks the certificate revocation list.
    /// A validly-signed non-`Active` snapshot is admitted so a node-status transition replaces the
    /// cached snapshot; requests are then gated Active-only by [`RelayTrustSnapshotCache::current`],
    /// so an admitted non-`Active` snapshot fails requests closed.
    ///
    /// # Errors
    /// Returns an error when the incoming snapshot fails admission or is not a valid successor of the
    /// cached snapshot.
    pub fn update(
        &mut self,
        snapshot: FederatedIssuerTrustSnapshot,
        expected_node_id: &str,
        now: u64,
    ) -> Result<(), NodeCoreError> {
        // Admission, not authorization: a structurally-valid, fresh, monotonic non-Active snapshot is
        // admitted so a node-status transition (e.g. Active -> Suspended) replaces the cached
        // snapshot. Requests are gated separately by the Active-only `current`, so an admitted
        // non-Active snapshot fails requests closed rather than leaving the stale Active in force.
        verify_federated_issuer_trust_snapshot_admission(&snapshot, expected_node_id, now)?;
        if let Some(existing) = &self.current {
            verify_federated_issuer_trust_snapshot_successor(existing, &snapshot)?;
        }
        self.current = Some(snapshot);
        Ok(())
    }

    /// Returns the current usable trust snapshot for `expected_node_id` at `now`.
    ///
    /// Fail-closed: errors when the cache is empty or the cached snapshot is no longer usable (wrong
    /// node, non-`Active`, past its hard staleness deadline, ...). Never returns an unusable snapshot.
    ///
    /// # Errors
    /// Returns an error when the cache is empty or the cached snapshot fails verification.
    pub fn current(
        &self,
        expected_node_id: &str,
        now: u64,
    ) -> Result<&FederatedIssuerTrustSnapshot, NodeCoreError> {
        let snapshot = self.current.as_ref().ok_or_else(|| {
            NodeCoreError::Unauthorized("relay trust snapshot cache is empty".to_owned())
        })?;
        verify_federated_issuer_trust_snapshot(snapshot, expected_node_id, now)?;
        Ok(snapshot)
    }

    /// Authenticated ingress: verifies the provider signature on `envelope` against the pinned
    /// provider public key first, and only then installs the inner snapshot via
    /// [`RelayTrustSnapshotCache::update`]. This is the required path for admitting a snapshot from an
    /// external provider — an unsigned or tampered envelope never reaches the cache.
    ///
    /// # Errors
    /// Returns an error when the envelope signature/window fails verification, or when the inner
    /// snapshot fails the structural/successor checks in [`RelayTrustSnapshotCache::update`].
    #[cfg(any(test, feature = "itest-provider-single-key"))]
    pub fn update_from_signed(
        &mut self,
        envelope: &SignedFederatedIssuerTrustSnapshot,
        expected_provider_public_key: &str,
        expected_node_id: &str,
        now: u64,
    ) -> Result<(), NodeCoreError> {
        verify_signed_federated_issuer_trust_snapshot(envelope, expected_provider_public_key, now)?;
        self.update(envelope.snapshot.clone(), expected_node_id, now)
    }

    /// T23-A2b2 accessors for persistence / anti-rollback bookkeeping.
    #[must_use]
    pub fn provider_epoch_high_water(&self) -> u64 {
        self.provider_epoch_high_water
    }

    #[must_use]
    pub fn keyring_epoch_high_water(&self) -> u64 {
        self.keyring_epoch_high_water
    }

    #[must_use]
    pub fn accepted_signer_key_id(&self) -> Option<&str> {
        self.accepted_signer_key_id.as_deref()
    }

    #[must_use]
    pub fn keyring_fingerprint_high_water(&self) -> Option<&str> {
        self.keyring_fingerprint_high_water.as_deref()
    }

    /// Restores the persisted anti-rollback high-waters (and accepted signer/fingerprint) after a relay
    /// restart, so a cold start cannot be tricked into accepting an already-superseded keyring/epoch or
    /// a same-epoch content replacement. The caller is responsible for having independently
    /// re-validated the persisted snapshot/keyring.
    pub fn restore_high_water(
        &mut self,
        accepted_signer_key_id: Option<String>,
        provider_epoch_high_water: u64,
        keyring_epoch_high_water: u64,
        keyring_fingerprint_high_water: Option<String>,
    ) {
        self.accepted_signer_key_id = accepted_signer_key_id;
        self.provider_epoch_high_water = provider_epoch_high_water;
        self.keyring_epoch_high_water = keyring_epoch_high_water;
        self.keyring_fingerprint_high_water = keyring_fingerprint_high_water;
    }

    /// Enforces keyring-level anti-rollback: the `keyring_epoch` must never regress, and at the same
    /// epoch the canonical content (fingerprint) must be identical — only a strictly higher epoch may
    /// change content. A pure check that makes no mutation, so callers can reject a rolled-back or
    /// same-epoch-replaced keyring while leaving the cache completely inert.
    ///
    /// # Errors
    /// Returns an error when the keyring epoch rolls back or its content changed at the same epoch.
    fn check_keyring_adoptable(
        &self,
        keyring: &ValidatedProviderKeyring,
    ) -> Result<(), NodeCoreError> {
        if keyring.keyring_epoch() < self.keyring_epoch_high_water {
            return Err(NodeCoreError::Unauthorized(
                "provider keyring epoch rolls back below the accepted high-water".to_owned(),
            ));
        }
        if keyring.keyring_epoch() == self.keyring_epoch_high_water
            && let Some(fingerprint) = &self.keyring_fingerprint_high_water
            && fingerprint != keyring.fingerprint()
        {
            return Err(NodeCoreError::Unauthorized(
                "provider keyring content changed without advancing keyring_epoch".to_owned(),
            ));
        }
        Ok(())
    }

    /// T23-A2b2 keyring-era authenticated ingress. Verifies the versioned provider-signed envelope
    /// against the validated keyring, enforces keyring/provider-epoch anti-rollback, then installs the
    /// inner snapshot via the same admission + successor rules as the legacy path — all in one
    /// transaction. On any failure the cache is left completely unchanged (inert), so a rejected update
    /// never partially advances a high-water or displaces the cached snapshot.
    ///
    /// Anti-seizure: [`verify_provider_signed_trust_snapshot`] pins `provider_epoch` to the signing
    /// key's exact `authorized_provider_epoch`, so a compromised overlapping key can neither forge a
    /// higher (seizing) epoch nor re-sign an epoch already advanced past by another key.
    ///
    /// # Errors
    /// Returns an error when the keyring epoch rolls back, the envelope fails verification, the
    /// provider epoch rolls back or is re-signed by a different key, or the inner snapshot fails
    /// admission/successor.
    pub fn update_from_keyring_signed(
        &mut self,
        envelope: &ProviderSignedTrustSnapshot,
        keyring: &ValidatedProviderKeyring,
        expected_node_id: &str,
        now: u64,
    ) -> Result<(), NodeCoreError> {
        self.check_keyring_adoptable(keyring)?;
        let entry = verify_provider_signed_trust_snapshot(envelope, keyring, now)?;
        if envelope.provider_epoch < self.provider_epoch_high_water {
            return Err(NodeCoreError::Unauthorized(
                "envelope provider_epoch rolls back below the accepted high-water".to_owned(),
            ));
        }
        if envelope.provider_epoch == self.provider_epoch_high_water
            && let Some(signer) = &self.accepted_signer_key_id
            && signer != &entry.key_id
        {
            return Err(NodeCoreError::Unauthorized(
                "a different provider key may not re-sign the current provider_epoch".to_owned(),
            ));
        }
        verify_federated_issuer_trust_snapshot_admission(
            &envelope.snapshot,
            expected_node_id,
            now,
        )?;
        if let Some(existing) = &self.current {
            verify_federated_issuer_trust_snapshot_successor(existing, &envelope.snapshot)?;
        }
        let signer_key_id = entry.key_id.clone();
        self.current = Some(envelope.snapshot.clone());
        self.accepted_signer_key_id = Some(signer_key_id);
        self.provider_epoch_high_water = envelope.provider_epoch;
        self.keyring_epoch_high_water = keyring.keyring_epoch();
        self.keyring_fingerprint_high_water = Some(keyring.fingerprint().to_owned());
        Ok(())
    }

    /// T23-A2b2: reconcile the cached snapshot against a freshly-validated keyring WITHOUT a new
    /// envelope. Enforces keyring-level anti-rollback (epoch + same-epoch fingerprint), advances the
    /// keyring high-water/fingerprint, and — critically — drops the cached snapshot if the signer that
    /// authorized it is no longer usable in this keyring (removed, retired, or outside its window), so
    /// a retirement fails the cache closed immediately rather than continuing on a retired signer.
    ///
    /// On a non-adoptable keyring (epoch rollback or same-epoch content change) it returns an error and
    /// leaves the cache completely unchanged, so a rolled-back or forged same-epoch keyring never
    /// triggers signer reconciliation or clears an existing valid cache.
    ///
    /// # Errors
    /// Returns an error when the keyring is not adoptable (epoch rollback or same-epoch content change).
    pub fn reconcile_keyring(
        &mut self,
        keyring: &ValidatedProviderKeyring,
        now: u64,
    ) -> Result<(), NodeCoreError> {
        self.check_keyring_adoptable(keyring)?;
        self.keyring_epoch_high_water = keyring.keyring_epoch();
        self.keyring_fingerprint_high_water = Some(keyring.fingerprint().to_owned());
        if let Some(signer) = self.accepted_signer_key_id.clone() {
            let still_valid = keyring.select(&signer).is_some_and(|entry| {
                entry.retired_at.is_none_or(|retired_at| now < retired_at)
                    && now.saturating_add(OBJECT_RELAY_CLOCK_SKEW_LEEWAY_SECONDS)
                        >= entry.not_before
                    && now < entry.not_after
            });
            if !still_valid {
                self.current = None;
            }
        }
        Ok(())
    }
}
#[cfg(test)]
#[path = "tests/trust.rs"]
mod tests;

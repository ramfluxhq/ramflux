// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Source signing is gated by the mutually confirmed local SAS and an opaque datastore cut.
use super::{
    FullBootstrap, PROFILE, PairingRole, Phase, SdkError, StartFull, TranscriptV3,
    encode_base64url, wire,
};
use ramflux_protocol::custody::pairing::{
    PairingWire,
    full_transfer::{
        CHUNK_BYTES, Manifest, ManifestKind, SecretBase64, SourceManifest, U64,
        lease::opaque_commitment, manifest_hash,
    },
};
use ramflux_storage::PreparedFullSource;
use zeroize::Zeroizing;

/// Short-lived source-data signing request. The private provider must match this local
/// account/context to its own branch owner. It grants no candidate or native publication.
pub struct FullSourceManifestSigningRequest<'a> {
    manifest: &'a Manifest,
    context: &'a TranscriptV3,
    account_id: &'a str,
}
impl FullSourceManifestSigningRequest<'_> {
    #[must_use]
    pub fn manifest(&self) -> &Manifest {
        self.manifest
    }
    #[must_use]
    pub fn context(&self) -> &TranscriptV3 {
        self.context
    }
    #[must_use]
    pub fn local_account_id(&self) -> &str {
        self.account_id
    }
}
impl FullBootstrap {
    /// Build/sign the exact datastore-prepared base after BOTH local SAS confirmations.
    /// Start/opening are frozen once; exact retries return the original signed object
    /// without another signer call. These are data-only operands, not publication approval.
    /// # Errors
    /// Refuses another role/phase, cancellation, changed prepared operands or wrong signature.
    pub fn prepare_source_start(
        &mut self,
        prepared: &PreparedFullSource,
        now: u64,
        sign: impl FnOnce(&FullSourceManifestSigningRequest<'_>) -> Result<String, SdkError>,
    ) -> Result<(SourceManifest, StartFull), SdkError> {
        self.live(now)?;
        if self.role != PairingRole::Initiator || self.phase != Phase::Start {
            return self.fail("WrongContext");
        }
        if prepared.is_cancelled() {
            return self.fail("Cancelled");
        }
        let encoding = prepared.encoding();
        let common = &self.context.initiator.common;
        let body = Manifest {
            schema: "ramflux.pairing.full_transfer.manifest.v1".into(),
            version: 1,
            transfer_id: common.transfer_id.clone().ok_or(SdkError::PairingCode("WrongContext"))?,
            account_anchor: common.account_anchor.clone(),
            source_ref: self.context.initiator.device_ref.clone(),
            destination_ref: self.context.responder.device_ref.clone(),
            base_record_hash: common.record_hash.clone(),
            snapshot_id: prepared.snapshot_id().into(),
            snapshot_cut: U64(0),
            previous_cut: None,
            parent_manifest_hash: None,
            kind: ManifestKind::Base,
            source_erasure_generation: U64(encoding.source_erasure_generation),
            storage_generation: U64(encoding.storage_generation),
            census_hash: encode_base64url(encoding.schema.census_hash),
            families: encoding.schema.families.clone(),
            total_bytes: U64(encoding.total_bytes),
            chunk_bytes: U64(u64::from(CHUNK_BYTES)),
            chunk_count: U64(encoding.chunk_count),
            chunks_root: encode_base64url(encoding.chunks_root),
            attachment_policy: "remote_ciphertext".into(),
        };
        body.validate().map_err(|error| wire(&error))?;
        if let Some((manifest, start, scope)) = &self.prepared_source {
            if *scope != prepared.fingerprint() || manifest.manifest != body {
                return self.fail("Replay");
            }
            return Ok((manifest.clone(), start.clone()));
        }
        let signature = sign(&FullSourceManifestSigningRequest {
            manifest: &body,
            context: &self.context,
            account_id: prepared.local_account_id(),
        })?;
        ramflux_crypto::verify_canonical_signature(
            &body.signing_bytes().map_err(|error| wire(&error))?,
            &signature,
            &self.context.initiator.branch_key,
        )?;
        if prepared.is_cancelled() {
            return self.fail("Cancelled");
        }
        let manifest = SourceManifest { manifest: body, source_signature: signature };
        let hash = manifest_hash(&manifest).map_err(|error| wire(&error))?;
        let opening = Zeroizing::new(ramflux_crypto::random_32()?);
        let start = StartFull {
            kind: "start_full".into(),
            profile: PROFILE.into(),
            manifest_hash: encode_base64url(hash),
            opaque_commitment: encode_base64url(opaque_commitment(&hash, &opening)),
            commitment_opening: SecretBase64::from_bytes(opening.as_slice()),
            snapshot_id: prepared.snapshot_id().into(),
            transfer_id: manifest.manifest.transfer_id.clone(),
        };
        start.validate().map_err(|error| wire(&error))?;
        self.prepared_source = Some((manifest.clone(), start.clone(), prepared.fingerprint()));
        Ok((manifest, start))
    }
}

// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! A complete bounded canonical manifest precedes any chunk/stage admission.
use super::{
    CHUNK_BYTES, DataPacket, MANIFEST_BYTES, PairingWire, Result, SourceManifest, WireError, b32,
    manifest_hash, require,
};
use zeroize::Zeroizing;

#[derive(Default)]
enum State {
    #[default]
    Empty,
    Collecting {
        hash: String,
        total: usize,
        bytes: Zeroizing<Vec<u8>>,
    },
    Complete,
    Poisoned,
}
/// Device-local assembly of already authenticated manifest packets, at most 1 MiB.
/// This validates framing/hash/canonical encoding only. The endpoint must still verify
/// its own compiled catalog, original branch signature, durable ledger and native scope.
/// Dropping or refusing an assembly wipes its partial bytes; restart retransmits offset0.
#[derive(Default)]
pub struct ManifestAssembler {
    state: State,
}
impl ManifestAssembler {
    /// Accept bounded consecutive parts, or an exact retained retry.
    /// A refusal retires this assembler; only a fresh owner can begin again. A complete
    /// object is returned once, before the separate staging owner checks/adopts it.
    /// # Errors
    /// Refuses changed operands/bytes, gaps/overlap, bounds, malformed/noncanonical objects
    /// or a digest differing from the declared complete signed manifest hash.
    pub fn push(&mut self, packet: &DataPacket) -> Result<Option<SourceManifest>> {
        let result = self.push_inner(packet);
        if result.is_err() {
            self.state = State::Poisoned;
        }
        result
    }
    fn push_inner(&mut self, packet: &DataPacket) -> Result<Option<SourceManifest>> {
        let mismatch = || WireError::Field("ManifestMismatch");
        require(matches!(self.state, State::Empty | State::Collecting { .. }), "ManifestMismatch")?;
        let DataPacket::Manifest { manifest_hash: hash, offset, total, bytes } = packet else {
            return Err(mismatch());
        };
        b32(hash, "manifest_hash")?;
        let total = usize::try_from(total.0).map_err(|_| mismatch())?;
        let offset = usize::try_from(offset.0).map_err(|_| mismatch())?;
        require(total > 0 && total <= MANIFEST_BYTES && offset < total, "ManifestMismatch")?;
        let part = bytes.decode(CHUNK_BYTES as usize)?;
        require(!part.is_empty() && part.len() <= total - offset, "ManifestMismatch")?;
        if matches!(self.state, State::Empty) {
            require(offset == 0, "ManifestMismatch")?;
            self.state = State::Collecting {
                hash: hash.clone(),
                total,
                bytes: Zeroizing::new(Vec::with_capacity(total)),
            };
        }
        let State::Collecting { hash: expected_hash, total: expected_total, bytes } =
            &mut self.state
        else {
            return Err(mismatch());
        };
        require(*expected_hash == *hash && *expected_total == total, "ManifestMismatch")?;
        if offset < bytes.len() {
            require(
                bytes.get(offset..offset + part.len()) == Some(part.as_slice()),
                "ManifestMismatch",
            )?;
            return Ok(None);
        }
        require(offset == bytes.len(), "ManifestMismatch")?;
        bytes.extend_from_slice(&part);
        if bytes.len() != total {
            return Ok(None);
        }
        let State::Collecting { hash, bytes, .. } = std::mem::take(&mut self.state) else {
            return Err(mismatch());
        };
        let manifest = SourceManifest::from_wire_bytes(&bytes)?;
        let canonical = Zeroizing::new(manifest.to_wire_bytes()?);
        require(canonical.as_slice() == bytes.as_slice(), "ManifestMismatch")?;
        require(crate::encode_base64url(manifest_hash(&manifest)?) == hash, "ManifestMismatch")?;
        self.state = State::Complete;
        Ok(Some(manifest))
    }
}

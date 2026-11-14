// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! One bounded candidate record on the authenticated full channel; no authority grant.
use crate::SdkError;
use ramflux_protocol::{
    canonical_json_bytes,
    custody::{DeviceSet, Envelope, object_hash, pairing::full_transfer::FullControlPayload},
};
use zeroize::{Zeroize, Zeroizing};
const CANDIDATE_BYTES: usize = 524_288;
const PART_BYTES: usize = 8192;
fn wrong() -> SdkError {
    SdkError::PairingCode("WrongContext")
}

pub(super) struct CandidateAssembly {
    invitation: String,
    transfer: String,
    record_hash: Option<String>,
    total: Option<usize>,
    next: u64,
    bytes: Zeroizing<Vec<u8>>,
    retired: bool,
}
impl CandidateAssembly {
    pub(super) fn new(invitation: String, transfer: String) -> Self {
        Self {
            invitation,
            transfer,
            record_hash: None,
            total: None,
            next: 0,
            bytes: Zeroizing::new(Vec::new()),
            retired: false,
        }
    }
    pub(super) fn push(
        &mut self,
        payload: &FullControlPayload,
    ) -> Result<Option<Envelope<DeviceSet>>, SdkError> {
        let result = self.accept(payload);
        if result.is_err() {
            self.retired = true;
            self.bytes.zeroize();
        }
        result
    }
    fn accept(
        &mut self,
        payload: &FullControlPayload,
    ) -> Result<Option<Envelope<DeviceSet>>, SdkError> {
        payload.require_sender("responder").map_err(|_| wrong())?;
        if self.retired {
            return Err(wrong());
        }
        match payload {
            FullControlPayload::CandidateReady { transfer_id, record_hash, compacted_ids_hash } => {
                if transfer_id != &self.transfer || self.record_hash.is_some() {
                    return Err(wrong());
                }
                // Annex D permits a capacity refusal when an unchanged compacted list
                // cannot be reconstructed. Never import a peer-supplied tombstone list.
                if compacted_ids_hash.is_some() {
                    return Err(SdkError::PairingCode("TransferCapacity"));
                }
                self.record_hash = Some(record_hash.clone());
                Ok(None)
            }
            FullControlPayload::ArtifactChunk { object_id, index, total_bytes, bytes, .. } => {
                if self.record_hash.is_none()
                    || object_id != &self.invitation
                    || *index != self.next
                {
                    return Err(wrong());
                }
                let total = usize::try_from(*total_bytes).map_err(|_| wrong())?;
                if total == 0
                    || total > CANDIDATE_BYTES
                    || self.total.is_some_and(|saved| saved != total)
                {
                    return Err(wrong());
                }
                let part = bytes.decode(PART_BYTES).map_err(|_| wrong())?;
                if part.len() > total.saturating_sub(self.bytes.len()) {
                    return Err(wrong());
                }
                self.total = Some(total);
                self.bytes.extend_from_slice(&part);
                self.next += 1;
                if self.bytes.len() != total {
                    return Ok(None);
                }
                self.retired = true;
                let record: Envelope<DeviceSet> =
                    ramflux_protocol::custody::decode(&self.bytes, CANDIDATE_BYTES)?;
                if canonical_json_bytes(&record)?.as_slice() != self.bytes.as_slice()
                    || Some(object_hash(&record)?).as_ref() != self.record_hash.as_ref()
                {
                    return Err(wrong());
                }
                self.bytes.zeroize();
                Ok(Some(record))
            }
            _ => Err(wrong()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ramflux_protocol::{custody::pairing::full_transfer::SecretBase64, encode_base64url};
    fn assembly() -> CandidateAssembly {
        CandidateAssembly::new(encode_base64url([1; 32]), encode_base64url([2; 32]))
    }
    fn ready() -> FullControlPayload {
        FullControlPayload::CandidateReady {
            transfer_id: encode_base64url([2; 32]),
            record_hash: encode_base64url([3; 32]),
            compacted_ids_hash: None,
        }
    }
    fn part(index: u64, total: u64, bytes: &[u8]) -> FullControlPayload {
        FullControlPayload::ArtifactChunk {
            object_kind: "candidate".into(),
            object_id: encode_base64url([1; 32]),
            index,
            count: total.div_ceil(8192),
            total_bytes: total,
            bytes: SecretBase64::from_bytes(bytes),
        }
    }
    #[test]
    fn pairing_full_candidate_assembly_retires_on_unannounced_crossed_gapped_or_changed_parts()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut unannounced = assembly();
        assert!(
            unannounced.push(&part(0, 1, b"x")).is_err(),
            "test: unannounced candidate consumed payload"
        );
        assert!(unannounced.push(&ready()).is_err(), "test: refused candidate assembly was reused");
        let mut crossed = assembly();
        crossed.push(&ready())?;
        let mut foreign = part(0, 1, b"x");
        if let FullControlPayload::ArtifactChunk { object_id, .. } = &mut foreign {
            *object_id = encode_base64url([9; 32]);
        }
        assert!(crossed.push(&foreign).is_err(), "test: candidate ignored invitation binding");
        let mut gapped = assembly();
        gapped.push(&ready())?;
        assert!(
            gapped.push(&part(1, 8193, b"x")).is_err(),
            "test: candidate skipped its first chunk"
        );
        let mut repeated = assembly();
        repeated.push(&ready())?;
        let bytes = [42; 8192];
        repeated.push(&part(0, 8193, &bytes))?;
        assert!(
            repeated.push(&part(0, 8193, &bytes)).is_err(),
            "test: candidate replay consumed another counter position"
        );
        assert!(repeated.bytes.is_empty(), "test: poisoned assembly retained partial candidate");
        let mut changed = assembly();
        changed.push(&ready())?;
        changed.push(&part(0, 8193, &bytes))?;
        assert!(
            changed.push(&part(1, 8194, b"xy")).is_err(),
            "test: candidate total changed midstream"
        );
        let mut malformed = assembly();
        malformed.push(&ready())?;
        assert!(
            malformed.push(&part(0, 1, b"x")).is_err(),
            "test: untyped candidate bytes reached authority inspection"
        );
        Ok(())
    }
}

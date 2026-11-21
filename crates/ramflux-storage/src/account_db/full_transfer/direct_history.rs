// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Narrow native history records; transfer authentication and erasure remain separate gates.
use crate::StorageError;
use prost::Message as _;
use ramflux_crypto::native_origin::{
    DirectEvidence, DirectVersion, Kind, OriginalHeader, OwnAuthoredCapture, OwnSentAttestation,
    RetainedOrigin, Routing,
};
use ramflux_protocol::message as g;
use std::io::{Read as _, Write};
use zeroize::{Zeroize as _, Zeroizing};

const PART_LIMIT: usize = super::super::raw_inner::MAX_HISTORY_CONTAINER_BYTES;
const MAGIC: &[u8; 4] = b"NDH1";
const ROOT_BYTES: usize = 43;
const PREFIX_BYTES: usize = MAGIC.len() + 1 + 2 * ROOT_BYTES + 8;
/// Two independently bounded native history parts, never an arbitrary metadata allowance.
pub const FULL_DIRECT_HISTORY_LIMIT: usize = PREFIX_BYTES + 2 * PART_LIMIT;

#[derive(Clone, Copy)]
enum Class {
    Received = 1,
    Authored = 2,
    OwnCopy = 3,
}

/// A typed portable native version under an independently authenticated same-account
/// transfer carrier. This record grants no permission, local cursor or erasure bypass.
pub struct FullDirectHistory {
    own: String,
    peer: String,
    class: Class,
    item: g::HistoryItem,
    attestation: Option<OwnSentAttestation>,
}
fn invalid() -> StorageError {
    StorageError::PairingField("UnsupportedRecord")
}
impl Drop for FullDirectHistory {
    fn drop(&mut self) {
        self.item.exact_inner.zeroize();
        if let Some(proof) = self.item.source_evidence.as_mut() {
            proof.report_opening.zeroize();
            proof.group_opening.zeroize();
            proof.group_plaintext.zeroize();
        }
    }
}
impl FullDirectHistory {
    /// Retain the existing native Message/Edit history item without forwarding authority.
    /// # Errors
    /// Refuses missing or invalid original proofs, foreign scope and unsupported shapes.
    pub fn received(own: &str, peer: &str, item: g::HistoryItem) -> Result<Self, StorageError> {
        let value = Self {
            own: own.into(),
            peer: peer.into(),
            class: Class::Received,
            item,
            attestation: None,
        };
        value.verify(own)?;
        Ok(value)
    }
    /// Project authored content away from transport, callback and context execution fields.
    /// # Errors
    /// Refuses a capture that is not exact own-account direct native history.
    pub fn authored(
        own: &str,
        peer: &str,
        capture: &OwnAuthoredCapture,
    ) -> Result<Self, StorageError> {
        capture.check_direct(own).map_err(|_| invalid())?;
        let item = g::HistoryItem {
            exact_inner: capture.sent.exact_inner.clone(),
            exact_original_identity: capture.original.encode_to_vec(),
            ..Default::default()
        };
        let value = Self {
            own: own.into(),
            peer: peer.into(),
            class: Class::Authored,
            item,
            attestation: None,
        };
        value.verify(own)?;
        Ok(value)
    }
    /// Preserve the exact enclosing own-root signature and separately carried original data.
    /// # Errors
    /// Refuses mismatched exact bytes, roots, original identity or unsupported native content.
    pub fn own_copy(
        own: &str,
        peer: &str,
        exact_inner: Vec<u8>,
        original: &g::EventIdentity,
        attestation: OwnSentAttestation,
    ) -> Result<Self, StorageError> {
        let item = g::HistoryItem {
            exact_inner,
            exact_original_identity: original.encode_to_vec(),
            ..Default::default()
        };
        let value = Self {
            own: own.into(),
            peer: peer.into(),
            class: Class::OwnCopy,
            item,
            attestation: Some(attestation),
        };
        value.verify(own)?;
        Ok(value)
    }
    #[must_use]
    pub fn exact_inner(&self) -> &[u8] {
        &self.item.exact_inner
    }
    #[must_use]
    pub fn peer_root(&self) -> &str {
        &self.peer
    }

    /// Verify against the authenticated transfer account, never an embedded account claim alone.
    /// Own-account data still requires the enclosing authenticated contribution.
    /// # Errors
    /// Refuses another account, mixed proof classes, missing originals or invalid native proofs.
    pub fn verify(&self, own: &str) -> Result<DirectVersion, StorageError> {
        if self.own != own || self.item.encoded_len() > PART_LIMIT || self.item.tombstone.is_some()
        {
            return Err(invalid());
        }
        let decoded = g::Inner::decode(self.item.exact_inner.as_slice()).map_err(|_| invalid())?;
        let current = decoded.identity.as_ref().ok_or_else(invalid)?;
        let original = if self.item.exact_original_identity.is_empty() {
            None
        } else {
            Some(
                g::original_header::decode_identity(&self.item.exact_original_identity)
                    .map_err(|_| invalid())?,
            )
        };
        let (origin, header);
        let evidence = match self.class {
            Class::Received => {
                if self.attestation.is_some() {
                    return Err(invalid());
                }
                origin = RetainedOrigin {
                    evidence: self.item.source_evidence.clone().ok_or_else(invalid)?,
                    reported_inner: Vec::new(),
                    routing: Routing {
                        kind: Kind::Direct,
                        conversation_id: current.conversation_id.clone(),
                        message_id: ramflux_protocol::encode_base64url(&current.id),
                        group_id: None,
                        group_message_id: None,
                        attachments: false,
                    },
                };
                header = match (&original, &self.item.original_metadata_evidence) {
                    (Some(_), Some(proof)) => Some(OriginalHeader {
                        exact_identity: self.item.exact_original_identity.clone(),
                        evidence: proof.clone(),
                    }),
                    (None, None) => None,
                    _ => return Err(invalid()),
                };
                DirectEvidence::Received { origin: &origin, original: header.as_ref() }
            }
            Class::Authored | Class::OwnCopy => {
                if self.item.source_evidence.is_some()
                    || self.item.original_metadata_evidence.is_some()
                {
                    return Err(invalid());
                }
                let original = original.as_ref().ok_or_else(invalid)?;
                match self.class {
                    Class::Authored if self.attestation.is_none() => {
                        DirectEvidence::AuthoredData { original }
                    }
                    Class::OwnCopy => {
                        if decoded.kind == 1 && original != current {
                            return Err(invalid());
                        }
                        DirectEvidence::OwnCopy {
                            attestation: self.attestation.as_ref().ok_or_else(invalid)?,
                            original: (decoded.kind == 3).then_some(original),
                        }
                    }
                    _ => return Err(invalid()),
                }
            }
        };
        DirectVersion::verify(&self.item.exact_inner, own, &self.peer, evidence)
            .map_err(|_| invalid())
    }

    /// Encode a private versioned record; callers own encrypted spooling and rollback.
    /// # Errors
    /// Refuses native bounds, invalid proof data or output failures.
    pub fn write(&self, output: &mut impl Write) -> Result<(), StorageError> {
        self.verify(&self.own)?;
        let item = Zeroizing::new(self.item.encode_to_vec());
        let mut proof = Limited::default();
        if let Some(attestation) = &self.attestation {
            serde_json::to_writer(&mut proof, attestation).map_err(|_| invalid())?;
        }
        output.write_all(MAGIC)?;
        output.write_all(&[self.class as u8])?;
        output.write_all(self.own.as_bytes())?;
        output.write_all(self.peer.as_bytes())?;
        write_part(output, &item)?;
        write_part(output, &proof.0)?;
        Ok(())
    }

    /// Decode only a bounded exact private record from an authenticated account contribution.
    /// # Errors
    /// Refuses old/unknown formats, trailing bytes, noncanonical protobuf, wrong account or proof.
    pub fn read(mut bytes: &[u8], own: &str) -> Result<Self, StorageError> {
        if bytes.len() > FULL_DIRECT_HISTORY_LIMIT || take(&mut bytes, MAGIC.len())? != MAGIC {
            return Err(invalid());
        }
        let mut tag = [0];
        bytes.read_exact(&mut tag)?;
        let class = match tag {
            [1] => Class::Received,
            [2] => Class::Authored,
            [3] => Class::OwnCopy,
            _ => return Err(invalid()),
        };
        let embedded = std::str::from_utf8(take(&mut bytes, ROOT_BYTES)?).map_err(|_| invalid())?;
        let peer = std::str::from_utf8(take(&mut bytes, ROOT_BYTES)?).map_err(|_| invalid())?;
        if embedded != own {
            return Err(invalid());
        }
        let encoded = read_part(&mut bytes)?;
        let item = g::HistoryItem::decode(encoded).map_err(|_| invalid())?;
        let mut value =
            Self { own: embedded.into(), peer: peer.into(), class, item, attestation: None };
        if Zeroizing::new(value.item.encode_to_vec()).as_slice() != encoded {
            return Err(invalid());
        }
        let proof = read_part(&mut bytes)?;
        if !proof.is_empty() {
            value.attestation =
                Some(ramflux_protocol::parse_i_json_secret(proof).map_err(|_| invalid())?);
        }
        if !bytes.is_empty() {
            return Err(invalid());
        }
        value.verify(own)?;
        Ok(value)
    }
}
fn take<'a>(bytes: &mut &'a [u8], count: usize) -> Result<&'a [u8], StorageError> {
    let part = bytes.get(..count).ok_or_else(invalid)?;
    *bytes = bytes.get(count..).ok_or_else(invalid)?;
    Ok(part)
}
fn read_part<'a>(bytes: &mut &'a [u8]) -> Result<&'a [u8], StorageError> {
    let mut length = [0; 4];
    bytes.read_exact(&mut length)?;
    let length = usize::try_from(u32::from_be_bytes(length)).map_err(|_| invalid())?;
    if length > PART_LIMIT {
        return Err(invalid());
    }
    take(bytes, length)
}
fn write_part(output: &mut impl Write, bytes: &[u8]) -> Result<(), StorageError> {
    if bytes.len() > PART_LIMIT {
        return Err(invalid());
    }
    output.write_all(&u32::try_from(bytes.len()).map_err(|_| invalid())?.to_be_bytes())?;
    output.write_all(bytes)?;
    Ok(())
}
#[derive(Default)]
struct Limited(Zeroizing<Vec<u8>>);
impl Write for Limited {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if self.0.len().checked_add(bytes.len()).is_none_or(|length| length > PART_LIMIT) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "native history part bound",
            ));
        }
        self.0.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

// Physical field admission has no authenticated account operand. Semantic import must
// still call read with the stage account; this embedded claim alone grants no receipt.
pub(super) fn payload_account(bytes: &[u8]) -> Result<&str, StorageError> {
    let start = MAGIC.len() + 1;
    std::str::from_utf8(bytes.get(start..start + ROOT_BYTES).ok_or_else(invalid)?)
        .map_err(|_| invalid())
}

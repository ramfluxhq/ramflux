// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain
//! Shared deterministic backend contract, enabled only for test support.
#![allow(clippy::unwrap_used, clippy::too_many_lines)]
use super::{AttachmentBackend, BackendSegment};
use ed25519_dalek::{Signer, SigningKey};
use ramflux_protocol::large_attachment::{ContentManifest, QualifiedOwner, SegmentLayout};
use std::io::Cursor;
/// Runs identical bounds, retry, persistence and cleanup assertions for each adapter.
/// # Panics
/// Panics if the adapter violates its contract. The callback owns an isolated test store.
pub fn contract_suite<B: AttachmentBackend>(
    make_backend: impl FnOnce(&BackendSegment) -> (B, Vec<u8>),
) {
    let bytes = vec![71; 524_305];
    let domain = b"ramflux.attachment.segment.cipher.v1";
    let mut preimage = u32::try_from(domain.len()).unwrap().to_be_bytes().to_vec();
    preimage.extend(domain);
    preimage.extend(u32::try_from(bytes.len()).unwrap().to_be_bytes());
    preimage.extend(&bytes);
    let key = SigningKey::from_bytes(&[93; 32]);
    let native = ContentManifest {
        object_id: [81; 32],
        owner: QualifiedOwner {
            account_anchor: "contract-owner".into(),
            device_id: "contract-device".into(),
            device_epoch: 1,
            signing_public_key: key.verifying_key().to_bytes(),
            home_node_id: "contract-node".into(),
        },
        layout: SegmentLayout { plaintext_length: 524_289, network_chunk_bytes: 524_288 },
        segment_digests: vec![*blake3::hash(&preimage).as_bytes()],
    };
    let signature = key.sign(&native.signing_bytes().unwrap()).to_bytes();
    let verified =
        ContentManifest::decode_signed(&native.signed_bytes(&signature).unwrap()).unwrap();
    let spec = BackendSegment::from_manifest(&verified, 1, 0).unwrap();
    let (backend, cursor) = make_backend(&spec);
    assert!(backend.write_chunk(&spec, 1, &mut Cursor::new(&bytes[..524_288])).is_err());
    assert!(backend.write_chunk(&spec, 0, &mut Cursor::new(&bytes[..15])).is_err());
    assert!(backend.write_chunk(&spec, 0, &mut Cursor::new(&bytes[..524_289])).is_err());
    backend.write_chunk(&spec, 0, &mut Cursor::new(&bytes[..524_288])).unwrap();
    backend.write_chunk(&spec, 0, &mut Cursor::new(&bytes[..524_288])).unwrap();
    assert!(backend.write_chunk(&spec, 0, &mut Cursor::new(vec![72; 524_288])).is_err());
    assert!(backend.commit(&spec).is_err());
    assert!(backend.read_range(&spec, 0, 16, &mut Vec::new()).is_err());
    backend.write_chunk(&spec, 524_288, &mut Cursor::new(&bytes[524_288..])).unwrap();
    backend.commit(&spec).unwrap();
    backend.commit(&spec).unwrap();
    assert!(backend.read_range(&spec, 0, 524_289, &mut Vec::new()).is_err());
    assert!(backend.read_range(&spec, 524_300, 6, &mut Vec::new()).is_err());
    let mut out = Vec::new();
    backend.read_range(&spec, 524_280, 25, &mut out).unwrap();
    assert_eq!(out, bytes[524_280..]);
    backend.reconcile(&spec).unwrap();
    let page = backend.enumerate(None, 1).unwrap();
    assert_eq!(page.len(), 1);
    assert!(page[0].committed);
    assert!(backend.enumerate(Some(&cursor), 1).unwrap().is_empty());
    assert!(backend.enumerate(None, 129).is_err());
    assert!(backend.enumerate(Some(&[0]), 1).is_err());
    backend.delete(&spec).unwrap();
    backend.delete(&spec).unwrap();
    assert!(backend.enumerate(None, 128).unwrap().is_empty());
    assert!(backend.read_range(&spec, 0, 16, &mut Vec::new()).is_err());
    assert!(backend.commit(&spec).is_err());
    assert!(backend.write_chunk(&spec, 0, &mut Cursor::new(&bytes[..524_288])).is_err());
}

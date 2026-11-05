// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain
//! Shared deterministic backend contract, enabled only for test support.
#![allow(clippy::unwrap_used, clippy::too_many_lines)]
use super::{AttachmentBackend, BackendError, BackendSegment};
use ed25519_dalek::{Signer, SigningKey};
use ramflux_protocol::large_attachment::{ContentManifest, QualifiedOwner, SegmentLayout};
use std::io::Cursor;
fn digest(bytes: &[u8]) -> [u8; 32] {
    let domain = b"ramflux.attachment.segment.cipher.v1";
    let mut preimage = u32::try_from(domain.len()).unwrap().to_be_bytes().to_vec();
    preimage.extend(domain);
    preimage.extend(u32::try_from(bytes.len()).unwrap().to_be_bytes());
    preimage.extend(bytes);
    *blake3::hash(&preimage).as_bytes()
}
/// Runs identical typed-error, retry, persistence and cleanup assertions for each adapter.
/// # Panics
/// Panics if the adapter violates its contract. The callback owns an isolated test store.
pub fn contract_suite<B: AttachmentBackend>(
    make_backend: impl FnOnce(&BackendSegment, &BackendSegment) -> (B, [Vec<u8>; 2]),
) {
    let bytes = vec![71; 4_194_304];
    let tail = vec![73; 524_305];
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
        layout: SegmentLayout { plaintext_length: 4_718_577, network_chunk_bytes: 524_288 },
        segment_digests: vec![digest(&bytes), digest(&tail)],
    };
    let signature = key.sign(&native.signing_bytes().unwrap()).to_bytes();
    let verified =
        ContentManifest::decode_signed(&native.signed_bytes(&signature).unwrap()).unwrap();
    let spec = BackendSegment::from_manifest(&verified, 1, 0).unwrap();
    let second = BackendSegment::from_manifest(&verified, 1, 1).unwrap();
    let (backend, [first_cursor, second_cursor]) = make_backend(&spec, &second);
    assert!(matches!(
        backend.write_chunk(&spec, 1, &mut Cursor::new(&bytes[..524_288])),
        Err(BackendError::Bounds)
    ));
    assert!(matches!(
        backend.write_chunk(&spec, 0, &mut Cursor::new(&bytes[..15])),
        Err(BackendError::Integrity)
    ));
    assert!(matches!(
        backend.write_chunk(&spec, 0, &mut Cursor::new(&bytes[..524_289])),
        Err(BackendError::Bounds)
    ));
    backend.write_chunk(&spec, 0, &mut Cursor::new(&bytes[..524_288])).unwrap();
    backend.write_chunk(&spec, 0, &mut Cursor::new(&bytes[..524_288])).unwrap();
    assert!(matches!(
        backend.write_chunk(&spec, 0, &mut Cursor::new(vec![72; 524_288])),
        Err(BackendError::Conflict)
    ));
    assert!(matches!(backend.commit(&spec), Err(BackendError::Integrity)));
    assert!(matches!(
        backend.read_range(&spec, 0, 16, &mut Vec::new()),
        Err(BackendError::Integrity)
    ));
    for (index, chunk) in bytes.chunks(524_288).enumerate().skip(1) {
        backend
            .write_chunk(&spec, u64::try_from(index).unwrap() * 524_288, &mut Cursor::new(chunk))
            .unwrap();
    }
    for (index, chunk) in tail.chunks(524_288).enumerate() {
        backend
            .write_chunk(&second, u64::try_from(index).unwrap() * 524_288, &mut Cursor::new(chunk))
            .unwrap();
    }
    backend.commit(&spec).unwrap();
    backend.commit(&spec).unwrap();
    backend.commit(&second).unwrap();
    assert!(matches!(
        backend.read_range(&spec, 0, 524_289, &mut Vec::new()),
        Err(BackendError::Bounds)
    ));
    assert!(matches!(
        backend.read_range(&spec, spec.length() - 5, 6, &mut Vec::new()),
        Err(BackendError::Bounds)
    ));
    let mut out = Vec::new();
    backend.read_range(&spec, 524_280, 25, &mut out).unwrap();
    assert_eq!(out, bytes[524_280..524_305]);
    backend.reconcile(&spec).unwrap();
    let page = backend.enumerate(None, 1).unwrap();
    assert_eq!(page.len(), 1);
    assert_eq!(page[0].spec, spec);
    assert!(page[0].committed);
    let page = backend.enumerate(Some(&first_cursor), 1).unwrap();
    assert_eq!(page.len(), 1);
    assert_eq!(page[0].spec, second);
    assert!(page[0].committed);
    assert!(backend.enumerate(Some(&second_cursor), 1).unwrap().is_empty());
    assert!(matches!(backend.enumerate(None, 129), Err(BackendError::Bounds)));
    assert!(matches!(backend.enumerate(Some(&[0]), 1), Err(BackendError::Bounds)));
    let stale = BackendSegment::from_manifest(&verified, 2, 0).unwrap();
    assert!(matches!(
        backend.write_chunk(&stale, 0, &mut Cursor::new(&bytes[..524_288])),
        Err(BackendError::Conflict)
    ));
    backend.delete(&spec).unwrap();
    backend.delete(&spec).unwrap();
    backend.delete(&second).unwrap();
    assert!(backend.enumerate(None, 128).unwrap().is_empty());
    assert!(matches!(
        backend.read_range(&spec, 0, 16, &mut Vec::new()),
        Err(BackendError::Retired)
    ));
    assert!(matches!(backend.commit(&spec), Err(BackendError::Retired)));
    assert!(matches!(
        backend.write_chunk(&spec, 0, &mut Cursor::new(&bytes[..524_288])),
        Err(BackendError::Retired)
    ));
}

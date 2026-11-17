// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use super::{FormatError, MediaKeySlot, QualifiedDevice};

fn slot(grant: Vec<u8>, capability: Vec<u8>) -> MediaKeySlot {
    MediaKeySlot {
        recipient: QualifiedDevice {
            account_anchor: "anchor".into(),
            device_id: "device".into(),
            device_epoch: 2,
        },
        encrypted_key: vec![9; 80],
        format: 1,
        grant_id: grant,
        read_capability: capability,
    }
}

#[test]
fn slot_tags_four_and_five_round_trip_and_unknown_tags_fail() -> Result<(), FormatError> {
    let full = slot(vec![3; 32], b"capability".to_vec());
    let bytes = full.encode()?;
    assert_eq!(MediaKeySlot::decode(&bytes)?, full);
    let shared = slot(Vec::new(), Vec::new());
    assert_eq!(shared.encode(), Err(FormatError("key slot")), "a slot without a grant is refused");
    let mut unknown = bytes.clone();
    unknown.extend_from_slice(&[6 << 3 | 2, 1, 1]);
    assert_eq!(MediaKeySlot::decode(&unknown), Err(FormatError("unknown slot field")));
    assert_eq!(slot(vec![1; 31], b"capability".to_vec()).encode(), Err(FormatError("key slot")));
    assert_eq!(slot(Vec::new(), b"capability".to_vec()).encode(), Err(FormatError("key slot")));
    assert_eq!(slot(vec![3; 32], vec![7; 8193]).encode(), Err(FormatError("key slot")));
    Ok(())
}

fn manifest(slots: Vec<MediaKeySlot>, shared: Vec<u8>) -> super::MediaManifest {
    super::MediaManifest {
        manifest_id: [1; 32],
        plaintext_digest: [2; 32],
        plaintext_length: 0,
        ciphertext_length: 16,
        encrypted_segment_bytes: super::SEGMENT_BYTES,
        network_chunk_bytes: 524_288,
        segment_digests: vec![[3; 32]],
        key_slots: slots,
        relay_origin: "relay".into(),
        read_capability: shared,
        expires_at: 9,
        retention_class: "relay_retained.v1".into(),
    }
}

#[test]
fn the_shared_manifest_capability_and_unpaired_slot_counts_are_refused() {
    let one = slot(vec![3; 32], b"capability".to_vec());
    assert!(manifest(vec![one.clone()], Vec::new()).canonical_bytes().is_ok(), "one entry is legal");
    assert_eq!(
        manifest(vec![one.clone()], b"shared".to_vec()).canonical_bytes(),
        Err(FormatError("manifest capability")),
        "a manifest-level capability is the retired shared layout"
    );
    assert_eq!(
        manifest(Vec::new(), Vec::new()).canonical_bytes(),
        Err(FormatError("key slot count")),
        "a manifest without entries is refused"
    );
    let mut many = Vec::new();
    for index in 0..65_u64 {
        let mut entry = one.clone();
        entry.recipient.device_epoch = index + 1;
        many.push(entry);
    }
    assert_eq!(
        manifest(many, Vec::new()).canonical_bytes(),
        Err(FormatError("key slot count")),
        "sixty-five entries are over the count ceiling"
    );
}

#[test]
fn two_entries_for_one_target_key_are_refused() {
    let one = slot(vec![3; 32], b"capability".to_vec());
    let mut again = one.clone();
    again.grant_id = vec![4; 32];
    assert_eq!(
        manifest(vec![one.clone(), again], Vec::new()).canonical_bytes(),
        Err(FormatError("duplicate key slot"))
    );
    let mut other_anchor = one.clone();
    other_anchor.recipient.account_anchor = "other".into();
    other_anchor.grant_id = vec![5; 32];
    assert!(
        manifest(vec![one, other_anchor], Vec::new()).canonical_bytes().is_ok(),
        "the same device id under another account anchor is a different device"
    );
}

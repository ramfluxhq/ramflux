// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use super::{SegmentError, SegmentSealer};
use ramflux_protocol::large_attachment::SegmentLayout;

#[test]
fn persisted_sealer_reuses_the_reserved_identity_at_index_zero() -> Result<(), SegmentError> {
    let layout = SegmentLayout { plaintext_length: 4, network_chunk_bytes: 524_288 };
    let key = [9; 32];
    let object = [4; 32];
    let mut first = SegmentSealer::from_persisted(key, object, layout)?;
    let mut second = SegmentSealer::from_persisted(key, object, layout)?;
    assert_eq!(first.object_id(), &object);
    assert_eq!(first.file_key(), &key);
    assert_eq!(first.seal(0, b"abcd")?, second.seal(0, b"abcd")?);
    assert!(matches!(
        SegmentSealer::from_persisted([0; 32], object, layout),
        Err(SegmentError::Persisted)
    ));
    assert!(matches!(
        SegmentSealer::from_persisted(key, [0; 32], layout),
        Err(SegmentError::Persisted)
    ));
    let bad = SegmentLayout { plaintext_length: 1, network_chunk_bytes: 7 };
    assert!(matches!(
        SegmentSealer::from_persisted(key, object, bad),
        Err(SegmentError::Format(_))
    ));
    Ok(())
}

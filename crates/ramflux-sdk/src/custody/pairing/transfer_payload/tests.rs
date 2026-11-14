// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use super::*;
type TestResult = Result<(), Box<dyn std::error::Error>>;

#[test]
fn pairing_retained_floor_artifact_checks_commitment_before_use() -> TestResult {
    let floor = RetainedFloor::Root {
        root: ramflux_protocol::encode_base64url([1; 32]),
        epoch: 2,
        attesting_head: AttestingHead {
            epoch: 3,
            hash: ramflux_protocol::encode_base64url([2; 32]),
        },
    };
    let mut floors = vec![floor; 4096];
    floors.push(RetainedFloor::Device {
        root: ramflux_protocol::encode_base64url([1; 32]),
        device: "secondary".into(),
        epoch: 2,
        attesting_head: AttestingHead {
            epoch: 4,
            hash: ramflux_protocol::encode_base64url([3; 32]),
        },
    });
    let (reference, bytes) = encode_retained_floors(&floors)?;
    assert_eq!(bytes.as_slice(), ramflux_protocol::canonical_json_bytes(&floors)?);
    assert_eq!(decode_retained_floors(&reference, &bytes)?, floors);
    for changed in [
        RetainedFloorsRef { count: reference.count + 1, ..reference.clone() },
        RetainedFloorsRef { total_len: reference.total_len + 1, ..reference.clone() },
        RetainedFloorsRef {
            object_hash: ramflux_protocol::encode_base64url([4; 32]),
            ..reference.clone()
        },
    ] {
        assert!(decode_retained_floors(&changed, &bytes).is_err());
    }
    let over = vec![floors[0].clone(); 8193];
    assert!(matches!(
        encode_retained_floors(&over),
        Err(SdkError::PairingCode("TransferFloorsTooLarge"))
    ));
    let over_bytes = vec![floors[0].clone(); 8192];
    assert!(matches!(
        encode_retained_floors(&over_bytes),
        Err(SdkError::PairingCode("TransferFloorsTooLarge"))
    ));
    let mut raw: serde_json::Value = serde_json::from_slice(&bytes)?;
    raw[0]["phrase"] = serde_json::json!("forbidden");
    assert!(
        decode_retained_floors(&reference, &ramflux_protocol::canonical_json_bytes(&raw)?).is_err()
    );
    Ok(())
}

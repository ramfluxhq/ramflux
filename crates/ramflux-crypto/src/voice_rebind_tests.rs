// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Independent HMAC vectors and every transcript coordinate are checked for both IP families.
use super::*;
type TestResult = Result<(), Box<dyn std::error::Error>>;
#[test]
fn rebind_hmac_matches_independent_ipv4_and_ipv6_sha256_vectors() -> TestResult {
    let key = std::array::from_fn(|i| u8::try_from(i).unwrap_or(0));
    let lease = ramflux_protocol::encode_base64url(std::array::from_fn::<_, 16, _>(|i| {
        u8::try_from(i).unwrap_or(0)
    }));
    let cookie = std::array::from_fn(|i| u8::try_from(i + 32).unwrap_or(0));
    for (address, expected) in [
        (
            "203.0.113.7:54321",
            [
                0x5a, 0x2f, 0xf8, 0xf9, 0xd9, 0xc8, 0x05, 0xd3, 0xa1, 0x58, 0xc9, 0x4d, 0x51, 0xbb,
                0x0b, 0xbe,
            ],
        ),
        (
            "[2001:db8::1234]:54321",
            [
                0x07, 0xd9, 0x11, 0xfa, 0x05, 0x81, 0x4f, 0x8c, 0x69, 0xaf, 0x12, 0xf9, 0x42, 0x0b,
                0x5a, 0xee,
            ],
        ),
    ] {
        let address = address.parse()?;
        let tag = voice_rebind_tag(&key, &lease, 1, &cookie, address)?;
        assert_eq!(tag, expected);
        verify_voice_rebind_tag(&key, &lease, 1, &cookie, address, &tag)?;
        let mut challenge = b"RFVC".to_vec();
        challenge.extend(cookie);
        match address.ip() {
            std::net::IpAddr::V4(ip) => {
                challenge.push(4);
                challenge.extend(ip.octets());
            }
            std::net::IpAddr::V6(ip) => {
                challenge.push(6);
                challenge.extend(ip.octets());
            }
        }
        challenge.extend(address.port().to_be_bytes());
        let response = voice_rebind_response(&key, &lease, 1, &challenge)?;
        assert_eq!(&response[..4], b"RFVE");
        assert_eq!(&response[4..36], &cookie);
        assert_eq!(&response[36..], &tag);
    }
    Ok(())
}
#[test]
fn rebind_proof_rejects_wrong_key_lease_side_cookie_address_and_tag_length() -> TestResult {
    let lease = ramflux_protocol::encode_base64url([1; 16]);
    let cookie = [2; 32];
    let source = "203.0.113.7:54321".parse()?;
    let tag = voice_rebind_tag(&[3; 32], &lease, 0, &cookie, source)?;
    for (key, id, side, nonce, address) in [
        ([4; 32], lease.clone(), 0, cookie, source),
        ([3; 32], ramflux_protocol::encode_base64url([2; 16]), 0, cookie, source),
        ([3; 32], lease.clone(), 1, cookie, source),
        ([3; 32], lease.clone(), 0, [3; 32], source),
        ([3; 32], lease.clone(), 0, cookie, "203.0.113.8:54321".parse()?),
        ([3; 32], lease.clone(), 0, cookie, "203.0.113.7:54322".parse()?),
    ] {
        assert!(verify_voice_rebind_tag(&key, &id, side, &nonce, address, &tag).is_err());
    }
    assert!(verify_voice_rebind_tag(&[3; 32], &lease, 0, &cookie, source, &tag[..15]).is_err());
    for malformed in [&[][..], &b"RFVC"[..], &[0; 55][..]] {
        assert!(voice_rebind_response(&[3; 32], &lease, 0, malformed).is_err());
    }
    Ok(())
}

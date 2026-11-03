// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! RFC 8032 section 7.1 Ed25519 vectors exercised through product signing APIs.
//! Reference: <https://www.rfc-editor.org/rfc/rfc8032.html#section-7.1>
use ed25519_dalek::{Signature, SigningKey};
use ramflux_crypto::{
    CanonicalSignatureBatchItem, CanonicalSignatureSingleKeyBatchItem, public_key_bytes_from_seed,
    sign_canonical_bytes_with_seed, verify_canonical_signature, verify_canonical_signatures_batch,
    verify_canonical_signatures_batch_single_key,
};
use ramflux_protocol::{decode_base64url, encode_base64url};
type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
struct Vector {
    name: &'static str,
    seed: &'static str,
    public: &'static str,
    message: &'static str,
    signature: &'static str,
}
const VECTORS: &[Vector] = &[
    Vector {
        name: "1",
        seed: "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
        public: "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
        message: "",
        signature: "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
    },
    Vector {
        name: "2",
        seed: "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
        public: "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
        message: "72",
        signature: "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
    },
    Vector {
        name: "3",
        seed: "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
        public: "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
        message: "af82",
        signature: "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a",
    },
    Vector {
        name: "SHA(abc)",
        seed: "833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42",
        public: "ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf",
        message: "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
        signature: "dc2a4459e7369633a52b1bf277839a00201009a3efbf3ecb69bea2186c26b58909351fc9ac90b3ecfdfbc7c66431e0303dca179c138ac17ad9bef1177331a704",
    },
];
struct Parsed {
    seed: [u8; 32],
    public: [u8; 32],
    message: Vec<u8>,
    signature: [u8; 64],
}
fn parse(vector: &Vector) -> TestResult<Parsed> {
    Ok(Parsed {
        seed: hex::decode(vector.seed)?.try_into().map_err(|_| "seed length")?,
        public: hex::decode(vector.public)?.try_into().map_err(|_| "key length")?,
        message: hex::decode(vector.message)?,
        signature: hex::decode(vector.signature)?.try_into().map_err(|_| "signature length")?,
    })
}
#[test]
fn rfc8032_signing_and_strict_verification_match_fixed_bytes() -> TestResult {
    for vector in VECTORS {
        let value = parse(vector)?;
        assert_eq!(public_key_bytes_from_seed(value.seed), value.public, "{}", vector.name);
        let signed = sign_canonical_bytes_with_seed(&value.message, value.seed);
        assert_eq!(decode_base64url(&signed)?, value.signature, "{}", vector.name);
        let public = encode_base64url(value.public);
        verify_canonical_signature(&value.message, &signed, &public)?;
        SigningKey::from_bytes(&value.seed)
            .verifying_key()
            .verify_strict(&value.message, &Signature::from_bytes(&value.signature))?;
        let mut changed = value.message;
        changed.push(0x42);
        assert!(verify_canonical_signature(&changed, &signed, &public).is_err());
    }
    Ok(())
}
#[test]
fn rfc8032_vectors_pass_multi_key_and_single_key_batch_wrappers() -> TestResult {
    let values = VECTORS.iter().map(parse).collect::<TestResult<Vec<_>>>()?;
    let items = values
        .iter()
        .map(|v| CanonicalSignatureBatchItem {
            public_key_bytes: &v.public,
            canonical: &v.message,
            signature_bytes: &v.signature,
        })
        .collect::<Vec<_>>();
    assert_eq!(verify_canonical_signatures_batch(&items), Ok(()));
    for value in &values {
        let items = [0, 1].map(|_| CanonicalSignatureSingleKeyBatchItem {
            canonical: &value.message,
            signature_bytes: &value.signature,
        });
        assert_eq!(verify_canonical_signatures_batch_single_key(&value.public, &items), Ok(()));
    }
    Ok(())
}
#[test]
fn noncanonical_s_is_rejected_by_strict_and_both_batch_wrappers() -> TestResult {
    let value = parse(&VECTORS[0])?;
    let mut invalid = value.signature;
    let order = hex::decode("edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010")?;
    let mut carry = 0_u16;
    for (byte, order) in invalid[32..].iter_mut().zip(order) {
        let sum = u16::from(*byte) + u16::from(order) + carry;
        *byte = u8::try_from(sum & 0xff)?;
        carry = sum >> 8;
    }
    assert_eq!(carry, 0);
    assert!(
        verify_canonical_signature(
            &value.message,
            &encode_base64url(invalid),
            &encode_base64url(value.public)
        )
        .is_err()
    );
    let signatures = [value.signature, invalid];
    let items = signatures
        .iter()
        .map(|signature| CanonicalSignatureBatchItem {
            public_key_bytes: &value.public,
            canonical: &value.message,
            signature_bytes: signature,
        })
        .collect::<Vec<_>>();
    assert_eq!(verify_canonical_signatures_batch(&items), Err(vec![1]));
    let items = signatures
        .iter()
        .map(|signature| CanonicalSignatureSingleKeyBatchItem {
            canonical: &value.message,
            signature_bytes: signature,
        })
        .collect::<Vec<_>>();
    assert_eq!(verify_canonical_signatures_batch_single_key(&value.public, &items), Err(vec![1]));
    Ok(())
}
#[test]
fn strict_verification_rejects_small_order_public_key_and_r() -> TestResult {
    let value = parse(&VECTORS[0])?;
    let mut identity = [0; 32];
    identity[0] = 1;
    let mut identity_signature = [0; 64];
    identity_signature[..32].copy_from_slice(&identity);
    assert!(
        verify_canonical_signature(
            b"weak-key",
            &encode_base64url(identity_signature),
            &encode_base64url(identity)
        )
        .is_err()
    );
    let mut invalid = value.signature;
    invalid[..32].copy_from_slice(&identity);
    assert!(
        verify_canonical_signature(
            &value.message,
            &encode_base64url(invalid),
            &encode_base64url(value.public)
        )
        .is_err()
    );
    Ok(())
}

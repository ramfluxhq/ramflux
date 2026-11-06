// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain
use super::{AttachmentToken, FormatError};
use ed25519_dalek::Signer;

type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;

fn bytes(v: &serde_json::Value) -> Result<Vec<u8>> {
    v.as_str()
        .ok_or("hex")?
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|p| Ok(u8::from_str_radix(std::str::from_utf8(p)?, 16)?))
        .collect()
}

fn key32(v: &serde_json::Value) -> Result<[u8; 32]> {
    Ok(bytes(v)?.try_into().map_err(|_| "32 bytes")?)
}

struct Frozen {
    json: serde_json::Value,
    token: Vec<u8>,
    signature: [u8; 64],
    issuer: ed25519_dalek::SigningKey,
}

impl Frozen {
    fn load() -> Result<Self> {
        let json: serde_json::Value = serde_json::from_str(include_str!(
            "../../tests/fixtures/large_attachment_renewal_v1.json"
        ))?;
        let r = &json["renewal"];
        let token = bytes(&r["token"]["bytes_hex"])?;
        let signature = bytes(&r["token"]["signature_hex"])?.try_into().map_err(|_| "sig")?;
        let issuer = ed25519_dalek::SigningKey::from_bytes(&key32(&r["source_issuer_seed_hex"])?);
        Ok(Self { json, token, signature, issuer })
    }

    fn key(&self) -> [u8; 32] {
        self.issuer.verifying_key().to_bytes()
    }

    fn container(token: &[u8], signature: &[u8]) -> Vec<u8> {
        let mut out = u32::try_from(token.len()).unwrap_or(0).to_be_bytes().to_vec();
        out.extend(token);
        out.extend(64_u32.to_be_bytes());
        out.extend(signature);
        out
    }
}

#[test]
fn large_renewal_token_matches_frozen_r4_vector() -> Result {
    let f = Frozen::load()?;
    let r = &f.json["renewal"];
    let t = AttachmentToken::decode(&f.token)?;
    // The token binds Htarget and never the renewal operation hash.
    assert_eq!(t.target_hash, key32(&r["target_ohash_hex"])?);
    assert_ne!(t.target_hash, key32(&r["renewal_ohash_hex"])?);
    assert_eq!(t.requester_digest, key32(&r["requester_key_digest_hex"])?);
    assert_eq!((t.grant_epoch, t.authority_generation, t.rights), (1, 3, 1));
    assert_eq!(t.canonical_bytes()?, f.token);
    assert_eq!(t.signing_bytes()?, bytes(&r["token"]["signing_bytes_hex"])?);
    assert_eq!(f.issuer.sign(&t.signing_bytes()?).to_bytes(), f.signature);
    let signed = Frozen::container(&f.token, &f.signature);
    let verified = AttachmentToken::decode_signed(&signed, &f.key())?;
    assert_eq!(verified.token(), &t);
    assert_eq!(verified.signed_bytes()?, signed);
    assert_eq!(t.signed_bytes(&f.key(), &f.signature)?, signed);

    // Hrenew placed in Ohash: the canonical bytes differ from the vector and the
    // frozen signature no longer verifies.
    let mut swapped = t.clone();
    swapped.target_hash = key32(&r["renewal_ohash_hex"])?;
    let swapped_bytes = swapped.canonical_bytes()?;
    assert_ne!(swapped_bytes, f.token);
    assert_eq!(
        AttachmentToken::decode_signed(&Frozen::container(&swapped_bytes, &f.signature), &f.key()),
        Err(FormatError("grant signature"))
    );

    // Trailing byte on the unsigned token and on the container.
    let mut trailing = f.token.clone();
    trailing.push(0);
    assert_eq!(AttachmentToken::decode(&trailing), Err(FormatError("token framing")));
    let mut container = signed.clone();
    container.push(0);
    assert_eq!(
        AttachmentToken::decode_signed(&container, &f.key()),
        Err(FormatError("token container"))
    );

    // Version 2.
    let mut v2 = f.token.clone();
    v2[7] = 2;
    assert_eq!(AttachmentToken::decode(&v2), Err(FormatError("token version")));

    // Issuer length: 256 bytes is accepted and round-trips, 257 is refused both ways.
    let mut long = t.clone();
    long.token_issuer = "i".repeat(256);
    assert_eq!(AttachmentToken::decode(&long.canonical_bytes()?)?, long);
    long.token_issuer = "i".repeat(257);
    assert_eq!(long.canonical_bytes(), Err(FormatError("native identity length")));
    let mut wire = f.token.clone();
    let issuer_len_at = wire.len() - 16 - t.token_issuer.len() - 4;
    wire[issuer_len_at..issuer_len_at + 4].copy_from_slice(&257_u32.to_be_bytes());
    assert_eq!(AttachmentToken::decode(&wire), Err(FormatError("native identity length")));
    Ok(())
}

#[test]
fn token_lifetime_rights_and_signature_bounds() -> Result {
    let f = Frozen::load()?;
    let t = AttachmentToken::decode(&f.token)?;
    // Vector lifetime is exactly 300 s: the inclusive bound is accepted.
    assert_eq!(t.expires_at - t.issued_at, 300);
    let mut over = t.clone();
    over.expires_at += 1;
    assert_eq!(over.canonical_bytes(), Err(FormatError("token lifetime")));
    over.expires_at = over.issued_at;
    assert_eq!(over.canonical_bytes(), Err(FormatError("token lifetime")));
    for mutate in [
        (|t: &mut AttachmentToken| t.grant_epoch = 0) as fn(&mut AttachmentToken),
        |t| t.authority_generation = 0,
        |t| t.rights = 0,
        |t| t.rights = 32,
    ] {
        let mut bad = t.clone();
        mutate(&mut bad);
        assert_eq!(bad.canonical_bytes(), Err(FormatError("token bounds")));
    }
    let mut flipped = f.signature;
    flipped[0] ^= 1;
    assert_eq!(
        AttachmentToken::decode_signed(&Frozen::container(&f.token, &flipped), &f.key()),
        Err(FormatError("grant signature"))
    );
    let other = ed25519_dalek::SigningKey::from_bytes(&[7; 32]).verifying_key().to_bytes();
    assert_eq!(
        AttachmentToken::decode_signed(&Frozen::container(&f.token, &f.signature), &other),
        Err(FormatError("grant signature"))
    );
    assert_eq!(AttachmentToken::decode(&vec![0; 1025]), Err(FormatError("token cap")));
    Ok(())
}

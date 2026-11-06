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

/// Offsets of the frozen vector token; every case below edits exactly one received field.
struct Layout {
    epoch: usize,
    authority_len: usize,
    generation: usize,
    rights: usize,
    issuer_len: usize,
    expires: usize,
}

fn layout(t: &AttachmentToken) -> Layout {
    let authority_len = 80;
    let generation = authority_len + 4 + t.source_authority.len();
    let rights = generation + 8 + 32;
    let issuer_len = rights + 4;
    let issued = issuer_len + 4 + t.token_issuer.len();
    Layout { epoch: 72, authority_len, generation, rights, issuer_len, expires: issued + 8 }
}

/// Inventory of every error site in `token.rs`/shared cursor, one received-byte case each:
/// token.rs:64 bounds (4), :69 lifetime (3), :116 cap (1), :120 version (2), :135 framing (1),
/// :148 container cap (1), :154/:158 container (2), identity length (4), UTF-8 (1),
/// truncation (2), `grant key` (1), `grant signature` (3). Total 25; `token length` (u32 to usize)
/// cannot fail on supported 64-bit targets.
#[test]
#[allow(clippy::too_many_lines)]
fn token_received_bytes_hit_each_error_site_and_inclusive_boundary() -> Result {
    let f = Frozen::load()?;
    let t = AttachmentToken::decode(&f.token)?;
    let l = layout(&t);
    let base = t.canonical_bytes()?;
    let edit = |f: &dyn Fn(&mut Vec<u8>)| {
        let mut b = base.clone();
        f(&mut b);
        b
    };
    let put32 =
        |b: &mut Vec<u8>, at: usize, v: u32| b[at..at + 4].copy_from_slice(&v.to_be_bytes());
    let put64 =
        |b: &mut Vec<u8>, at: usize, v: u64| b[at..at + 8].copy_from_slice(&v.to_be_bytes());
    let issued = t.issued_at;
    let cases: Vec<(&str, Vec<u8>, &str)> = vec![
        ("epoch 0", edit(&|b| put64(b, l.epoch, 0)), "token bounds"),
        ("generation 0", edit(&|b| put64(b, l.generation, 0)), "token bounds"),
        ("rights 0", edit(&|b| put32(b, l.rights, 0)), "token bounds"),
        ("rights 32", edit(&|b| put32(b, l.rights, 32)), "token bounds"),
        ("expires == issued", edit(&|b| put64(b, l.expires, issued)), "token lifetime"),
        ("expires < issued", edit(&|b| put64(b, l.expires, issued - 1)), "token lifetime"),
        ("lifetime 301", edit(&|b| put64(b, l.expires, issued + 301)), "token lifetime"),
        ("cap", vec![0; 1025], "token cap"),
        ("magic", edit(&|b| b[0] ^= 1), "token version"),
        ("version 2", edit(&|b| b[7] = 2), "token version"),
        ("trailing byte", edit(&|b| b.push(0)), "token framing"),
        ("source authority 0", edit(&|b| put32(b, l.authority_len, 0)), "native identity length"),
        (
            "source authority 257",
            edit(&|b| put32(b, l.authority_len, 257)),
            "native identity length",
        ),
        ("issuer 0", edit(&|b| put32(b, l.issuer_len, 0)), "native identity length"),
        ("issuer 257", edit(&|b| put32(b, l.issuer_len, 257)), "native identity length"),
        ("source authority utf8", edit(&|b| b[l.authority_len + 4] = 0xFF), "native UTF8"),
        (
            "truncated",
            edit(&|b| {
                b.pop();
            }),
            "truncated native",
        ),
    ];
    for (name, bytes, want) in &cases {
        assert_eq!(AttachmentToken::decode(bytes), Err(FormatError(want)), "{name}");
    }

    // Container error sites, each on otherwise valid signed bytes.
    let signed = Frozen::container(&f.token, &f.signature);
    let mut container: Vec<(&str, Vec<u8>, &str)> = Vec::new();
    container.push(("container cap", vec![0; 1153], "token container cap"));
    let mut short_sig = signed.clone();
    let sig_len_at = 4 + f.token.len();
    short_sig[sig_len_at..sig_len_at + 4].copy_from_slice(&63_u32.to_be_bytes());
    container.push(("signature length 63", short_sig, "token container"));
    let mut trailing = signed.clone();
    trailing.push(0);
    container.push(("container trailing", trailing, "token container"));
    container.push((
        "container truncated",
        signed[..signed.len() - 1].to_vec(),
        "truncated native",
    ));
    let mut flipped_field = signed.clone();
    flipped_field[4 + l.generation + 7] ^= 1; // generation 3 -> 2: valid token, wrong signature
    container.push(("signed field flipped", flipped_field, "grant signature"));
    let mut flipped_sig = signed.clone();
    let last = flipped_sig.len() - 1;
    flipped_sig[last] ^= 1;
    container.push(("signature flipped", flipped_sig, "grant signature"));
    for (name, bytes, want) in &container {
        assert_eq!(
            AttachmentToken::decode_signed(bytes, &f.key()),
            Err(FormatError(want)),
            "{name}"
        );
    }
    let wrong = ed25519_dalek::SigningKey::from_bytes(&[7; 32]).verifying_key().to_bytes();
    assert_eq!(
        AttachmentToken::decode_signed(&signed, &wrong),
        Err(FormatError("grant signature"))
    );
    let invalid_key = (0..=255_u8)
        .map(|b| [b; 32])
        .find(|k| ed25519_dalek::VerifyingKey::from_bytes(k).is_err())
        .ok_or("no invalid ed25519 key among repeated bytes")?;
    assert_eq!(
        AttachmentToken::decode_signed(&signed, &invalid_key),
        Err(FormatError("grant key"))
    );
    assert_eq!(cases.len() + container.len() + 2, 25);

    // Inclusive boundaries are accepted and round-trip byte-identically.
    let mut ok = Vec::new();
    for mutate in [
        (|t: &mut AttachmentToken| t.rights = 31) as fn(&mut AttachmentToken),
        |t| t.rights = 1,
        |t| t.source_authority = "s".repeat(256),
        |t| t.token_issuer = "i".repeat(256),
        |t| t.source_authority = "s".into(),
        |t| t.expires_at = t.issued_at + 1,
        |t| t.expires_at = t.issued_at + 300,
        |t| t.grant_epoch = u64::MAX,
        |t| t.authority_generation = u64::MAX,
        |t| t.grant_epoch = 1,
        |t| t.authority_generation = 1,
        |t| t.token_issuer = "i".into(),
    ] {
        let mut v = t.clone();
        mutate(&mut v);
        let bytes = v.canonical_bytes()?;
        let back = AttachmentToken::decode(&bytes)?;
        assert_eq!(back, v);
        assert_eq!(back.canonical_bytes()?, bytes);
        ok.push(bytes);
    }
    assert_eq!(ok.len(), 12);
    let mut over = t.clone();
    over.source_authority = "s".repeat(257);
    assert_eq!(over.canonical_bytes(), Err(FormatError("native identity length")));
    Ok(())
}

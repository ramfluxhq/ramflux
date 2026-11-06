// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain
use super::*;
type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;
fn bytes(s: &str) -> Result<Vec<u8>> {
    s.as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|p| Ok(u8::from_str_radix(std::str::from_utf8(p)?, 16)?))
        .collect()
}
fn fixture() -> Result<RenewalRequest> {
    let j: serde_json::Value = serde_json::from_str(include_str!(
        "../../tests/fixtures/large_attachment_renewal_v1.json"
    ))?;
    let r = &j["renewal"];
    Ok(RenewalRequest {
        operation: bytes(r["renewal_operation_hex"].as_str().ok_or("operation")?)?,
        body: bytes(r["renewal_body_hex"].as_str().ok_or("body")?)?,
    })
}
#[test]
fn renewal_codecs_refuse_exact_bounds_and_cross_field_changes() -> Result {
    let request = fixture()?;
    let (renew, target) = request.target()?;
    operation_bounds(&target);
    for field in 0..7 {
        let mut r = renew.clone();
        match field {
            0 => r.object_id[0] ^= 1,
            1 => r.manifest_hash[0] ^= 1,
            2 => r.grant_id[0] ^= 1,
            3 => r.grant_epoch += 1,
            4 => r.authority_generation += 1,
            5 => r.payload_generation += 1,
            _ => r.operation_id = target.operation_id,
        }
        let changed = RenewalRequest { operation: r.canonical_bytes()?, ..request.clone() };
        assert_eq!(changed.target(), Err(FormatError("renewal target binding")));
    }
    for field in 0..3 {
        let mut r = renew.clone();
        match field {
            0 => r.segment_index = 1,
            1 => r.offset = 1,
            _ => r.length = 1,
        }
        assert_eq!(r.canonical_bytes(), Err(FormatError("operation unused range")));
    }
    let mut r = renew.clone();
    r.body_digest[0] ^= 1;
    assert_eq!(
        RenewalRequest { operation: r.canonical_bytes()?, ..request.clone() }.target(),
        Err(FormatError("renewal body digest"))
    );
    let mut changed = request.clone();
    changed.body.push(0);
    assert_eq!(changed.target(), Err(FormatError("renewal body framing")));
    changed.body = vec![0; 8193];
    assert_eq!(changed.target(), Err(FormatError("renewal body cap")));
    changed = request.clone();
    changed.body[0] ^= 1;
    assert_eq!(changed.target(), Err(FormatError("renewal body version")));
    changed = request.clone();
    changed.body[8..12].copy_from_slice(&u32::MAX.to_be_bytes());
    assert_eq!(changed.target(), Err(FormatError("truncated native")));
    let mut op = request.operation.clone();
    op.push(0);
    assert_eq!(AttachmentOperation::decode(&op), Err(FormatError("operation framing")));
    assert_eq!(AttachmentOperation::decode(&vec![0; 4097]), Err(FormatError("operation cap")));
    op = request.operation.clone();
    op[7] = 2;
    assert_eq!(AttachmentOperation::decode(&op), Err(FormatError("operation version")));
    for n in 0..request.operation.len() {
        assert_eq!(
            AttachmentOperation::decode(&request.operation[..n]),
            Err(FormatError("truncated native"))
        );
    }
    let mut head = target.clone();
    head.op = 2;
    head.method = "HEAD".into();
    head.length = 0;
    assert!(head.canonical_bytes().is_ok());
    head.offset = 1;
    assert_eq!(head.canonical_bytes(), Err(FormatError("operation unused range")));
    let mut missing = target.clone();
    missing.op = 3;
    missing.method = "POST".into();
    missing.path =
        format!("/attachments/{}/{}/missing", hex(&missing.object_id), hex(&missing.manifest_hash));
    missing.length = 256;
    assert!(missing.canonical_bytes().is_ok());
    for field in 0..4 {
        let mut t = missing.clone();
        match field {
            0 => t.length = 0,
            1 => t.length = 257,
            2 => t.offset = u64::MAX,
            _ => t.segment_index = 1,
        }
        assert_eq!(t.canonical_bytes(), Err(FormatError("operation page")));
    }
    assert_eq!(
        RenewalRequest::new(&renew, &renew.audience, [7; 32]),
        Err(FormatError("renewal target kind"))
    );
    Ok(())
}
#[test]
fn renewal_proof_lifetime_and_requester_identity_bounds() -> Result {
    let q = QualifiedOwner {
        account_anchor: "a".into(),
        device_id: "d".into(),
        device_epoch: 1,
        signing_public_key: [1; 32],
        home_node_id: "h".into(),
    };
    let mut other = q.clone();
    other.home_node_id = "other".into();
    assert_eq!(requester_digest(&q)?, requester_digest(&other)?);
    other.device_epoch = 0;
    assert_eq!(requester_digest(&other), Err(FormatError("device epoch")));
    for field in 0..2 {
        let mut bad = q.clone();
        if field == 0 {
            bad.account_anchor.clear();
        } else {
            bad.device_id = "x".repeat(257);
        }
        assert_eq!(requester_digest(&bad), Err(FormatError("native identity length")));
    }
    let p = RequesterPop {
        operation_hash: [1; 32],
        requester_digest: [2; 32],
        nonce: [3; 32],
        issued_at: 100,
        expires_at: 130,
        forward_digest: [4; 32],
    };
    for (issued, expires) in
        [(0, 0), (100, 100), (100, 99), (100, 131), (u64::MAX, u64::MAX), (0, u64::MAX)]
    {
        let bad = RequesterPop { issued_at: issued, expires_at: expires, ..p.clone() };
        assert_eq!(bad.canonical_bytes(), Err(FormatError("proof lifetime")));
    }
    assert!(p.canonical_bytes().is_ok());
    Ok(())
}

fn operation_bounds(target: &AttachmentOperation) {
    for (field, error) in [
        (0, "operation kind"),
        (1, "operation endpoint"),
        (2, "operation endpoint"),
        (3, "operation generation"),
        (4, "operation generation"),
        (5, "operation generation"),
        (6, "operation range"),
        (7, "operation range"),
        (8, "operation range"),
        (9, "read body"),
        (10, "native identity length"),
    ] {
        let mut t = target.clone();
        match field {
            0 => t.op = 4,
            1 => t.method = "POST".into(),
            2 => t.path.push('/'),
            3 => t.grant_epoch = 0,
            4 => t.authority_generation = 0,
            5 => t.payload_generation = 0,
            6 => t.length = 0,
            7 => t.length = 1_048_577,
            8 => t.offset = u64::MAX,
            9 => t.body_digest[0] ^= 1,
            _ => t.audience = "x".repeat(257),
        }
        assert_eq!(t.canonical_bytes(), Err(FormatError(error)));
    }
    let mut max = target.clone();
    max.audience = "x".repeat(256);
    max.length = 1_048_576;
    max.offset = u64::from(super::super::SEGMENT_BYTES) - max.length;
    assert!(max.canonical_bytes().is_ok());
    let mut empty = target.clone();
    empty.audience.clear();
    assert_eq!(empty.canonical_bytes(), Err(FormatError("native identity length")));
}
#[test]
fn renewal_attestation_and_pop_refuse_each_signed_binding() -> Result {
    let j: serde_json::Value = serde_json::from_str(include_str!(
        "../../tests/fixtures/large_attachment_renewal_v1.json"
    ))?;
    let read = |v: &serde_json::Value| -> Result<Vec<u8>> { bytes(v.as_str().ok_or("hex")?) };
    let r = &j["renewal"];
    let w = ForwardAttestation::decode(&read(&r["home"]["bytes_hex"])?)?;
    let p = RequesterPop::decode(&read(&r["renewal_pop"]["bytes_hex"])?)?;
    let gbytes = read(&j["case"]["grant_unsigned_hex"])?;
    let mut container = b"RFC1".to_vec();
    container.extend(u32::try_from(gbytes.len())?.to_be_bytes());
    container.extend(gbytes);
    container.extend(64_u32.to_be_bytes());
    container.extend(read(&j["case"]["grant_signature_hex"])?);
    let grant = super::super::ScopedAttachmentGrant::decode_signed(&container)?;
    let request = fixture()?;
    let now = w.issued_at;
    w.validate(&request, &grant, &w.requester, &w.challenge, now)?;
    p.validate(&w, now)?;
    for field in 0..8 {
        let mut bad = w.clone();
        match field {
            0 => bad.requester.signing_public_key[0] ^= 1,
            1 => bad.grant_hash[0] ^= 1,
            2 => bad.grant_id[0] ^= 1,
            3 => bad.grant_epoch += 1,
            4 => bad.source_issuer.push('x'),
            5 => bad.challenge[0] ^= 1,
            6 => bad.operation_hash[0] ^= 1,
            _ => bad.requester.home_node_id.push('x'),
        }
        assert_eq!(
            bad.validate(&request, &grant, &w.requester, &w.challenge, now),
            Err(FormatError("forward request binding"))
        );
    }
    for field in 0..3 {
        let mut bad = p.clone();
        match field {
            0 => bad.operation_hash[0] ^= 1,
            1 => bad.requester_digest[0] ^= 1,
            _ => bad.forward_digest[0] ^= 1,
        }
        assert_eq!(bad.validate(&w, now), Err(FormatError("pop binding")));
    }
    assert_eq!(p.validate(&w, p.expires_at), Err(FormatError("pop time")));
    let mut early = p.clone();
    early.issued_at -= 1;
    early.expires_at -= 1;
    assert_eq!(early.validate(&w, now), Err(FormatError("pop time")));
    let mut late = p.clone();
    late.issued_at += 1;
    late.expires_at += 1;
    assert_eq!(late.validate(&w, now), Err(FormatError("pop time")));
    let mut future = p.clone();
    future.issued_at += 6;
    assert_eq!(future.validate(&w, now), Err(FormatError("pop time")));
    assert_eq!(
        w.validate(&request, &grant, &w.requester, &w.challenge, w.expires_at),
        Err(FormatError("forward time"))
    );
    assert_eq!(
        w.validate(&request, &grant, &w.requester, &w.challenge, now - 6),
        Err(FormatError("forward time"))
    );
    let mut bad = w.clone();
    bad.grant_epoch = 0;
    assert_eq!(bad.canonical_bytes(), Err(FormatError("forward home binding")));
    bad = w.clone();
    bad.home_issuer = "x".repeat(257);
    bad.requester.home_node_id = bad.home_issuer.clone();
    assert_eq!(bad.canonical_bytes(), Err(FormatError("native identity length")));
    let mut encoded = w.canonical_bytes()?;
    encoded.push(0);
    assert_eq!(ForwardAttestation::decode(&encoded), Err(FormatError("forward framing")));
    assert_eq!(ForwardAttestation::decode(&vec![0; 2049]), Err(FormatError("forward cap")));
    encoded = w.canonical_bytes()?;
    encoded[7] = 2;
    assert_eq!(ForwardAttestation::decode(&encoded), Err(FormatError("forward version")));
    let mut encoded = p.canonical_bytes()?;
    encoded.push(0);
    assert_eq!(RequesterPop::decode(&encoded), Err(FormatError("pop length")));
    encoded = p.canonical_bytes()?;
    encoded[7] = 2;
    assert_eq!(RequesterPop::decode(&encoded), Err(FormatError("pop version")));
    Ok(())
}

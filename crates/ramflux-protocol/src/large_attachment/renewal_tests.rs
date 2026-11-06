// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain
use super::super::{ScopedAttachmentGrant, VerifiedScopedGrant};
use super::*;
use ed25519_dalek::Signer;
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
fn signed_grant(
    mut grant: ScopedAttachmentGrant,
    owner: &ed25519_dalek::SigningKey,
) -> Result<VerifiedScopedGrant> {
    grant.owner.signing_public_key = owner.verifying_key().to_bytes();
    let signature = owner.sign(&grant.signing_bytes()?).to_bytes();
    Ok(ScopedAttachmentGrant::decode_signed(&grant.signed_bytes(&signature)?)?)
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
fn renewal_validation_refuses_each_independent_grant_and_policy_mismatch() -> Result {
    let j: serde_json::Value = serde_json::from_str(include_str!(
        "../../tests/fixtures/large_attachment_renewal_v1.json"
    ))?;
    let gbytes = bytes(j["case"]["grant_unsigned_hex"].as_str().ok_or("grant")?)?;
    let mut container = b"RFC1".to_vec();
    container.extend(u32::try_from(gbytes.len())?.to_be_bytes());
    container.extend(gbytes);
    container.extend(64_u32.to_be_bytes());
    container.extend(bytes(j["case"]["grant_signature_hex"].as_str().ok_or("signature")?)?);
    let original = ScopedAttachmentGrant::decode_signed(&container)?;
    let owner = ed25519_dalek::SigningKey::from_bytes(&[81; 32]);
    let baseline = signed_grant(original.grant().clone(), &owner)?;
    let request = fixture()?;
    let (renew, target) = request.target()?;
    let requester = baseline.grant().grantee.clone();
    let now = 1_700_000_001;

    request.validate(&baseline, &requester, &renew.audience, &target.audience, now)?;

    for field in 0..4 {
        let mut changed = baseline.grant().clone();
        match field {
            0 => changed.object_id[0] ^= 1,
            1 => changed.manifest_hash[0] ^= 1,
            2 => changed.grant_id[0] ^= 1,
            _ => changed.epoch += 1,
        }
        let changed = signed_grant(changed, &owner)?;
        assert_eq!(
            request.validate(&changed, &requester, &renew.audience, &target.audience, now),
            Err(FormatError("renewal grant binding")),
            "grant binding field {field}"
        );
    }

    let mut changed_requester = requester.clone();
    changed_requester.device_epoch += 1;
    assert_eq!(
        request.validate(&baseline, &changed_requester, &renew.audience, &target.audience, now),
        Err(FormatError("renewal requester"))
    );
    assert_eq!(
        request.validate(&baseline, &requester, "other-source", &target.audience, now),
        Err(FormatError("renewal audience"))
    );
    assert_eq!(
        request.validate(&baseline, &requester, &renew.audience, "other-relay", now),
        Err(FormatError("renewal audience"))
    );

    for (rights, expected) in [(1, "renewal rights"), (8, "renewal rights")] {
        let mut changed = baseline.grant().clone();
        changed.rights = rights;
        let changed = signed_grant(changed, &owner)?;
        assert_eq!(
            request.validate(&changed, &requester, &renew.audience, &target.audience, now),
            Err(FormatError(expected))
        );
    }
    for (field, issued_at, expires_at) in
        [(0, now + 1, baseline.grant().expires_at), (1, baseline.grant().issued_at, now)]
    {
        let mut changed = baseline.grant().clone();
        if field == 0 {
            changed.issued_at = issued_at;
        } else {
            changed.expires_at = expires_at;
        }
        let changed = signed_grant(changed, &owner)?;
        assert_eq!(
            request.validate(&changed, &requester, &renew.audience, &target.audience, now),
            Err(FormatError("renewal grant time"))
        );
    }
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

type Case = (String, Vec<u8>, &'static str);
type Fe = std::result::Result<(), FormatError>;

#[derive(Default)]
struct Counts {
    errors: usize,
    positives: usize,
}

struct Vectors {
    request: RenewalRequest,
    renew: AttachmentOperation,
    target: AttachmentOperation,
    ro: Vec<u8>,
    w: Vec<u8>,
    p: Vec<u8>,
    w_orig: ForwardAttestation,
    p_orig: RequesterPop,
    grant: VerifiedScopedGrant,
}

fn fixture_json() -> Result<serde_json::Value> {
    Ok(serde_json::from_str(include_str!("../../tests/fixtures/large_attachment_renewal_v1.json"))?)
}

fn read_hex(v: &serde_json::Value) -> Result<Vec<u8>> {
    bytes(v.as_str().ok_or("hex")?)
}

fn vectors() -> Result<Vectors> {
    let j = fixture_json()?;
    let r = &j["renewal"];
    let request = fixture()?;
    let (renew, target) = request.target()?;
    let w = read_hex(&r["home"]["bytes_hex"])?;
    let p = read_hex(&r["renewal_pop"]["bytes_hex"])?;
    Ok(Vectors {
        ro: request.operation.clone(),
        w_orig: ForwardAttestation::decode(&w)?,
        p_orig: RequesterPop::decode(&p)?,
        grant: load_grant(&j)?,
        request,
        renew,
        target,
        w,
        p,
    })
}

fn load_grant(j: &serde_json::Value) -> Result<VerifiedScopedGrant> {
    let gbytes = read_hex(&j["case"]["grant_unsigned_hex"])?;
    let mut container = b"RFC1".to_vec();
    container.extend(u32::try_from(gbytes.len())?.to_be_bytes());
    container.extend(gbytes);
    container.extend(64_u32.to_be_bytes());
    container.extend(read_hex(&j["case"]["grant_signature_hex"])?);
    Ok(ScopedAttachmentGrant::decode_signed(&container)?)
}

/// Overwrites `value` starting `from_end` bytes before the end of `bytes`.
fn put_from_end(bytes: &mut [u8], from_end: usize, value: &[u8]) {
    let start = bytes.len() - from_end;
    bytes[start..start + value.len()].copy_from_slice(value);
}

fn put_at(bytes: &mut [u8], at: usize, value: u64) {
    bytes[at..at + 8].copy_from_slice(&value.to_be_bytes());
}

fn flip_from_end(bytes: &mut [u8], from_end: usize) {
    let i = bytes.len() - from_end;
    bytes[i] ^= 1;
}

fn mutated(base: &[u8], mutate: impl FnOnce(&mut Vec<u8>)) -> Vec<u8> {
    let mut b = base.to_vec();
    mutate(&mut b);
    b
}

fn case(
    cases: &mut Vec<Case>,
    label: &str,
    base: &[u8],
    mutate: impl FnOnce(&mut Vec<u8>),
    error: &'static str,
) {
    cases.push((label.to_owned(), mutated(base, mutate), error));
}

fn refuse(c: &mut Counts, label: &str, got: Fe, want: &'static str) {
    c.errors += 1;
    assert_eq!(got, Err(FormatError(want)), "{label}");
}

fn accept(c: &mut Counts, label: &str, got: Fe) {
    c.positives += 1;
    assert_eq!(got, Ok(()), "{label}");
}

fn dec_o(b: &[u8]) -> Fe {
    AttachmentOperation::decode(b).map(|_| ())
}

fn dec_w(b: &[u8]) -> Fe {
    ForwardAttestation::decode(b).map(|_| ())
}

fn dec_p(b: &[u8]) -> Fe {
    RequesterPop::decode(b).map(|_| ())
}

fn run_decode(c: &mut Counts, cases: Vec<Case>, dec: fn(&[u8]) -> Fe) {
    for (label, b, want) in cases {
        refuse(c, &label, dec(&b), want);
    }
}

/// Byte offset just past the identity whose u32 length prefix starts at `at`.
fn ident_end(b: &[u8], at: usize) -> Result<usize> {
    let prefix = b.get(at..at + 4).ok_or("identity prefix")?;
    Ok(at + 4 + usize::try_from(u32::from_be_bytes(prefix.try_into()?))?)
}

/// Replaces the identity whose length prefix starts at `at` with `content`, re-framing its length.
fn splice_ident(b: &[u8], at: usize, content: &[u8]) -> Result<Vec<u8>> {
    let end = ident_end(b, at)?;
    let mut out = b[..at].to_vec();
    out.extend(u32::try_from(content.len())?.to_be_bytes());
    out.extend_from_slice(content);
    out.extend_from_slice(&b[end..]);
    Ok(out)
}

struct WPos {
    anchor: usize,
    device: usize,
    device_epoch: usize,
    key: usize,
    home: usize,
    grant_epoch: usize,
    source: usize,
    home_issuer: usize,
    challenge: usize,
    op_hash: usize,
    issued: usize,
}

fn w_pos(w: &[u8]) -> Result<WPos> {
    let anchor = 8;
    let device = ident_end(w, anchor)?;
    let device_epoch = ident_end(w, device)?;
    let key = device_epoch + 8;
    let home = key + 32;
    let grant_epoch = ident_end(w, home)? + 64;
    let source = grant_epoch + 8;
    let home_issuer = ident_end(w, source)?;
    let challenge = ident_end(w, home_issuer)?;
    let op_hash = challenge + 32;
    Ok(WPos {
        anchor,
        device,
        device_epoch,
        key,
        home,
        grant_epoch,
        source,
        home_issuer,
        challenge,
        op_hash,
        issued: op_hash + 32,
    })
}

fn operation_header_rows(v: &Vectors, c: &mut Counts) -> Result {
    let ro = &v.ro;
    let path_at = ident_end(ro, 12)?;
    let path_last = ident_end(ro, path_at)? - 1;
    let mut cases: Vec<Case> = Vec::new();
    cases.push(("O over 4096 bytes".into(), vec![0; 4097], "operation cap"));
    case(&mut cases, "O version", ro, |b| b[7] = 2, "operation version");
    case(&mut cases, "O trailing byte", ro, |b| b.push(0), "operation framing");
    case(
        &mut cases,
        "O op kind 4",
        ro,
        |b| b[8..12].copy_from_slice(&4_u32.to_be_bytes()),
        "operation kind",
    );
    case(&mut cases, "O method byte", ro, |b| b[16] ^= 1, "operation endpoint");
    case(&mut cases, "O path last byte", ro, |b| b[path_last] ^= 1, "operation endpoint");
    case(
        &mut cases,
        "O grant epoch zero",
        ro,
        |b| put_from_end(b, 112, &[0; 8]),
        "operation generation",
    );
    case(
        &mut cases,
        "O authority generation zero",
        ro,
        |b| put_from_end(b, 104, &[0; 8]),
        "operation generation",
    );
    case(
        &mut cases,
        "O payload generation zero",
        ro,
        |b| put_from_end(b, 64, &[0; 8]),
        "operation generation",
    );
    case(&mut cases, "O method byte non-UTF-8", ro, |b| b[16] = 0xff, "native UTF8");
    case(
        &mut cases,
        "O truncated by one byte",
        ro,
        |b| {
            b.pop();
        },
        "truncated native",
    );
    run_decode(c, cases, dec_o);
    Ok(())
}

fn operation_unused_range_rows(v: &Vectors, c: &mut Counts) {
    let ro = &v.ro;
    let mut cases: Vec<Case> = Vec::new();
    case(
        &mut cases,
        "renewal O segment index",
        ro,
        |b| put_from_end(b, 56, &1_u64.to_be_bytes()),
        "operation unused range",
    );
    case(
        &mut cases,
        "renewal O offset",
        ro,
        |b| put_from_end(b, 48, &1_u64.to_be_bytes()),
        "operation unused range",
    );
    case(
        &mut cases,
        "renewal O length",
        ro,
        |b| put_from_end(b, 40, &1_u64.to_be_bytes()),
        "operation unused range",
    );
    run_decode(c, cases, dec_o);
}

fn operation_range_rows(v: &Vectors, c: &mut Counts) -> Result {
    operation_unused_range_rows(v, c);
    let mut page = v.target.clone();
    page.op = 3;
    page.method = "POST".into();
    page.path =
        format!("/attachments/{}/{}/missing", hex(&page.object_id), hex(&page.manifest_hash));
    page.length = 1;
    page.offset = 0;
    let page = page.canonical_bytes()?;
    let mut read = v.target.clone();
    read.op = 1;
    read.method = "GET".into();
    read.path =
        format!("/attachments/{}/{}/segments/0", hex(&read.object_id), hex(&read.manifest_hash));
    read.length = 1;
    read.offset = 0;
    read.body_digest = body_digest(&[]);
    let read = read.canonical_bytes()?;
    let seg = u64::from(super::super::SEGMENT_BYTES);
    let mut cases: Vec<Case> = Vec::new();
    case(
        &mut cases,
        "page segment index",
        &page,
        |b| put_from_end(b, 56, &1_u64.to_be_bytes()),
        "operation page",
    );
    case(
        &mut cases,
        "page length zero",
        &page,
        |b| put_from_end(b, 40, &0_u64.to_be_bytes()),
        "operation page",
    );
    case(
        &mut cases,
        "page length 257",
        &page,
        |b| put_from_end(b, 40, &257_u64.to_be_bytes()),
        "operation page",
    );
    case(
        &mut cases,
        "page offset u64::MAX",
        &page,
        |b| put_from_end(b, 48, &u64::MAX.to_be_bytes()),
        "operation page",
    );
    case(
        &mut cases,
        "read length zero",
        &read,
        |b| put_from_end(b, 40, &0_u64.to_be_bytes()),
        "operation range",
    );
    case(
        &mut cases,
        "read length 1 MiB + 1 at offset 0",
        &read,
        |b| put_from_end(b, 40, &1_048_577_u64.to_be_bytes()),
        "operation range",
    );
    case(
        &mut cases,
        "read offset u64::MAX length 1 (overflow)",
        &read,
        |b| put_from_end(b, 48, &u64::MAX.to_be_bytes()),
        "operation range",
    );
    case(
        &mut cases,
        "read range past segment end",
        &read,
        |b| put_from_end(b, 48, &seg.to_be_bytes()),
        "operation range",
    );
    run_decode(c, cases, dec_o);
    let read_body = mutated(&read, |b| flip_from_end(b, 32));
    refuse(c, "read body digest", dec_o(&read_body), "read body");
    operation_range_positives(v, c)?;

    Ok(())
}

fn operation_range_positives(v: &Vectors, c: &mut Counts) -> Result {
    let seg = u64::from(super::super::SEGMENT_BYTES);
    // Inclusive positives: length cap, segment edge, page range edge.
    let mut max_read = v.target.clone();
    max_read.op = 1;
    max_read.method = "GET".into();
    max_read.path = read_path(&max_read);
    max_read.length = 1_048_576;
    max_read.offset = 0;
    max_read.body_digest = body_digest(&[]);
    accept(c, "read length exactly 1 MiB", dec_o(&max_read.canonical_bytes()?));
    let mut edge_read = max_read.clone();
    edge_read.length = 1;
    edge_read.offset = seg - 1;
    accept(c, "read last byte of segment", dec_o(&edge_read.canonical_bytes()?));
    let mut max_page = v.target.clone();
    max_page.op = 3;
    max_page.method = "POST".into();
    max_page.path = format!(
        "/attachments/{}/{}/missing",
        hex(&max_page.object_id),
        hex(&max_page.manifest_hash)
    );
    max_page.length = 256;
    max_page.offset = 0;
    accept(c, "page length exactly 256", dec_o(&max_page.canonical_bytes()?));
    max_page.offset = u64::MAX - 256;
    accept(c, "page offset+length == u64::MAX", dec_o(&max_page.canonical_bytes()?));
    Ok(())
}

fn read_path(op: &AttachmentOperation) -> String {
    format!("/attachments/{}/{}/segments/0", hex(&op.object_id), hex(&op.manifest_hash))
}

fn identity_rows(v: &Vectors, c: &mut Counts) -> Result {
    let ro = &v.ro;
    let w = &v.w;
    let path_at = ident_end(ro, 12)?;
    let aud_at = ident_end(ro, path_at)?;
    let wp = w_pos(w)?;
    let mut ocases: Vec<Case> = Vec::new();
    for (name, at) in [("method", 12), ("path", path_at), ("audience", aud_at)] {
        case(
            &mut ocases,
            &format!("O {name} length zero"),
            ro,
            |b| b[at..at + 4].copy_from_slice(&0_u32.to_be_bytes()),
            "native identity length",
        );
        case(
            &mut ocases,
            &format!("O {name} length 257"),
            ro,
            |b| b[at..at + 4].copy_from_slice(&257_u32.to_be_bytes()),
            "native identity length",
        );
    }
    let mut wcases: Vec<Case> = Vec::new();
    for (name, at) in [
        ("account anchor", wp.anchor),
        ("device id", wp.device),
        ("home node", wp.home),
        ("source issuer", wp.source),
        ("home issuer", wp.home_issuer),
    ] {
        case(
            &mut wcases,
            &format!("W {name} length zero"),
            w,
            |b| b[at..at + 4].copy_from_slice(&0_u32.to_be_bytes()),
            "native identity length",
        );
        case(
            &mut wcases,
            &format!("W {name} length 257"),
            w,
            |b| b[at..at + 4].copy_from_slice(&257_u32.to_be_bytes()),
            "native identity length",
        );
    }
    run_decode(c, ocases, dec_o);
    run_decode(c, wcases, dec_w);

    // Inclusive maxima (256 bytes). Method and path cannot be valid at 256 bytes, so they
    // prove the length check passed by reaching the endpoint refusal.
    let max = vec![b'a'; 256];
    let mut method = b"POST".to_vec();
    method.resize(256, b'x');
    let mut path = b"/s9/attachments/renew".to_vec();
    path.resize(256, b'x');
    for (label, bytes) in [
        ("O method at max", splice_ident(ro, 12, &method)?),
        ("O path at max", splice_ident(ro, path_at, &path)?),
    ] {
        c.positives += 1;
        assert_eq!(dec_o(&bytes), Err(FormatError("operation endpoint")), "{label}");
    }
    accept(c, "O audience at max", dec_o(&splice_ident(ro, aud_at, &max)?));
    accept(c, "W account anchor at max", dec_w(&splice_ident(w, wp.anchor, &max)?));
    accept(c, "W device id at max", dec_w(&splice_ident(w, wp.device, &max)?));
    accept(c, "W source issuer at max", dec_w(&splice_ident(w, wp.source, &max)?));
    let pair = splice_ident(&splice_ident(w, wp.home_issuer, &max)?, wp.home, &max)?;
    accept(c, "W home node and home issuer at max", dec_w(&pair));
    Ok(())
}

fn forward_decode_rows(v: &Vectors, c: &mut Counts) -> Result {
    let w = &v.w;
    let wp = w_pos(w)?;
    let issued: [u8; 8] = w[wp.issued..wp.issued + 8].try_into()?;
    let iss = u64::from_be_bytes(issued);
    let mut cases: Vec<Case> = Vec::new();
    cases.push(("W over 2048 bytes".into(), vec![0; 2049], "forward cap"));
    case(&mut cases, "W version", w, |b| b[7] = 2, "forward version");
    case(&mut cases, "W trailing byte", w, |b| b.push(0), "forward framing");
    case(
        &mut cases,
        "W truncated by one byte",
        w,
        |b| {
            b.pop();
        },
        "truncated native",
    );
    case(&mut cases, "W device epoch zero", w, |b| put_at(b, wp.device_epoch, 0), "device epoch");
    case(
        &mut cases,
        "W grant epoch zero",
        w,
        |b| put_at(b, wp.grant_epoch, 0),
        "forward home binding",
    );
    case(
        &mut cases,
        "W home node differs from home issuer",
        w,
        |b| b[wp.home + 4] ^= 1,
        "forward home binding",
    );
    case(
        &mut cases,
        "W lifetime zero (expires == issued)",
        w,
        |b| put_at(b, wp.issued + 8, iss),
        "proof lifetime",
    );
    case(
        &mut cases,
        "W lifetime 31 seconds",
        w,
        |b| put_at(b, wp.issued + 8, iss + 31),
        "proof lifetime",
    );
    run_decode(c, cases, dec_w);
    accept(
        c,
        "W lifetime exactly 30 seconds",
        dec_w(&mutated(w, |b| put_at(b, wp.issued + 8, iss + 30))),
    );
    accept(
        c,
        "W lifetime exactly 1 second",
        dec_w(&mutated(w, |b| put_at(b, wp.issued + 8, iss + 1))),
    );
    Ok(())
}

fn forward_validate_rows(v: &Vectors, c: &mut Counts) -> Result {
    let w0 = &v.w_orig;
    let now = w0.issued_at;
    let gexp = v.grant.grant().expires_at;
    let wb = &v.w;
    let p = w_pos(wb)?;
    let ge = p.grant_epoch;
    let rows: Vec<(&str, Vec<u8>, &'static str)> = vec![
        ("W requester key", mutated(wb, |b| b[p.key] ^= 1), "forward request binding"),
        ("W grant hash", mutated(wb, |b| b[ge - 64] ^= 1), "forward request binding"),
        ("W grant id", mutated(wb, |b| b[ge - 32] ^= 1), "forward request binding"),
        ("W grant epoch", mutated(wb, |b| b[ge + 7] = 2), "forward request binding"),
        ("W source issuer", mutated(wb, |b| b[p.source + 4] ^= 1), "forward request binding"),
        ("W challenge", mutated(wb, |b| b[p.challenge] ^= 1), "forward request binding"),
        ("W operation hash", mutated(wb, |b| b[p.op_hash] ^= 1), "forward request binding"),
        (
            "W issued more than 5 s ahead",
            mutated(wb, |b| {
                put_from_end(b, 16, &(now + 6).to_be_bytes());
                put_from_end(b, 8, &(now + 7).to_be_bytes());
            }),
            "forward time",
        ),
        (
            "W expired at validation time",
            mutated(wb, |b| {
                put_from_end(b, 16, &(now - 1).to_be_bytes());
                put_from_end(b, 8, &now.to_be_bytes());
            }),
            "forward time",
        ),
        (
            "W expiry after grant expiry",
            mutated(wb, |b| {
                put_from_end(b, 16, &(gexp - 29).to_be_bytes());
                put_from_end(b, 8, &(gexp + 1).to_be_bytes());
            }),
            "forward time",
        ),
    ];
    for (label, bytes, want) in rows {
        let got = ForwardAttestation::decode(&bytes)?.validate(
            &v.request,
            &v.grant,
            &w0.requester,
            &w0.challenge,
            now,
        );
        refuse(c, label, got, want);
    }
    let sk = ed25519_dalek::SigningKey::from_bytes(&[82; 32]);
    let pk = sk.verifying_key().to_bytes();
    let sig = sk.sign(&w0.signing_bytes()?).to_bytes();
    accept(c, "W signature verifies", w0.verify(&pk, &sig));
    let mut bad = sig;
    bad[0] ^= 1;
    refuse(c, "W signature byte flip", w0.verify(&pk, &bad), "grant signature");

    // Inclusive positives: issued exactly 5 s ahead, expiry exactly at grant expiry.
    let at_skew = mutated(wb, |b| {
        put_from_end(b, 16, &(now + 5).to_be_bytes());
        put_from_end(b, 8, &(now + 6).to_be_bytes());
    });
    accept(
        c,
        "W issued exactly 5 s ahead",
        ForwardAttestation::decode(&at_skew)?.validate(
            &v.request,
            &v.grant,
            &w0.requester,
            &w0.challenge,
            now,
        ),
    );
    let at_grant = mutated(wb, |b| {
        put_from_end(b, 16, &(gexp - 30).to_be_bytes());
        put_from_end(b, 8, &gexp.to_be_bytes());
    });
    accept(
        c,
        "W expiry exactly at grant expiry",
        ForwardAttestation::decode(&at_grant)?.validate(
            &v.request,
            &v.grant,
            &w0.requester,
            &w0.challenge,
            gexp - 30,
        ),
    );
    accept(
        c,
        "W unmodified vector validates",
        w0.validate(&v.request, &v.grant, &w0.requester, &w0.challenge, now),
    );
    Ok(())
}

fn pop_decode_rows(v: &Vectors, c: &mut Counts) -> Result {
    let pb = &v.p;
    let iss = u64::from_be_bytes(pb[104..112].try_into()?);
    let mut cases: Vec<Case> = Vec::new();
    case(&mut cases, "P version", pb, |b| b[7] = 2, "pop version");
    case(&mut cases, "P trailing byte", pb, |b| b.push(0), "pop length");
    case(&mut cases, "P lifetime zero", pb, |b| put_at(b, 112, iss), "proof lifetime");
    case(&mut cases, "P lifetime 31 seconds", pb, |b| put_at(b, 112, iss + 31), "proof lifetime");
    run_decode(c, cases, dec_p);
    accept(c, "P lifetime exactly 30 seconds", dec_p(&mutated(pb, |b| put_at(b, 112, iss + 30))));
    accept(c, "P lifetime exactly 1 second", dec_p(&mutated(pb, |b| put_at(b, 112, iss + 1))));
    Ok(())
}

fn pop_validate_rows(v: &Vectors, c: &mut Counts) -> Result {
    let w0 = &v.w_orig;
    let now = w0.issued_at;
    let pb = &v.p;
    let iss = u64::from_be_bytes(pb[104..112].try_into()?);
    let times = |issued: u64, expires: u64| {
        mutated(pb, |b| {
            put_at(b, 104, issued);
            put_at(b, 112, expires);
        })
    };
    let rows: Vec<(&str, Vec<u8>, u64, &'static str)> = vec![
        ("P operation hash", mutated(pb, |b| b[8] ^= 1), now, "pop binding"),
        ("P requester digest", mutated(pb, |b| b[40] ^= 1), now, "pop binding"),
        ("P forward digest", mutated(pb, |b| b[120] ^= 1), now, "pop binding"),
        ("P issued before W issued", times(iss - 1, iss + 29), now, "pop time"),
        ("P expiry after W expiry", times(iss + 1, iss + 31), now, "pop time"),
        ("P issued more than 5 s ahead", times(now + 6, now + 7), now, "pop time"),
        ("P expired at validation time", times(now + 28, now + 29), now + 40, "pop time"),
    ];
    for (label, bytes, at, want) in rows {
        let got = RequesterPop::decode(&bytes)?.validate(w0, at);
        refuse(c, label, got, want);
    }
    let sk = ed25519_dalek::SigningKey::from_bytes(&[83; 32]);
    let pk = sk.verifying_key().to_bytes();
    let p0 = &v.p_orig;
    let sig = sk.sign(&p0.signing_bytes()?).to_bytes();
    accept(c, "P signature verifies", p0.verify(&pk, &sig));
    let mut bad = sig;
    bad[0] ^= 1;
    refuse(c, "P signature byte flip", p0.verify(&pk, &bad), "grant signature");
    accept(
        c,
        "P issued exactly 5 s ahead",
        RequesterPop::decode(&times(now + 5, now + 6))?.validate(w0, now),
    );
    accept(c, "P unmodified vector validates", p0.validate(w0, now));
    Ok(())
}

fn renewal_body_rows(v: &Vectors, c: &mut Counts) -> Result {
    let body = &v.request.body;
    let ro = &v.ro;
    let tid = v.target.operation_id;
    let req =
        |op: Vec<u8>, body: Vec<u8>| RenewalRequest { operation: op, body }.target().map(|_| ());
    refuse(c, "renewal body over 8192 bytes", req(ro.clone(), vec![0; 8193]), "renewal body cap");
    refuse(
        c,
        "renewal body version",
        req(ro.clone(), mutated(body, |b| b[0] ^= 1)),
        "renewal body version",
    );
    refuse(
        c,
        "renewal body trailing byte",
        req(ro.clone(), mutated(body, |b| b.push(0))),
        "renewal body framing",
    );
    refuse(
        c,
        "renewal body target length beyond body",
        req(ro.clone(), mutated(body, |b| b[8..12].copy_from_slice(&u32::MAX.to_be_bytes()))),
        "truncated native",
    );
    refuse(
        c,
        "renewal body digest",
        req(mutated(ro, |b| flip_from_end(b, 32)), body.clone()),
        "renewal body digest",
    );
    let binding: Vec<(&str, Vec<u8>)> = vec![
        ("object id", mutated(ro, |b| flip_from_end(b, 208))),
        ("manifest hash", mutated(ro, |b| flip_from_end(b, 176))),
        ("grant id", mutated(ro, |b| flip_from_end(b, 144))),
        ("grant epoch", mutated(ro, |b| put_from_end(b, 112, &2_u64.to_be_bytes()))),
        ("authority generation", mutated(ro, |b| put_from_end(b, 104, &2_u64.to_be_bytes()))),
        ("payload generation", mutated(ro, |b| put_from_end(b, 64, &2_u64.to_be_bytes()))),
        ("operation id equal to target", mutated(ro, |b| put_from_end(b, 96, &tid))),
    ];
    for (label, op) in binding {
        refuse(
            c,
            &format!("renewal target binding: {label}"),
            req(op, body.clone()),
            "renewal target binding",
        );
    }

    // Renewal audience (O) and relay audience (target) are checked against the caller's source and relay.
    let requester = v.grant.grant().grantee.clone();
    let now = v.w_orig.issued_at;
    let source = v.renew.audience.clone();
    let relay = v.target.audience.clone();
    let path_at = ident_end(ro, 12)?;
    let aud_at = ident_end(ro, path_at)?;
    let renew_aud =
        RenewalRequest { operation: mutated(ro, |b| b[aud_at + 4] ^= 1), body: body.clone() };
    refuse(
        c,
        "renewal O audience byte",
        renew_aud.validate(&v.grant, &requester, &source, &relay, now),
        "renewal audience",
    );
    let tb = v.target.canonical_bytes()?;
    let t_path = ident_end(&tb, 12)?;
    let t_aud = ident_end(&tb, t_path)?;
    let body2 = mutated(body, |b| b[12 + t_aud + 4] ^= 1);
    let mut renew2 = v.renew.clone();
    renew2.body_digest = body_digest(&body2);
    let relay_aud = RenewalRequest { operation: renew2.canonical_bytes()?, body: body2 };
    refuse(
        c,
        "renewal target relay audience byte",
        relay_aud.validate(&v.grant, &requester, &source, &relay, now),
        "renewal audience",
    );

    // A well-formed renewal whose target is an operation 8 is refused by kind, not by binding.
    let mut t8 = v.target.clone();
    t8.op = 8;
    t8.method = "POST".into();
    t8.path = "/s9/attachments/renew".into();
    t8.segment_index = 0;
    t8.offset = 0;
    t8.length = 0;
    let mut frame = b"RFRQ".to_vec();
    frame.extend(1_u32.to_be_bytes());
    lp(&mut frame, &t8.canonical_bytes()?)?;
    let mut renew8 = v.renew.clone();
    renew8.body_digest = body_digest(&frame);
    refuse(
        c,
        "renewal target kind 8",
        req(renew8.canonical_bytes()?, frame),
        "renewal target kind",
    );
    Ok(())
}

const INVENTORY_OPERATION_HEADER: usize = 11;
const INVENTORY_OPERATION_RANGE: usize = 12;
const INVENTORY_IDENTITY: usize = 16;
const INVENTORY_FORWARD_DECODE: usize = 9;
const INVENTORY_FORWARD_VALIDATE: usize = 11;
const INVENTORY_POP_DECODE: usize = 4;
const INVENTORY_POP_VALIDATE: usize = 8;
const INVENTORY_RENEWAL_BODY: usize = 15;
/// Sum of the family counts above; the pre-existing grant-level test adds 11 more refusals.
const INVENTORY_ERROR_ROWS: usize = 86;

#[test]
fn renewal_received_bytes_operation_header_matrix() -> Result {
    let v = vectors()?;
    let mut c = Counts::default();
    operation_header_rows(&v, &mut c)?;
    assert_eq!(c.errors, INVENTORY_OPERATION_HEADER);
    Ok(())
}

#[test]
fn renewal_received_bytes_operation_range_matrix() -> Result {
    let v = vectors()?;
    let mut c = Counts::default();
    operation_range_rows(&v, &mut c)?;
    assert_eq!(c.errors, INVENTORY_OPERATION_RANGE);
    assert_eq!(c.positives, 4);
    Ok(())
}

#[test]
fn renewal_received_bytes_identity_matrix() -> Result {
    let v = vectors()?;
    let mut c = Counts::default();
    identity_rows(&v, &mut c)?;
    assert_eq!(c.errors, INVENTORY_IDENTITY);
    assert_eq!(c.positives, 7);
    Ok(())
}

#[test]
fn renewal_received_bytes_forward_matrix() -> Result {
    let v = vectors()?;
    let mut c = Counts::default();
    forward_decode_rows(&v, &mut c)?;
    assert_eq!(c.errors, INVENTORY_FORWARD_DECODE);
    let mut c = Counts::default();
    forward_validate_rows(&v, &mut c)?;
    assert_eq!(c.errors, INVENTORY_FORWARD_VALIDATE);
    Ok(())
}

#[test]
fn renewal_received_bytes_pop_matrix() -> Result {
    let v = vectors()?;
    let mut c = Counts::default();
    pop_decode_rows(&v, &mut c)?;
    assert_eq!(c.errors, INVENTORY_POP_DECODE);
    let mut c = Counts::default();
    pop_validate_rows(&v, &mut c)?;
    assert_eq!(c.errors, INVENTORY_POP_VALIDATE);
    Ok(())
}

#[test]
fn renewal_received_bytes_body_matrix() -> Result {
    let v = vectors()?;
    let mut c = Counts::default();
    renewal_body_rows(&v, &mut c)?;
    assert_eq!(c.errors, INVENTORY_RENEWAL_BODY);
    Ok(())
}

#[test]
fn renewal_inventory_total_matches_test_rows() {
    let sum = INVENTORY_OPERATION_HEADER
        + INVENTORY_OPERATION_RANGE
        + INVENTORY_IDENTITY
        + INVENTORY_FORWARD_DECODE
        + INVENTORY_FORWARD_VALIDATE
        + INVENTORY_POP_DECODE
        + INVENTORY_POP_VALIDATE
        + INVENTORY_RENEWAL_BODY;
    assert_eq!(sum, INVENTORY_ERROR_ROWS);
}

#[test]
fn renewal_vectors_round_trip_byte_identical() -> Result {
    let j = fixture_json()?;
    let r = &j["renewal"];
    let request = fixture()?;
    let (renew, target) = request.target()?;
    let target_bytes = target.canonical_bytes()?;
    assert_eq!(
        AttachmentOperation::decode(&request.operation)?.canonical_bytes()?,
        request.operation
    );
    assert_eq!(AttachmentOperation::decode(&target_bytes)?.canonical_bytes()?, target_bytes);
    let w_bytes = read_hex(&r["home"]["bytes_hex"])?;
    assert_eq!(ForwardAttestation::decode(&w_bytes)?.canonical_bytes()?, w_bytes);
    let p_bytes = read_hex(&r["renewal_pop"]["bytes_hex"])?;
    assert_eq!(RequesterPop::decode(&p_bytes)?.canonical_bytes()?, p_bytes);
    let rebuilt = RenewalRequest::new(&target, &renew.audience, renew.operation_id)?;
    assert_eq!(rebuilt, request);
    Ok(())
}

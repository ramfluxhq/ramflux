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

fn read_hex(v: &serde_json::Value) -> Result<Vec<u8>> {
    bytes(v.as_str().ok_or("hex")?)
}

/// Overwrites `value` starting `from_end` bytes before the end of `bytes`.
fn put_from_end(bytes: &mut [u8], from_end: usize, value: &[u8]) {
    let start = bytes.len() - from_end;
    bytes[start..start + value.len()].copy_from_slice(value);
}

fn case(
    cases: &mut Vec<Case>,
    label: &str,
    base: &[u8],
    mutate: impl FnOnce(&mut Vec<u8>),
    error: &'static str,
) {
    let mut b = base.to_vec();
    mutate(&mut b);
    cases.push((label.to_owned(), b, error));
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

#[test]
fn renewal_operation_received_bytes_refuse_single_field_mutation() -> Result {
    let request = fixture()?;
    let (_, target) = request.target()?;
    let target_bytes = target.canonical_bytes()?;

    // O: renewal (op 8) and embedded target (op 3). Shared header and tail fields.
    let mut ops = Vec::new();
    for (name, base) in [("renewal O", &request.operation), ("target O", &target_bytes)] {
        let method_len = usize::try_from(u32::from_be_bytes(base[12..16].try_into()?))?;
        let path_len_at = 16 + method_len;
        let path_len =
            usize::try_from(u32::from_be_bytes(base[path_len_at..path_len_at + 4].try_into()?))?;
        let path_last = path_len_at + 4 + path_len - 1;
        case(
            &mut ops,
            &format!("{name}: op kind"),
            base,
            |b| b[8..12].copy_from_slice(&4_u32.to_be_bytes()),
            "operation kind",
        );
        case(&mut ops, &format!("{name}: version"), base, |b| b[7] = 2, "operation version");
        case(&mut ops, &format!("{name}: method byte"), base, |b| b[16] ^= 1, "operation endpoint");
        case(
            &mut ops,
            &format!("{name}: path byte"),
            base,
            |b| b[path_last] ^= 1,
            "operation endpoint",
        );
        case(
            &mut ops,
            &format!("{name}: method identity over max"),
            base,
            |b| b[12..16].copy_from_slice(&257_u32.to_be_bytes()),
            "native identity length",
        );
        case(
            &mut ops,
            &format!("{name}: grant epoch zero"),
            base,
            |b| put_from_end(b, 112, &[0; 8]),
            "operation generation",
        );
        case(
            &mut ops,
            &format!("{name}: authority generation zero"),
            base,
            |b| put_from_end(b, 104, &[0; 8]),
            "operation generation",
        );
        case(
            &mut ops,
            &format!("{name}: payload generation zero"),
            base,
            |b| put_from_end(b, 64, &[0; 8]),
            "operation generation",
        );
        case(&mut ops, &format!("{name}: trailing byte"), base, |b| b.push(0), "operation framing");
    }
    for (label, b, error) in &ops {
        assert_eq!(AttachmentOperation::decode(b), Err(FormatError(error)), "{label}");
    }
    Ok(())
}

#[test]
fn renewal_operation_range_received_bytes_refuse_single_field_mutation() -> Result {
    let request = fixture()?;
    let (_, target) = request.target()?;
    let mut ops = Vec::new();
    // Renewal O carries no range: any non-zero segment, offset or length is refused.
    let renewal_base = &request.operation;
    case(
        &mut ops,
        "renewal O: segment index",
        renewal_base,
        |b| put_from_end(b, 56, &1_u64.to_be_bytes()),
        "operation unused range",
    );
    case(
        &mut ops,
        "renewal O: offset",
        renewal_base,
        |b| put_from_end(b, 48, &1_u64.to_be_bytes()),
        "operation unused range",
    );
    case(
        &mut ops,
        "renewal O: length",
        renewal_base,
        |b| put_from_end(b, 40, &1_u64.to_be_bytes()),
        "operation unused range",
    );
    // Page op 3 carries the page range: segment 0, length 1..=256, offset+length no overflow.
    let mut page3 = target.clone();
    page3.op = 3;
    page3.method = "POST".into();
    page3.path =
        format!("/attachments/{}/{}/missing", hex(&page3.object_id), hex(&page3.manifest_hash));
    page3.length = 1;
    page3.offset = 0;
    let page_base = page3.canonical_bytes()?;
    case(
        &mut ops,
        "page O (op 3): segment",
        &page_base,
        |b| put_from_end(b, 56, &1_u64.to_be_bytes()),
        "operation page",
    );
    case(
        &mut ops,
        "page O (op 3): length zero",
        &page_base,
        |b| put_from_end(b, 40, &0_u64.to_be_bytes()),
        "operation page",
    );
    case(
        &mut ops,
        "page O (op 3): length 257",
        &page_base,
        |b| put_from_end(b, 40, &257_u64.to_be_bytes()),
        "operation page",
    );
    case(
        &mut ops,
        "page O (op 3): offset max",
        &page_base,
        |b| put_from_end(b, 48, &u64::MAX.to_be_bytes()),
        "operation page",
    );
    // Read op 1 range: length 1..=1 MiB and offset+length inside one segment.
    let mut op1 = target.clone();
    op1.op = 1;
    op1.method = "GET".into();
    op1.path =
        format!("/attachments/{}/{}/segments/0", hex(&op1.object_id), hex(&op1.manifest_hash));
    op1.length = 1;
    op1.offset = u64::from(super::super::SEGMENT_BYTES) - 1;
    op1.body_digest = body_digest(&[]);
    let op1_bytes = op1.canonical_bytes()?;
    AttachmentOperation::decode(&op1_bytes)?;
    case(
        &mut ops,
        "read O: length zero",
        &op1_bytes,
        |b| put_from_end(b, 40, &0_u64.to_be_bytes()),
        "operation range",
    );
    case(
        &mut ops,
        "read O: length over 1 MiB",
        &op1_bytes,
        |b| put_from_end(b, 40, &1_048_577_u64.to_be_bytes()),
        "operation range",
    );
    case(
        &mut ops,
        "read O: range past segment end",
        &op1_bytes,
        |b| put_from_end(b, 48, &u64::from(super::super::SEGMENT_BYTES).to_be_bytes()),
        "operation range",
    );
    for (label, b, error) in &ops {
        assert_eq!(AttachmentOperation::decode(b), Err(FormatError(error)), "{label}");
    }

    Ok(())
}

#[test]
fn renewal_forward_received_bytes_refuse_single_field_mutation() -> Result {
    let j: serde_json::Value = serde_json::from_str(include_str!(
        "../../tests/fixtures/large_attachment_renewal_v1.json"
    ))?;
    let w_bytes = read_hex(&j["renewal"]["home"]["bytes_hex"])?;
    // W: home-signed attestation. Requester identity and trailing bytes are decode-level.
    let mut attest = Vec::new();
    case(&mut attest, "W: version", &w_bytes, |b| b[7] = 2, "forward version");
    case(&mut attest, "W: trailing byte", &w_bytes, |b| b.push(0), "forward framing");
    case(
        &mut attest,
        "W: requester identity over max",
        &w_bytes,
        |b| b[8..12].copy_from_slice(&257_u32.to_be_bytes()),
        "native identity length",
    );
    case(
        &mut attest,
        "W: requester identity empty",
        &w_bytes,
        |b| b[8..12].copy_from_slice(&0_u32.to_be_bytes()),
        "native identity length",
    );
    for (label, b, error) in &attest {
        assert_eq!(ForwardAttestation::decode(b), Err(FormatError(error)), "{label}");
    }

    Ok(())
}

#[test]
fn renewal_pop_received_bytes_refuse_single_field_mutation() -> Result {
    let j: serde_json::Value = serde_json::from_str(include_str!(
        "../../tests/fixtures/large_attachment_renewal_v1.json"
    ))?;
    let p_bytes = read_hex(&j["renewal"]["renewal_pop"]["bytes_hex"])?;
    // P: fixed-length proof. Binding mismatches decode and fail at validate.
    let mut pops = Vec::new();
    case(&mut pops, "P: version", &p_bytes, |b| b[7] = 2, "pop version");
    case(&mut pops, "P: trailing byte", &p_bytes, |b| b.push(0), "pop length");
    case(
        &mut pops,
        "P: truncated",
        &p_bytes,
        |b| {
            b.pop();
        },
        "pop length",
    );
    for (label, b, error) in &pops {
        assert_eq!(RequesterPop::decode(b), Err(FormatError(error)), "{label}");
    }
    Ok(())
}

#[test]
fn renewal_received_bytes_validate_each_binding_mismatch() -> Result {
    let j: serde_json::Value = serde_json::from_str(include_str!(
        "../../tests/fixtures/large_attachment_renewal_v1.json"
    ))?;
    let r = &j["renewal"];
    let request = fixture()?;
    let w = ForwardAttestation::decode(&read_hex(&r["home"]["bytes_hex"])?)?;
    let p_bytes = read_hex(&r["renewal_pop"]["bytes_hex"])?;
    let grant = load_grant(&j)?;
    let now = w.issued_at;
    w.validate(&request, &grant, &w.requester, &w.challenge, now)?;

    let mut pops = Vec::new();
    case(&mut pops, "P: operation hash", &p_bytes, |b| b[8] ^= 1, "pop binding");
    case(&mut pops, "P: requester digest", &p_bytes, |b| b[40] ^= 1, "pop binding");
    case(&mut pops, "P: forward digest", &p_bytes, |b| b[120] ^= 1, "pop binding");
    for (label, b, error) in &pops {
        let p = RequesterPop::decode(b)?;
        assert_eq!(p.validate(&w, now), Err(FormatError(error)), "{label}");
    }

    // W expiry later than the grant expiry is a validate-time refusal, and the boundary is inclusive.
    let g_exp = grant.grant().expires_at;
    let mut late = read_hex(&r["home"]["bytes_hex"])?;
    put_from_end(&mut late, 16, &(g_exp - 29).to_be_bytes());
    put_from_end(&mut late, 8, &(g_exp + 1).to_be_bytes());
    let late = ForwardAttestation::decode(&late)?;
    assert_eq!(
        late.validate(&request, &grant, &late.requester, &late.challenge, late.issued_at),
        Err(FormatError("forward time"))
    );
    let mut edge = read_hex(&r["home"]["bytes_hex"])?;
    put_from_end(&mut edge, 16, &(g_exp - 30).to_be_bytes());
    put_from_end(&mut edge, 8, &g_exp.to_be_bytes());
    let edge = ForwardAttestation::decode(&edge)?;
    edge.validate(&request, &grant, &edge.requester, &edge.challenge, edge.issued_at)?;
    Ok(())
}

#[test]
fn renewal_positive_inclusive_boundaries_decode() -> Result {
    let request = fixture()?;
    let (_, target) = request.target()?;
    let j: serde_json::Value = serde_json::from_str(include_str!(
        "../../tests/fixtures/large_attachment_renewal_v1.json"
    ))?;
    let w = ForwardAttestation::decode(&read_hex(&j["renewal"]["home"]["bytes_hex"])?)?;

    // Requester identity at exactly the 256-byte maximum.
    let mut max_w = w.clone();
    max_w.requester.account_anchor = "a".repeat(256);
    let max_bytes = max_w.canonical_bytes()?;
    assert_eq!(ForwardAttestation::decode(&max_bytes)?, max_w);

    // Page range at offset+length == u64::MAX (no overflow) and read range ending at the segment edge.
    let mut page = target.clone();
    page.op = 3;
    page.method = "POST".into();
    page.path =
        format!("/attachments/{}/{}/missing", hex(&page.object_id), hex(&page.manifest_hash));
    page.length = 256;
    page.offset = u64::MAX - 256;
    assert_eq!(AttachmentOperation::decode(&page.canonical_bytes()?)?, page);
    let mut read = target.clone();
    read.op = 1;
    read.method = "GET".into();
    read.path =
        format!("/attachments/{}/{}/segments/0", hex(&read.object_id), hex(&read.manifest_hash));
    read.length = 1_048_576;
    read.offset = u64::from(super::super::SEGMENT_BYTES) - 1_048_576;
    read.body_digest = body_digest(&[]);
    assert_eq!(AttachmentOperation::decode(&read.canonical_bytes()?)?, read);
    Ok(())
}

#[test]
fn renewal_vectors_round_trip_byte_identical() -> Result {
    let j: serde_json::Value = serde_json::from_str(include_str!(
        "../../tests/fixtures/large_attachment_renewal_v1.json"
    ))?;
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

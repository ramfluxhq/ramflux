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

/// Predicate inventory (id, location and predicate). Generated from the renewal.rs source.
const INVENTORY: &[(&str, &str)] = &[
    ("A01", "renewal.rs:38 grant_epoch == 0"),
    ("A02", "renewal.rs:38 authority_generation == 0"),
    ("A03", "renewal.rs:38 payload_generation == 0"),
    ("A04", "renewal.rs:48 match op: `_` arm (operation kind)"),
    ("A05", "renewal.rs:50 method != expected method"),
    ("A06", "renewal.rs:50 path != expected path"),
    ("A07", "renewal.rs:53 matches!(op, 2 | 8)"),
    ("A08", "renewal.rs:54 segment_index != 0"),
    ("A09", "renewal.rs:54 offset != 0"),
    ("A10", "renewal.rs:54 length != 0"),
    ("A11", "renewal.rs:58 op == 1"),
    ("A12", "renewal.rs:59 length == 0"),
    ("A13", "renewal.rs:60 length > 1_048_576"),
    ("A14", "renewal.rs:63 offset.checked_add(length) is None"),
    ("A15", "renewal.rs:64 checked end > SEGMENT_BYTES"),
    ("A16", "renewal.rs:68 op == 3"),
    ("A17", "renewal.rs:69 segment_index != 0 (page)"),
    ("A18", "renewal.rs:70 length == 0 (page)"),
    ("A19", "renewal.rs:71 length > 256 (page)"),
    ("A20", "renewal.rs:72 offset.checked_add(length) is None (page)"),
    ("A21", "renewal.rs:76 matches!(op, 1 | 2)"),
    ("A22", "renewal.rs:76 body_digest != body_digest(&[])"),
    ("B01", "renewal.rs:100 bytes.len() > 4096"),
    ("B02", "renewal.rs:104 take(4) != b\"RFO1\""),
    ("B03", "renewal.rs:104 u32() != 1 (operation version)"),
    ("B04", "renewal.rs:124 !c.0.is_empty() (trailing bytes)"),
    ("B05", "native.rs:173 Cursor::take None arm (O entry, truncation)"),
    ("C01", "native.rs:189 O method: n == 0"),
    ("C02", "native.rs:189 O method: n > 256"),
    ("C03", "native.rs:191 O method: from_utf8 Err"),
    ("C04", "native.rs:189 O path: n == 0"),
    ("C05", "native.rs:189 O path: n > 256"),
    ("C06", "native.rs:191 O path: from_utf8 Err"),
    ("C07", "native.rs:189 O audience: n == 0"),
    ("C08", "native.rs:189 O audience: n > 256"),
    ("C09", "native.rs:191 O audience: from_utf8 Err"),
    ("C10", "native.rs:189 W anchor: n == 0"),
    ("C11", "native.rs:189 W anchor: n > 256"),
    ("C12", "native.rs:191 W anchor: from_utf8 Err"),
    ("C13", "native.rs:189 W device id: n == 0"),
    ("C14", "native.rs:189 W device id: n > 256"),
    ("C15", "native.rs:191 W device id: from_utf8 Err"),
    ("C16", "native.rs:189 W home node: n == 0"),
    ("C17", "native.rs:189 W home node: n > 256"),
    ("C18", "native.rs:191 W home node: from_utf8 Err"),
    ("C19", "native.rs:189 W source issuer: n == 0"),
    ("C20", "native.rs:189 W source issuer: n > 256"),
    ("C21", "native.rs:191 W source issuer: from_utf8 Err"),
    ("C22", "native.rs:189 W home issuer: n == 0"),
    ("C23", "native.rs:189 W home issuer: n > 256"),
    ("C24", "native.rs:191 W home issuer: from_utf8 Err"),
    ("D01", "renewal.rs:174 body.len() > 8192"),
    ("D02", "renewal.rs:179 take(4) != b\"RFRQ\""),
    ("D03", "renewal.rs:179 u32() != 1 (body version)"),
    ("D04", "native.rs:173 Cursor::take None arm (body entry)"),
    ("D05", "renewal.rs:184 !c.0.is_empty() (body trailing)"),
    ("D06", "renewal.rs:187 renew.op != 8 (outer kind)"),
    ("D07", "renewal.rs:187 !matches!(target.op, 1..=3)"),
    ("D08", "renewal.rs:190 renew.body_digest != body_digest(body)"),
    ("D09", "renewal.rs:193 renew.object_id != target.object_id"),
    ("D10", "renewal.rs:194 renew.manifest_hash != target.manifest_hash"),
    ("D11", "renewal.rs:195 renew.grant_id != target.grant_id"),
    ("D12", "renewal.rs:196 renew.grant_epoch != target.grant_epoch"),
    ("D13", "renewal.rs:197 renew.authority_generation != target.authority_generation"),
    ("D14", "renewal.rs:198 renew.payload_generation != target.payload_generation"),
    ("D15", "renewal.rs:199 renew.operation_id == target.operation_id"),
    ("E01", "renewal.rs:341 grantee.account_anchor != requester.account_anchor (derived eq leg)"),
    ("E02", "renewal.rs:341 grantee.device_id != requester.device_id (derived eq leg)"),
    ("E03", "renewal.rs:341 grantee.device_epoch != requester.device_epoch (derived eq leg)"),
    (
        "E04",
        "renewal.rs:341 grantee.signing_public_key != requester.signing_public_key (derived eq leg)",
    ),
    ("E05", "renewal.rs:341 grantee.home_node_id != requester.home_node_id (derived eq leg)"),
    ("E06", "renewal.rs:344 renew.audience != source"),
    ("E07", "renewal.rs:344 target.audience != relay"),
    ("E08", "renewal.rs:347 target.object_id != g.object_id"),
    ("E09", "renewal.rs:348 target.manifest_hash != g.manifest_hash"),
    ("E10", "renewal.rs:349 target.grant_id != g.grant_id"),
    ("E11", "renewal.rs:350 target.grant_epoch != g.epoch"),
    ("E12", "renewal.rs:355 g.rights & (8|right) != (8|right)"),
    ("E13", "renewal.rs:358 now < g.issued_at"),
    ("E14", "renewal.rs:358 now >= g.expires_at"),
    ("F01", "renewal.rs:423 bytes.len() > 2048"),
    ("F02", "renewal.rs:427 take(4) != b\"RFW1\""),
    ("F03", "renewal.rs:427 u32() != 1 (forward version)"),
    ("F04", "renewal.rs:449 !c.0.is_empty() (forward trailing bytes)"),
    ("F05", "native.rs:173 Cursor::take None arm (W entry, truncation)"),
    ("F06", "renewal.rs:247 lifetime: issued >= expires (W)"),
    ("F07", "renewal.rs:247 lifetime: expires - issued > 30 (W)"),
    ("F08", "renewal.rs:257 grant_epoch == 0 (W)"),
    ("F09", "renewal.rs:257 requester.home_node_id != home_issuer (W)"),
    ("F10", "renewal.rs:149 qualified: device_epoch == 0 (W requester)"),
    ("G01", "renewal.rs:375 requester.account_anchor != expected (derived eq leg)"),
    ("G02", "renewal.rs:375 requester.device_id != expected (derived eq leg)"),
    ("G03", "renewal.rs:375 requester.device_epoch != expected (derived eq leg)"),
    ("G04", "renewal.rs:375 requester.signing_public_key != expected (derived eq leg)"),
    ("G05", "renewal.rs:375 requester.home_node_id != expected (derived eq leg)"),
    ("G06", "renewal.rs:376 challenge != expected"),
    ("G07", "renewal.rs:377 grant_hash != grant hash"),
    ("G08", "renewal.rs:378 grant_id != grant.grant_id"),
    ("G09", "renewal.rs:379 grant_epoch != grant.epoch"),
    ("G10", "renewal.rs:380 source_issuer != request audience"),
    ("G11", "renewal.rs:381 operation_hash != request operation hash"),
    ("G12", "renewal.rs:386 issued_at > now + 5"),
    ("G13", "renewal.rs:387 expires_at <= now"),
    ("G14", "renewal.rs:388 expires_at > grant.expires_at"),
    ("H01", "renewal.rs:459 bytes.len() != 152 (pop length)"),
    ("H02", "renewal.rs:463 take(4) != b\"RFP1\""),
    ("H03", "renewal.rs:463 u32() != 1 (pop version)"),
    ("H04", "renewal.rs:247 lifetime: issued >= expires (P)"),
    ("H05", "renewal.rs:247 lifetime: expires - issued > 30 (P)"),
    ("I01", "renewal.rs:400 operation_hash != w.operation_hash"),
    ("I02", "renewal.rs:401 requester_digest != requester_digest(w.requester)"),
    ("I03", "renewal.rs:402 forward_digest != w.hash()"),
    ("I04", "renewal.rs:406 issued_at < w.issued_at"),
    ("I05", "renewal.rs:407 expires_at > w.expires_at"),
    ("I06", "renewal.rs:408 issued_at > now + 5"),
    ("I07", "renewal.rs:409 expires_at <= now"),
    ("J01", "grant.rs:150 W verify_strict Err (grant signature)"),
    ("J02", "grant.rs:150 P verify_strict Err (grant signature)"),
];

type Fe = std::result::Result<(), FormatError>;

/// One row per predicate instance. `hits` records ids; `failures` collects mismatches so a
/// per-predicate break-the-fix shows exactly which rows fail.
#[derive(Default)]
struct Rows {
    hits: Vec<&'static str>,
    failures: Vec<String>,
}

/// `want` is the exact refusal, or `None` when the row must be accepted.
fn row(r: &mut Rows, id: &'static str, label: &str, got: Fe, want: Option<&'static str>) {
    r.hits.push(id);
    let expect = want.map_or(Ok(()), |e| Err(FormatError(e)));
    if got != expect {
        r.failures.push(format!("{id} {label}: got {got:?}, want {expect:?}"));
    }
}

fn fixture_json() -> Result<serde_json::Value> {
    Ok(serde_json::from_str(include_str!("../../tests/fixtures/large_attachment_renewal_v1.json"))?)
}

fn read_hex(v: &serde_json::Value) -> Result<Vec<u8>> {
    bytes(v.as_str().ok_or("hex")?)
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

fn dec_o(b: &[u8]) -> Fe {
    AttachmentOperation::decode(b).map(|_| ())
}

fn dec_w(b: &[u8]) -> Fe {
    ForwardAttestation::decode(b).map(|_| ())
}

fn dec_p(b: &[u8]) -> Fe {
    RequesterPop::decode(b).map(|_| ())
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

fn read_path(op: &AttachmentOperation) -> String {
    format!(
        "/attachments/{}/{}/segments/{}",
        hex(&op.object_id),
        hex(&op.manifest_hash),
        op.segment_index
    )
}

/// Valid read (op 1) at segment 0, offset 0, length 1, empty body digest.
fn read_base(v: &Vectors) -> AttachmentOperation {
    let mut op = v.target.clone();
    op.op = 1;
    op.method = "GET".into();
    op.segment_index = 0;
    op.path = read_path(&op);
    op.offset = 0;
    op.length = 1;
    op.body_digest = body_digest(&[]);
    op
}

/// Valid missing page (op 3) at segment 0, length 1, offset 0.
fn page_base(v: &Vectors) -> AttachmentOperation {
    let mut op = v.target.clone();
    op.op = 3;
    op.method = "POST".into();
    op.segment_index = 0;
    op.path = format!("/attachments/{}/{}/missing", hex(&op.object_id), hex(&op.manifest_hash));
    op.offset = 0;
    op.length = 1;
    op
}

fn rows_operation_canonical(v: &Vectors, r: &mut Rows) -> Result {
    let ro = &v.ro;
    let path_at = ident_end(ro, 12)?;
    let path_last = ident_end(ro, path_at)? - 1;
    let generation = Some("operation generation");
    row(
        r,
        "A01",
        "renewal O grant epoch zero",
        dec_o(&mutated(ro, |b| put_from_end(b, 112, &[0; 8]))),
        generation,
    );
    row(
        r,
        "A02",
        "renewal O authority generation zero",
        dec_o(&mutated(ro, |b| put_from_end(b, 104, &[0; 8]))),
        generation,
    );
    row(
        r,
        "A03",
        "renewal O payload generation zero",
        dec_o(&mutated(ro, |b| put_from_end(b, 64, &[0; 8]))),
        generation,
    );
    row(
        r,
        "A04",
        "renewal O op kind 4",
        dec_o(&mutated(ro, |b| b[8..12].copy_from_slice(&4_u32.to_be_bytes()))),
        Some("operation kind"),
    );
    row(
        r,
        "A05",
        "renewal O method byte",
        dec_o(&mutated(ro, |b| b[16] ^= 1)),
        Some("operation endpoint"),
    );
    row(
        r,
        "A06",
        "renewal O path last byte",
        dec_o(&mutated(ro, |b| b[path_last] ^= 1)),
        Some("operation endpoint"),
    );
    rows_operation_page(v, r)?;
    rows_operation_range(v, r)
}

fn rows_operation_page(v: &Vectors, r: &mut Rows) -> Result {
    let page = page_base(v).canonical_bytes()?;
    let page_err = Some("operation page");
    row(
        r,
        "A17",
        "page O segment index 1",
        dec_o(&mutated(&page, |b| put_from_end(b, 56, &1_u64.to_be_bytes()))),
        page_err,
    );
    row(
        r,
        "A18",
        "page O length zero",
        dec_o(&mutated(&page, |b| put_from_end(b, 40, &0_u64.to_be_bytes()))),
        page_err,
    );
    row(
        r,
        "A19",
        "page O length 257",
        dec_o(&mutated(&page, |b| put_from_end(b, 40, &257_u64.to_be_bytes()))),
        page_err,
    );
    row(
        r,
        "A20",
        "page O offset u64::MAX length 1",
        dec_o(&mutated(&page, |b| put_from_end(b, 48, &u64::MAX.to_be_bytes()))),
        page_err,
    );
    Ok(())
}

fn rows_operation_range(v: &Vectors, r: &mut Rows) -> Result {
    let ro = &v.ro;
    let read = read_base(v).canonical_bytes()?;
    let seg = u64::from(super::super::SEGMENT_BYTES);
    let mut seg1 = read_base(v);
    seg1.segment_index = 1;
    seg1.path = read_path(&seg1);
    row(
        r,
        "A07",
        "read O at segment 1 is not an unused range",
        dec_o(&seg1.canonical_bytes()?),
        None,
    );
    let unused = Some("operation unused range");
    row(
        r,
        "A08",
        "renewal O segment index 1",
        dec_o(&mutated(ro, |b| put_from_end(b, 56, &1_u64.to_be_bytes()))),
        unused,
    );
    row(
        r,
        "A09",
        "renewal O offset 1",
        dec_o(&mutated(ro, |b| put_from_end(b, 48, &1_u64.to_be_bytes()))),
        unused,
    );
    row(
        r,
        "A10",
        "renewal O length 1",
        dec_o(&mutated(ro, |b| put_from_end(b, 40, &1_u64.to_be_bytes()))),
        unused,
    );
    let mut past = page_base(v);
    past.offset = seg + 5;
    row(
        r,
        "A11",
        "page O offset past segment is not a read range",
        dec_o(&past.canonical_bytes()?),
        None,
    );
    let range = Some("operation range");
    row(
        r,
        "A12",
        "read O length zero",
        dec_o(&mutated(&read, |b| put_from_end(b, 40, &0_u64.to_be_bytes()))),
        range,
    );
    row(
        r,
        "A13",
        "read O length 1 MiB + 1",
        dec_o(&mutated(&read, |b| put_from_end(b, 40, &1_048_577_u64.to_be_bytes()))),
        range,
    );
    row(
        r,
        "A14",
        "read O offset u64::MAX length 1 (overflow)",
        dec_o(&mutated(&read, |b| put_from_end(b, 48, &u64::MAX.to_be_bytes()))),
        range,
    );
    row(
        r,
        "A15",
        "read O range past segment end",
        dec_o(&mutated(&read, |b| put_from_end(b, 48, &seg.to_be_bytes()))),
        range,
    );
    let mut long = read_base(v);
    long.length = 257;
    row(r, "A16", "read O length 257 is not a page", dec_o(&long.canonical_bytes()?), None);
    row(r, "A21", "renewal O (op 8) is not read-digest checked", dec_o(ro), None);
    row(
        r,
        "A22",
        "read O body digest",
        dec_o(&mutated(&read, |b| flip_from_end(b, 32))),
        Some("read body"),
    );
    Ok(())
}

fn rows_operation_decode(v: &Vectors, r: &mut Rows) {
    let ro = &v.ro;
    row(r, "B01", "O over 4096 bytes", dec_o(&vec![0; 4097]), Some("operation cap"));
    row(r, "B02", "O magic", dec_o(&mutated(ro, |b| b[0] ^= 1)), Some("operation version"));
    row(r, "B03", "O version 2", dec_o(&mutated(ro, |b| b[7] = 2)), Some("operation version"));
    row(r, "B04", "O trailing byte", dec_o(&mutated(ro, |b| b.push(0))), Some("operation framing"));
    row(
        r,
        "B05",
        "O truncated by one byte",
        dec_o(&mutated(ro, |b| {
            b.pop();
        })),
        Some("truncated native"),
    );
}

const C_IDS: [&str; 24] = [
    "C01", "C02", "C03", "C04", "C05", "C06", "C07", "C08", "C09", "C10", "C11", "C12", "C13",
    "C14", "C15", "C16", "C17", "C18", "C19", "C20", "C21", "C22", "C23", "C24",
];

fn rows_identity(v: &Vectors, r: &mut Rows) -> Result {
    let ro = &v.ro;
    let w = &v.w;
    let path_at = ident_end(ro, 12)?;
    let aud_at = ident_end(ro, path_at)?;
    let wp = w_pos(w)?;
    let o_fields = [("O method", 12_usize), ("O path", path_at), ("O audience", aud_at)];
    let w_fields = [
        ("W anchor", wp.anchor),
        ("W device id", wp.device),
        ("W home node", wp.home),
        ("W source issuer", wp.source),
        ("W home issuer", wp.home_issuer),
    ];
    let mut k = 0;
    for (_, at) in o_fields {
        row(
            r,
            C_IDS[k],
            "O identity zero length",
            dec_o(&mutated(ro, |b| b[at..at + 4].copy_from_slice(&0_u32.to_be_bytes()))),
            Some("native identity length"),
        );
        row(
            r,
            C_IDS[k + 1],
            "O identity length 257",
            dec_o(&mutated(ro, |b| b[at..at + 4].copy_from_slice(&257_u32.to_be_bytes()))),
            Some("native identity length"),
        );
        row(
            r,
            C_IDS[k + 2],
            "O identity non-UTF-8",
            dec_o(&mutated(ro, |b| b[at + 4] = 0xff)),
            Some("native UTF8"),
        );
        k += 3;
    }
    for (_, at) in w_fields {
        row(
            r,
            C_IDS[k],
            "W identity zero length",
            dec_w(&mutated(w, |b| b[at..at + 4].copy_from_slice(&0_u32.to_be_bytes()))),
            Some("native identity length"),
        );
        row(
            r,
            C_IDS[k + 1],
            "W identity length 257",
            dec_w(&mutated(w, |b| b[at..at + 4].copy_from_slice(&257_u32.to_be_bytes()))),
            Some("native identity length"),
        );
        row(
            r,
            C_IDS[k + 2],
            "W identity non-UTF-8",
            dec_w(&mutated(w, |b| b[at + 4] = 0xff)),
            Some("native UTF8"),
        );
        k += 3;
    }
    Ok(())
}

fn rows_renewal_body(v: &Vectors, r: &mut Rows) -> Result {
    let body = &v.request.body;
    let ro = &v.ro;
    let req =
        |op: Vec<u8>, body: Vec<u8>| RenewalRequest { operation: op, body }.target().map(|_| ());
    let kind = Some("renewal target kind");
    row(
        r,
        "D01",
        "renewal body over 8192 bytes",
        req(ro.clone(), vec![0; 8193]),
        Some("renewal body cap"),
    );
    row(
        r,
        "D02",
        "renewal body magic",
        req(ro.clone(), mutated(body, |b| b[0] ^= 1)),
        Some("renewal body version"),
    );
    row(
        r,
        "D03",
        "renewal body version 2",
        req(ro.clone(), mutated(body, |b| b[7] = 2)),
        Some("renewal body version"),
    );
    row(
        r,
        "D04",
        "renewal body target length beyond body",
        req(ro.clone(), mutated(body, |b| b[8..12].copy_from_slice(&u32::MAX.to_be_bytes()))),
        Some("truncated native"),
    );
    row(
        r,
        "D05",
        "renewal body trailing byte",
        req(ro.clone(), mutated(body, |b| b.push(0))),
        Some("renewal body framing"),
    );
    let mut outer = page_base(v);
    outer.audience = v.renew.audience.clone();
    outer.operation_id = v.renew.operation_id;
    outer.body_digest = body_digest(body);
    row(
        r,
        "D06",
        "outer operation is Missing (valid), not renewal",
        req(outer.canonical_bytes()?, body.clone()),
        kind,
    );
    let t8 = {
        let mut t = v.target.clone();
        t.op = 8;
        t.method = "POST".into();
        t.path = "/s9/attachments/renew".into();
        t.segment_index = 0;
        t.offset = 0;
        t.length = 0;
        t
    };
    let mut frame = b"RFRQ".to_vec();
    frame.extend(1_u32.to_be_bytes());
    lp(&mut frame, &t8.canonical_bytes()?)?;
    let mut renew8 = v.renew.clone();
    renew8.body_digest = body_digest(&frame);
    row(r, "D07", "embedded target is operation 8", req(renew8.canonical_bytes()?, frame), kind);
    row(
        r,
        "D08",
        "renewal body digest",
        req(mutated(ro, |b| flip_from_end(b, 32)), body.clone()),
        Some("renewal body digest"),
    );
    rows_renewal_bindings(v, r);
    Ok(())
}

fn rows_renewal_bindings(v: &Vectors, r: &mut Rows) {
    let ro = &v.ro;
    let body = &v.request.body;
    let tid = v.target.operation_id;
    let req =
        |op: Vec<u8>, body: Vec<u8>| RenewalRequest { operation: op, body }.target().map(|_| ());
    let binding = Some("renewal target binding");
    row(
        r,
        "D09",
        "renewal object id",
        req(mutated(ro, |b| flip_from_end(b, 208)), body.clone()),
        binding,
    );
    row(
        r,
        "D10",
        "renewal manifest hash",
        req(mutated(ro, |b| flip_from_end(b, 176)), body.clone()),
        binding,
    );
    row(
        r,
        "D11",
        "renewal grant id",
        req(mutated(ro, |b| flip_from_end(b, 144)), body.clone()),
        binding,
    );
    row(
        r,
        "D12",
        "renewal grant epoch",
        req(mutated(ro, |b| put_from_end(b, 112, &2_u64.to_be_bytes())), body.clone()),
        binding,
    );
    row(
        r,
        "D13",
        "renewal authority generation",
        req(mutated(ro, |b| put_from_end(b, 104, &2_u64.to_be_bytes())), body.clone()),
        binding,
    );
    row(
        r,
        "D14",
        "renewal payload generation",
        req(mutated(ro, |b| put_from_end(b, 64, &2_u64.to_be_bytes())), body.clone()),
        binding,
    );
    row(
        r,
        "D15",
        "renewal operation id equal to target",
        req(mutated(ro, |b| put_from_end(b, 96, &tid)), body.clone()),
        binding,
    );
}

fn rows_renewal_grant(v: &Vectors, r: &mut Rows) -> Result {
    let owner = ed25519_dalek::SigningKey::from_bytes(&[81; 32]);
    let base = signed_grant(v.grant.grant().clone(), &owner)?;
    let requester = base.grant().grantee.clone();
    let now = 1_700_000_001;
    let source = v.renew.audience.clone();
    let relay = v.target.audience.clone();
    let ro = &v.ro;
    let body = &v.request.body;
    let who = Some("renewal requester");
    let g = base.grant().clone();
    let with_grantee = |f: &dyn Fn(&mut crate::large_attachment::ScopedAttachmentGrant)| -> Result<VerifiedScopedGrant> {
        let mut c = g.clone();
        f(&mut c);
        signed_grant(c, &owner)
    };
    let check = |c: &VerifiedScopedGrant| {
        RenewalRequest { operation: ro.clone(), body: body.clone() }
            .validate(c, &requester, &source, &relay, now)
    };
    row(
        r,
        "E01",
        "grantee account anchor",
        check(&with_grantee(&|c| c.grantee.account_anchor.push('x'))?),
        who,
    );
    row(
        r,
        "E02",
        "grantee device id",
        check(&with_grantee(&|c| c.grantee.device_id.push('x'))?),
        who,
    );
    row(
        r,
        "E03",
        "grantee device epoch",
        check(&with_grantee(&|c| c.grantee.device_epoch += 1)?),
        who,
    );
    row(
        r,
        "E04",
        "grantee signing key",
        check(&with_grantee(&|c| c.grantee.signing_public_key[0] ^= 1)?),
        who,
    );
    row(
        r,
        "E05",
        "grantee home node",
        check(&with_grantee(&|c| c.grantee.home_node_id.push('x'))?),
        who,
    );
    rows_renewal_audience(v, r)?;
    let grant_err = Some("renewal grant binding");
    row(r, "E08", "grant object id", check(&with_grantee(&|c| c.object_id[0] ^= 1)?), grant_err);
    row(
        r,
        "E09",
        "grant manifest hash",
        check(&with_grantee(&|c| c.manifest_hash[0] ^= 1)?),
        grant_err,
    );
    row(r, "E10", "grant id", check(&with_grantee(&|c| c.grant_id[0] ^= 1)?), grant_err);
    row(r, "E11", "grant epoch", check(&with_grantee(&|c| c.epoch += 1)?), grant_err);
    row(
        r,
        "E12",
        "grant rights without renewal bit",
        check(&with_grantee(&|c| c.rights = 1)?),
        Some("renewal rights"),
    );
    let early = RenewalRequest { operation: ro.clone(), body: body.clone() };
    row(
        r,
        "E13",
        "now before grant issue",
        early.validate(&base, &requester, &source, &relay, g.issued_at - 1),
        Some("renewal grant time"),
    );
    row(
        r,
        "E14",
        "now at grant expiry",
        early.validate(&base, &requester, &source, &relay, g.expires_at),
        Some("renewal grant time"),
    );
    Ok(())
}

fn rows_renewal_audience(v: &Vectors, r: &mut Rows) -> Result {
    let owner = ed25519_dalek::SigningKey::from_bytes(&[81; 32]);
    let base = signed_grant(v.grant.grant().clone(), &owner)?;
    let requester = base.grant().grantee.clone();
    let now = 1_700_000_001;
    let source = v.renew.audience.clone();
    let relay = v.target.audience.clone();
    let ro = &v.ro;
    let body = &v.request.body;
    let aud = ident_end(ro, ident_end(ro, 12)?)?;
    let renew_aud =
        RenewalRequest { operation: mutated(ro, |b| b[aud + 4] ^= 1), body: body.clone() };
    row(
        r,
        "E06",
        "renewal audience byte",
        renew_aud.validate(&base, &requester, &source, &relay, now),
        Some("renewal audience"),
    );
    let tb = v.target.canonical_bytes()?;
    let t_aud = ident_end(&tb, ident_end(&tb, 12)?)?;
    let body2 = mutated(body, |b| b[12 + t_aud + 4] ^= 1);
    let mut renew2 = v.renew.clone();
    renew2.body_digest = body_digest(&body2);
    let relay_aud = RenewalRequest { operation: renew2.canonical_bytes()?, body: body2 };
    row(
        r,
        "E07",
        "target relay audience byte",
        relay_aud.validate(&base, &requester, &source, &relay, now),
        Some("renewal audience"),
    );
    Ok(())
}

fn rows_forward_decode(v: &Vectors, r: &mut Rows) -> Result {
    let w = &v.w;
    let wp = w_pos(w)?;
    let iss = u64::from_be_bytes(w[wp.issued..wp.issued + 8].try_into()?);
    row(r, "F01", "W over 2048 bytes", dec_w(&vec![0; 2049]), Some("forward cap"));
    row(r, "F02", "W magic", dec_w(&mutated(w, |b| b[0] ^= 1)), Some("forward version"));
    row(r, "F03", "W version 2", dec_w(&mutated(w, |b| b[7] = 2)), Some("forward version"));
    row(r, "F04", "W trailing byte", dec_w(&mutated(w, |b| b.push(0))), Some("forward framing"));
    row(
        r,
        "F05",
        "W truncated by one byte",
        dec_w(&mutated(w, |b| {
            b.pop();
        })),
        Some("truncated native"),
    );
    row(
        r,
        "F06",
        "W expires equal to issued",
        dec_w(&mutated(w, |b| put_at(b, wp.issued + 8, iss))),
        Some("proof lifetime"),
    );
    row(
        r,
        "F07",
        "W lifetime 31 seconds",
        dec_w(&mutated(w, |b| put_at(b, wp.issued + 8, iss + 31))),
        Some("proof lifetime"),
    );
    row(
        r,
        "F08",
        "W grant epoch zero",
        dec_w(&mutated(w, |b| put_at(b, wp.grant_epoch, 0))),
        Some("forward home binding"),
    );
    row(
        r,
        "F09",
        "W home node differs from home issuer",
        dec_w(&mutated(w, |b| b[wp.home + 4] ^= 1)),
        Some("forward home binding"),
    );
    row(
        r,
        "F10",
        "W requester device epoch zero",
        dec_w(&mutated(w, |b| put_at(b, wp.device_epoch, 0))),
        Some("device epoch"),
    );
    Ok(())
}

fn rows_forward_validate(v: &Vectors, r: &mut Rows) -> Result {
    let w0 = &v.w_orig;
    let now = w0.issued_at;
    let gexp = v.grant.grant().expires_at;
    let wb = &v.w;
    let p = w_pos(wb)?;
    let ge = p.grant_epoch;
    let req = w0.requester.clone();
    let ch = w0.challenge;
    let check = |bytes: &[u8], at: u64| {
        ForwardAttestation::decode(bytes)
            .and_then(|w| w.validate(&v.request, &v.grant, &req, &ch, at))
    };
    let bind = Some("forward request binding");
    let time = Some("forward time");
    row(
        r,
        "G01",
        "W requester account anchor",
        check(&mutated(wb, |b| b[p.anchor + 4] ^= 1), now),
        bind,
    );
    row(
        r,
        "G02",
        "W requester device id",
        check(&mutated(wb, |b| b[p.device + 4] ^= 1), now),
        bind,
    );
    row(
        r,
        "G03",
        "W requester device epoch 2",
        check(&mutated(wb, |b| put_at(b, p.device_epoch, 2)), now),
        bind,
    );
    row(r, "G04", "W requester signing key", check(&mutated(wb, |b| b[p.key] ^= 1), now), bind);
    row(
        r,
        "G05",
        "W requester home (home issuer kept consistent)",
        check(
            &mutated(wb, |b| {
                b[p.home + 4] ^= 1;
                b[p.home_issuer + 4] ^= 1;
            }),
            now,
        ),
        bind,
    );
    row(r, "G06", "W challenge", check(&mutated(wb, |b| b[p.challenge] ^= 1), now), bind);
    row(r, "G07", "W grant hash", check(&mutated(wb, |b| b[ge - 64] ^= 1), now), bind);
    row(r, "G08", "W grant id", check(&mutated(wb, |b| b[ge - 32] ^= 1), now), bind);
    row(r, "G09", "W grant epoch 2", check(&mutated(wb, |b| b[ge + 7] = 2), now), bind);
    row(r, "G10", "W source issuer", check(&mutated(wb, |b| b[p.source + 4] ^= 1), now), bind);
    row(r, "G11", "W operation hash", check(&mutated(wb, |b| b[p.op_hash] ^= 1), now), bind);
    let at_times = |issued: u64, expires: u64| {
        mutated(wb, |b| {
            put_from_end(b, 16, &issued.to_be_bytes());
            put_from_end(b, 8, &expires.to_be_bytes());
        })
    };
    row(r, "G12", "W issued more than 5 s ahead", check(&at_times(now + 6, now + 7), now), time);
    row(
        r,
        "G13",
        "W expired at its own validation time",
        check(&at_times(now, now + 5), now + 10),
        time,
    );
    row(
        r,
        "G14",
        "W expiry after grant expiry",
        check(&at_times(gexp - 29, gexp + 1), gexp - 29),
        time,
    );
    Ok(())
}

fn rows_pop_decode(v: &Vectors, r: &mut Rows) -> Result {
    let pb = &v.p;
    let iss = u64::from_be_bytes(pb[104..112].try_into()?);
    row(r, "H01", "P length 153", dec_p(&mutated(pb, |b| b.push(0))), Some("pop length"));
    row(r, "H02", "P magic", dec_p(&mutated(pb, |b| b[0] ^= 1)), Some("pop version"));
    row(r, "H03", "P version 2", dec_p(&mutated(pb, |b| b[7] = 2)), Some("pop version"));
    row(
        r,
        "H04",
        "P expires equal to issued",
        dec_p(&mutated(pb, |b| put_at(b, 112, iss))),
        Some("proof lifetime"),
    );
    row(
        r,
        "H05",
        "P lifetime 31 seconds",
        dec_p(&mutated(pb, |b| put_at(b, 112, iss + 31))),
        Some("proof lifetime"),
    );
    Ok(())
}

fn rows_pop_validate(v: &Vectors, r: &mut Rows) {
    let w0 = &v.w_orig;
    let now = w0.issued_at;
    let pb = &v.p;
    let times = |issued: u64, expires: u64| {
        mutated(pb, |b| {
            put_at(b, 104, issued);
            put_at(b, 112, expires);
        })
    };
    let check =
        |bytes: &[u8], at: u64| RequesterPop::decode(bytes).and_then(|p| p.validate(w0, at));
    let bind = Some("pop binding");
    let time = Some("pop time");
    row(r, "I01", "P operation hash", check(&mutated(pb, |b| b[8] ^= 1), now), bind);
    row(r, "I02", "P requester digest", check(&mutated(pb, |b| b[40] ^= 1), now), bind);
    row(r, "I03", "P forward digest", check(&mutated(pb, |b| b[120] ^= 1), now), bind);
    row(r, "I04", "P issued before W issued", check(&times(now - 1, now + 29), now), time);
    row(r, "I05", "P expiry after W expiry", check(&times(now + 1, now + 31), now), time);
    row(r, "I06", "P issued more than 5 s ahead", check(&times(now + 6, now + 7), now), time);
    row(
        r,
        "I07",
        "P expired at its own validation time",
        check(&times(now, now + 5), now + 10),
        time,
    );
}

fn rows_signatures(v: &Vectors, r: &mut Rows) -> Result {
    let w0 = &v.w_orig;
    let sk = ed25519_dalek::SigningKey::from_bytes(&[82; 32]);
    let pk = sk.verifying_key().to_bytes();
    let sig = sk.sign(&w0.signing_bytes()?).to_bytes();
    w0.verify(&pk, &sig)?;
    let mut bad = sig;
    bad[0] ^= 1;
    row(r, "J01", "W signature byte flip", w0.verify(&pk, &bad), Some("grant signature"));
    let p0 = &v.p_orig;
    let sk2 = ed25519_dalek::SigningKey::from_bytes(&[83; 32]);
    let pk2 = sk2.verifying_key().to_bytes();
    let sig2 = sk2.sign(&p0.signing_bytes()?).to_bytes();
    p0.verify(&pk2, &sig2)?;
    let mut bad2 = sig2;
    bad2[0] ^= 1;
    row(r, "J02", "P signature byte flip", p0.verify(&pk2, &bad2), Some("grant signature"));
    Ok(())
}

/// Inclusive boundary acceptances, counted separately from the predicate inventory.
fn boundary_positives(v: &Vectors) -> Result {
    let ro = &v.ro;
    let w = &v.w;
    let path_at = ident_end(ro, 12)?;
    let aud_at = ident_end(ro, path_at)?;
    let max = vec![b'a'; 256];
    let mut method = b"POST".to_vec();
    method.resize(256, b'x');
    let mut path = b"/s9/attachments/renew".to_vec();
    path.resize(256, b'x');
    assert_eq!(dec_o(&splice_ident(ro, 12, &method)?), Err(FormatError("operation endpoint")));
    assert_eq!(dec_o(&splice_ident(ro, path_at, &path)?), Err(FormatError("operation endpoint")));
    dec_o(&splice_ident(ro, aud_at, &max)?)?;
    let wp = w_pos(w)?;
    dec_w(&splice_ident(w, wp.anchor, &max)?)?;
    dec_w(&splice_ident(w, wp.device, &max)?)?;
    dec_w(&splice_ident(w, wp.source, &max)?)?;
    dec_w(&splice_ident(&splice_ident(w, wp.home_issuer, &max)?, wp.home, &max)?)?;
    let seg = u64::from(super::super::SEGMENT_BYTES);
    let mut read = read_base(v);
    read.length = 1_048_576;
    dec_o(&read.canonical_bytes()?)?;
    read.length = 1;
    read.offset = seg - 1;
    dec_o(&read.canonical_bytes()?)?;
    let mut page = page_base(v);
    page.length = 256;
    dec_o(&page.canonical_bytes()?)?;
    page.offset = u64::MAX - 256;
    dec_o(&page.canonical_bytes()?)?;
    let iss = u64::from_be_bytes(w[wp.issued..wp.issued + 8].try_into()?);
    dec_w(&mutated(w, |b| put_at(b, wp.issued + 8, iss + 30)))?;
    dec_w(&mutated(w, |b| put_at(b, wp.issued + 8, iss + 1)))?;
    let now = v.w_orig.issued_at;
    let gexp = v.grant.grant().expires_at;
    let at_skew = mutated(w, |b| {
        put_from_end(b, 16, &(now + 5).to_be_bytes());
        put_from_end(b, 8, &(now + 6).to_be_bytes());
    });
    ForwardAttestation::decode(&at_skew)?.validate(
        &v.request,
        &v.grant,
        &v.w_orig.requester,
        &v.w_orig.challenge,
        now,
    )?;
    let at_grant = mutated(w, |b| {
        put_from_end(b, 16, &(gexp - 30).to_be_bytes());
        put_from_end(b, 8, &gexp.to_be_bytes());
    });
    ForwardAttestation::decode(&at_grant)?.validate(
        &v.request,
        &v.grant,
        &v.w_orig.requester,
        &v.w_orig.challenge,
        gexp - 30,
    )?;
    v.w_orig.validate(&v.request, &v.grant, &v.w_orig.requester, &v.w_orig.challenge, now)?;
    let pb = &v.p;
    let piss = u64::from_be_bytes(pb[104..112].try_into()?);
    dec_p(&mutated(pb, |b| put_at(b, 112, piss + 30)))?;
    dec_p(&mutated(pb, |b| put_at(b, 112, piss + 1)))?;
    let skew_p = mutated(pb, |b| {
        put_at(b, 104, now + 5);
        put_at(b, 112, now + 6);
    });
    RequesterPop::decode(&skew_p)?.validate(&v.w_orig, now)?;
    v.p_orig.validate(&v.w_orig, now)?;
    Ok(())
}

fn family(f: fn(&Vectors, &mut Rows) -> Result) -> Result {
    let v = vectors()?;
    let mut r = Rows::default();
    f(&v, &mut r)?;
    assert!(r.failures.is_empty(), "{:#?}", r.failures);
    Ok(())
}

#[test]
fn renewal_rows_operation_canonical() -> Result {
    family(rows_operation_canonical)
}

#[test]
fn renewal_rows_operation_decode_and_identity() -> Result {
    family(|v, r| {
        rows_operation_decode(v, r);
        rows_identity(v, r)
    })
}

#[test]
fn renewal_rows_renewal_body() -> Result {
    family(rows_renewal_body)
}

#[test]
fn renewal_rows_renewal_grant() -> Result {
    family(rows_renewal_grant)
}

#[test]
fn renewal_rows_forward_decode_and_validate() -> Result {
    family(|v, r| {
        rows_forward_decode(v, r)?;
        rows_forward_validate(v, r)
    })
}

#[test]
fn renewal_rows_pop_and_signatures() -> Result {
    family(|v, r| {
        rows_pop_decode(v, r)?;
        rows_pop_validate(v, r);
        rows_signatures(v, r)
    })
}

#[test]
fn renewal_boundary_positives_accept() -> Result {
    let v = vectors()?;
    boundary_positives(&v)
}

#[test]
fn renewal_predicate_rows_match_inventory() -> Result {
    let v = vectors()?;
    let mut r = Rows::default();
    rows_operation_canonical(&v, &mut r)?;
    rows_operation_decode(&v, &mut r);
    rows_identity(&v, &mut r)?;
    rows_renewal_body(&v, &mut r)?;
    rows_renewal_grant(&v, &mut r)?;
    rows_forward_decode(&v, &mut r)?;
    rows_forward_validate(&v, &mut r)?;
    rows_pop_decode(&v, &mut r)?;
    rows_pop_validate(&v, &mut r);
    rows_signatures(&v, &mut r)?;
    assert!(r.failures.is_empty(), "{:#?}", r.failures);
    let mut hits = r.hits.clone();
    hits.sort_unstable();
    let mut inv: Vec<&str> = INVENTORY.iter().map(|(id, _)| *id).collect();
    inv.sort_unstable();
    assert_eq!(hits, inv, "each predicate instance has exactly one row");
    assert_eq!(INVENTORY.len(), 118);
    Ok(())
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

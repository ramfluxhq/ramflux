// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use super::*;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use ramflux_protocol::dm_fs_v3 as p;
use serde_json::Value;
type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;
fn wire() -> Result<Value> {
    Ok(serde_json::from_str(include_str!(
        "../../../ramflux-protocol/fixtures/dm_fs_v3/wire_vectors.json"
    ))?)
}
fn crypto() -> Result<Value> {
    Ok(serde_json::from_str(include_str!(
        "../../../ramflux-protocol/fixtures/dm_fs_v3/crypto_vectors.json"
    ))?)
}
fn bytes(v: &Value) -> Result<Vec<u8>> {
    Ok(hex::decode(v.as_str().ok_or("hex")?)?)
}
fn fixed<const N: usize>(v: &Value) -> Result<[u8; N]> {
    bytes(v)?.try_into().map_err(|_| "width".into())
}
fn raw(name: &str) -> Result<Vec<u8>> {
    let w = wire()?;
    let v = w["positive"]
        .as_array()
        .ok_or("positive")?
        .iter()
        .find(|v| v["name"] == name)
        .ok_or("vector")?;
    bytes(&v["bytes"])
}
fn target() -> Result<p::QualifiedBranch> {
    Ok(p::QualifiedBranch::from_bytes(&raw("QualifiedBranch")?)?)
}
struct DeterministicSigner(SigningKey);
impl std::fmt::Debug for DeterministicSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("DeterministicSigner(<redacted>)")
    }
}
impl NativePrekeySigner for DeterministicSigner {
    fn public_key(&self) -> [u8; 32] {
        self.0.verifying_key().to_bytes()
    }
    fn sign(&self, domain: NativeSignatureDomain, body: &[u8]) -> [u8; 64] {
        let mut preimage = domain.as_str().as_bytes().to_vec();
        preimage.push(0);
        preimage.extend_from_slice(body);
        self.0.sign(&preimage).to_bytes()
    }
}
fn signed_fixture(wire: &Value, signature: &Value) -> Result<(String, Vec<u8>)> {
    for vector in wire["positive"].as_array().ok_or("positive")? {
        if vector["input"]["signature"] == *signature {
            return Ok((
                vector["type"].as_str().ok_or("type")?.to_owned(),
                bytes(&vector["bytes"])?,
            ));
        }
        if vector["input"]["request"]["signature"] == *signature {
            let raw = bytes(&vector["bytes"])?;
            let request = fields(&raw)?.into_iter().find(|(id, _)| *id == 2).ok_or("request")?.1;
            return Ok(("NativePrekeyRequest".into(), request));
        }
    }
    Err("signed fixture".into())
}
fn signature_domain(kind: &str) -> Result<NativeSignatureDomain> {
    match kind {
        "SignedNativePrekeyBase" => Ok(NativeSignatureDomain::Base),
        "SignedNativeOpk" => Ok(NativeSignatureDomain::Opk),
        "OwnerPrekeyUpdate" => Ok(NativeSignatureDomain::OwnerUpdate),
        "NativePrekeyRequest" => Ok(NativeSignatureDomain::Request),
        "PrekeyLeaseResult" => Ok(NativeSignatureDomain::LeaseResult),
        "OwnerPrekeyStatus" => Ok(NativeSignatureDomain::OwnerStatus),
        _ => Err("signature role".into()),
    }
}
fn verify_document(
    kind: &str,
    raw: &[u8],
    key: &[u8; 32],
) -> std::result::Result<(), NativePrekeyError> {
    match kind {
        "SignedNativePrekeyBase" => verify_base(&p::SignedNativePrekeyBase::from_bytes(raw)?),
        "SignedNativeOpk" => verify_opk(
            &p::SignedNativeOpk::from_bytes(raw)?,
            &target().map_err(|_| NativePrekeyError::Binding)?,
        ),
        "OwnerPrekeyUpdate" => verify_owner_update(&p::OwnerPrekeyUpdate::from_bytes(raw)?),
        "NativePrekeyRequest" => verify_request(&p::NativePrekeyRequest::from_bytes(raw)?),
        "PrekeyLeaseResult" => verify_lease_result(&p::PrekeyLeaseResult::from_bytes(raw)?, key),
        "OwnerPrekeyStatus" => verify_owner_status(&p::OwnerPrekeyStatus::from_bytes(raw)?, key),
        _ => Err(NativePrekeyError::Binding),
    }
}
fn sign_document(kind: &str, raw: &[u8], signer: &dyn NativePrekeySigner) -> Result<Vec<u8>> {
    match kind {
        "SignedNativePrekeyBase" => {
            Ok(sign_base(p::SignedNativePrekeyBase::from_bytes(raw)?, signer)?.to_bytes()?)
        }
        "SignedNativeOpk" => {
            Ok(sign_opk(p::SignedNativeOpk::from_bytes(raw)?, signer, &target()?)?.to_bytes()?)
        }
        "OwnerPrekeyUpdate" => {
            Ok(sign_owner_update(p::OwnerPrekeyUpdate::from_bytes(raw)?, signer)?.to_bytes()?)
        }
        "NativePrekeyRequest" => {
            Ok(sign_request(p::NativePrekeyRequest::from_bytes(raw)?, signer)?.to_bytes()?)
        }
        "PrekeyLeaseResult" => {
            Ok(sign_lease_result(p::PrekeyLeaseResult::from_bytes(raw)?, signer)?.to_bytes()?)
        }
        "OwnerPrekeyStatus" => {
            Ok(sign_owner_status(p::OwnerPrekeyStatus::from_bytes(raw)?, signer)?.to_bytes()?)
        }
        _ => Err("signature role".into()),
    }
}

#[test]
fn dm_fs_v3_signatures_match_independent_vectors() -> Result {
    let w = wire()?;
    let c = crypto()?;
    let mut count = 0;
    for vector in c["signatures"].as_array().ok_or("signatures")? {
        let (kind, raw) = signed_fixture(&w, &vector["signature"])?;
        let key = fixed(&vector["public"])?;
        let signer = DeterministicSigner(SigningKey::from_bytes(&fixed(&vector["seed"])?));
        verify_document(&kind, &raw, &key)?;
        if matches!(kind.as_str(), "PrekeyLeaseResult" | "OwnerPrekeyStatus") {
            assert!(verify_document(&kind, &raw, &[0; 32]).is_err());
        }
        assert_eq!(sign_document(&kind, &raw, &signer)?, raw);
        let preimage = bytes(&vector["preimage"])?;
        let domain = signature_domain(&kind)?;
        let prefix = domain.as_str().as_bytes();
        assert_eq!(&preimage[..prefix.len()], prefix);
        assert_eq!(preimage[prefix.len()], 0);
        assert_eq!(
            signer.sign(domain, &preimage[prefix.len() + 1..]),
            fixed::<64>(&vector["signature"])?
        );
        count += 1;
    }
    assert_eq!(count, 10);
    Ok(())
}
fn native_prekey_signer_contract(signer: &dyn NativePrekeySigner, debug: &str) -> Result {
    assert!(debug.contains("<redacted>"));
    assert!(!debug.contains(&hex::encode([14; 32])));
    assert!(!debug.contains(&format!("{:?}", [14u8; 32])));
    let key = VerifyingKey::from_bytes(&signer.public_key())?;
    let domains = [
        NativeSignatureDomain::Base,
        NativeSignatureDomain::Opk,
        NativeSignatureDomain::OwnerUpdate,
        NativeSignatureDomain::Request,
        NativeSignatureDomain::LeaseResult,
        NativeSignatureDomain::OwnerStatus,
    ];
    let mut signatures = std::collections::BTreeSet::new();
    for domain in domains {
        let body = b"public contract body";
        let sig = signer.sign(domain, body);
        let mut message = domain.as_str().as_bytes().to_vec();
        message.push(0);
        message.extend_from_slice(body);
        key.verify_strict(&message, &Signature::from_bytes(&sig))?;
        assert!(signatures.insert(sig));
        message.push(1);
        assert!(key.verify_strict(&message, &Signature::from_bytes(&sig)).is_err());
        assert_ne!(sig, signer.sign(domain, b"different public body"));
    }
    Ok(())
}
#[test]
fn dm_fs_v3_all_native_prekey_signers_share_contract() -> Result {
    let branch = crate::DeviceBranch {
        principal_id: "fixture-principal".into(),
        device_id: "fixture-device".into(),
        device_epoch: 1,
        signing_key: SigningKey::from_bytes(&[14; 32]),
    };
    let deterministic = DeterministicSigner(SigningKey::from_bytes(&[14; 32]));
    native_prekey_signer_contract(&branch, &format!("{branch:?}"))?;
    native_prekey_signer_contract(&deterministic, &format!("{deterministic:?}"))?;
    let document = p::SignedNativePrekeyBase::from_bytes(&raw("SignedNativePrekeyBase")?)?;
    assert_eq!(sign_base(document.clone(), &branch)?, document);
    assert_eq!(branch.public_key(), deterministic.public_key());
    Ok(())
}
fn native_digest(name: &str) -> Result<[u8; 32]> {
    let value = match name {
        "branch_binding" => branch_binding(&target()?)?,
        "base_hash" => {
            base_hash(&p::SignedNativePrekeyBase::from_bytes(&raw("SignedNativePrekeyBase")?)?)?
        }
        "lease_operation_id" => {
            lease_operation_id(&p::PrekeyLeaseIntent::from_bytes(&raw("PrekeyLeaseIntent")?)?)?
        }
        "request_argument" => request_argument_hash(NativePrekeyArgument::Lease(
            &p::PrekeyLeaseIntent::from_bytes(&raw("PrekeyLeaseIntent")?)?,
        ))?,
        "publish_argument" => request_argument_hash(NativePrekeyArgument::Publish(
            &p::OwnerPrekeyUpdate::from_bytes(&raw("OwnerPrekeyUpdate")?)?,
        ))?,
        "status_argument" => request_argument_hash(NativePrekeyArgument::Status(
            &p::OwnerStatusQuery::from_bytes(&raw("OwnerStatusQuery")?)?,
        ))?,
        "request_hash" => {
            request_hash(&p::NativePrekeyRequest::from_bytes(&raw("NativePrekeyRequest")?)?)?
        }
        "status_request_hash" => {
            request_hash(&p::NativePrekeyStatus::from_bytes(&raw("NativePrekeyStatus")?)?.request)?
        }
        "bundle_hash_opk" => bundle_hash(&p::PrekeyLeaseResult::from_bytes(&raw("lease_opk")?)?)?,
        "bundle_hash_spk_only" => {
            bundle_hash(&p::PrekeyLeaseResult::from_bytes(&raw("lease_spk_only")?)?)?
        }
        "transcript_hash_opk" => {
            transcript_hash(&p::BootstrapTranscript::from_bytes(&raw("transcript_opk")?)?)?
        }
        "transcript_hash_spk_only" => {
            transcript_hash(&p::BootstrapTranscript::from_bytes(&raw("transcript_spk_only")?)?)?
        }
        "publication_snapshot_hash" => publication_snapshot_hash(
            &p::PrekeyPublicationSnapshot::from_bytes(&raw("PrekeyPublicationSnapshot")?)?,
        )?,
        "retirement_digest" => {
            let c = crypto()?;
            let mut entries = Vec::new();
            for v in c["retirement_list_vector"]["entries"].as_array().ok_or("entries")? {
                entries.push(p::RetirementRef {
                    generation: v["generation"].as_u64().ok_or("generation")?,
                    serial: v["serial"].as_u64().ok_or("serial")?,
                    key_id: fixed(&v["key_id"])?,
                });
            }
            retirement_digest(&entries)?
        }
        _ if name.starts_with("frame_result_hash_") => {
            frame_result_hash(&p::NativePrekeyResult::from_bytes(&raw(name
                .strip_prefix("frame_result_hash_")
                .ok_or("result")?)?)?)?
        }
        _ => return Err("hash role".into()),
    };
    Ok(value)
}
#[test]
fn dm_fs_v3_hashes_match_independent_vectors() -> Result {
    let c = crypto()?;
    let mut count = 0;
    for v in c["hashes"].as_array().ok_or("hashes")? {
        let name = v["name"].as_str().ok_or("name")?;
        if !name.starts_with("custody_") {
            assert_eq!(native_digest(name)?, fixed::<32>(&v["digest"])?, "{name}");
            count += 1;
        }
    }
    assert_eq!(count, 18);
    let schema: Value = serde_json::from_str(include_str!(
        "../../../ramflux-protocol/fixtures/dm_fs_v3/wire_schema.json"
    ))?;
    let mut domains = std::collections::BTreeSet::new();
    for rule in NATIVE_HASH_RULES {
        assert_eq!(schema["hash_rules"][rule.role]["domain"], rule.domain);
        assert!(domains.insert(rule.domain));
        assert_ne!(rule.canonical, "");
        assert!(ramflux_protocol::domain::ALL.contains(&rule.domain));
    }
    assert_eq!(domains.len(), 10);
    Ok(())
}
fn transcript(mode: &str) -> Result {
    let expected = p::BootstrapTranscript::from_bytes(&raw(&format!("transcript_{mode}"))?)?;
    let built = bootstrap_transcript(
        p::BootstrapHeader::from_bytes(&raw(&format!("header_{mode}"))?)?,
        expected.envelope_created_at,
        expected.envelope_ttl,
        expected.routed_ad.clone(),
    )?;
    assert_eq!(built.to_bytes()?, raw(&format!("transcript_{mode}"))?);
    let key = SigningKey::from_bytes(&[60; 32]).verifying_key().to_bytes();
    verify_bootstrap_transcript(
        &built,
        &p::PrekeyLeaseResult::from_bytes(&raw(&format!("lease_{mode}"))?)?,
        &key,
    )?;
    let c = crypto()?;
    let name = format!("transcript_hash_{mode}");
    let golden = c["hashes"]
        .as_array()
        .ok_or("hashes")?
        .iter()
        .find(|v| v["name"] == name)
        .ok_or("transcript golden")?;
    assert_eq!(transcript_hash(&built)?, fixed::<32>(&golden["digest"])?);
    Ok(())
}
#[test]
fn dm_fs_v3_transcript_vector_opk() -> Result {
    transcript("opk")
}
#[test]
fn dm_fs_v3_transcript_vector_spk_only() -> Result {
    transcript("spk_only")
}
fn fields(raw: &[u8]) -> Result<Vec<(u16, Vec<u8>)>> {
    let mut out = Vec::new();
    let mut pos = 8;
    while pos < raw.len() {
        let id = u16::from_be_bytes(raw[pos..pos + 2].try_into()?);
        let length = usize::try_from(u32::from_be_bytes(raw[pos + 2..pos + 6].try_into()?))?;
        out.push((id, raw[pos + 6..pos + 6 + length].to_vec()));
        pos += 6 + length;
    }
    Ok(out)
}
fn replace(raw: &[u8], id: u16, value: &[u8]) -> Result<Vec<u8>> {
    let mut out = raw[..8].to_vec();
    for (field, body) in fields(raw)? {
        let body = if id == field { value } else { &body };
        out.extend_from_slice(&field.to_be_bytes());
        out.extend_from_slice(&u32::try_from(body.len())?.to_be_bytes());
        out.extend_from_slice(body);
    }
    Ok(out)
}
#[test]
fn dm_fs_v3_tamper_rejection_matrix() -> Result {
    let w = wire()?;
    let c = crypto()?;
    let mut count = 0;
    for sig in c["signatures"].as_array().ok_or("signatures")? {
        let (kind, raw) = signed_fixture(&w, &sig["signature"])?;
        let key = fixed(&sig["public"])?;
        for (id, mut body) in fields(&raw)? {
            if kind == "NativePrekeyRequest" && id == 2 {
                body = if body == b"publish" { b"status".to_vec() } else { b"publish".to_vec() };
            } else {
                let last = body.last_mut().ok_or("field")?;
                *last ^= 1;
            }
            // Explicit decode rows: profile (all documents), overlong request
            // expiry, invalid fallback/state codes, and absent OPK tag -> short present.
            let expected = match (kind.as_str(), id) {
                (_, 1)
                | ("NativePrekeyRequest", 13)
                | ("PrekeyLeaseResult", 10)
                | ("OwnerPrekeyStatus", 9) => NativePrekeyError::Decode(p::DecodeError::Value),
                ("PrekeyLeaseResult", 3) if body.len() == 1 => {
                    NativePrekeyError::Decode(p::DecodeError::Truncated)
                }
                ("SignedNativeOpk", 2) | ("PrekeyLeaseResult", 5) => NativePrekeyError::Binding,
                _ => NativePrekeyError::Signature,
            };
            assert_eq!(
                verify_document(&kind, &replace(&raw, id, &body)?, &key),
                Err(expected),
                "{kind} field {id}"
            );
            count += 1;
        }
    }
    assert_eq!(count, 109);
    let mut base = p::SignedNativePrekeyBase::from_bytes(&raw("SignedNativePrekeyBase")?)?;
    let mut opk = p::SignedNativeOpk::from_bytes(&raw("SignedNativeOpk")?)?;
    std::mem::swap(&mut base.signature, &mut opk.signature);
    assert!(verify_base(&base).is_err());
    assert!(verify_opk(&opk, &target()?).is_err());
    for (id, mut body) in fields(&raw("QualifiedBranch")?)? {
        *body.last_mut().ok_or("branch field")? ^= 1;
        let mut base = p::SignedNativePrekeyBase::from_bytes(&raw("SignedNativePrekeyBase")?)?;
        base.branch =
            p::QualifiedBranch::from_bytes(&replace(&raw("QualifiedBranch")?, id, &body)?)?;
        assert!(verify_base(&base).is_err());
    }
    // Fixed small-order identity point and zero S: strict verification must
    // reject the weak key and R point.
    let mut weak = p::SignedNativePrekeyBase::from_bytes(&raw("SignedNativePrekeyBase")?)?;
    weak.branch.signing_key = [0; 32];
    weak.branch.signing_key[0] = 1;
    weak.signature = [0; 64];
    weak.signature[0] = 1;
    assert_eq!(verify_base(&weak), Err(NativePrekeyError::Signature));
    let key = SigningKey::from_bytes(&[60; 32]).verifying_key().to_bytes();
    for mode in ["opk", "spk_only"] {
        let raw_transcript = raw(&format!("transcript_{mode}"))?;
        let original = p::BootstrapTranscript::from_bytes(&raw_transcript)?;
        let expected = transcript_hash(&original)?;
        for (id, mut body) in fields(&raw_transcript)? {
            *body.last_mut().ok_or("transcript field")? ^= 1;
            if let Ok(changed) =
                p::BootstrapTranscript::from_bytes(&replace(&raw_transcript, id, &body)?)
            {
                assert_ne!(transcript_hash(&changed)?, expected);
            }
        }
        for (id, mut body) in fields(&raw(&format!("header_{mode}"))?)? {
            *body.last_mut().ok_or("header field")? ^= 1;
            let changed = replace(&raw(&format!("header_{mode}"))?, id, &body)?;
            if let Ok(header) = p::BootstrapHeader::from_bytes(&changed) {
                let mut value = original.clone();
                value.header = header;
                assert_ne!(transcript_hash(&value)?, expected);
            }
        }
        let lease = p::PrekeyLeaseResult::from_bytes(&raw(&format!("lease_{mode}"))?)?;
        let mut changed = original.clone();
        changed.header.opk_id = Some([0; 32]);
        changed.header.opk_key = Some([0; 32]);
        assert!(verify_bootstrap_transcript(&changed, &lease, &key).is_err());
        let mut changed = original;
        changed.header.operation_id[0] ^= 1;
        assert!(verify_bootstrap_transcript(&changed, &lease, &key).is_err());
    }
    Ok(())
}
#[test]
fn dm_fs_v3_hash_helpers_reject_decoder_limits() -> Result {
    let w = wire()?;
    for (kind, id, count, element) in [
        (p::WireType::OwnerPrekeyUpdate, 4, 65, "SignedNativeOpk"),
        (p::WireType::OwnerPrekeyUpdate, 5, 401, "RetirementRef"),
        (p::WireType::OwnerStatusQuery, 3, 201, "RetirementRef"),
    ] {
        let mut list = u16::try_from(count)?.to_be_bytes().to_vec();
        let element = raw(element)?;
        for _ in 0..count {
            list.extend_from_slice(&u32::try_from(element.len())?.to_be_bytes());
            list.extend_from_slice(&element);
        }
        let name = if kind == p::WireType::OwnerPrekeyUpdate {
            "OwnerPrekeyUpdate"
        } else {
            "OwnerStatusQuery"
        };
        let bad = replace(&raw(name)?, id, &list)?;
        if kind == p::WireType::OwnerPrekeyUpdate {
            assert_eq!(p::OwnerPrekeyUpdate::from_bytes(&bad), Err(p::DecodeError::Count));
        } else {
            assert_eq!(p::OwnerStatusQuery::from_bytes(&bad), Err(p::DecodeError::Count));
        }
    }
    let reference = p::RetirementRef::from_bytes(&raw("RetirementRef")?)?;
    assert_eq!(
        retirement_digest(&vec![reference; 401]),
        Err(NativePrekeyError::Decode(p::DecodeError::Count))
    );
    for (name, kind) in [
        ("SignedNativePrekeyBase", p::WireType::SignedNativePrekeyBase),
        ("NativePrekeyRequest", p::WireType::NativePrekeyRequest),
        ("BootstrapTranscript", p::WireType::BootstrapTranscript),
    ] {
        let oversized = vec![0; kind.ceiling() + 1];
        assert!(matches!(p::scan(kind, &oversized), Err(p::DecodeError::TypeCeiling)));
        assert!(w["positive"].as_array().ok_or("positive")?.iter().any(|v| v["type"] == name));
    }
    Ok(())
}

#[test]
fn dm_fs_v3_transcript_rejects_each_lease_binding_in_both_modes() -> Result {
    type Mutation = (&'static str, fn(&mut p::BootstrapHeader));
    let mutations: [Mutation; 15] = [
        ("source", |h| h.source.record_hash[0] ^= 1),
        ("target", |h| h.target.record_hash[0] ^= 1),
        ("base", |h| h.base.signature[0] ^= 1),
        ("base_hash", |h| h.base_hash[0] ^= 1),
        ("bundle_hash", |h| h.bundle_hash[0] ^= 1),
        ("spk_id", |h| h.spk_id[0] ^= 1),
        ("spk_serial", |h| h.spk_serial += 1),
        ("generation", |h| h.generation += 1),
        ("operation_id", |h| h.operation_id[0] ^= 1),
        ("issued_at", |h| h.issued_at += 1),
        ("leased_at", |h| h.leased_at += 1),
        ("deadline", |h| h.deadline += 1),
        ("opk_id", |h| {
            let mut id = h.opk_id.unwrap_or([0; 32]);
            id[0] ^= 1;
            h.opk_id = Some(id);
        }),
        ("opk_key", |h| {
            let mut key = h.opk_key.unwrap_or([0; 32]);
            key[0] ^= 1;
            h.opk_key = Some(key);
        }),
        ("routed_ad", |h| h.routed_ad[0] ^= 1),
    ];
    let key = SigningKey::from_bytes(&[60; 32]).verifying_key().to_bytes();
    let mut count = 0;
    for mode in ["opk", "spk_only"] {
        let original = p::BootstrapTranscript::from_bytes(&raw(&format!("transcript_{mode}"))?)?;
        let lease = p::PrekeyLeaseResult::from_bytes(&raw(&format!("lease_{mode}"))?)?;
        verify_bootstrap_transcript(&original, &lease, &key)?;
        for (name, mutate) in mutations {
            let mut changed = original.clone();
            mutate(&mut changed.header);
            let expected = if mode == "spk_only" && matches!(name, "opk_id" | "opk_key") {
                NativePrekeyError::Decode(p::DecodeError::Value)
            } else {
                NativePrekeyError::Binding
            };
            assert_eq!(
                verify_bootstrap_transcript(&changed, &lease, &key),
                Err(expected),
                "{mode} {name}"
            );
            count += 1;
        }
        let mut changed = original.clone();
        if changed.header.opk_id.is_some() {
            changed.header.opk_id = None;
            changed.header.opk_key = None;
        } else {
            changed.header.opk_id = Some([0; 32]);
            changed.header.opk_key = Some([0; 32]);
        }
        assert_eq!(
            verify_bootstrap_transcript(&changed, &lease, &key),
            Err(NativePrekeyError::Binding),
            "{mode} OPK presence"
        );
        count += 1;
        let mut changed = original;
        changed.routed_ad[0] ^= 1;
        assert_eq!(
            verify_bootstrap_transcript(&changed, &lease, &key),
            Err(NativePrekeyError::Binding),
            "{mode} transcript AD"
        );
        count += 1;
    }
    assert_eq!(count, 34);
    Ok(())
}

// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use super::*;
use serde_json::Value;
type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;
const WIRE: &str = include_str!("../../fixtures/dm_fs_v3/wire_vectors.json");
const CRYPTO: &str = include_str!("../../fixtures/dm_fs_v3/crypto_vectors.json");
fn fixtures() -> Result<Value> {
    Ok(serde_json::from_str(WIRE)?)
}
fn text(value: &Value) -> Result<String> {
    Ok(value.as_str().ok_or("text")?.to_owned())
}
fn number(value: &Value) -> Result<u64> {
    value.as_u64().ok_or_else(|| "integer".into())
}
fn hex(value: &str) -> Result<Vec<u8>> {
    if !value.len().is_multiple_of(2) {
        return Err("odd hex".into());
    }
    (0..value.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&value[i..i + 2], 16).map_err(Into::into))
        .collect()
}
fn fixed<const N: usize>(value: &Value) -> Result<[u8; N]> {
    hex(value.as_str().ok_or("hex")?)?.try_into().map_err(|_| "width".into())
}
fn list<T>(value: &Value, decode: fn(&Value) -> Result<T>) -> Result<Vec<T>> {
    value.as_array().ok_or("list")?.iter().map(decode).collect()
}
fn vector<'a>(fixtures: &'a Value, name: &str) -> Result<&'a Value> {
    fixtures["positive"]
        .as_array()
        .ok_or("positive")?
        .iter()
        .find(|v| v["name"] == name)
        .ok_or_else(|| "vector missing".into())
}
fn raw(vector: &Value) -> Result<Vec<u8>> {
    hex(vector["bytes"].as_str().ok_or("bytes")?)
}

fn branch(v: &Value) -> Result<QualifiedBranch> {
    Ok(QualifiedBranch {
        account_anchor: fixed(&v["account_anchor"])?,
        principal_id: text(&v["principal_id"])?,
        device_id: text(&v["device_id"])?,
        device_epoch: number(&v["device_epoch"])?,
        certificate_hash: fixed(&v["certificate_hash"])?,
        record_hash: fixed(&v["record_hash"])?,
        signing_key: fixed(&v["signing_key"])?,
        agreement_key: fixed(&v["agreement_key"])?,
    })
}

fn base(v: &Value) -> Result<SignedNativePrekeyBase> {
    Ok(SignedNativePrekeyBase {
        profile: text(&v["profile"])?,
        branch: branch(&v["branch"])?,
        generation: number(&v["generation"])?,
        spk_id: fixed(&v["spk_id"])?,
        spk_serial: number(&v["spk_serial"])?,
        spk_key: fixed(&v["spk_key"])?,
        issued_at: number(&v["issued_at"])?,
        expires_at: number(&v["expires_at"])?,
        update_counter: number(&v["update_counter"])?,
        capabilities: text(&v["capabilities"])?,
        signature: fixed(&v["signature"])?,
    })
}

fn opk(v: &Value) -> Result<SignedNativeOpk> {
    Ok(SignedNativeOpk {
        profile: text(&v["profile"])?,
        branch_binding: fixed(&v["branch_binding"])?,
        generation: number(&v["generation"])?,
        serial: number(&v["serial"])?,
        opk_id: fixed(&v["opk_id"])?,
        opk_key: fixed(&v["opk_key"])?,
        signature: fixed(&v["signature"])?,
    })
}

fn retirement(v: &Value) -> Result<RetirementRef> {
    Ok(RetirementRef {
        generation: number(&v["generation"])?,
        serial: number(&v["serial"])?,
        key_id: fixed(&v["key_id"])?,
    })
}

fn update(v: &Value) -> Result<OwnerPrekeyUpdate> {
    Ok(OwnerPrekeyUpdate {
        profile: text(&v["profile"])?,
        base: base(&v["base"])?,
        update_counter: number(&v["update_counter"])?,
        additive_opks: list(&v["additive_opks"], opk)?,
        retirements: list(&v["retirements"], retirement)?,
        signature: fixed(&v["signature"])?,
    })
}

fn snapshot(v: &Value) -> Result<PrekeyPublicationSnapshot> {
    Ok(PrekeyPublicationSnapshot {
        profile: text(&v["profile"])?,
        update: update(&v["update"])?,
        counter: number(&v["counter"])?,
        epoch: number(&v["epoch"])?,
        generation: number(&v["generation"])?,
        pending_retirements: list(&v["pending_retirements"], retirement)?,
        retirement_digest: fixed(&v["retirement_digest"])?,
    })
}

#[test]
fn dm_fs_v3_base_canonical_vector() -> Result {
    let fixtures = fixtures()?;
    let vector = vector(&fixtures, "SignedNativePrekeyBase")?;
    let expected = base(&vector["input"])?;
    let bytes = raw(vector)?;
    assert_eq!(expected.to_bytes()?, bytes);
    assert_eq!(SignedNativePrekeyBase::from_bytes(&bytes)?, expected);
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert!(SignedNativePrekeyBase::from_bytes(&trailing).is_err());
    let mut unknown = bytes;
    unknown[8..10].copy_from_slice(&u16::MAX.to_be_bytes());
    assert!(SignedNativePrekeyBase::from_bytes(&unknown).is_err());
    let crypto: Value = serde_json::from_str(CRYPTO)?;
    let signature = crypto["signatures"]
        .as_array()
        .ok_or("signatures")?
        .iter()
        .find(|v| v["name"] == "SignedNativePrekeyBase")
        .ok_or("signature")?;
    let preimage = hex(signature["preimage"].as_str().ok_or("preimage")?)?;
    let boundary = preimage.iter().position(|b| *b == 0).ok_or("domain separator")? + 1;
    assert_eq!(expected.signing_body_bytes()?, preimage[boundary..]);
    Ok(())
}

#[test]
fn dm_fs_v3_opk_canonical_vector() -> Result {
    let fixtures = fixtures()?;
    let vector = vector(&fixtures, "SignedNativeOpk")?;
    let expected = opk(&vector["input"])?;
    let bytes = raw(vector)?;
    assert_eq!(expected.to_bytes()?, bytes);
    assert_eq!(SignedNativeOpk::from_bytes(&bytes)?, expected);
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert!(SignedNativeOpk::from_bytes(&trailing).is_err());
    let mut unknown = bytes;
    unknown[8..10].copy_from_slice(&u16::MAX.to_be_bytes());
    assert!(SignedNativeOpk::from_bytes(&unknown).is_err());
    let crypto: Value = serde_json::from_str(CRYPTO)?;
    let signature = crypto["signatures"]
        .as_array()
        .ok_or("signatures")?
        .iter()
        .find(|v| v["name"] == "SignedNativeOpk")
        .ok_or("signature")?;
    let preimage = hex(signature["preimage"].as_str().ok_or("preimage")?)?;
    let boundary = preimage.iter().position(|b| *b == 0).ok_or("domain separator")? + 1;
    assert_eq!(expected.signing_body_bytes()?, preimage[boundary..]);
    Ok(())
}

#[test]
fn dm_fs_v3_owner_update_canonical_vector() -> Result {
    let fixtures = fixtures()?;
    let vector = vector(&fixtures, "OwnerPrekeyUpdate")?;
    let expected = update(&vector["input"])?;
    let bytes = raw(vector)?;
    assert_eq!(expected.to_bytes()?, bytes);
    assert_eq!(OwnerPrekeyUpdate::from_bytes(&bytes)?, expected);
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert!(OwnerPrekeyUpdate::from_bytes(&trailing).is_err());
    let mut unknown = bytes;
    unknown[8..10].copy_from_slice(&u16::MAX.to_be_bytes());
    assert!(OwnerPrekeyUpdate::from_bytes(&unknown).is_err());
    let crypto: Value = serde_json::from_str(CRYPTO)?;
    let signature = crypto["signatures"]
        .as_array()
        .ok_or("signatures")?
        .iter()
        .find(|v| v["name"] == "OwnerPrekeyUpdate")
        .ok_or("signature")?;
    let preimage = hex(signature["preimage"].as_str().ok_or("preimage")?)?;
    let boundary = preimage.iter().position(|b| *b == 0).ok_or("domain separator")? + 1;
    assert_eq!(expected.signing_body_bytes()?, preimage[boundary..]);
    Ok(())
}

#[test]
fn dm_fs_v3_publication_snapshot_vector() -> Result {
    let fixtures = fixtures()?;
    let vector = vector(&fixtures, "PrekeyPublicationSnapshot")?;
    let expected = snapshot(&vector["input"])?;
    let bytes = raw(vector)?;
    assert_eq!(expected.to_bytes()?, bytes);
    assert_eq!(PrekeyPublicationSnapshot::from_bytes(&bytes)?, expected);
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert!(PrekeyPublicationSnapshot::from_bytes(&trailing).is_err());
    let mut unknown = bytes;
    unknown[8..10].copy_from_slice(&u16::MAX.to_be_bytes());
    assert!(PrekeyPublicationSnapshot::from_bytes(&unknown).is_err());
    Ok(())
}

#[test]
fn dm_fs_v3_size_limits_exact_and_plus_one() -> Result {
    let fixtures = fixtures()?;
    let mut base = base(&vector(&fixtures, "SignedNativePrekeyBase")?["input"])?;
    let opk = opk(&vector(&fixtures, "SignedNativeOpk")?["input"])?;
    base.branch.principal_id = "p".repeat(256);
    base.branch.device_id = "é".repeat(128);
    base.capabilities = "c".repeat(64);
    let canonical = base.to_bytes()?;
    assert!(canonical.len() <= 2_048);
    assert_eq!(SignedNativePrekeyBase::from_bytes(&canonical)?, base);
    // OPKs retain only fixed branch_binding, never inherited strings.
    let mut invalid_code = base.clone();
    invalid_code.capabilities = "register,\nmessage".into();
    assert_eq!(invalid_code.to_bytes(), Err(DecodeError::Value));
    let mut invalid_profile = base.clone();
    invalid_profile.profile = "unknown".into();
    assert_eq!(invalid_profile.to_bytes(), Err(DecodeError::Value));
    let opk_bytes = opk.to_bytes()?;
    assert!(opk_bytes.len() <= 512);
    assert_eq!(SignedNativeOpk::from_bytes(&opk_bytes)?, opk);
    for (principal, device) in [
        ("p".repeat(257), "device".into()),
        ("principal".into(), "é".repeat(129)),
        ("bad\nID".into(), "device".into()),
    ] {
        let mut invalid = base.clone();
        invalid.branch.principal_id = principal;
        invalid.branch.device_id = device;
        assert_eq!(invalid.to_bytes(), Err(DecodeError::Value));
    }
    let mut update = update(&vector(&fixtures, "OwnerPrekeyUpdate")?["input"])?;
    update.base = base.clone();
    update.additive_opks = vec![opk.clone(); 64];
    let retirement = update.retirements.first().ok_or("retirement")?.clone();
    update.retirements = vec![retirement.clone(); 400];
    let bytes = update.to_bytes()?;
    assert_eq!(bytes.len(), 48_798);
    assert_eq!(OwnerPrekeyUpdate::from_bytes(&bytes)?, update);
    update.additive_opks.push(opk);
    assert_eq!(
        update.to_bytes(),
        Err(DecodeError::Count),
        "65 OPKs must be refused before encoding"
    );
    update.additive_opks.pop();
    update.retirements.push(retirement.clone());
    assert_eq!(update.to_bytes(), Err(DecodeError::Count));
    let mut snapshot = snapshot(&vector(&fixtures, "PrekeyPublicationSnapshot")?["input"])?;
    snapshot.pending_retirements = vec![retirement.clone(); 400];
    assert_eq!(PrekeyPublicationSnapshot::from_bytes(&snapshot.to_bytes()?)?, snapshot);
    snapshot.pending_retirements.push(retirement);
    assert_eq!(snapshot.to_bytes(), Err(DecodeError::Count));
    // These fixed schemas cannot fill every byte of their total ceiling. At the
    // exact ceiling, padding is rejected as trailing data; cap+1 rejects size first.
    for (kind, mut bytes) in [
        (WireType::SignedNativePrekeyBase, canonical),
        (WireType::SignedNativeOpk, opk_bytes),
        (WireType::OwnerPrekeyUpdate, bytes),
    ] {
        bytes.resize(kind.ceiling(), 0);
        assert_eq!(scan(kind, &bytes).err(), Some(DecodeError::Trailing));
        bytes.push(0);
        assert_eq!(scan(kind, &bytes).err(), Some(DecodeError::TypeCeiling));
    }
    // Decision r7 permits every collection and inherited ID at maximum simultaneously.
    update.retirements.pop();
    snapshot.pending_retirements.pop();
    snapshot.update = update;
    let maximal = snapshot.to_bytes()?;
    assert_eq!(maximal.len(), 80_132);
    assert_eq!(PrekeyPublicationSnapshot::from_bytes(&maximal)?, snapshot);
    let mut oversized = maximal;
    oversized.resize(WireType::PrekeyPublicationSnapshot.ceiling() + 1, 0);
    assert_eq!(PrekeyPublicationSnapshot::from_bytes(&oversized), Err(DecodeError::TypeCeiling));
    Ok(())
}

// Build negative frames directly from fixed literal bytes, bypassing the writers
// whose count validation is being tested. All declared children are fully present.
fn replace_raw_field(kind: WireType, raw: &[u8], id: u16, replacement: &[u8]) -> Result<Vec<u8>> {
    let view = scan(kind, raw)?;
    let mut out = raw[..8].to_vec();
    for field in view.fields() {
        let value = if field.id == id { replacement } else { field.value };
        out.extend_from_slice(&field.id.to_be_bytes());
        out.extend_from_slice(&u32::try_from(value.len())?.to_be_bytes());
        out.extend_from_slice(value);
    }
    Ok(out)
}
fn complete_raw_list(element: &[u8], count: u16) -> Result<Vec<u8>> {
    let mut out = count.to_be_bytes().to_vec();
    for _ in 0..count {
        out.extend_from_slice(&u32::try_from(element.len())?.to_be_bytes());
        out.extend_from_slice(element);
    }
    Ok(out)
}

#[test]
fn dm_fs_v3_capabilities_syntax_is_bounded() -> Result {
    let w = fixtures()?;
    let v = vector(&w, "SignedNativePrekeyBase")?;
    let original = raw(v)?;
    let mut value = base(&v["input"])?;
    for invalid in [
        "",
        ",register",
        "register,",
        "register,,message",
        ",",
        "register message",
        "régi",
        "register\nmessage",
        "register/message",
        "cap\u{80}",
    ] {
        value.capabilities = invalid.into();
        assert_eq!(
            value.to_bytes(),
            Err(DecodeError::Value),
            "invalid capability syntax: {invalid:?}"
        );
        let bad =
            replace_raw_field(WireType::SignedNativePrekeyBase, &original, 10, invalid.as_bytes())?;
        assert_eq!(SignedNativePrekeyBase::from_bytes(&bad), Err(DecodeError::Value));
    }
    for valid in ["register,message", "Cap_1.foo:bar-baz", "c"] {
        value.capabilities = valid.into();
        assert_eq!(SignedNativePrekeyBase::from_bytes(&value.to_bytes()?)?, value);
    }
    value.capabilities = "c".repeat(64);
    assert!(value.to_bytes().is_ok());
    value.capabilities.push('c');
    assert_eq!(value.to_bytes(), Err(DecodeError::FieldCeiling));
    Ok(())
}

#[test]
fn dm_fs_v3_over_limit_collection_frames_return_count() -> Result {
    let w = fixtures()?;
    let maxima = w["filled_maximum"].as_array().ok_or("maxima")?;
    let update =
        raw(maxima.iter().find(|v| v["type"] == "OwnerPrekeyUpdate").ok_or("max update")?)?;
    let snapshot = raw(maxima
        .iter()
        .find(|v| v["type"] == "PrekeyPublicationSnapshot")
        .ok_or("max snapshot")?)?;
    let opk = raw(vector(&w, "SignedNativeOpk")?)?;
    let retirement = raw(vector(&w, "RetirementRef")?)?;
    let opks = complete_raw_list(&opk, 65)?;
    let retirements = complete_raw_list(&retirement, 401)?;
    for (field, list) in [(4, opks), (5, retirements.clone())] {
        let bad_update = replace_raw_field(WireType::OwnerPrekeyUpdate, &update, field, &list)?;
        assert_eq!(
            OwnerPrekeyUpdate::from_bytes(&bad_update),
            Err(DecodeError::Count),
            "over-limit complete owner update"
        );
        let nested =
            replace_raw_field(WireType::PrekeyPublicationSnapshot, &snapshot, 2, &bad_update)?;
        assert_eq!(PrekeyPublicationSnapshot::from_bytes(&nested), Err(DecodeError::Count));
    }
    let bad_snapshot =
        replace_raw_field(WireType::PrekeyPublicationSnapshot, &snapshot, 6, &retirements)?;
    assert_eq!(PrekeyPublicationSnapshot::from_bytes(&bad_snapshot), Err(DecodeError::Count));
    Ok(())
}

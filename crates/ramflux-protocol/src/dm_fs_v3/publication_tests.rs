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
    let canonical = base.to_bytes()?;
    assert!(canonical.len() <= 2_048);
    assert_eq!(SignedNativePrekeyBase::from_bytes(&canonical)?, base);
    // OPKs retain only fixed branch_binding, never inherited strings.
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
    update.additive_opks = vec![opk.clone(); 64];
    let retirement = update.retirements.first().ok_or("retirement")?.clone();
    update.retirements = vec![retirement.clone(); 400];
    let bytes = update.to_bytes()?;
    assert!(bytes.len() <= 65_536);
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
    // A snapshot combines two individually legal lists; its aggregate cap remains binding.
    update.retirements.pop();
    snapshot.pending_retirements.pop();
    snapshot.update = update;
    assert_eq!(snapshot.to_bytes(), Err(DecodeError::TypeCeiling));
    Ok(())
}

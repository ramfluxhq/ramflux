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
fn text(v: &Value) -> Result<String> {
    Ok(v.as_str().ok_or("text")?.to_owned())
}
fn number(v: &Value) -> Result<u64> {
    v.as_u64().ok_or_else(|| "integer".into())
}
fn hex(s: &str) -> Result<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return Err("odd hex".into());
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(Into::into))
        .collect()
}
fn fixed<const N: usize>(v: &Value) -> Result<[u8; N]> {
    hex(v.as_str().ok_or("hex")?)?.try_into().map_err(|_| "width".into())
}
fn list<T>(v: &Value, read: fn(&Value) -> Result<T>) -> Result<Vec<T>> {
    v.as_array().ok_or("array")?.iter().map(read).collect()
}
fn vector<'a>(w: &'a Value, name: &str) -> Result<&'a Value> {
    w["positive"]
        .as_array()
        .ok_or("positive")?
        .iter()
        .find(|v| v["name"] == name)
        .ok_or_else(|| "missing vector".into())
}
fn raw(v: &Value) -> Result<Vec<u8>> {
    hex(v["bytes"].as_str().ok_or("bytes")?)
}
fn signing_body(v: &Value) -> Result<Vec<u8>> {
    let c: Value = serde_json::from_str(CRYPTO)?;
    let s = c["signatures"]
        .as_array()
        .ok_or("signatures")?
        .iter()
        .find(|s| s["signature"] == v["input"]["signature"])
        .ok_or("signature")?;
    let preimage = hex(s["preimage"].as_str().ok_or("preimage")?)?;
    let start = preimage.iter().position(|b| *b == 0).ok_or("domain NUL")? + 1;
    Ok(preimage[start..].to_vec())
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
fn public_view(v: &Value) -> Result<PublicPrekeyView> {
    Ok(PublicPrekeyView {
        profile: text(&v["profile"])?,
        base: base(&v["base"])?,
        authority: branch(&v["authority"])?,
        home_generation: number(&v["home_generation"])?,
    })
}
fn intent(v: &Value) -> Result<PrekeyLeaseIntent> {
    Ok(PrekeyLeaseIntent {
        profile: text(&v["profile"])?,
        requester: branch(&v["requester"])?,
        target: branch(&v["target"])?,
        base_hash: fixed(&v["base_hash"])?,
        home_generation: number(&v["home_generation"])?,
        issued_at: number(&v["issued_at"])?,
        expires_at: number(&v["expires_at"])?,
        nonce: fixed(&v["nonce"])?,
    })
}
fn lease(v: &Value) -> Result<PrekeyLeaseResult> {
    Ok(PrekeyLeaseResult {
        profile: text(&v["profile"])?,
        base: base(&v["base"])?,
        opk: if v["opk"].is_null() { None } else { Some(opk(&v["opk"])?) },
        requester: branch(&v["requester"])?,
        target: branch(&v["target"])?,
        operation_id: fixed(&v["operation_id"])?,
        issued_at: number(&v["issued_at"])?,
        leased_at: number(&v["leased_at"])?,
        deadline: number(&v["deadline"])?,
        fallback: text(&v["fallback"])?,
        signature: fixed(&v["signature"])?,
    })
}
fn query(v: &Value) -> Result<OwnerStatusQuery> {
    Ok(OwnerStatusQuery {
        profile: text(&v["profile"])?,
        owner: branch(&v["owner"])?,
        requested_ids: list(&v["requested_ids"], retirement)?,
    })
}
fn entry(v: &Value) -> Result<OwnerStatusEntry> {
    Ok(OwnerStatusEntry {
        key_id: fixed(&v["key_id"])?,
        generation: number(&v["generation"])?,
        serial: number(&v["serial"])?,
        leased_at: number(&v["leased_at"])?,
        deadline: number(&v["deadline"])?,
        state: text(&v["state"])?,
    })
}
fn status(v: &Value) -> Result<OwnerPrekeyStatus> {
    Ok(OwnerPrekeyStatus {
        profile: text(&v["profile"])?,
        owner: branch(&v["owner"])?,
        base_hash: fixed(&v["base_hash"])?,
        publication_counter: number(&v["publication_counter"])?,
        generation_floor: number(&v["generation_floor"])?,
        activation: number(&v["activation"])?,
        retirement_ack: fixed(&v["retirement_ack"])?,
        unleased_count: number(&v["unleased_count"])?,
        entries: list(&v["entries"], entry)?,
        signature: fixed(&v["signature"])?,
    })
}

#[test]
fn dm_fs_v3_public_view_vector() -> Result {
    let w = fixtures()?;
    let v = vector(&w, "PublicPrekeyView")?;
    let expected = public_view(&v["input"])?;
    let bytes = raw(v)?;
    assert_eq!(expected.to_bytes()?, bytes);
    assert_eq!(PublicPrekeyView::from_bytes(&bytes)?, expected);
    let mut bad = bytes;
    bad.push(0);
    assert!(PublicPrekeyView::from_bytes(&bad).is_err());
    Ok(())
}
#[test]
fn dm_fs_v3_lease_intent_operation_id_vector() -> Result {
    let w = fixtures()?;
    let v = vector(&w, "PrekeyLeaseIntent")?;
    let expected = intent(&v["input"])?;
    let bytes = raw(v)?;
    assert_eq!(expected.to_bytes()?, bytes);
    assert_eq!(PrekeyLeaseIntent::from_bytes(&bytes)?, expected);
    assert_eq!(expected.operation_id_input_bytes()?, bytes);
    let c: Value = serde_json::from_str(CRYPTO)?;
    let slot = c["hashes"]
        .as_array()
        .ok_or("hashes")?
        .iter()
        .find(|h| h["name"] == "lease_operation_id")
        .ok_or("operation slot")?;
    assert_eq!(hex(slot["canonical"].as_str().ok_or("canonical")?)?, bytes);
    let mut bad = bytes;
    bad[8..10].copy_from_slice(&u16::MAX.to_be_bytes());
    assert!(PrekeyLeaseIntent::from_bytes(&bad).is_err());
    Ok(())
}
#[test]
fn dm_fs_v3_lease_result_vector() -> Result {
    let w = fixtures()?;
    for (name, has_opk) in [("lease_opk", true), ("lease_spk_only", false)] {
        let v = vector(&w, name)?;
        let expected = lease(&v["input"])?;
        let bytes = raw(v)?;
        assert_eq!(expected.opk.is_some(), has_opk);
        assert_eq!(expected.to_bytes()?, bytes);
        assert_eq!(PrekeyLeaseResult::from_bytes(&bytes)?, expected);
        assert_eq!(expected.signing_body_bytes()?, signing_body(v)?);
        let mut trailing = bytes;
        trailing.push(0);
        assert!(PrekeyLeaseResult::from_bytes(&trailing).is_err());
    }
    Ok(())
}
#[test]
fn dm_fs_v3_owner_status_vector() -> Result {
    let w = fixtures()?;
    let v = vector(&w, "OwnerPrekeyStatus")?;
    let expected = status(&v["input"])?;
    let bytes = raw(v)?;
    assert_eq!(expected.to_bytes()?, bytes);
    assert_eq!(OwnerPrekeyStatus::from_bytes(&bytes)?, expected);
    assert_eq!(expected.signing_body_bytes()?, signing_body(v)?);
    let mut bad = bytes;
    bad.push(0);
    assert!(OwnerPrekeyStatus::from_bytes(&bad).is_err());
    Ok(())
}
#[test]
fn dm_fs_v3_status_limits_exact_and_plus_one() -> Result {
    let w = fixtures()?;
    let v = vector(&w, "owner_status_query_maximum_ids")?;
    let mut query = query(&v["input"])?;
    assert_eq!(query.requested_ids.len(), 200);
    assert_eq!(query.owner.principal_id.len(), 256);
    assert_eq!(query.owner.device_id.len(), 256);
    let bytes = query.to_bytes()?;
    assert_eq!(bytes, raw(v)?);
    assert_eq!(bytes.len(), 16_390);
    assert_eq!(OwnerStatusQuery::from_bytes(&bytes)?, query);
    query.requested_ids.push(query.requested_ids.first().ok_or("request")?.clone());
    assert_eq!(query.to_bytes(), Err(DecodeError::Count));
    let maxima = w["filled_maximum"].as_array().ok_or("maxima")?;
    let v = maxima.iter().find(|v| v["type"] == "OwnerPrekeyStatus").ok_or("status maximum")?;
    let bytes = raw(v)?;
    let mut status = OwnerPrekeyStatus::from_bytes(&bytes)?;
    assert_eq!(status.entries.len(), 200);
    assert_eq!(status.owner.principal_id.len(), 256);
    assert_eq!(status.owner.device_id.len(), 256);
    assert_eq!(bytes.len(), 36_192);
    assert_eq!(status.to_bytes()?, bytes);
    status.entries.push(status.entries.first().ok_or("entry")?.clone());
    assert_eq!(status.to_bytes(), Err(DecodeError::Count));
    Ok(())
}

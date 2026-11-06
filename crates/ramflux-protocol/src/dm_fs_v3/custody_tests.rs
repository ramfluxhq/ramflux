// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use super::*;
use crate::{canonical_json_bytes, custody::*, decode_base64url, domain, encode_base64url};
use serde_json::{Value, json};
type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;
fn vectors() -> Result<Vec<Value>> {
    Ok(serde_json::from_str(include_str!("../../fixtures/dm_fs_v3/custody_vectors.json"))?)
}
#[test]
fn dm_fs_v3_custody_action_hash_vectors() -> Result {
    let rows = vectors()?;
    assert_eq!(rows.len(), 3);
    for row in rows {
        let action: CustodyProofAction =
            decode(&serde_json::to_vec(&row["action"])?, MAX_CUSTODY_FRAME_BYTES)?;
        assert_eq!(serde_json::to_value(&action)?, row["action"]);
        assert_eq!(canonical_json_bytes(&action)?, hex_bytes(&row["action_jcs"])?);
        let mut preimage = b"ramflux.identity.custody_action.v1\0".to_vec();
        preimage.extend(canonical_json_bytes(&action)?);
        assert_eq!(preimage, hex_bytes(&row["action_preimage"])?);
        assert_eq!(blake3::hash(&preimage).as_bytes().as_slice(), hex_bytes(&row["digest"])?);
        assert_eq!(custody_action_hash(&action)?, row["action_hash"]);
        assert_eq!(action.capability(), "register");
        match action {
            CustodyProofAction::PrekeyStatus { query } => {
                assert_eq!(decode_base64url(&query)?, hex_bytes(&row["embedded_rfs1"])?);
            }
            CustodyProofAction::RegisterUpdate { update } => {
                assert_eq!(decode_base64url(&update)?, hex_bytes(&row["embedded_rfs1"])?);
            }
            CustodyProofAction::Register { prekey_bundle } => assert_eq!(
                prekey_bundle,
                json!({"fixture":"unchanged-register-control","profile":"old-native","version":1})
            ),
            _ => return Err("unexpected fixture operation".into()),
        }
        let body: BranchProofV3 = serde_json::from_value(row["proof_body"].clone())?;
        assert_eq!(
            signing_bytes(domain::BRANCH_PROOF_V3, &body)?,
            hex_bytes(&row["proof_transcript"])?
        );
        assert_eq!(
            body.action_hash,
            custody_action_hash(&serde_json::from_value(row["action"].clone())?)?
        );
    }
    Ok(())
}
// Avoid another fixture dependency solely for hexadecimal decoding.
fn hex_bytes(v: &Value) -> Result<Vec<u8>> {
    let text = v.as_str().ok_or("hex")?;
    (0..text.len()).step_by(2).map(|i| Ok(u8::from_str_radix(&text[i..i + 2], 16)?)).collect()
}
fn rejects(value: &Value) -> Result {
    assert!(matches!(
        decode::<CustodyProofAction>(&serde_json::to_vec(value)?, MAX_CUSTODY_FRAME_BYTES),
        Err(crate::ProtocolError::Canonical(_))
    ));
    Ok(())
}
#[test]
fn dm_fs_v3_custody_carriers_reject_each_field_and_cross_field() -> Result {
    let rows = vectors()?;
    for row in &rows[1..] {
        let action = &row["action"];
        let field = if action["operation"] == "prekey_status" { "query" } else { "update" };
        let other = if field == "query" { "update" } else { "query" };
        for bad in [
            json!(""),
            json!("="),
            json!("-_=="),
            json!("not base64!"),
            Value::Null,
            json!(4),
            json!({}),
        ] {
            let mut v = action.clone();
            v[field] = bad;
            rejects(&v)?;
        }
        let mut v = action.clone();
        v.as_object_mut().ok_or("action")?.remove(field);
        rejects(&v)?;
        let mut v = action.clone();
        v[other] = json!("unexpected");
        rejects(&v)?;
        let mut v = action.clone();
        v.as_object_mut().ok_or("action")?.remove("operation");
        rejects(&v)?;
        let mut v = action.clone();
        v["operation"] = json!("unknown");
        rejects(&v)?;
        let mut v = action.clone();
        v[field] = json!(format!("{}=", action[field].as_str().ok_or("carrier")?));
        rejects(&v)?;
        let other_row = if field == "query" { &rows[2] } else { &rows[1] };
        let mut v = action.clone();
        v[field] = other_row["action"][other].clone();
        rejects(&v)?;
        let mut bytes = decode_base64url(action[field].as_str().ok_or("carrier")?)?;
        bytes.push(0);
        let mut v = action.clone();
        v[field] = json!(encode_base64url(bytes));
        rejects(&v)?;
        let kind =
            if field == "query" { WireType::OwnerStatusQuery } else { WireType::OwnerPrekeyUpdate };
        let mut v = action.clone();
        v[field] = json!(encode_base64url(vec![0; kind.ceiling() + 1]));
        rejects(&v)?;
        let raw = serde_json::to_string(action)?;
        for duplicate in [
            format!(
                "{},\"{field}\":{}}}",
                &raw[..raw.len() - 1],
                serde_json::to_string(&action[field])?
            ),
            format!(
                "{},\"operation\":{}}}",
                &raw[..raw.len() - 1],
                serde_json::to_string(&action["operation"])?
            ),
        ] {
            assert!(
                decode::<CustodyProofAction>(duplicate.as_bytes(), MAX_CUSTODY_FRAME_BYTES)
                    .is_err()
            );
        }
        let invalid = if field == "query" {
            CustodyProofAction::PrekeyStatus { query: String::new() }
        } else {
            CustodyProofAction::RegisterUpdate { update: String::new() }
        };
        assert!(matches!(custody_action_hash(&invalid), Err(crate::ProtocolError::Canonical(_))));
    }
    Ok(())
}
fn replace(bytes: &[u8], id: u16, value: &[u8]) -> Result<Vec<u8>> {
    let mut out = bytes[..8].to_vec();
    let mut cursor = 8;
    while cursor < bytes.len() {
        let field = u16::from_be_bytes(bytes[cursor..cursor + 2].try_into()?);
        let size = usize::try_from(u32::from_be_bytes(bytes[cursor + 2..cursor + 6].try_into()?))?;
        let body = if field == id { value } else { &bytes[cursor + 6..cursor + 6 + size] };
        out.extend(field.to_be_bytes());
        out.extend(u32::try_from(body.len())?.to_be_bytes());
        out.extend(body);
        cursor += 6 + size;
    }
    Ok(out)
}
#[test]
fn dm_fs_v3_custody_carrier_collection_limits() -> Result {
    let rows = vectors()?;
    let reference = RetirementRef { generation: 1, serial: 1, key_id: [1; 32] }.to_bytes()?;
    let update = OwnerPrekeyUpdate::from_bytes(&decode_base64url(
        rows[2]["action"]["update"].as_str().ok_or("update")?,
    )?)?;
    for (index, field, count, element) in [
        (1, 3, 201, reference.clone()),
        (2, 4, 65, update.additive_opks.first().ok_or("opk")?.to_bytes()?),
        (2, 5, 401, reference),
    ] {
        let name = if index == 1 { "query" } else { "update" };
        let bytes = decode_base64url(rows[index]["action"][name].as_str().ok_or("carrier")?)?;
        let mut list = u16::try_from(count)?.to_be_bytes().to_vec();
        for _ in 0..count {
            list.extend(u32::try_from(element.len())?.to_be_bytes());
            list.extend(&element);
        }
        let bytes = replace(&bytes, field, &list)?;
        if index == 1 {
            assert_eq!(OwnerStatusQuery::from_bytes(&bytes), Err(DecodeError::Count));
        } else {
            assert_eq!(OwnerPrekeyUpdate::from_bytes(&bytes), Err(DecodeError::Count));
        }
        let mut action = rows[index]["action"].clone();
        action[name] = json!(encode_base64url(bytes));
        rejects(&action)?;
    }
    Ok(())
}

#[test]
fn dm_fs_v3_custody_carriers_accept_maximal_collections() -> Result {
    let wire: Value =
        serde_json::from_str(include_str!("../../fixtures/dm_fs_v3/wire_vectors.json"))?;
    let query = wire["positive"]
        .as_array()
        .ok_or("positive")?
        .iter()
        .find(|v| v["name"] == "owner_status_query_maximum_ids")
        .ok_or("max query")?;
    let action: CustodyProofAction = decode(
        &serde_json::to_vec(&json!({"operation":"prekey_status","query":query["base64url"]}))?,
        MAX_CUSTODY_FRAME_BYTES,
    )?;
    assert_eq!(action.capability(), "register");
    let rows = vectors()?;
    let mut update = OwnerPrekeyUpdate::from_bytes(&decode_base64url(
        rows[2]["action"]["update"].as_str().ok_or("update")?,
    )?)?;
    update.base.branch.principal_id = "p".repeat(256);
    update.base.branch.device_id = "d".repeat(256);
    update.base.capabilities = "a".repeat(64);
    let opk = update.additive_opks.first().ok_or("opk")?.clone();
    update.additive_opks = (0..64)
        .map(|i| {
            let mut v = opk.clone();
            v.opk_id[0] = i;
            v
        })
        .collect();
    update.retirements =
        (0..400).map(|i| RetirementRef { generation: 1, serial: i, key_id: [2; 32] }).collect();
    let bytes = update.to_bytes()?;
    assert!(bytes.len() <= 65_536);
    let value = json!({"operation":"register_update","update":encode_base64url(&bytes)});
    let action: CustodyProofAction = decode(&serde_json::to_vec(&value)?, MAX_CUSTODY_FRAME_BYTES)?;
    assert_eq!(serde_json::to_value(&action)?, value);
    Ok(())
}

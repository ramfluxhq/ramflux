// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use super::{FullInstall, Install, PriorGeneration, decode, encode};
use ramflux_protocol::{
    canonical_json_bytes, custody::pairing::full_transfer::U64, encode_base64url,
};
use serde_json::Value;
type ResultOf<T = ()> = Result<T, Box<dyn std::error::Error>>;
fn h(value: u8) -> String {
    encode_base64url([value; 32])
}

pub(super) fn fixture() -> Install {
    Install {
        schema: "ramflux.pairing.Install.v3".into(),
        version: 3,
        account_id: "acct".into(),
        account_anchor: h(2),
        operation_id: h(20),
        recipient_ref: ramflux_protocol::custody::DeviceRef {
            account_anchor: h(2),
            device_id: "B".into(),
            device_epoch: 1,
        },
        recipient_mode: "existing".into(),
        install_purpose: "transfer_destination".into(),
        record_hash: Some(h(3)),
        prior_record_hash: Some(h(4)),
        branch_vault_ref: "B-branch".into(),
        data_vault_ref: "B-data".into(),
        primary_vault_ref: Some("B-primary".into()),
        state: "installed".into(),
        cleanup_ref: None,
        cleanup_owner_ref: None,
        full_transfer: Some(FullInstall {
            chain_hash: h(5),
            db_relative_path: "accounts/acct/generation-next/account.db".into(),
            object_relative_path: "accounts/acct/generation-next/objects".into(),
            stage_id: h(6),
            generation_nonce: h(7),
            expected_prior_generation: PriorGeneration {
                db_relative_path: "accounts/acct/generation-old/account.db".into(),
                object_relative_path: "accounts/acct/generation-old/objects".into(),
            },
            expected_prior_privacy_epoch: U64(8),
            initial_union_root: h(9),
        }),
    }
}

#[test]
fn pairing_full_install_v3_requires_closed_union_and_prior_generation_operands() -> ResultOf {
    let row = fixture();
    let bytes = encode(&row)?;
    assert_eq!(decode(&bytes)?, row);
    let value = serde_json::to_value(&row)?;
    let fields = [
        "chain_hash",
        "db_relative_path",
        "object_relative_path",
        "stage_id",
        "generation_nonce",
        "expected_prior_generation",
        "expected_prior_privacy_epoch",
        "initial_union_root",
    ];
    for field in fields {
        let mut bad = value.clone();
        bad["full_transfer"].as_object_mut().ok_or("full object")?.remove(field);
        assert!(decode(&canonical_json_bytes(&bad)?).is_err(), "missing {field}");
    }
    for pointer in ["/full_transfer", "/full_transfer/expected_prior_generation"] {
        let mut bad = value.clone();
        bad.pointer_mut(pointer)
            .ok_or("object")?
            .as_object_mut()
            .ok_or("object")?
            .insert("unknown".into(), Value::Bool(true));
        assert!(decode(&canonical_json_bytes(&bad)?).is_err(), "unknown {pointer}");
    }
    for (pointer, replacement) in [
        ("/full_transfer", Value::Null),
        ("/full_transfer/generation_nonce", Value::String(h(7) + "=")),
        ("/full_transfer/initial_union_root", Value::String("short".into())),
        ("/full_transfer/expected_prior_privacy_epoch", Value::String(u64::MAX.to_string())),
    ] {
        let mut bad = value.clone();
        *bad.pointer_mut(pointer).ok_or("field")? = replacement;
        assert!(decode(&canonical_json_bytes(&bad)?).is_err(), "invalid {pointer}");
    }
    let mut missing = value.clone();
    missing.as_object_mut().ok_or("install")?.remove("full_transfer");
    assert!(decode(&canonical_json_bytes(&missing)?).is_err());
    for purpose in ["enroll", "transfer_source", "authority_refresh"] {
        let mut bad = row.clone();
        bad.install_purpose = purpose.into();
        assert!(encode(&bad).is_err(), "v3 on {purpose}");
    }
    Ok(())
}

#[test]
fn pairing_full_install_v3_keeps_v2_bytes_and_refuses_unsafe_or_prior_paths() -> ResultOf {
    let mut legacy = fixture();
    legacy.schema = "ramflux.pairing.Install.v2".into();
    legacy.version = 2;
    legacy.full_transfer = None;
    let bytes = encode(&legacy)?;
    let old: Value = ramflux_protocol::parse_i_json(&bytes)?;
    assert!(old.get("full_transfer").is_none(), "v2 gained a serialized field");
    assert_eq!(decode(&bytes)?, legacy);
    for replacement in [Value::Null, serde_json::to_value(fixture().full_transfer)?] {
        let mut bad = old.clone();
        bad["full_transfer"] = replacement;
        assert!(decode(&canonical_json_bytes(&bad)?).is_err(), "v2 accepted v3 member");
    }
    for path in [
        "",
        "/absolute",
        "../escape",
        "accounts//db",
        "accounts/./db",
        "C:/db",
        "accounts\\db",
        "accounts/db\n",
    ] {
        let mut bad = fixture();
        bad.full_transfer.as_mut().ok_or("full")?.db_relative_path = path.into();
        assert!(encode(&bad).is_err(), "unsafe path {path:?}");
    }
    let mut bad = fixture();
    let full = bad.full_transfer.as_mut().ok_or("full")?;
    full.db_relative_path = full.expected_prior_generation.db_relative_path.clone();
    assert!(encode(&bad).is_err(), "reused prior generation path");
    Ok(())
}

#[test]
fn pairing_full_install_legacy_reopen_cannot_admit_hash_only_full_generation() -> ResultOf {
    let root = std::env::temp_dir()
        .join(format!("full-install-gate-{}", encode_base64url(ramflux_crypto::random_32()?)));
    std::fs::create_dir_all(&root)?;
    let row = fixture();
    super::write_installed(&root, &row)?;
    let gate = crate::custody::pairing::install_gate::reopen(
        &root,
        "acct",
        row.record_hash.as_deref(),
        true,
    )?;
    assert!(
        !gate.admits_ordinary_networking(),
        "record hash alone admitted unverified v3 generation"
    );
    assert!(!gate.files_and_db_agree);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

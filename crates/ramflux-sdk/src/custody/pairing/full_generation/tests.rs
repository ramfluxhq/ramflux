// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Metadata gates only; union bytes, G2 races and installed authority need component proof.
use super::*;
use ramflux_storage::LocalAccountRecord;
type ResultOf<T = ()> = Result<T, Box<dyn std::error::Error>>;
fn fixture() -> ResultOf<(Install, AdoptionRow, AccountGenerationSelection)> {
    let install = crate::custody::pairing::install_store::full_tests::fixture();
    let adoption = crate::custody::pairing::activate::adoption(&install)?;
    let full = install.full_transfer.as_ref().ok_or("full")?;
    let selected = AccountGenerationSelection {
        account: LocalAccountRecord {
            local_account_id: install.account_id.clone(),
            principal_commitment: install.account_anchor.clone(),
            db_relative_path: full.db_relative_path.clone(),
            object_dir_relative_path: full.object_relative_path.clone(),
            account_state: "active".into(),
        },
        manifest_json: Some(FullGenerationManifest::for_install(&install)?.encode()?),
    };
    Ok((install, adoption, selected))
}

#[test]
fn pairing_full_generation_manifest_is_closed_and_cannot_be_legacy_recovery_marker() -> ResultOf {
    let (install, _, _) = fixture()?;
    let manifest = FullGenerationManifest::for_install(&install)?;
    assert_eq!(FullGenerationManifest::decode(&manifest.encode()?)?, manifest);
    let value = serde_json::to_value(&manifest)?;
    for field in [
        "schema",
        "local_account_id",
        "account_anchor",
        "origin",
        "operation_id",
        "record_hash",
        "full_transfer",
    ] {
        let mut bad = value.clone();
        bad.as_object_mut().ok_or("object")?.remove(field);
        assert!(
            FullGenerationManifest::decode(&canonical_json_bytes(&bad)?).is_err(),
            "missing {field}"
        );
    }
    let mut bad = value.clone();
    bad["unknown"] = true.into();
    assert!(FullGenerationManifest::decode(&canonical_json_bytes(&bad)?).is_err());
    let legacy = serde_json::json!({"schema":"ramflux.local.native_data_generation.v1",
        "local_account_id":install.account_id,"account_anchor":install.account_anchor});
    assert!(FullGenerationManifest::decode(&canonical_json_bytes(&legacy)?).is_err());
    let mut bad = value;
    bad["origin"] = "backup".into();
    assert!(FullGenerationManifest::decode(&canonical_json_bytes(&bad)?).is_err());
    Ok(())
}

#[test]
fn pairing_full_generation_metadata_requires_nonce_root_paths_and_all_three_receipts() -> ResultOf {
    let (install, adoption, selected) = fixture()?;
    compare_selected_full_generation(&install, &adoption, selected)?;
    for mutation in 0..10 {
        let (install, mut adoption, mut selected) = fixture()?;
        let wrong = ramflux_protocol::encode_base64url([88; 32]);
        match mutation {
            0 => adoption.full_generation_nonce = Some(wrong),
            1 => adoption.full_initial_union_root = Some(wrong),
            2 => adoption.record_hash = wrong,
            3 => selected.account.db_relative_path = "accounts/acct/another/account.db".into(),
            4 => selected.account.object_dir_relative_path = "accounts/acct/another/objects".into(),
            5 => selected.account.account_state = "removed".into(),
            6 => selected.manifest_json = None,
            7 | 8 => {
                let mut marker = FullGenerationManifest::for_install(&install)?;
                if mutation == 7 {
                    marker.full_transfer.generation_nonce = wrong;
                } else {
                    marker.full_transfer.initial_union_root = wrong;
                }
                selected.manifest_json = Some(marker.encode()?);
            }
            _ => selected.account.principal_commitment = wrong,
        }
        assert!(
            compare_selected_full_generation(&install, &adoption, selected).is_err(),
            "mismatch {mutation}"
        );
    }
    Ok(())
}

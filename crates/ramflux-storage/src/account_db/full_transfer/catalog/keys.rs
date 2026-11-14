// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Full-transfer SQL family declarations for keys.
use super::{
    CellRule, CellType, CodecRule, Disposition, FamilyRule, FamilySelector, FieldRule, MergeRule,
    U64,
};

pub(super) const RULE_2: FamilyRule = table_rule!(
    "sql/account_key_check",
    "account_key_check",
    Rebuild,
    PreferLocal,
    false,
    [],
    [
        (
            "singleton_id",
            I64,
            true,
            Rebuild,
            PreferLocal,
            CodecRule::Scalar { cell_type: CellType::I64 }
        ),
        (
            "key_fingerprint",
            Utf8,
            false,
            Rebuild,
            PreferLocal,
            CodecRule::Scalar { cell_type: CellType::Utf8 }
        ),
    ]
);

pub(super) const RULE_3: FamilyRule = table_rule!(
    "sql/account_mac_bundle/local",
    "account_mac_bundle",
    Exclude,
    PreferLocal,
    false,
    [],
    [
        (
            "bundle_id",
            Utf8,
            true,
            Exclude,
            PreferLocal,
            CodecRule::Scalar { cell_type: CellType::Utf8 }
        ),
        (
            "subkeys",
            Bytes,
            false,
            Exclude,
            PreferLocal,
            CodecRule::Scalar { cell_type: CellType::Bytes }
        ),
        (
            "is_current",
            I64,
            false,
            Exclude,
            PreferLocal,
            CodecRule::Scalar { cell_type: CellType::I64 }
        ),
    ]
);

pub(super) const RULE_4: FamilyRule = table_rule!(
    "sql/account_mac_bundle/portable",
    "account_mac_bundle",
    Transfer,
    ImportedBundle,
    true,
    ["bundle_id"],
    [
        (
            "bundle_id",
            Utf8,
            true,
            Transfer,
            Immutable,
            CodecRule::SqlBase64 { decoded_bytes: U64(32), nullable: false }
        ),
        ("subkeys", Bytes, false, Transfer, ImportedBundle, CodecRule::SqlMacSubkeys),
        (
            "is_current",
            I64,
            false,
            Exclude,
            PreferLocal,
            CodecRule::Scalar { cell_type: CellType::I64 }
        ),
    ]
);

pub(super) const RULE_159: FamilyRule = table_rule!(
    "sql/full_imported_mac_bundle",
    "full_imported_mac_bundle",
    Transfer,
    ImportedBundle,
    true,
    ["source_ref", "bundle_id"],
    [
        ("source_ref", Utf8, false, Transfer, Immutable, CodecRule::SqlDeviceRef),
        (
            "bundle_id",
            Utf8,
            false,
            Transfer,
            Immutable,
            CodecRule::SqlBase64 { decoded_bytes: U64(32), nullable: false }
        ),
        ("subkeys", Bytes, false, Transfer, ImportedBundle, CodecRule::SqlMacSubkeys),
    ]
);

// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Message ordering requires its history owner before a nonempty family can transfer.
use super::{
    CellRule, CellType, CodecRule, Disposition, FamilyRule, FamilySelector, FieldRule, MergeRule,
    U64,
};
pub(super) const RULE: FamilyRule = table_rule!(
    "sql/runtime_message_sequence",
    "runtime_message_sequence",
    Transfer,
    Immutable,
    false,
    ["message_id"],
    [
        (
            "message_id",
            Utf8,
            true,
            Transfer,
            Immutable,
            CodecRule::RequiresOwner {
                owner: "runtime_message_sequence",
                cell_type: CellType::Utf8
            }
        ),
        ("seq", I64, false, Transfer, Immutable, CodecRule::Scalar { cell_type: CellType::I64 })
    ]
);

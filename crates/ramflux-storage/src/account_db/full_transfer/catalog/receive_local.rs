// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Local receive coordinates are rebuilt; pending input must settle before a cut.
use super::{
    CellRule, CellType, CodecRule, Disposition, FamilyRule, FamilySelector, FieldRule, MergeRule,
    U64,
};
use crate::{StorageError, database::Connection};
use std::collections::BTreeSet;

macro_rules! rebuild {
    ($id:literal, $table:literal, [$(($name:literal, $kind:ident)),*]) => {
        table_rule!($id, $table, Rebuild, PreferLocal, false, [], [
            $(($name, $kind, false, Rebuild, PreferLocal, CodecRule::Scalar { cell_type: CellType::$kind })),*
        ])
    };
}
pub(super) const ACK: FamilyRule = rebuild!(
    "sql/gateway_ack_intent",
    "gateway_ack_intent",
    [
        ("target_delivery_id", Utf8),
        ("incarnation_id", Utf8),
        ("inbox_seq", Bytes),
        ("created_at", I64),
        ("attempts", I64),
        ("next_attempt_at", I64),
        ("expires_at", I64)
    ]
);
pub(super) const EPOCH: FamilyRule = rebuild!(
    "sql/gateway_receive_epoch",
    "gateway_receive_epoch",
    [
        ("target_delivery_id", Utf8),
        ("incarnation_id", Utf8),
        ("incarnation_verified", I64),
        ("retired_incarnations", Bytes),
        ("activated_cursor", Bytes),
        ("legacy_uncertain_through", Bytes)
    ]
);
pub(super) const RECEIPT: FamilyRule = rebuild!(
    "sql/gateway_receive_receipt",
    "gateway_receive_receipt",
    [
        ("target_delivery_id", Utf8),
        ("incarnation_id", Utf8),
        ("inbox_seq", Bytes),
        ("disposition", Utf8),
        ("retain_until", I64),
        ("first_seen", I64)
    ]
);
pub(super) const WORK: FamilyRule = rebuild!(
    "sql/gateway_receive_work",
    "gateway_receive_work",
    [
        ("target_delivery_id", Utf8),
        ("incarnation_id", Utf8),
        ("inbox_seq", Bytes),
        ("entry_json", Bytes),
        ("admission_key", Utf8),
        ("byte_len", I64)
    ]
);
// Loss history is data, not an executable cursor. It remains refused when nonempty
// until its inert-history owner is implemented; it is never silently discarded.
pub(super) const LOSS: FamilyRule = table_rule!(
    "sql/gateway_inbox_loss",
    "gateway_inbox_loss",
    Transfer,
    InertHistory,
    false,
    ["target_delivery_id", "incarnation_id", "from_seq", "to_seq"],
    [
        (
            "target_delivery_id",
            Utf8,
            false,
            Transfer,
            InertHistory,
            CodecRule::RequiresOwner { owner: "gateway_inbox_loss", cell_type: CellType::Utf8 }
        ),
        (
            "incarnation_id",
            Utf8,
            false,
            Transfer,
            InertHistory,
            CodecRule::Scalar { cell_type: CellType::Utf8 }
        ),
        (
            "from_seq",
            Bytes,
            false,
            Transfer,
            InertHistory,
            CodecRule::Scalar { cell_type: CellType::Bytes }
        ),
        (
            "to_seq",
            Bytes,
            false,
            Transfer,
            InertHistory,
            CodecRule::Scalar { cell_type: CellType::Bytes }
        ),
        (
            "count",
            Bytes,
            false,
            Transfer,
            InertHistory,
            CodecRule::Scalar { cell_type: CellType::Bytes }
        ),
        (
            "reason",
            Utf8,
            false,
            Transfer,
            InertHistory,
            CodecRule::Scalar { cell_type: CellType::Utf8 }
        ),
        (
            "recorded_at",
            I64,
            false,
            Transfer,
            InertHistory,
            CodecRule::Scalar { cell_type: CellType::I64 }
        ),
        (
            "classification",
            Utf8,
            false,
            Transfer,
            InertHistory,
            CodecRule::Scalar { cell_type: CellType::Utf8 }
        ),
    ]
);

/// Never discard a current input merely because its transport coordinates cannot move.
/// All callers inspect their exact pinned cut, including A deltas and current-B refresh.
pub(in crate::account_db::full_transfer) fn require_quiescent(
    connection: &Connection,
    tables: &BTreeSet<String>,
) -> Result<(), StorageError> {
    let work: bool = tables.contains("gateway_receive_work")
        && connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM gateway_receive_work)",
            [],
            |row| row.get(0),
        )?;
    let open: bool = tables.contains("gateway_receive_receipt") && connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM gateway_receive_receipt WHERE disposition IN ('staged','held'))", [], |row| row.get(0),
    )?;
    if work || open {
        tracing::warn!(
            category = "receive_pending_input",
            "full transfer source cut awaits ordinary receive settlement"
        );
        return Err(StorageError::PairingField("SnapshotBusy"));
    }
    Ok(())
}

#[cfg(test)]
mod tests;

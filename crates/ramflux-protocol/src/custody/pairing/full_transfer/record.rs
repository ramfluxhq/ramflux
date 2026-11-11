// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! A bounded header precedes streamed exact cells. It contains no application payload.
use super::{PairingWire, Result, U64, budget, identifier, require};
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecordOp {
    Put,
    Absent,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CellType {
    Null,
    I64,
    F64,
    Utf8,
    Bytes,
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecordHeader {
    pub family: String,
    pub codec_version: U64,
    pub key: String,
    pub op: RecordOp,
    pub cell_types: Vec<CellType>,
    pub cell_lengths: Vec<U64>,
}
impl PairingWire for RecordHeader {
    const LIMIT: usize = 65_536;
    fn validate(&self) -> Result<()> {
        identifier(&self.family)?;
        require(self.codec_version.0 > 0 && !self.key.is_empty(), "record_key")?;
        require(self.cell_types.len() == self.cell_lengths.len(), "cell_lengths")?;
        if self.op == RecordOp::Absent {
            require(self.cell_types.is_empty(), "absent")?;
        }
        let mut length = 0_u64;
        for (kind, bytes) in self.cell_types.iter().zip(&self.cell_lengths) {
            require(
                match kind {
                    CellType::Null => bytes.0 == 0,
                    CellType::I64 | CellType::F64 => bytes.0 == 8,
                    CellType::Utf8 | CellType::Bytes => true,
                },
                "cell_length",
            )?;
            length = length.checked_add(bytes.0).ok_or(super::WireError::Size)?;
        }
        require(length <= i64::MAX.cast_unsigned(), "record_length")?;
        budget(self, Self::LIMIT)
    }
}

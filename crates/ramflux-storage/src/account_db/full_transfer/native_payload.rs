// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Closed native payload framing. These checks grant neither origin nor installation authority.
use crate::StorageError;
#[cfg(test)]
use prost::Message as _;
#[cfg(test)]
use ramflux_protocol::message as g;
use std::io::{Read, Write};
use zeroize::Zeroizing;

/// Physical native formats have their own bounds, separate from small SQL metadata.
/// The enclosing semantic owner must bind original evidence, account and erasure state.
#[derive(Clone, Copy, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NativePayload {
    DirectHistoryV1,
    DirectRecordV1,
}
fn invalid() -> StorageError {
    StorageError::PairingField("UnsupportedRecord")
}
impl NativePayload {
    pub(super) const fn family(self) -> &'static str {
        match self {
            Self::DirectHistoryV1 | Self::DirectRecordV1 => "sql/runtime_message_content",
        }
    }
    pub(super) const fn max_bytes(self) -> usize {
        match self {
            Self::DirectHistoryV1 => super::FULL_DIRECT_HISTORY_LIMIT,
            Self::DirectRecordV1 => super::FULL_DIRECT_RECORD_LIMIT,
        }
    }
    pub(super) fn validate(self, bytes: &[u8]) -> Result<(), StorageError> {
        if bytes.is_empty() || bytes.len() > self.max_bytes() {
            return Err(invalid());
        }
        match self {
            Self::DirectRecordV1 => {
                let own = super::direct_record::payload_account(bytes)?;
                super::FullDirectRecord::read(bytes, own).map(|_| ())
            }
            Self::DirectHistoryV1 => {
                let own = super::direct_history::payload_account(bytes)?;
                super::FullDirectHistory::read(bytes, own).map(|_| ())
            }
        }
    }
    pub(super) fn copy(
        self,
        length: u64,
        reader: &mut impl Read,
        writer: &mut impl Write,
    ) -> Result<(), StorageError> {
        if length == 0 || length > self.max_bytes() as u64 {
            return Err(invalid());
        }
        // This is the compiled native decoder's fixed input bound, never a record-sized
        // allocation or a capacity taken from a peer header. Other row cells stay streamed.
        let mut scratch = Zeroizing::new(vec![0; self.max_bytes()]);
        let bytes = scratch
            .get_mut(..usize::try_from(length).map_err(|_| invalid())?)
            .ok_or_else(invalid)?;
        reader.read_exact(bytes)?;
        self.validate(bytes)?;
        writer.write_all(bytes)?;
        Ok(())
    }
}
#[cfg(test)]
mod tests;

#[cfg(test)]
pub(super) mod test_support;

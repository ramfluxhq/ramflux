// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Closed native payload framing. These checks grant neither origin nor installation authority.
use crate::StorageError;
use prost::Message as _;
use ramflux_protocol::message as g;
use std::io::{Read, Write};
use zeroize::Zeroizing;

/// Physical native formats have their own bounds, separate from small SQL metadata.
/// The enclosing semantic owner must bind original evidence, account and erasure state.
#[derive(Clone, Copy, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NativePayload {
    DirectInnerV1,
}
fn invalid() -> StorageError {
    StorageError::PairingField("UnsupportedRecord")
}
impl NativePayload {
    pub(super) const fn family(self) -> &'static str {
        match self {
            Self::DirectInnerV1 => "sql/runtime_message_content",
        }
    }
    pub(super) const fn max_bytes(self) -> usize {
        match self {
            Self::DirectInnerV1 => g::validation::MAX_INNER_BYTES,
        }
    }
    pub(super) fn validate(self, bytes: &[u8]) -> Result<(), StorageError> {
        if bytes.is_empty() || bytes.len() > self.max_bytes() {
            return Err(invalid());
        }
        match self {
            Self::DirectInnerV1 => direct_inner(bytes),
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
fn direct_inner(bytes: &[u8]) -> Result<(), StorageError> {
    let scanned = g::validation::scan_inner(bytes).map_err(|_| invalid())?;
    if scanned.outcome != g::validation::ScanOutcome::Supported || !matches!(scanned.kind, 1 | 3) {
        return Err(invalid());
    }
    let inner = g::Inner::decode(bytes).map_err(|_| invalid())?;
    let identity = inner.identity.as_ref().ok_or_else(invalid)?;
    g::identity::verify(identity).map_err(|_| invalid())?;
    if identity.group_id.is_some()
        || identity.group_epoch.is_some()
        || identity.device_sequence & (1 << 63) != 0
    {
        return Err(invalid());
    }
    let content =
        g::registry::decode_body(inner.kind, &inner.body, inner.layer).map_err(|_| invalid())?;
    if matches!(content.value, Some(g::content::Value::Message(message)) if message.sealed_group.is_some())
    {
        return Err(invalid());
    }
    Ok(())
}

#[cfg(test)]
mod tests;

#[cfg(test)]
pub(super) mod test_support;

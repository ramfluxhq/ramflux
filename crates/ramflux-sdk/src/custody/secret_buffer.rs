// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Fixed-capacity serialization that cannot leave secret copies in abandoned reallocations.
use crate::SdkError;
use std::io::{self, Write};
use zeroize::Zeroizing;

struct SecretBuffer {
    bytes: Zeroizing<Vec<u8>>,
    limit: usize,
}
impl SecretBuffer {
    fn new(limit: usize) -> Self {
        Self { bytes: Zeroizing::new(Vec::with_capacity(limit)), limit }
    }
}
impl Write for SecretBuffer {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > self.limit.saturating_sub(self.bytes.len()) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "secret frame exceeds its budget",
            ));
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

pub(crate) fn serialize_secret<T: serde::Serialize>(
    value: &T,
    limit: usize,
) -> Result<Zeroizing<Vec<u8>>, SdkError> {
    let mut writer = SecretBuffer::new(limit);
    serde_json::to_writer(&mut writer, value).map_err(|_| SdkError::CustodySetupInvalid)?;
    Ok(writer.bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn secret_json_never_reallocates_and_refuses_escape_expansion_over_budget()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut buffer = SecretBuffer::new(256);
        let capacity = buffer.bytes.capacity();
        let address = buffer.bytes.as_ptr();
        let secret = Zeroizing::new("word ".repeat(24));
        serde_json::to_writer(&mut buffer, &secret)?;
        assert_eq!(capacity, buffer.bytes.capacity());
        assert_eq!(address, buffer.bytes.as_ptr());
        let expanded = Zeroizing::new("\n".repeat(128));
        assert!(serde_json::to_writer(&mut buffer, &expanded).is_err());
        assert_eq!(capacity, buffer.bytes.capacity());
        assert_eq!(address, buffer.bytes.as_ptr());
        assert!(buffer.bytes.len() <= 256);
        Ok(())
    }
}

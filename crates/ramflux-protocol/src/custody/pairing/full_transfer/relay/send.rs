// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! One retained HTTP-body allocation. The node borrows ciphertext rather than decoding/copying it.
use super::{EncryptedPacket, PairingWire, Result, U64, WireError, b32, budget, require};
use serde::{Deserialize, Serialize};

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SendFull {
    pub kind: String,
    pub packet: EncryptedPacket,
    pub profile: String,
    pub token: super::super::SecretBase64,
}
impl PairingWire for SendFull {
    const LIMIT: usize = super::super::PACKET_BYTES;
    fn to_wire_bytes(&self) -> Result<Vec<u8>> {
        let mut encoded = self.encode_secret()?;
        Ok(std::mem::take(&mut *encoded))
    }
    fn from_wire_bytes(input: &[u8]) -> Result<Self> {
        BorrowedSendFull::from_wire_bytes(input)?;
        crate::parse_i_json_secret(input).map_err(|_| WireError::Shape)
    }
    fn validate(&self) -> Result<()> {
        require(self.kind == "send_full" && self.profile == super::super::PROFILE, "profile")?;
        self.packet.validate()?;
        require(self.token.decode(32)?.len() == 32, "role_token")?;
        budget(self, Self::LIMIT)
    }
}

impl SendFull {
    /// Direct JCS encoding without a Value tree containing the role token.
    /// # Errors
    /// Refuses an invalid or oversized complete full-data request.
    pub fn encode_secret(&self) -> Result<zeroize::Zeroizing<Vec<u8>>> {
        self.validate()?;
        let mut bytes = zeroize::Zeroizing::new(Vec::with_capacity(Self::LIMIT));
        serde_json::to_writer(&mut *bytes, self).map_err(|_| WireError::Json)?;
        Ok(bytes)
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BorrowedPacket<'a> {
    pub ciphertext: &'a str,
    pub counter: U64,
    pub epoch: &'a str,
    pub lease_id: &'a str,
    pub role: &'a str,
}
/// This view is usable only while its charged original body is retained.
/// Authentication and budget reservation must precede reading beyond the ordinary 16-KiB cap.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BorrowedSendFull<'a> {
    pub kind: &'a str,
    #[serde(borrow)]
    pub packet: BorrowedPacket<'a>,
    pub profile: &'a str,
    pub token: &'a str,
}
impl<'a> BorrowedSendFull<'a> {
    /// Strict borrowed parse of original canonical full-data Send bytes.
    /// Does not allocate a second ciphertext, decode ciphertext or construct a Value tree.
    /// # Errors
    /// Refuses excess bytes, bad I-JSON/shape/base64, counters, profile and noncanonical bytes.
    pub fn from_wire_bytes(input: &'a [u8]) -> Result<Self> {
        if input.len() > SendFull::LIMIT {
            return Err(WireError::Size);
        }
        let value: Self = crate::parse_i_json_secret(input).map_err(|_| WireError::Shape)?;
        value.validate()?;
        let mut compare = Compare { input, offset: 0 };
        serde_json::to_writer(&mut compare, &value).map_err(|_| WireError::NonCanonical)?;
        require(compare.offset == input.len(), "canonical")?;
        Ok(value)
    }
    /// Locate the exact packet object for a shared-buffer poll reply, excluding its role token.
    /// The relay must separately match this request against the pre-body admission permit.
    /// # Errors
    /// Refuses another body/layout or malformed packet fields without creating a ciphertext copy.
    pub fn packet_range(&self, input: &[u8]) -> Result<std::ops::Range<usize>> {
        const PREFIX: &[u8] = b"{\"kind\":\"send_full\",\"packet\":";
        self.validate()?;
        require(input.len() <= SendFull::LIMIT && input.starts_with(PREFIX), "canonical")?;
        let start = PREFIX.len();
        let mut compare = Compare { input, offset: start };
        serde_json::to_writer(&mut compare, &self.packet).map_err(|_| WireError::NonCanonical)?;
        Ok(start..compare.offset)
    }

    fn validate(&self) -> Result<()> {
        require(self.kind == "send_full" && self.profile == super::super::PROFILE, "profile")?;
        let packet = &self.packet;
        b32(packet.lease_id, "lease_id")?;
        b32(packet.epoch, "epoch")?;
        b32(self.token, "role_token")?;
        require(matches!(packet.role, "initiator" | "responder"), "role")?;
        require(packet.counter.0 < super::super::PACKETS_PER_KEY, "ResumeRequired")?;
        canonical_ciphertext(packet.ciphertext)?;
        // The owned endpoint encoder reserves 4096 bytes for relay metadata too.
        budget(packet, EncryptedPacket::LIMIT)
    }
}
fn digit(byte: u8) -> Option<u8> {
    match byte {
        b'A'..=b'Z' => Some(byte - b'A'),
        b'a'..=b'z' => Some(byte - b'a' + 26),
        b'0'..=b'9' => Some(byte - b'0' + 52),
        b'-' => Some(62),
        b'_' => Some(63),
        _ => None,
    }
}
fn canonical_ciphertext(value: &str) -> Result<()> {
    require(
        value.len() <= super::super::PACKET_CIPHERTEXT_BYTES.div_ceil(3) * 4
            && value.len() % 4 != 1,
        "ciphertext",
    )?;
    let mut last = 0;
    for byte in value.bytes() {
        last = digit(byte).ok_or(WireError::Field("ciphertext"))?;
    }
    require(
        match value.len() % 4 {
            2 => last.trailing_zeros() >= 4,
            3 => last.trailing_zeros() >= 2,
            _ => true,
        },
        "ciphertext",
    )?;
    let decoded_len = value.len() / 4 * 3
        + match value.len() % 4 {
            2 => 1,
            3 => 2,
            _ => 0,
        };
    require((16..=super::super::PACKET_CIPHERTEXT_BYTES).contains(&decoded_len), "ciphertext")
}
struct Compare<'a> {
    input: &'a [u8],
    offset: usize,
}
impl std::io::Write for Compare<'_> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        let end = self.offset.checked_add(bytes.len()).ok_or(std::io::ErrorKind::InvalidData)?;
        if self.input.get(self.offset..end) != Some(bytes) {
            return Err(std::io::ErrorKind::InvalidData.into());
        }
        self.offset = end;
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    type TestResult = std::result::Result<(), Box<dyn std::error::Error>>;
    fn b(byte: u8) -> String {
        crate::encode_base64url([byte; 32])
    }
    #[test]
    fn full_send_borrows_maximum_ciphertext_from_single_charged_body() -> TestResult {
        let send = SendFull {
            kind: "send_full".into(),
            profile: super::super::super::PROFILE.into(),
            token: super::super::super::SecretBase64::from_bytes(&[3; 32]),
            packet: EncryptedPacket {
                ciphertext: crate::encode_base64url(vec![0; 349_528 + 1024 + 16]),
                counter: U64(65_535),
                epoch: b(4),
                lease_id: b(5),
                role: "initiator".into(),
            },
        };
        let body = send.to_wire_bytes()?;
        let view = BorrowedSendFull::from_wire_bytes(&body)?;
        let start = body.as_slice().as_ptr_range();
        let cipher = view.packet.ciphertext.as_bytes().as_ptr_range();
        assert!(cipher.start >= start.start && cipher.end <= start.end);
        assert_eq!(view.packet.counter, U64(65_535));
        let range = view.packet_range(&body)?;
        assert_eq!(&body[range], send.packet.to_wire_bytes()?);
        let mut oversized = send.clone();
        oversized.packet.ciphertext =
            crate::encode_base64url(vec![0; super::super::super::PACKET_CIPHERTEXT_BYTES + 1]);
        assert!(oversized.validate().is_err());
        assert!(BorrowedSendFull::from_wire_bytes(&serde_json::to_vec(&oversized)?).is_err());

        let duplicate = String::from_utf8(body.clone())?
            .replace("\"kind\":\"send_full\"", "\"kind\":\"send_full\",\"kind\":\"send_full\"");
        assert!(BorrowedSendFull::from_wire_bytes(duplicate.as_bytes()).is_err());
        let spaced = String::from_utf8(body)?.replacen(':', ": ", 1);
        assert!(BorrowedSendFull::from_wire_bytes(spaced.as_bytes()).is_err());
        Ok(())
    }
    #[test]
    fn full_send_borrowed_base64_validator_agrees_with_independent_decoder() -> TestResult {
        for length in 0..80 {
            let bytes = vec![u8::try_from(length)?; length];
            let encoded = crate::encode_base64url(bytes);
            assert_eq!(canonical_ciphertext(&encoded).is_ok(), length >= 16);
            assert!(canonical_ciphertext(&(encoded + "=")).is_err());
        }
        for value in [
            "A",
            "x",
            "AAAAAAAAAAAAAAAAAAAAAB",
            "AAAAAAAAAAAAAAAAAAAAAAB",
            "!!!!!!!!!!!!!!!!!!!!!!!!",
        ] {
            assert!(canonical_ciphertext(value).is_err());
        }
        Ok(())
    }
}

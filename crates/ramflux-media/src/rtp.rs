// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! The minimal RTP header (RFC 3550 §5.1) CALL-01 §4 uses: version 2, no
//! padding, no extension, no CSRC; the marker, payload type, sequence
//! number, timestamp and SSRC.
//!
//! The 12 header bytes travel in clear (the relay may count and order
//! packets) and are `SFrame` metadata: authenticated, so an altered sequence
//! number or timestamp fails decryption.

/// Length of the minimal header.
pub const HEADER_LEN: usize = 12;

/// The dynamic payload type used for Opus (RFC 7587 §6.1 leaves it to the
/// session; both ends use this one).
pub const OPUS_PAYLOAD_TYPE: u8 = 111;

/// A minimal RTP header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RtpHeader {
    /// Marker bit (set on the first packet after silence, RFC 7587 §4.1).
    pub marker: bool,
    /// Payload type.
    pub payload_type: u8,
    /// Sequence number.
    pub sequence: u16,
    /// Timestamp, in 48 kHz samples (RFC 7587 §4.1).
    pub timestamp: u32,
    /// Synchronization source.
    pub ssrc: u32,
}

impl RtpHeader {
    /// The 12 header bytes.
    #[must_use]
    pub fn encode(&self) -> [u8; HEADER_LEN] {
        let mut out = [0_u8; HEADER_LEN];
        out[0] = 0x80;
        out[1] = (u8::from(self.marker) << 7) | (self.payload_type & 0x7f);
        out[2..4].copy_from_slice(&self.sequence.to_be_bytes());
        out[4..8].copy_from_slice(&self.timestamp.to_be_bytes());
        out[8..12].copy_from_slice(&self.ssrc.to_be_bytes());
        out
    }

    /// Reads the header at the start of `packet`. Only the minimal form is
    /// accepted (version 2, no padding, extension or CSRC).
    #[must_use]
    pub fn decode(packet: &[u8]) -> Option<Self> {
        let bytes: &[u8; HEADER_LEN] = packet.get(..HEADER_LEN)?.try_into().ok()?;
        if bytes[0] != 0x80 {
            return None;
        }
        Some(Self {
            marker: bytes[1] & 0x80 != 0,
            payload_type: bytes[1] & 0x7f,
            sequence: u16::from_be_bytes([bytes[2], bytes[3]]),
            timestamp: u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]),
            ssrc: u32::from_be_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_and_refusals() {
        let header = RtpHeader {
            marker: true,
            payload_type: OPUS_PAYLOAD_TYPE,
            sequence: 0xfffe,
            timestamp: 0x0102_0304,
            ssrc: 0xdead_beef,
        };
        let bytes = header.encode();
        assert_eq!(bytes[..2], [0x80, 0x80 | 0x6f]);
        assert_eq!(RtpHeader::decode(&bytes), Some(header));
        assert_eq!(RtpHeader::decode(&bytes[..11]), None);
        let mut padded = bytes;
        padded[0] = 0xa0;
        assert_eq!(RtpHeader::decode(&padded), None);
        let mut with_csrc = bytes;
        with_csrc[0] = 0x81;
        assert_eq!(RtpHeader::decode(&with_csrc), None);
    }
}

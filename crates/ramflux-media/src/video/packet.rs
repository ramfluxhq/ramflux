// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Video packetization (V2.1): one H.264 access unit (AVCC, 4-byte big-endian
//! NAL lengths) split into fragments on RTP payload type 112.
//!
//! Plaintext packet: `rtp header (12) || video header (40) || fragment`. The
//! RTP header and the video header are `SFrame` metadata (authenticated, never
//! encrypted); the fragment is the sealed payload. On the wire the `SFrame`
//! header and tag follow the metadata. Worst case: 12 + 40 + 1,000 + 33 bytes
//! of `SFrame` framing, before the 36-byte relay token.
//!
//! This is a custom format with no RFC 6184 interoperability claim.

use crate::rtp::{self, RtpHeader};

/// RTP payload type of video packets (audio is 111).
pub const VIDEO_PAYLOAD_TYPE: u8 = 112;
/// Length of the video header that follows the RTP header.
pub const VIDEO_HEADER_LEN: usize = 40;
/// Authenticated metadata of a video packet: RTP header plus video header.
pub const METADATA_LEN: usize = rtp::HEADER_LEN + VIDEO_HEADER_LEN;
/// The only video header version defined.
pub const VIDEO_VERSION: u8 = 1;
/// Largest access unit, parameter sets included.
pub const MAX_AU_BYTES: usize = 48_000;
/// Most NAL units in one access unit.
pub const MAX_NALS: usize = 64;
/// Largest SPS or PPS.
pub const MAX_PARAMETER_SET_BYTES: usize = 1_024;
/// Most fragments of one access unit.
pub const MAX_FRAGMENTS: usize = 48;
/// Largest fragment payload.
pub const MAX_FRAGMENT_BYTES: usize = 1_000;
/// RTP clock of video (RFC 3551 style 90 kHz), derived from `pts_us`.
pub const CLOCK_HZ: u64 = 90_000;

/// Flag: an IDR (key) access unit.
pub const FLAG_IDR: u8 = 0x01;
/// Flag: the access unit carries parameter sets (SPS/PPS).
pub const FLAG_CONFIG: u8 = 0x02;
const KNOWN_FLAGS: u8 = FLAG_IDR | FLAG_CONFIG;
/// Rotation is quarter turns clockwise: 0, 90, 180 or 270 degrees.
const ROTATIONS: u8 = 4;
const NAL_SPS: u8 = 7;
const NAL_PPS: u8 = 8;

/// Why a video packet or access unit is refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    /// The access unit is empty or larger than [`MAX_AU_BYTES`].
    #[error("video access unit is empty or larger than 48,000 bytes")]
    AccessUnitSize,
    /// The access unit is not well-formed AVCC.
    #[error("malformed AVCC video access unit")]
    Avcc,
    /// A parameter set is larger than [`MAX_PARAMETER_SET_BYTES`].
    #[error("video parameter set larger than 1,024 bytes")]
    ParameterSet,
    /// The video header is malformed (version, flags, rotation, counts).
    #[error("malformed video header")]
    Header,
    /// The fragment does not fit its access unit or its size bound.
    #[error("video fragment outside its access unit")]
    Fragment,
    /// The packet is not a video RTP packet of this call.
    #[error("not a video RTP packet")]
    NotVideo,
}

/// The video header of one fragment (40 bytes, network order).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FragmentHeader {
    /// IDR (key) access unit.
    pub idr: bool,
    /// Carries parameter sets.
    pub config: bool,
    /// Quarter turns clockwise, `0..=3`.
    pub rotation: u8,
    /// Track revision (u32, wire).
    pub track_revision: u32,
    /// Access unit identifier, unique within the track revision.
    pub frame_id: u64,
    /// Presentation time, microseconds on the call clock.
    pub pts_us: u64,
    /// Length of the whole access unit.
    pub au_len: u32,
    /// Parameter-set revision.
    pub config_revision: u32,
    /// Index of this fragment, `0..fragment_count`.
    pub fragment_index: u16,
    /// Fragments in the access unit, `1..=48`.
    pub fragment_count: u16,
    /// Offset of this fragment's payload inside the access unit.
    pub offset: u32,
}

impl FragmentHeader {
    /// The 40 header bytes.
    #[must_use]
    pub fn encode(&self) -> [u8; VIDEO_HEADER_LEN] {
        let mut out = [0_u8; VIDEO_HEADER_LEN];
        let mut flags = 0_u8;
        if self.idr {
            flags |= FLAG_IDR;
        }
        if self.config {
            flags |= FLAG_CONFIG;
        }
        out[0] = VIDEO_VERSION;
        out[1] = flags;
        out[2] = self.rotation;
        out[4..8].copy_from_slice(&self.track_revision.to_be_bytes());
        out[8..16].copy_from_slice(&self.frame_id.to_be_bytes());
        out[16..24].copy_from_slice(&self.pts_us.to_be_bytes());
        out[24..28].copy_from_slice(&self.au_len.to_be_bytes());
        out[28..32].copy_from_slice(&self.config_revision.to_be_bytes());
        out[32..34].copy_from_slice(&self.fragment_index.to_be_bytes());
        out[34..36].copy_from_slice(&self.fragment_count.to_be_bytes());
        out[36..40].copy_from_slice(&self.offset.to_be_bytes());
        out
    }

    /// Reads the header at the start of `bytes`.
    ///
    /// # Errors
    ///
    /// [`Error::Header`] for a short or malformed header (version, unknown
    /// flags, rotation, reserved byte, fragment counts); [`Error::AccessUnitSize`]
    /// for an access unit length outside `1..=48,000`.
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        let raw: &[u8; VIDEO_HEADER_LEN] =
            bytes.get(..VIDEO_HEADER_LEN).and_then(|b| b.try_into().ok()).ok_or(Error::Header)?;
        if raw[0] != VIDEO_VERSION
            || raw[1] & !KNOWN_FLAGS != 0
            || raw[2] >= ROTATIONS
            || raw[3] != 0
        {
            return Err(Error::Header);
        }
        let au_len = u32::from_be_bytes([raw[24], raw[25], raw[26], raw[27]]);
        if au_len == 0 || usize::try_from(au_len).is_ok_and(|len| len > MAX_AU_BYTES) {
            return Err(Error::AccessUnitSize);
        }
        let fragment_index = u16::from_be_bytes([raw[32], raw[33]]);
        let fragment_count = u16::from_be_bytes([raw[34], raw[35]]);
        if fragment_count == 0
            || usize::from(fragment_count) > MAX_FRAGMENTS
            || fragment_index >= fragment_count
        {
            return Err(Error::Header);
        }
        Ok(Self {
            idr: raw[1] & FLAG_IDR != 0,
            config: raw[1] & FLAG_CONFIG != 0,
            rotation: raw[2],
            track_revision: u32::from_be_bytes([raw[4], raw[5], raw[6], raw[7]]),
            frame_id: u64::from_be_bytes([
                raw[8], raw[9], raw[10], raw[11], raw[12], raw[13], raw[14], raw[15],
            ]),
            pts_us: u64::from_be_bytes([
                raw[16], raw[17], raw[18], raw[19], raw[20], raw[21], raw[22], raw[23],
            ]),
            au_len,
            config_revision: u32::from_be_bytes([raw[28], raw[29], raw[30], raw[31]]),
            fragment_index,
            fragment_count,
            offset: u32::from_be_bytes([raw[36], raw[37], raw[38], raw[39]]),
        })
    }
}

/// Reads one authenticated fragment: `meta` is the 40-byte video header (already
/// authenticated), `payload` the decrypted fragment.
///
/// # Errors
///
/// The header errors of [`FragmentHeader::decode`], or [`Error::Fragment`] when
/// the payload is empty, larger than [`MAX_FRAGMENT_BYTES`], or runs past the
/// end of the access unit.
pub fn decode_fragment(meta: &[u8], payload: &[u8]) -> Result<FragmentHeader, Error> {
    let header = FragmentHeader::decode(meta)?;
    let offset = usize::try_from(header.offset).map_err(|_| Error::Fragment)?;
    let au_len = usize::try_from(header.au_len).map_err(|_| Error::Fragment)?;
    let end = offset.checked_add(payload.len()).ok_or(Error::Fragment)?;
    if payload.is_empty() || payload.len() > MAX_FRAGMENT_BYTES || end > au_len {
        return Err(Error::Fragment);
    }
    Ok(header)
}

/// One complete encoded access unit, as the host supplies or receives it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccessUnit {
    /// Access unit identifier.
    pub frame_id: u64,
    /// Presentation time, microseconds on the call clock.
    pub pts_us: u64,
    /// IDR (key) access unit.
    pub idr: bool,
    /// Carries parameter sets.
    pub config: bool,
    /// Quarter turns clockwise, `0..=3`.
    pub rotation: u8,
    /// Track revision.
    pub track_revision: u32,
    /// Parameter-set revision.
    pub config_revision: u32,
    /// AVCC bytes: 4-byte big-endian NAL lengths, then the NAL units.
    pub data: Vec<u8>,
}

/// Checks that `au` is well-formed AVCC within the bounds.
///
/// # Errors
///
/// [`Error::AccessUnitSize`], [`Error::Avcc`] (truncated length or NAL, zero
/// length, more than [`MAX_NALS`]) or [`Error::ParameterSet`].
pub fn validate_avcc(au: &[u8]) -> Result<(), Error> {
    if au.is_empty() || au.len() > MAX_AU_BYTES {
        return Err(Error::AccessUnitSize);
    }
    let mut pos = 0_usize;
    let mut nals = 0_usize;
    while pos < au.len() {
        let prefix = au.get(pos..pos + 4).ok_or(Error::Avcc)?;
        let len = usize::try_from(u32::from_be_bytes([prefix[0], prefix[1], prefix[2], prefix[3]]))
            .map_err(|_| Error::Avcc)?;
        pos += 4;
        nals += 1;
        if len == 0 || nals > MAX_NALS {
            return Err(Error::Avcc);
        }
        let end = pos.checked_add(len).ok_or(Error::Avcc)?;
        let nal = au.get(pos..end).ok_or(Error::Avcc)?;
        let nal_type = nal.first().ok_or(Error::Avcc)? & 0x1f;
        if (nal_type == NAL_SPS || nal_type == NAL_PPS) && len > MAX_PARAMETER_SET_BYTES {
            return Err(Error::ParameterSet);
        }
        pos = end;
    }
    Ok(())
}

/// The 32-bit RTP timestamp of `pts_us` on the 90 kHz clock (wrapping).
#[must_use]
pub fn rtp_timestamp(pts_us: u64) -> u32 {
    let ticks = pts_us.checked_mul(CLOCK_HZ).map_or(0, |scaled| scaled / 1_000_000);
    u32::try_from(ticks & 0xffff_ffff).unwrap_or(0)
}

/// Splits access units into plaintext video packets with RTP sequence numbers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Packetizer {
    ssrc: u32,
    sequence: u16,
}

impl Packetizer {
    /// A packetizer for stream `ssrc`, starting at RTP sequence `sequence`.
    #[must_use]
    pub fn new(ssrc: u32, sequence: u16) -> Self {
        Self { ssrc, sequence }
    }

    /// The plaintext packets of `au` in fragment order. Each packet is
    /// `rtp || video header || fragment`; seal the fragment with the first
    /// [`METADATA_LEN`] bytes as metadata.
    ///
    /// # Errors
    ///
    /// The validation errors of [`validate_avcc`], or [`Error::Fragment`] if
    /// the fragment arithmetic leaves its header fields.
    pub fn packetize(&mut self, au: &AccessUnit) -> Result<Vec<Vec<u8>>, Error> {
        validate_avcc(&au.data)?;
        let au_len = u32::try_from(au.data.len()).map_err(|_| Error::AccessUnitSize)?;
        let chunks: Vec<&[u8]> = au.data.chunks(MAX_FRAGMENT_BYTES).collect();
        let count = u16::try_from(chunks.len()).map_err(|_| Error::Fragment)?;
        let mut packets = Vec::with_capacity(chunks.len());
        for (index, chunk) in chunks.iter().enumerate() {
            let offset = u32::try_from(index * MAX_FRAGMENT_BYTES).map_err(|_| Error::Fragment)?;
            let fragment_index = u16::try_from(index).map_err(|_| Error::Fragment)?;
            let header = FragmentHeader {
                idr: au.idr,
                config: au.config,
                rotation: au.rotation,
                track_revision: au.track_revision,
                frame_id: au.frame_id,
                pts_us: au.pts_us,
                au_len,
                config_revision: au.config_revision,
                fragment_index,
                fragment_count: count,
                offset,
            };
            let rtp = RtpHeader {
                marker: fragment_index + 1 == count,
                payload_type: VIDEO_PAYLOAD_TYPE,
                sequence: self.sequence,
                timestamp: rtp_timestamp(au.pts_us),
                ssrc: self.ssrc,
            }
            .encode();
            self.sequence = self.sequence.wrapping_add(1);
            let mut packet = Vec::with_capacity(METADATA_LEN + chunk.len());
            packet.extend_from_slice(&rtp);
            packet.extend_from_slice(&header.encode());
            packet.extend_from_slice(chunk);
            packets.push(packet);
        }
        Ok(packets)
    }
}

/// Extends 16-bit RTP sequence numbers to 64 bits (RFC 3550 §A.1 style) so
/// wrap-around and loss counts stay exact.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct SequenceTracker {
    highest: Option<u64>,
}

impl SequenceTracker {
    /// The extended sequence of `sequence`, relative to the highest seen.
    /// `None` when it would lie before the first sequence seen.
    pub fn extend(&mut self, sequence: u16) -> Option<u64> {
        let Some(highest) = self.highest else {
            self.highest = Some(u64::from(sequence));
            return Some(u64::from(sequence));
        };
        let last = u16::try_from(highest & 0xffff).unwrap_or(0);
        let raw = sequence.wrapping_sub(last);
        let delta = if raw < 0x8000 { i64::from(raw) } else { i64::from(raw) - 0x1_0000 };
        let extended = u64::try_from(i64::try_from(highest).ok()? + delta).ok()?;
        self.highest = Some(highest.max(extended));
        Some(extended)
    }
}

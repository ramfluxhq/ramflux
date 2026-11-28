// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! One access unit in, one access unit out, and the redacted video status.
//! The host copies bytes. This module keeps no pointer into host memory.

use super::super::{CAbiError, RamfluxErrorCode};
use super::exports;
use crate::bus::media::InProcessMediaControl;
use ramflux_media::video::packet::{self, AccessUnit, MAX_AU_BYTES};

/// IDR (key) access unit.
pub const RAMFLUX_V2_VIDEO_FLAG_IDR: u16 = 1;
/// The access unit carries parameter sets.
pub const RAMFLUX_V2_VIDEO_FLAG_CONFIG: u16 = 2;
/// The only frame-header version.
pub const RAMFLUX_V2_VIDEO_FRAME_VERSION: u32 = 1;
/// Largest access unit the engine accepts.
pub const RAMFLUX_V2_VIDEO_MAX_AU_BYTES: usize = MAX_AU_BYTES;

const KNOWN_FLAGS: u16 = RAMFLUX_V2_VIDEO_FLAG_IDR | RAMFLUX_V2_VIDEO_FLAG_CONFIG;
const TEXT_MAX: usize = 256;

/// Metadata of one access unit. `struct_size` is `size_of` of this struct.
/// Flags: bit 0 IDR, bit 1 parameter sets. `rotation` is quarter turns, `0..=3`.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RamfluxV2VideoFrame {
    pub struct_size: u32,
    pub version: u32,
    pub frame_id: u64,
    pub pts_us: u64,
    pub track_revision: u32,
    pub config_revision: u32,
    pub rotation: u16,
    pub flags: u16,
    /// Must be zero. Keeps the header a multiple of its alignment.
    pub reserved: u32,
}

/// Redacted video status. The itest feeder counters are not here.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RamfluxV2VideoStatus {
    pub struct_size: u32,
    pub video_target_bps: u32,
    pub keyframe_request_revision: u32,
    pub keyframe_ack_revision: u32,
}

fn invalid(message: &str) -> CAbiError {
    CAbiError::new(RamfluxErrorCode::InvalidArgument, message)
}

fn drive<T: Send>(future: impl std::future::Future<Output = T> + Send) -> Result<T, CAbiError> {
    static RUNTIME: std::sync::OnceLock<Result<tokio::runtime::Runtime, std::io::Error>> =
        std::sync::OnceLock::new();
    let runtime = RUNTIME.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_time()
            .thread_name("ramflux-video-abi")
            .build()
    });
    let runtime = runtime
        .as_ref()
        .map_err(|_| CAbiError::new(RamfluxErrorCode::Internal, "video runtime"))?;
    Ok(runtime.block_on(future))
}

fn readable<T>(ptr: *const T) -> bool {
    !ptr.is_null() && ptr.is_aligned()
}

fn writable<T>(ptr: *mut T) -> bool {
    !ptr.is_null() && ptr.is_aligned()
}

fn control(handle: u64) -> Result<InProcessMediaControl, CAbiError> {
    let client = exports::client(handle)?;
    client.media.clone().ok_or_else(|| invalid("media"))
}

fn text(ptr: *const u8, len: usize) -> Result<String, CAbiError> {
    if ptr.is_null() || len == 0 || len > TEXT_MAX {
        return Err(invalid("text"));
    }
    // SAFETY: the host lends `len` readable bytes until this call returns.
    let bytes = unsafe { std::slice::from_raw_parts(ptr, len) };
    let text = std::str::from_utf8(bytes).map_err(|_| invalid("text"))?;
    if text.chars().any(char::is_control) {
        return Err(invalid("text"));
    }
    Ok(text.to_owned())
}

fn read_frame(frame: *const RamfluxV2VideoFrame) -> Result<RamfluxV2VideoFrame, CAbiError> {
    if !readable(frame) {
        return Err(invalid("frame"));
    }
    // SAFETY: the host lends one aligned frame until this call returns.
    let frame = unsafe { frame.read() };
    let size = u32::try_from(std::mem::size_of::<RamfluxV2VideoFrame>()).unwrap_or(u32::MAX);
    if frame.struct_size != size || frame.version != RAMFLUX_V2_VIDEO_FRAME_VERSION {
        return Err(invalid("frame"));
    }
    if frame.rotation > 3 || frame.flags & !KNOWN_FLAGS != 0 || frame.reserved != 0 {
        return Err(invalid("frame"));
    }
    Ok(frame)
}

fn copy_in(ptr: *const u8, len: usize) -> Result<Vec<u8>, CAbiError> {
    if ptr.is_null() || len == 0 || len > MAX_AU_BYTES {
        return Err(invalid("access unit"));
    }
    // SAFETY: the host lends `len` readable bytes until this call returns.
    let bytes = unsafe { std::slice::from_raw_parts(ptr, len) };
    Ok(bytes.to_vec())
}

fn write_frame(out: *mut RamfluxV2VideoFrame, frame: RamfluxV2VideoFrame) -> Result<(), CAbiError> {
    if !writable(out) {
        return Err(invalid("frame"));
    }
    // SAFETY: the host checked `struct_size` on the way in; the slot stays writable for this call.
    let slot = unsafe { out.read() };
    let size = u32::try_from(std::mem::size_of::<RamfluxV2VideoFrame>()).unwrap_or(u32::MAX);
    if slot.struct_size != size {
        return Err(invalid("frame"));
    }
    // SAFETY: the same slot was readable above and stays writable until this call returns.
    unsafe { out.write(frame) };
    Ok(())
}

fn write_status(
    out: *mut RamfluxV2VideoStatus,
    status: RamfluxV2VideoStatus,
) -> Result<(), CAbiError> {
    if !writable(out) {
        return Err(invalid("status"));
    }
    // SAFETY: the host lends one aligned status slot until this call returns.
    let slot = unsafe { out.read() };
    let size = u32::try_from(std::mem::size_of::<RamfluxV2VideoStatus>()).unwrap_or(u32::MAX);
    if slot.struct_size != size {
        return Err(invalid("status"));
    }
    // SAFETY: the same slot was readable above and stays writable until this call returns.
    unsafe { out.write(status) };
    Ok(())
}

fn write_usize(out: *mut usize, value: usize) -> Result<(), CAbiError> {
    if !writable(out) {
        return Err(invalid("written"));
    }
    // SAFETY: the host lends one aligned writable `usize` until this call returns.
    unsafe { out.write(value) };
    Ok(())
}

fn copy_out(dst: *mut u8, capacity: usize, src: &[u8]) -> Result<(), CAbiError> {
    if dst.is_null() || src.len() > capacity {
        return Err(invalid("access unit"));
    }
    // SAFETY: `src.len()` is within the host's writable `capacity` for this call.
    let out = unsafe { std::slice::from_raw_parts_mut(dst, src.len()) };
    out.copy_from_slice(src);
    Ok(())
}

fn unit_from_frame(frame: RamfluxV2VideoFrame, data: Vec<u8>) -> Result<AccessUnit, CAbiError> {
    let rotation = u8::try_from(frame.rotation).map_err(|_| invalid("frame"))?;
    Ok(AccessUnit {
        frame_id: frame.frame_id,
        pts_us: frame.pts_us,
        idr: frame.flags & RAMFLUX_V2_VIDEO_FLAG_IDR != 0,
        config: frame.flags & RAMFLUX_V2_VIDEO_FLAG_CONFIG != 0,
        rotation,
        track_revision: frame.track_revision,
        config_revision: frame.config_revision,
        data,
    })
}

fn frame_from_unit(unit: &AccessUnit) -> RamfluxV2VideoFrame {
    let mut flags = 0;
    if unit.idr {
        flags |= RAMFLUX_V2_VIDEO_FLAG_IDR;
    }
    if unit.config {
        flags |= RAMFLUX_V2_VIDEO_FLAG_CONFIG;
    }
    RamfluxV2VideoFrame {
        struct_size: u32::try_from(std::mem::size_of::<RamfluxV2VideoFrame>()).unwrap_or(0),
        version: RAMFLUX_V2_VIDEO_FRAME_VERSION,
        frame_id: unit.frame_id,
        pts_us: unit.pts_us,
        track_revision: unit.track_revision,
        config_revision: unit.config_revision,
        rotation: u16::from(unit.rotation),
        flags,
        reserved: 0,
    }
}

/// Copy one AVCC access unit into the live in-process engine.
/// An IDR acknowledges the peer's current keyframe request.
/// Returns 0, or 1 for a bad buffer, 12 when the account cannot use the engine.
#[allow(
    clippy::too_many_arguments,
    reason = "the C frame export copies one access unit across separate host buffers"
)]
#[unsafe(no_mangle)]
#[must_use]
pub extern "C" fn ramflux_v2_video_submit(
    client: u64,
    account: *const u8,
    account_len: usize,
    call_id: *const u8,
    call_len: usize,
    frame: *const RamfluxV2VideoFrame,
    au: *const u8,
    au_len: usize,
) -> i32 {
    exports::call(|| {
        let account = text(account, account_len)?;
        let call_id = text(call_id, call_len)?;
        let frame = read_frame(frame)?;
        let data = copy_in(au, au_len)?;
        let unit = unit_from_frame(frame, data)?;
        packet::validate_avcc(&unit.data).map_err(|_| invalid("access unit"))?;
        let media = control(client)?;
        drive(media.submit_video(&account, &call_id, unit))?
            .map_err(|error| super::super::map_sdk_error(&error))?;
        Ok(())
    })
}

/// Copy one complete access unit out. `written` is 0 when none is waiting; the buffer is unchanged.
/// A unit larger than `capacity` stays queued and returns 1.
#[allow(
    clippy::too_many_arguments,
    reason = "the C frame export copies one access unit across separate host buffers"
)]
#[unsafe(no_mangle)]
#[must_use]
pub extern "C" fn ramflux_v2_video_take(
    client: u64,
    account: *const u8,
    account_len: usize,
    call_id: *const u8,
    call_len: usize,
    frame: *mut RamfluxV2VideoFrame,
    au: *mut u8,
    capacity: usize,
    written: *mut usize,
) -> i32 {
    exports::call(|| {
        write_usize(written, 0)?;
        let account = text(account, account_len)?;
        let call_id = text(call_id, call_len)?;
        // The output slot must name this struct. Other fields are overwritten.
        if !writable(frame) {
            return Err(invalid("frame"));
        }
        // SAFETY: the host lends one aligned frame slot until this call returns.
        let slot_size = unsafe { (*frame).struct_size };
        let size = u32::try_from(std::mem::size_of::<RamfluxV2VideoFrame>()).unwrap_or(u32::MAX);
        if slot_size != size {
            return Err(invalid("frame"));
        }
        if au.is_null() {
            return Err(invalid("access unit"));
        }
        let media = control(client)?;
        let taken = drive(media.take_video(&account, &call_id, capacity))?
            .map_err(|error| super::super::map_sdk_error(&error))?;
        match taken {
            None => Ok(()),
            Some(unit) => {
                copy_out(au, capacity, &unit.data)?;
                write_frame(frame, frame_from_unit(&unit))?;
                write_usize(written, unit.data.len())
            }
        }
    })
}

/// Copy `video_target_bps`, the peer's keyframe request, and this side's ack.
#[unsafe(no_mangle)]
#[must_use]
pub extern "C" fn ramflux_v2_video_status(
    client: u64,
    account: *const u8,
    account_len: usize,
    call_id: *const u8,
    call_len: usize,
    out: *mut RamfluxV2VideoStatus,
) -> i32 {
    exports::call(|| {
        let account = text(account, account_len)?;
        let call_id = text(call_id, call_len)?;
        if out.is_null() {
            return Err(invalid("status"));
        }
        let media = control(client)?;
        let status = drive(media.status(&account, &call_id))?
            .map_err(|error| super::super::map_sdk_error(&error))?;
        write_status(
            out,
            RamfluxV2VideoStatus {
                struct_size: u32::try_from(std::mem::size_of::<RamfluxV2VideoStatus>())
                    .unwrap_or(0),
                video_target_bps: status.stats.video_target_bps,
                keyframe_request_revision: status.stats.keyframe_request_revision,
                keyframe_ack_revision: status.stats.keyframe_ack_revision,
            },
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const FRAME_BYTES: usize = 40;

    fn pack(frame: &RamfluxV2VideoFrame) -> [u8; FRAME_BYTES] {
        let mut out = [0_u8; FRAME_BYTES];
        out[0..4].copy_from_slice(&frame.struct_size.to_le_bytes());
        out[4..8].copy_from_slice(&frame.version.to_le_bytes());
        out[8..16].copy_from_slice(&frame.frame_id.to_le_bytes());
        out[16..24].copy_from_slice(&frame.pts_us.to_le_bytes());
        out[24..28].copy_from_slice(&frame.track_revision.to_le_bytes());
        out[28..32].copy_from_slice(&frame.config_revision.to_le_bytes());
        out[32..34].copy_from_slice(&frame.rotation.to_le_bytes());
        out[34..36].copy_from_slice(&frame.flags.to_le_bytes());
        out[36..40].copy_from_slice(&frame.reserved.to_le_bytes());
        out
    }

    fn unpack(bytes: &[u8]) -> Result<RamfluxV2VideoFrame, ()> {
        let raw: &[u8; FRAME_BYTES] =
            bytes.get(..FRAME_BYTES).and_then(|b| b.try_into().ok()).ok_or(())?;
        let frame = RamfluxV2VideoFrame {
            struct_size: u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]),
            version: u32::from_le_bytes([raw[4], raw[5], raw[6], raw[7]]),
            frame_id: u64::from_le_bytes([
                raw[8], raw[9], raw[10], raw[11], raw[12], raw[13], raw[14], raw[15],
            ]),
            pts_us: u64::from_le_bytes([
                raw[16], raw[17], raw[18], raw[19], raw[20], raw[21], raw[22], raw[23],
            ]),
            track_revision: u32::from_le_bytes([raw[24], raw[25], raw[26], raw[27]]),
            config_revision: u32::from_le_bytes([raw[28], raw[29], raw[30], raw[31]]),
            rotation: u16::from_le_bytes([raw[32], raw[33]]),
            flags: u16::from_le_bytes([raw[34], raw[35]]),
            reserved: u32::from_le_bytes([raw[36], raw[37], raw[38], raw[39]]),
        };
        if frame.version != RAMFLUX_V2_VIDEO_FRAME_VERSION
            || frame.rotation > 3
            || frame.flags & !KNOWN_FLAGS != 0
            || frame.reserved != 0
        {
            return Err(());
        }
        Ok(frame)
    }

    #[test]
    fn video_frame_header_round_trip() {
        let frame = RamfluxV2VideoFrame {
            struct_size: u32::try_from(FRAME_BYTES).expect("test: header size"),
            version: RAMFLUX_V2_VIDEO_FRAME_VERSION,
            frame_id: 0x0102_0304_0506_0708,
            pts_us: 33_333,
            track_revision: 7,
            config_revision: 9,
            rotation: 1,
            flags: RAMFLUX_V2_VIDEO_FLAG_IDR | RAMFLUX_V2_VIDEO_FLAG_CONFIG,
            reserved: 0,
        };
        let back = unpack(&pack(&frame)).expect("test: header unpack");
        assert_eq!(back, frame, "C frame header fields survive pack and unpack");
        assert_eq!(
            std::mem::size_of::<RamfluxV2VideoFrame>(),
            FRAME_BYTES,
            "the C frame header is 40 bytes with no padding"
        );
        assert!(unpack(&[0_u8; 8]).is_err(), "a short header is refused");
    }
}

// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! SHA-1 and standard base64 for the WebSocket accept key. No extra crate.

const MAX_SHA_INPUT: usize = 1024;
const GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

/// `Sec-WebSocket-Accept` for a client key. Refuses an over-long key.
pub(super) fn websocket_accept(key: &str) -> Option<String> {
    if key.len() > 128 {
        return None;
    }
    let mut joined = String::with_capacity(key.len() + GUID.len());
    joined.push_str(key);
    joined.push_str(GUID);
    let digest = sha1(joined.as_bytes())?;
    base64(&digest)
}

/// Fills `dest` from `/dev/urandom`.
///
/// # Errors
/// Returns an error when the device cannot be read.
pub(super) fn random_bytes(dest: &mut [u8]) -> std::io::Result<()> {
    if dest.len() > 64 {
        return Err(std::io::Error::other("random request is too long"));
    }
    let mut file = std::fs::File::open("/dev/urandom")?;
    std::io::Read::read_exact(&mut file, dest)
}

fn sha1(message: &[u8]) -> Option<[u8; 20]> {
    if message.len() > MAX_SHA_INPUT {
        return None;
    }
    let mut padded = Vec::with_capacity(message.len().saturating_add(72));
    padded.extend_from_slice(message);
    padded.push(0x80);
    while padded.len() % 64 != 56 {
        padded.push(0);
    }
    let bits = u64::try_from(message.len()).ok()?.saturating_mul(8);
    padded.extend_from_slice(&bits.to_be_bytes());
    let mut state = [0x6745_2301_u32, 0xEFCD_AB89, 0x98BA_DCFE, 0x1032_5476, 0xC3D2_E1F0];
    let mut offset = 0;
    while offset + 64 <= padded.len() {
        let chunk = padded.get(offset..offset + 64)?;
        compress(&mut state, chunk)?;
        offset += 64;
    }
    let mut out = [0_u8; 20];
    for (index, word) in state.into_iter().enumerate() {
        write_word(&mut out, index, word);
    }
    Some(out)
}

fn compress(state: &mut [u32; 5], chunk: &[u8]) -> Option<()> {
    let mut words = [0_u32; 80];
    for index in 0..16 {
        let start = index * 4;
        let raw = chunk.get(start..start + 4)?;
        let bytes = <[u8; 4]>::try_from(raw).ok()?;
        *words.get_mut(index)? = u32::from_be_bytes(bytes);
    }
    for index in 16..80 {
        let mixed = *words.get(index - 3)?
            ^ *words.get(index - 8)?
            ^ *words.get(index - 14)?
            ^ *words.get(index - 16)?;
        *words.get_mut(index)? = mixed.rotate_left(1);
    }
    let mut h0 = *state.first()?;
    let mut h1 = *state.get(1)?;
    let mut h2 = *state.get(2)?;
    let mut h3 = *state.get(3)?;
    let mut h4 = *state.get(4)?;
    for index in 0..80 {
        let (mixed, constant) = round_fk(index, h1, h2, h3)?;
        let word = *words.get(index)?;
        let temp = h0
            .rotate_left(5)
            .wrapping_add(mixed)
            .wrapping_add(h4)
            .wrapping_add(constant)
            .wrapping_add(word);
        h4 = h3;
        h3 = h2;
        h2 = h1.rotate_left(30);
        h1 = h0;
        h0 = temp;
    }
    let saved = *state;
    *state.first_mut()? = saved.first()?.wrapping_add(h0);
    *state.get_mut(1)? = saved.get(1)?.wrapping_add(h1);
    *state.get_mut(2)? = saved.get(2)?.wrapping_add(h2);
    *state.get_mut(3)? = saved.get(3)?.wrapping_add(h3);
    *state.get_mut(4)? = saved.get(4)?.wrapping_add(h4);
    Some(())
}

fn round_fk(index: usize, b: u32, c: u32, d: u32) -> Option<(u32, u32)> {
    if index < 20 {
        Some(((b & c) | (!b & d), 0x5A82_7999))
    } else if index < 40 {
        Some((b ^ c ^ d, 0x6ED9_EBA1))
    } else if index < 60 {
        Some(((b & c) | (b & d) | (c & d), 0x8F1B_BCDC))
    } else if index < 80 {
        Some((b ^ c ^ d, 0xCA62_C1D6))
    } else {
        None
    }
}

fn write_word(out: &mut [u8; 20], index: usize, value: u32) {
    let start = index.saturating_mul(4);
    for (shift, byte) in value.to_be_bytes().into_iter().enumerate() {
        if let Some(slot) = out.get_mut(start.saturating_add(shift)) {
            *slot = byte;
        }
    }
}

pub(super) fn base64(input: &[u8]) -> Option<String> {
    if input.len() > 64 {
        return None;
    }
    let mut out = String::new();
    for chunk in input.chunks(3) {
        let b0 = u32::from(*chunk.first()?);
        let b1 = chunk.get(1).copied().map_or(0, u32::from);
        let b2 = chunk.get(2).copied().map_or(0, u32::from);
        let packed = (b0 << 16) | (b1 << 8) | b2;
        push_b64(&mut out, packed >> 18)?;
        push_b64(&mut out, packed >> 12)?;
        if chunk.len() > 1 {
            push_b64(&mut out, packed >> 6)?;
        } else {
            out.push('=');
        }
        if chunk.len() > 2 {
            push_b64(&mut out, packed)?;
        } else {
            out.push('=');
        }
    }
    Some(out)
}

fn push_b64(out: &mut String, value: u32) -> Option<()> {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let index = usize::try_from(value & 0b11_1111).ok()?;
    let byte = *TABLE.get(index)?;
    out.push(char::from(byte));
    Some(())
}

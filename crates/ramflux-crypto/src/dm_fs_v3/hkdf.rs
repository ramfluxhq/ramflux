// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Scoped RFC 5869 HKDF with an owned scalar SHA-256/HMAC backend.
//! SHA-256 follows FIPS 180-4 / RFC 6234; all owned secret storage is explicit.
//! Borrowed inputs and compiler/register copies are outside this erasure contract.
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Native HKDF rejects lengths without including input material in its errors.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum NativeHkdfError {
    /// RFC 5869 permits at most 255 SHA-256 blocks; this API requires nonempty output.
    #[error("native HKDF output length rejected")]
    OutputLength,
    /// SHA-256's bit-length counter would overflow.
    #[error("native HKDF input length rejected")]
    InputLength,
    #[cfg(test)]
    #[error("fixture-only early return")]
    Injected,
}
type Result<T> = std::result::Result<T, NativeHkdfError>;

/// A temporary handoff erased at owner drop; deliberately no Clone, Debug or serde.
pub struct NativeHkdfOutput<const N: usize> {
    bytes: [u8; N],
}
impl<const N: usize> AsRef<[u8]> for NativeHkdfOutput<N> {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}
impl<const N: usize> Zeroize for NativeHkdfOutput<N> {
    fn zeroize(&mut self) {
        self.bytes.zeroize();
    }
}
impl<const N: usize> Drop for NativeHkdfOutput<N> {
    fn drop(&mut self) {
        self.zeroize();
        observe_bytes("output", &self.bytes);
    }
}
impl<const N: usize> ZeroizeOnDrop for NativeHkdfOutput<N> {}

struct Secret<const N: usize> {
    bytes: [u8; N],
    slot: &'static str,
}
impl<const N: usize> Secret<N> {
    fn new(slot: &'static str) -> Self {
        Self { bytes: [0; N], slot }
    }
}
impl<const N: usize> Drop for Secret<N> {
    fn drop(&mut self) {
        self.bytes.zeroize();
        observe_bytes(self.slot, &self.bytes);
    }
}
struct Prk([u8; 32]);
impl Drop for Prk {
    fn drop(&mut self) {
        self.0.zeroize(); // Actual PRK erasure; the regression proof removes this line only.
        observe_bytes("prk", &self.0);
    }
}

struct Sha256State {
    state: [u32; 8],
    block: [u8; 64],
    schedule: [u32; 64],
    work: [u32; 8],
    round: [u32; 2],
    final_bytes: [u8; 32],
    total: u64,
    used: usize,
    kind: &'static str,
}
impl Sha256State {
    fn new(kind: &'static str) -> Self {
        Self {
            state: [
                0x6a09_e667,
                0xbb67_ae85,
                0x3c6e_f372,
                0xa54f_f53a,
                0x510e_527f,
                0x9b05_688c,
                0x1f83_d9ab,
                0x5be0_cd19,
            ],
            block: [0; 64],
            schedule: [0; 64],
            work: [0; 8],
            round: [0; 2],
            final_bytes: [0; 32],
            total: 0,
            used: 0,
            kind,
        }
    }
    fn update(&mut self, mut bytes: &[u8]) -> Result<()> {
        self.total = self
            .total
            .checked_add(u64::try_from(bytes.len()).map_err(|_| NativeHkdfError::InputLength)?)
            .filter(|n| *n <= u64::MAX / 8)
            .ok_or(NativeHkdfError::InputLength)?;
        while !bytes.is_empty() {
            let take = (64 - self.used).min(bytes.len());
            self.block[self.used..self.used + take].copy_from_slice(&bytes[..take]);
            self.used += take;
            bytes = &bytes[take..];
            if self.used == 64 {
                self.compress();
            }
        }
        Ok(())
    }
    fn finish(mut self, output: &mut [u8; 32]) -> Result<()> {
        self.block[self.used] = 0x80;
        self.used += 1;
        if self.used > 56 {
            self.compress();
        }
        self.block[56..].copy_from_slice(&(self.total * 8).to_be_bytes());
        self.compress();
        for i in 0..8 {
            for j in 0..4 {
                self.final_bytes[4 * i + j] = u8::try_from((self.state[i] >> (24 - 8 * j)) & 255)
                    .map_err(|_| NativeHkdfError::InputLength)?;
            }
        }
        output.copy_from_slice(&self.final_bytes);
        Ok(())
    }
    fn compress(&mut self) {
        for i in 0..16 {
            let j = 4 * i;
            self.schedule[i] = (u32::from(self.block[j]) << 24)
                | (u32::from(self.block[j + 1]) << 16)
                | (u32::from(self.block[j + 2]) << 8)
                | u32::from(self.block[j + 3]);
        }
        for i in 16..64 {
            self.schedule[i] = self.schedule[i - 16]
                .wrapping_add(small0(self.schedule[i - 15]))
                .wrapping_add(self.schedule[i - 7])
                .wrapping_add(small1(self.schedule[i - 2]));
        }
        self.work.copy_from_slice(&self.state);
        for (i, constant) in K.iter().enumerate() {
            self.round[0] = self.work[7]
                .wrapping_add(big1(self.work[4]))
                .wrapping_add((self.work[4] & self.work[5]) ^ (!self.work[4] & self.work[6]))
                .wrapping_add(*constant)
                .wrapping_add(self.schedule[i]);
            self.round[1] = big0(self.work[0]).wrapping_add(
                (self.work[0] & self.work[1])
                    ^ (self.work[0] & self.work[2])
                    ^ (self.work[1] & self.work[2]),
            );
            self.work[7] = self.work[6];
            self.work[6] = self.work[5];
            self.work[5] = self.work[4];
            self.work[4] = self.work[3].wrapping_add(self.round[0]);
            self.work[3] = self.work[2];
            self.work[2] = self.work[1];
            self.work[1] = self.work[0];
            self.work[0] = self.round[0].wrapping_add(self.round[1]);
        }
        for i in 0..8 {
            self.state[i] = self.state[i].wrapping_add(self.work[i]);
        }
        self.wipe_work();
        self.used = 0;
    }
    fn wipe_work(&mut self) {
        self.block.zeroize();
        observe_bytes("sha_block", &self.block);
        self.schedule.zeroize();
        observe_words("sha_schedule", &self.schedule);
        self.work.zeroize();
        observe_words("sha_work", &self.work);
        self.round.zeroize();
        observe_words("sha_round", &self.round);
    }
}
impl Drop for Sha256State {
    fn drop(&mut self) {
        self.state.zeroize();
        observe_words(self.kind, &self.state);
        self.final_bytes.zeroize();
        observe_bytes("sha_final", &self.final_bytes);
        self.wipe_work();
        self.total.zeroize();
        self.used.zeroize();
        observe_meta(self.total, self.used);
    }
}
fn small0(x: u32) -> u32 {
    x.rotate_right(7) ^ x.rotate_right(18) ^ (x >> 3)
}
fn small1(x: u32) -> u32 {
    x.rotate_right(17) ^ x.rotate_right(19) ^ (x >> 10)
}
fn big0(x: u32) -> u32 {
    x.rotate_right(2) ^ x.rotate_right(13) ^ x.rotate_right(22)
}
fn big1(x: u32) -> u32 {
    x.rotate_right(6) ^ x.rotate_right(11) ^ x.rotate_right(25)
}
// Public SHA-256 round constants, the fractional cube roots of the first 64 primes.
const K: [u32; 64] = [
    0x428a_2f98,
    0x7137_4491,
    0xb5c0_fbcf,
    0xe9b5_dba5,
    0x3956_c25b,
    0x59f1_11f1,
    0x923f_82a4,
    0xab1c_5ed5,
    0xd807_aa98,
    0x1283_5b01,
    0x2431_85be,
    0x550c_7dc3,
    0x72be_5d74,
    0x80de_b1fe,
    0x9bdc_06a7,
    0xc19b_f174,
    0xe49b_69c1,
    0xefbe_4786,
    0x0fc1_9dc6,
    0x240c_a1cc,
    0x2de9_2c6f,
    0x4a74_84aa,
    0x5cb0_a9dc,
    0x76f9_88da,
    0x983e_5152,
    0xa831_c66d,
    0xb003_27c8,
    0xbf59_7fc7,
    0xc6e0_0bf3,
    0xd5a7_9147,
    0x06ca_6351,
    0x1429_2967,
    0x27b7_0a85,
    0x2e1b_2138,
    0x4d2c_6dfc,
    0x5338_0d13,
    0x650a_7354,
    0x766a_0abb,
    0x81c2_c92e,
    0x9272_2c85,
    0xa2bf_e8a1,
    0xa81a_664b,
    0xc24b_8b70,
    0xc76c_51a3,
    0xd192_e819,
    0xd699_0624,
    0xf40e_3585,
    0x106a_a070,
    0x19a4_c116,
    0x1e37_6c08,
    0x2748_774c,
    0x34b0_bcb5,
    0x391c_0cb3,
    0x4ed8_aa4a,
    0x5b9c_ca4f,
    0x682e_6ff3,
    0x748f_82ee,
    0x78a5_636f,
    0x84c8_7814,
    0x8cc7_0208,
    0x90be_fffa,
    0xa450_6ceb,
    0xbef9_a3f7,
    0xc671_78f2,
];

fn hmac(key: &[u8], parts: &[&[u8]], output: &mut [u8; 32]) -> Result<()> {
    let mut normalized = Secret::<32>::new("normalized_key");
    let mut key_block = Secret::<64>::new("hmac_key");
    if key.len() > 64 {
        let mut hash = Sha256State::new("normalize_state");
        hash.update(key)?;
        hash.finish(&mut normalized.bytes)?;
        key_block.bytes[..32].copy_from_slice(&normalized.bytes);
    } else {
        key_block.bytes[..key.len()].copy_from_slice(key);
    }
    let mut ipad = Secret::<64>::new("ipad");
    let mut opad = Secret::<64>::new("opad");
    for i in 0..64 {
        ipad.bytes[i] = key_block.bytes[i] ^ 0x36;
        opad.bytes[i] = key_block.bytes[i] ^ 0x5c;
    }
    let mut inner = Sha256State::new("inner_state");
    inner.update(&ipad.bytes)?;
    for part in parts {
        inner.update(part)?;
    }
    let mut digest = Secret::<32>::new("inner_digest");
    inner.finish(&mut digest.bytes)?;
    let mut outer = Sha256State::new("outer_state");
    outer.update(&opad.bytes)?;
    outer.update(&digest.bytes)?;
    outer.finish(output)
}
struct Session<const N: usize> {
    prk: Prk,
    previous: Secret<32>,
    output: NativeHkdfOutput<N>,
    offset: usize,
    block: usize,
}
impl<const N: usize> Session<N> {
    fn new(ikm: &[u8], salt: &[u8]) -> Result<Self> {
        let mut prk = Prk([0; 32]);
        hmac(salt, &[ikm], &mut prk.0)?;
        Ok(Self {
            prk,
            previous: Secret::new("previous"),
            output: NativeHkdfOutput { bytes: [0; N] },
            offset: 0,
            block: 0,
        })
    }
    fn step(&mut self, info: &[u8]) -> Result<()> {
        let mut current = Secret::<32>::new("current_block");
        let counter = [u8::try_from(self.block + 1).map_err(|_| NativeHkdfError::OutputLength)?];
        let previous =
            if self.block == 0 { &self.previous.bytes[..0] } else { &self.previous.bytes[..] };
        hmac(&self.prk.0, &[previous, info, &counter], &mut current.bytes)?;
        let count = (N - self.offset).min(32);
        self.output.bytes[self.offset..self.offset + count]
            .copy_from_slice(&current.bytes[..count]);
        self.previous.bytes.zeroize();
        observe_bytes("previous_replaced", &self.previous.bytes);
        self.previous.bytes.copy_from_slice(&current.bytes);
        self.offset += count;
        self.block += 1;
        Ok(())
    }
}
/// Derive a scoped native HKDF handoff, with no shared-kdf or bootstrap caller.
/// # Errors
/// Rejects zero/>8160 output bytes or a SHA-256 length overflow.
pub(crate) fn native_hkdf<const N: usize>(
    ikm: &[u8],
    salt: &[u8],
    info: &[u8],
) -> Result<NativeHkdfOutput<N>> {
    if N == 0 || N > 255 * 32 {
        return Err(NativeHkdfError::OutputLength);
    }
    let mut session = Session::<N>::new(ikm, salt)?;
    while session.offset < N {
        session.step(info)?;
    }
    Ok(session.output)
}
#[cfg(test)]
pub(super) fn exercise<const N: usize>(
    ikm: &[u8],
    salt: &[u8],
    info: &[u8],
    steps: usize,
) -> Result<()> {
    let mut session = Session::<N>::new(ikm, salt)?;
    for _ in 0..steps {
        session.step(info)?;
    }
    Err(NativeHkdfError::Injected)
}
#[cfg(test)]
pub(super) fn scoped_drop<const N: usize>(ikm: &[u8], salt: &[u8], info: &[u8]) -> Result<()> {
    let mut session = Session::<N>::new(ikm, salt)?;
    session.step(info)?;
    drop(session);
    Ok(())
}
#[cfg(test)]
pub(super) fn test_sha(bytes: &[u8]) -> Result<NativeHkdfOutput<32>> {
    let mut output = NativeHkdfOutput { bytes: [0; 32] };
    let mut hash = Sha256State::new("standalone_state");
    for part in bytes.chunks(7) {
        hash.update(part)?;
    }
    hash.finish(&mut output.bytes)?;
    Ok(output)
}
#[cfg(test)]
fn observe_bytes(slot: &'static str, bytes: &[u8]) {
    super::hkdf_tests::observe_bytes(slot, bytes);
}
#[cfg(not(test))]
fn observe_bytes(_slot: &'static str, _bytes: &[u8]) {}
#[cfg(test)]
fn observe_words(slot: &'static str, words: &[u32]) {
    super::hkdf_tests::observe_words(slot, words);
}
#[cfg(not(test))]
fn observe_words(_slot: &'static str, _words: &[u32]) {}
#[cfg(test)]
fn observe_meta(total: u64, used: usize) {
    super::hkdf_tests::observe_meta(total, used);
}
#[cfg(not(test))]
fn observe_meta(_total: u64, _used: usize) {}
#[cfg(test)]
pub(super) fn test_intermediates<const N: usize>(
    ikm: &[u8],
    salt: &[u8],
    info: &[u8],
    prk: &[u8],
    blocks: &[[u8; 32]],
    expected: &[u8],
) -> Result<bool> {
    let mut session = Session::<N>::new(ikm, salt)?;
    let mut matches = session.prk.0 == prk;
    let mut block = 0;
    while session.offset < N {
        session.step(info)?;
        matches &= blocks.get(block).is_some_and(|expected| session.previous.bytes == *expected);
        block += 1;
    }
    matches &= block == blocks.len() && session.output.as_ref() == expected;
    Ok(matches)
}

#[cfg(test)]
pub(super) fn test_hmac(key: &[u8], parts: &[&[u8]]) -> Result<NativeHkdfOutput<32>> {
    let mut output = NativeHkdfOutput { bytes: [0; 32] };
    hmac(key, parts, &mut output.bytes)?;
    Ok(output)
}

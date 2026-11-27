// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use hpke::rand_core::{TryCryptoRng, TryRng};
use std::convert::Infallible;

use super::LgError;

/// OS randomness whose failure is reported through the `TryRng` error type, so a POPRF
/// `Error::Protocol` surfaces instead of a panic (design M1).
#[derive(Debug, Default, Clone, Copy)]
pub(crate) struct FallibleOsRng;

#[derive(Debug, Clone, Copy)]
pub(crate) struct RandomUnavailable;

impl core::error::Error for RandomUnavailable {}

impl core::fmt::Display for RandomUnavailable {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("os randomness unavailable")
    }
}

impl TryRng for FallibleOsRng {
    type Error = RandomUnavailable;

    fn try_next_u32(&mut self) -> Result<u32, RandomUnavailable> {
        let mut bytes = [0_u8; 4];
        self.try_fill_bytes(&mut bytes)?;
        Ok(u32::from_le_bytes(bytes))
    }

    fn try_next_u64(&mut self) -> Result<u64, RandomUnavailable> {
        let mut bytes = [0_u8; 8];
        self.try_fill_bytes(&mut bytes)?;
        Ok(u64::from_le_bytes(bytes))
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), RandomUnavailable> {
        getrandom::fill(dest).map_err(|_| RandomUnavailable)
    }
}

impl TryCryptoRng for FallibleOsRng {}

/// Fixed bytes handed out once (derives the POPRF root key from a stored 32-byte seed through the
/// allowed root-key constructor).
pub(crate) struct SeedRng<'a> {
    seed: &'a [u8; 32],
}

impl<'a> SeedRng<'a> {
    pub(crate) const fn new(seed: &'a [u8; 32]) -> Self {
        Self { seed }
    }
}

impl TryRng for SeedRng<'_> {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Infallible> {
        Ok(0)
    }

    fn try_next_u64(&mut self) -> Result<u64, Infallible> {
        Ok(0)
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Infallible> {
        for (slot, byte) in dest.iter_mut().zip(self.seed.iter()) {
            *slot = *byte;
        }
        Ok(())
    }
}

impl TryCryptoRng for SeedRng<'_> {}

/// Fills a fixed array from the operating system.
///
/// # Errors
/// Returns [`LgError::Random`] when the OS refuses randomness.
pub fn random_array<const N: usize>() -> Result<[u8; N], LgError> {
    let mut out = [0_u8; N];
    getrandom::fill(&mut out).map_err(|_| LgError::Random)?;
    Ok(out)
}

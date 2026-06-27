// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use crate::{CryptoError, random_32};
use std::collections::BTreeSet;
use std::fmt;
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecoveryQuorumMemberKind {
    RootShare,
    DeviceShare,
    GuardianShare,
    HardwareTokenShare,
}

#[derive(Clone, Eq, PartialEq, Zeroize, ZeroizeOnDrop)]
pub struct RecoveryShare {
    #[zeroize(skip)]
    pub share_id: u8,
    #[zeroize(skip)]
    pub threshold: u8,
    #[zeroize(skip)]
    pub total: u8,
    #[zeroize(skip)]
    pub member_kind: Option<RecoveryQuorumMemberKind>,
    pub value: [u8; 32],
}

impl fmt::Debug for RecoveryShare {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RecoveryShare")
            .field("share_id", &self.share_id)
            .field("threshold", &self.threshold)
            .field("total", &self.total)
            .field("member_kind", &self.member_kind)
            .field("value", &"<redacted>")
            .finish()
    }
}

/// Splits a 32-byte recovery secret into a Shamir k-of-n quorum over GF(256).
///
/// # Errors
/// Returns an error when threshold/total are invalid or fresh random coefficient material cannot
/// be generated.
pub fn create_recovery_quorum(
    secret: [u8; 32],
    threshold: u8,
    total: u8,
) -> Result<Vec<RecoveryShare>, CryptoError> {
    validate_quorum_parameters(threshold, total)?;
    let mut coefficients = Vec::with_capacity(usize::from(threshold.saturating_sub(1)));
    for _ in 1..threshold {
        coefficients.push(random_32()?);
    }
    Ok((1..=total)
        .map(|share_id| RecoveryShare {
            share_id,
            threshold,
            total,
            member_kind: None,
            value: eval_share(&secret, &coefficients, share_id),
        })
        .collect())
}

/// Recovers a 32-byte secret from any threshold-sized set of unique shares.
///
/// # Errors
/// Returns an error when the supplied shares contain invalid metadata or fewer than the recorded
/// threshold number of unique shares.
pub fn recover_secret_from_quorum(shares: &[RecoveryShare]) -> Result<[u8; 32], CryptoError> {
    let first = shares.first().ok_or(CryptoError::RecoveryQuorumInsufficient)?;
    validate_quorum_parameters(first.threshold, first.total)?;
    let threshold = usize::from(first.threshold);
    let mut seen = BTreeSet::new();
    let mut unique_shares = Vec::with_capacity(threshold);
    for share in shares {
        validate_share_metadata(share, first.threshold, first.total)?;
        if seen.insert(share.share_id) {
            unique_shares.push(share);
            if unique_shares.len() == threshold {
                break;
            }
        }
    }
    if unique_shares.len() < threshold {
        return Err(CryptoError::RecoveryQuorumInsufficient);
    }
    interpolate_secret_at_zero(&unique_shares)
}

fn validate_quorum_parameters(threshold: u8, total: u8) -> Result<(), CryptoError> {
    if threshold == 0 || total == 0 || threshold > total {
        return Err(CryptoError::RecoveryQuorumInvalidParameters);
    }
    Ok(())
}

fn validate_share_metadata(
    share: &RecoveryShare,
    threshold: u8,
    total: u8,
) -> Result<(), CryptoError> {
    if share.threshold != threshold
        || share.total != total
        || share.share_id == 0
        || share.share_id > total
    {
        return Err(CryptoError::RecoveryQuorumInvalidParameters);
    }
    Ok(())
}

fn eval_share(secret: &[u8; 32], coefficients: &[[u8; 32]], x: u8) -> [u8; 32] {
    let mut value = [0_u8; 32];
    for byte_idx in 0..32 {
        let mut y = coefficients
            .iter()
            .rev()
            .fold(0_u8, |accumulator, coefficient| gf_mul(accumulator, x) ^ coefficient[byte_idx]);
        y = gf_mul(y, x) ^ secret[byte_idx];
        value[byte_idx] = y;
    }
    value
}

fn interpolate_secret_at_zero(shares: &[&RecoveryShare]) -> Result<[u8; 32], CryptoError> {
    let mut secret = [0_u8; 32];
    for (share_idx, share) in shares.iter().enumerate() {
        let mut basis = 1_u8;
        for (other_idx, other) in shares.iter().enumerate() {
            if share_idx == other_idx {
                continue;
            }
            let denominator = share.share_id ^ other.share_id;
            let inverse =
                gf_inv(denominator).ok_or(CryptoError::RecoveryQuorumInvalidParameters)?;
            basis = gf_mul(basis, gf_mul(other.share_id, inverse));
        }
        for (byte_idx, byte) in secret.iter_mut().enumerate() {
            *byte ^= gf_mul(share.value[byte_idx], basis);
        }
    }
    Ok(secret)
}

fn gf_mul(mut a: u8, mut b: u8) -> u8 {
    let mut product = 0_u8;
    while b != 0 {
        if b & 1 != 0 {
            product ^= a;
        }
        let high = a & 0x80;
        a <<= 1;
        if high != 0 {
            a ^= 0x1b;
        }
        b >>= 1;
    }
    product
}

fn gf_inv(value: u8) -> Option<u8> {
    if value == 0 {
        return None;
    }
    let mut result = 1_u8;
    for _ in 0..254 {
        result = gf_mul(result, value);
    }
    Some(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shamir_quorums_recover_from_threshold_combinations() -> Result<(), CryptoError> {
        for (threshold, total) in [(2_u8, 3_u8), (3, 5), (3, 3), (5, 7)] {
            assert_threshold_recovery(threshold, total)?;
        }
        Ok(())
    }

    #[test]
    fn recovery_quorum_rejects_invalid_parameters() {
        for (threshold, total) in [(0_u8, 3_u8), (2, 0), (4, 3)] {
            assert!(matches!(
                create_recovery_quorum([1_u8; 32], threshold, total),
                Err(CryptoError::RecoveryQuorumInvalidParameters)
            ));
        }
    }

    #[test]
    fn recovery_quorum_member_kind_is_metadata_only() -> Result<(), CryptoError> {
        let secret = [0x42; 32];
        let mut shares = create_recovery_quorum(secret, 3, 5)?;
        shares[0].member_kind = Some(RecoveryQuorumMemberKind::RootShare);
        shares[1].member_kind = Some(RecoveryQuorumMemberKind::DeviceShare);
        shares[2].member_kind = Some(RecoveryQuorumMemberKind::GuardianShare);
        shares[3].member_kind = Some(RecoveryQuorumMemberKind::HardwareTokenShare);
        assert_eq!(recover_secret_from_quorum(&shares[..3])?, secret);
        Ok(())
    }

    fn assert_threshold_recovery(threshold: u8, total: u8) -> Result<(), CryptoError> {
        let secret = recovery_test_secret(threshold, total);
        let shares = create_recovery_quorum(secret, threshold, total)?;
        assert_eq!(shares.len(), usize::from(total));
        assert!(matches!(
            recover_secret_from_quorum(&shares[..usize::from(threshold.saturating_sub(1))]),
            Err(CryptoError::RecoveryQuorumInsufficient)
        ));
        for subset in threshold_subsets(&shares, usize::from(threshold)) {
            assert_eq!(recover_secret_from_quorum(&subset)?, secret);
        }
        Ok(())
    }

    fn recovery_test_secret(threshold: u8, total: u8) -> [u8; 32] {
        let mut secret = [0_u8; 32];
        for (idx, byte) in secret.iter_mut().enumerate() {
            *byte = u8::try_from(idx).unwrap_or(0) ^ threshold.wrapping_mul(17) ^ total;
        }
        secret
    }

    fn threshold_subsets(shares: &[RecoveryShare], threshold: usize) -> Vec<Vec<RecoveryShare>> {
        let mut subsets = Vec::new();
        let mut current = Vec::with_capacity(threshold);
        collect_threshold_subsets(shares, threshold, 0, &mut current, &mut subsets);
        subsets
    }

    fn collect_threshold_subsets(
        shares: &[RecoveryShare],
        threshold: usize,
        start: usize,
        current: &mut Vec<RecoveryShare>,
        subsets: &mut Vec<Vec<RecoveryShare>>,
    ) {
        if current.len() == threshold {
            subsets.push(current.clone());
            return;
        }
        let remaining_needed = threshold - current.len();
        let last_start = shares.len().saturating_sub(remaining_needed);
        for idx in start..=last_start {
            current.push(shares[idx].clone());
            collect_threshold_subsets(shares, threshold, idx + 1, current, subsets);
            current.pop();
        }
    }
}

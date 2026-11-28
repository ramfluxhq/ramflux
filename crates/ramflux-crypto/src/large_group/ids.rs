// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Genesis v2, `group_id` and the token epoch `info` of MLS-SPEC r1.1 sections 2.1 and 5.

use super::LgError;
use super::codec::{Dec, Enc};
use super::token::TokenBucket;

/// Fixed issuance batch (spec 2.6).
pub const BATCH_SIZE: usize = 20;
/// The only tier of the beta: 1 000 members (owner O5; the 5 000 tier is refused).
pub const TIER_1000: u32 = 1_000;
/// Leaf cap of the 1 000 tier, applied on create, join and receive.
pub const LEAF_CAP: u32 = 3_000;
/// `info(te, bucket)` is 14 + 32 + 4 + 1 bytes.
pub const TOKEN_INFO_LEN: usize = 51;

const GENESIS_SCHEMA: &[u8] = b"rf.lg.genesis.v2";
const TOKEN_INFO_PREFIX: &[u8; 14] = b"rf-lg-token-v1";
const MAX_NODE_ID: usize = 256;

/// The owner-signed, host-visible genesis; `group_id = BLAKE3-256(canonical genesis bytes)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Genesis {
    pub host_node_id: String,
    pub host_head_pk: [u8; 32],
    pub owner_p_pub: [u8; 32],
    pub token_root_pk: [u8; 32],
    /// Join approval ON: an invite join is valid only in an admin-committed commit.
    pub approval: bool,
    pub join_pk_0: [u8; 32],
    /// Always [`TIER_1000`] in the beta.
    pub tier: u32,
    pub created_at: u64,
    pub nonce: [u8; 32],
}

impl Genesis {
    /// Refuses a tier other than [`TIER_1000`] (`tier_unavailable`).
    ///
    /// # Errors
    /// Returns a format error for any other tier.
    pub fn check(&self) -> Result<(), LgError> {
        if self.tier == TIER_1000 { Ok(()) } else { Err(LgError::Format("tier_unavailable")) }
    }

    /// Canonical bytes (the `group_id` preimage).
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut enc = Enc::new(GENESIS_SCHEMA);
        enc.var(self.host_node_id.as_bytes())
            .fixed(&self.host_head_pk)
            .fixed(&self.owner_p_pub)
            .fixed(&self.token_root_pk)
            .u8(u8::from(self.approval))
            .fixed(&self.join_pk_0)
            .u32(self.tier)
            .u64(self.created_at)
            .fixed(&self.nonce);
        enc.finish()
    }

    /// # Errors
    /// Refuses malformed bytes, a wrong schema, an unsupported tier or trailing data.
    pub fn decode(bytes: &[u8]) -> Result<Self, LgError> {
        let mut dec = Dec::new(bytes);
        if dec.var(GENESIS_SCHEMA.len())? != GENESIS_SCHEMA {
            return Err(LgError::Format("genesis schema"));
        }
        let node = dec.var(MAX_NODE_ID)?;
        let host_node_id =
            String::from_utf8(node.to_vec()).map_err(|_| LgError::Format("host node id"))?;
        let genesis = Self {
            host_node_id,
            host_head_pk: dec.fixed()?,
            owner_p_pub: dec.fixed()?,
            token_root_pk: dec.fixed()?,
            approval: match dec.u8()? {
                0 => false,
                1 => true,
                _ => return Err(LgError::Format("approval flag")),
            },
            join_pk_0: dec.fixed()?,
            tier: dec.u32()?,
            created_at: dec.u64()?,
            nonce: dec.fixed()?,
        };
        dec.finish()?;
        genesis.check()?;
        Ok(genesis)
    }

    /// `group_id = BLAKE3-256(canonical genesis bytes)`.
    #[must_use]
    pub fn group_id(&self) -> [u8; 32] {
        group_id_of(&self.encode())
    }
}

/// `group_id` of already-encoded genesis bytes.
#[must_use]
pub fn group_id_of(genesis_bytes: &[u8]) -> [u8; 32] {
    *blake3::hash(genesis_bytes).as_bytes()
}

/// `info(te, bucket) = "rf-lg-token-v1" ‖ group_id ‖ I2OSP(te, 4) ‖ bucket` (fixed 51 bytes,
/// RFC 9497 section 5.4). The bucket byte makes a token redeemable in one bucket only.
#[must_use]
pub fn token_info(group_id: &[u8; 32], te: u32, bucket: TokenBucket) -> [u8; TOKEN_INFO_LEN] {
    let mut out = [0_u8; TOKEN_INFO_LEN];
    let (prefix, rest) = out.split_at_mut(TOKEN_INFO_PREFIX.len());
    prefix.copy_from_slice(TOKEN_INFO_PREFIX);
    let (gid, rest) = rest.split_at_mut(32);
    gid.copy_from_slice(group_id);
    let (epoch, code) = rest.split_at_mut(4);
    epoch.copy_from_slice(&te.to_be_bytes());
    code.copy_from_slice(&[bucket.code()]);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Genesis {
        Genesis {
            host_node_id: "node-a".to_owned(),
            host_head_pk: [1; 32],
            owner_p_pub: [2; 32],
            token_root_pk: [3; 32],
            approval: true,
            join_pk_0: [4; 32],
            tier: TIER_1000,
            created_at: 7,
            nonce: [5; 32],
        }
    }

    #[test]
    fn genesis_round_trips_and_refuses_other_tiers() {
        let genesis = sample();
        let decoded = Genesis::decode(&genesis.encode()).expect("test: genesis decodes");
        assert_eq!(decoded, genesis, "genesis v2 must round trip");
        let mut other = sample();
        other.tier = 5_000;
        assert!(Genesis::decode(&other.encode()).is_err(), "tier 5000 is unavailable in the beta");
    }

    #[test]
    fn token_info_separates_buckets() {
        let gid = [9; 32];
        assert_ne!(
            token_info(&gid, 1, TokenBucket::Post),
            token_info(&gid, 1, TokenBucket::Commit),
            "buckets must not share an info string"
        );
        for other in [TokenBucket::Post, TokenBucket::Commit, TokenBucket::Open] {
            assert_ne!(
                token_info(&gid, 1, TokenBucket::Attach),
                token_info(&gid, 1, other),
                "an attach token must not redeem in another bucket"
            );
        }
    }
}

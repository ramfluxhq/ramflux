// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Genesis, `group_id` and the epoch `info` of design v7 sections 2.3 and 2.4.

use super::LgError;
use super::codec::{Dec, Enc};

/// Fixed issuance batch (design section 2.3).
pub const BATCH_SIZE: usize = 20;
/// Beta member cap (owner item 8).
pub const MEMBER_CAP: u32 = 1_000;
/// `info(te)` is 14 + 32 + 4 bytes.
pub const TOKEN_INFO_LEN: usize = 50;

const GENESIS_SCHEMA: &[u8] = b"rf.lg.genesis.v1";
const TOKEN_INFO_PREFIX: &[u8; 14] = b"rf-lg-token-v1";
const MAX_NODE_ID: usize = 256;

/// Per-group join approval setting (owner item 9).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JoinPolicy {
    /// Join approval ON: an admin writes `W`.
    ApprovalOn,
    /// Join approval OFF: a valid invite joins at once, any member delivers the key.
    ApprovalOff,
}

impl JoinPolicy {
    const fn code(self) -> u8 {
        match self {
            Self::ApprovalOn => 1,
            Self::ApprovalOff => 0,
        }
    }

    fn from_code(code: u8) -> Result<Self, LgError> {
        match code {
            1 => Ok(Self::ApprovalOn),
            0 => Ok(Self::ApprovalOff),
            _ => Err(LgError::Format("join policy")),
        }
    }
}

/// The owner-signed, host-visible genesis; `group_id = BLAKE3(canonical genesis bytes)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Genesis {
    pub host_node_id: String,
    pub host_head_pk: [u8; 32],
    pub owner_p_pub: [u8; 32],
    pub token_root_pk: [u8; 32],
    pub join_policy: JoinPolicy,
    pub join_pk_0: [u8; 32],
    pub member_cap: u32,
    pub created_at: u64,
    pub nonce: [u8; 32],
}

impl Genesis {
    /// Canonical bytes (the `group_id` preimage).
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut enc = Enc::new(GENESIS_SCHEMA);
        enc.var(self.host_node_id.as_bytes())
            .fixed(&self.host_head_pk)
            .fixed(&self.owner_p_pub)
            .fixed(&self.token_root_pk)
            .u8(self.join_policy.code())
            .fixed(&self.join_pk_0)
            .u32(self.member_cap)
            .u64(self.created_at)
            .fixed(&self.nonce);
        enc.finish()
    }

    /// # Errors
    /// Refuses malformed bytes, a wrong schema or trailing data.
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
            join_policy: JoinPolicy::from_code(dec.u8()?)?,
            join_pk_0: dec.fixed()?,
            member_cap: dec.u32()?,
            created_at: dec.u64()?,
            nonce: dec.fixed()?,
        };
        dec.finish()?;
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

/// `info(te) = "rf-lg-token-v1" ‖ group_id ‖ I2OSP(te, 4)` (fixed 50 bytes, RFC 9497 section 5.4).
#[must_use]
pub fn token_info(group_id: &[u8; 32], te: u32) -> [u8; TOKEN_INFO_LEN] {
    let mut out = [0_u8; TOKEN_INFO_LEN];
    let (prefix, rest) = out.split_at_mut(TOKEN_INFO_PREFIX.len());
    prefix.copy_from_slice(TOKEN_INFO_PREFIX);
    let (gid, epoch) = rest.split_at_mut(32);
    gid.copy_from_slice(group_id);
    epoch.copy_from_slice(&te.to_be_bytes());
    out
}

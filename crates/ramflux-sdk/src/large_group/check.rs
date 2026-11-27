// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Member-side checks of design 2.4.1 and the roll table of 2.3: admin chain against the signed
//! `admin_chain_head`, epoch position `(epoch, prev_key_seq)`, `kc`, slot inclusion.

use ramflux_crypto::large_group::{
    EpochKey, Genesis, LgReader as Dec, RollKind, RollRecord, SignedKeyBody, SignedReq,
    admin_chain_head, derive_kc, leaf_hash, ratchet_epoch_key, verify_audit_path, w_body_hash,
};

/// Why a key delivery is not used (flag the author, show the host warning).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum KeyFault {
    Position,
    AdminChainHead,
    Signer,
    Inclusion,
    Kc,
    Body,
}

impl KeyFault {
    pub(crate) const fn text(self) -> &'static str {
        match self {
            Self::Position => "key entry at a wrong epoch position",
            Self::AdminChainHead => "admin chain does not end at the signed head",
            Self::Signer => "key entry signer is not allowed",
            Self::Inclusion => "slot does not verify against the slot root",
            Self::Kc => "key confirmation does not match the ratchet",
            Self::Body => "key body malformed",
        }
    }
}

/// Verifies an admin chain (`prev ‖ signed request` entries) and returns the admin set at its end
/// (owner included). The owner is never demoted.
pub(crate) fn verify_admin_chain(
    gid: &[u8; 32],
    owner: &[u8; 32],
    chain: &[Vec<u8>],
) -> Result<Vec<[u8; 32]>, KeyFault> {
    let mut admins = vec![*owner];
    for (index, entry) in chain.iter().enumerate() {
        let mut dec = Dec::new(entry);
        let prev: [u8; 32] = dec.fixed().map_err(|_| KeyFault::Body)?;
        let raw = dec.var(16 * 1024).map_err(|_| KeyFault::Body)?;
        if prev != admin_chain_head(gid, chain.get(..index).unwrap_or(&[])) {
            return Err(KeyFault::AdminChainHead);
        }
        let req = SignedReq::decode(raw).map_err(|_| KeyFault::Body)?;
        req.verify("admin").map_err(|_| KeyFault::Signer)?;
        let mut body = Dec::new(&req.body);
        let action = body.u8().map_err(|_| KeyFault::Body)?;
        let target: [u8; 32] = body.fixed().map_err(|_| KeyFault::Body)?;
        match action {
            1 if req.p == *owner => {
                if !admins.contains(&target) {
                    admins.push(target);
                }
            }
            2 if admins.contains(&req.p) && target != *owner => admins.retain(|p| *p != target),
            _ => return Err(KeyFault::Signer),
        }
    }
    Ok(admins)
}

/// Epoch position, `admin_chain_head` and signer checks shared by members and joiners.
pub(crate) fn check_body(
    gid: &[u8; 32],
    body: &SignedKeyBody,
    want_epoch: u64,
    want_prev: u64,
    chain: &[Vec<u8>],
) -> Result<(), KeyFault> {
    if body.group_id != *gid || body.key_epoch != want_epoch || body.prev_key_seq != want_prev {
        return Err(KeyFault::Position);
    }
    if body.admin_chain_head != admin_chain_head(gid, chain) {
        return Err(KeyFault::AdminChainHead);
    }
    Ok(())
}

/// Where a `W`/`W'` sits: the host-visible `W_body` inputs.
pub(crate) struct Position<'a> {
    pub gid: &'a [u8; 32],
    pub kind: u8,
    pub key_epoch: u64,
    pub prev_key_seq: u64,
    pub joiners: &'a [[u8; 32]],
}

/// Member path: derive `K_{e+1}` from the host-visible `W_body` (advance always), then compare the
/// signed `kc` with the own derivation.
pub(crate) fn ratchet_and_kc(
    at: &Position<'_>,
    k_e: &EpochKey,
    signed_kc: Option<&[u8; 32]>,
) -> Result<(EpochKey, bool), KeyFault> {
    let w_body = w_body_hash(at.gid, at.kind, at.key_epoch, at.prev_key_seq, at.joiners)
        .map_err(|_| KeyFault::Body)?;
    let next = ratchet_epoch_key(k_e, &w_body).map_err(|_| KeyFault::Body)?;
    let kc = derive_kc(&next, at.gid, at.key_epoch).map_err(|_| KeyFault::Body)?;
    Ok((next, signed_kc.is_some_and(|signed| *signed == kc)))
}

/// Joiner path: the slot must be in the signed root with the signed count.
pub(crate) fn check_inclusion(
    p: &[u8; 32],
    ct: &[u8],
    index: u32,
    slot_count: u32,
    path: &[[u8; 32]],
    root: &[u8; 32],
) -> Result<(), KeyFault> {
    if verify_audit_path(&leaf_hash(p, ct), u64::from(index), u64::from(slot_count), path, root) {
        Ok(())
    } else {
        Err(KeyFault::Inclusion)
    }
}

/// Parsed `token_epoch` entry body.
pub(crate) struct RollEntry {
    pub te: u32,
    pub reason: u8,
    pub started_at_ms: u64,
}

pub(crate) fn parse_roll(body: &[u8]) -> Option<RollEntry> {
    let mut dec = Dec::new(body);
    let te = dec.u32().ok()?;
    let reason = dec.u8().ok()?;
    let refs = usize::try_from(dec.u32().ok()?).ok()?;
    if refs > 64 {
        return None;
    }
    for _ in 0..refs {
        dec.u64().ok()?;
    }
    let started_at_ms = dec.u64().ok()?;
    dec.finish().ok()?;
    Some(RollEntry { te, reason, started_at_ms })
}

/// Maps the host's roll reason byte (0 revoke by admin, 1 revoke by leave, 2 daily, 3 spent full)
/// to a roll-table record. Removals and leaves are P2, so their references cannot be validated yet
/// and such a roll is treated as failing its rule.
pub(crate) fn roll_record(roll: &RollEntry, appended_at_ms: u64) -> Option<RollRecord> {
    let kind = match roll.reason {
        0 => RollKind::RevokeAdmin,
        1 => RollKind::RevokeLeave,
        2 => RollKind::Daily,
        3 => RollKind::SpentFull,
        _ => return None,
    };
    if roll.started_at_ms.abs_diff(appended_at_ms) > 60_000 {
        return None;
    }
    Some(RollRecord { kind, started_at_ms: appended_at_ms, refs_valid: false })
}

/// The owner public key of a genesis.
pub(crate) fn owner_of(genesis: &[u8]) -> Option<(Genesis, [u8; 32])> {
    let parsed = Genesis::decode(genesis).ok()?;
    let owner = parsed.owner_p_pub;
    Some((parsed, owner))
}

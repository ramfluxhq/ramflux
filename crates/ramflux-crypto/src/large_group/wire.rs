// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Shared host/client wire layouts of the large-group requests (deterministic, length-prefixed).
//!
//! Every request is a [`SignedReq`] signed by the pseudonym `P` (never by a device or account key)
//! except create, join and the debug requests, which carry their own proofs.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};

use super::codec::{Dec, Enc};
use super::content::{EntryHeader, TAG_SLOTS};
use super::{LgError, MAX_BUCKET};

const REQ_DOMAIN: &[u8] = b"rf-lg-req-v1";
const MAX_BODY: usize = 16 * 1024;
const MAX_SLOTS: usize = 100;
const MAX_SLOT_CT: usize = 24 * 1024;
const MAX_PATH_NODES: usize = 16;
const MAX_ENTRIES_PER_READ: usize = 64;
const MAX_KD_META: usize = 4096;
const MAX_ADMIN_CHAIN: usize = 64;

/// A request signed by one pseudonym over `(op, group_id, body)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedReq {
    pub gid: [u8; 32],
    pub p: [u8; 32],
    pub body: Vec<u8>,
    pub sig: [u8; 64],
}

fn req_message(op: &str, gid: &[u8; 32], body: &[u8]) -> Vec<u8> {
    let mut enc = Enc::new(REQ_DOMAIN);
    enc.var(op.as_bytes()).fixed(gid).var(body);
    enc.finish()
}

impl SignedReq {
    /// Signs `body` as pseudonym `seed` for operation `op`.
    #[must_use]
    pub fn sign(op: &str, gid: &[u8; 32], seed: &[u8; 32], body: Vec<u8>) -> Self {
        let key = SigningKey::from_bytes(seed);
        let sig = key.sign(&req_message(op, gid, &body)).to_bytes();
        Self { gid: *gid, p: key.verifying_key().to_bytes(), body, sig }
    }

    /// # Errors
    /// Returns an error when the signature does not verify for `op`.
    pub fn verify(&self, op: &str) -> Result<(), LgError> {
        let key = VerifyingKey::from_bytes(&self.p).map_err(|_| LgError::Verify("pseudonym"))?;
        key.verify(&req_message(op, &self.gid, &self.body), &Signature::from_bytes(&self.sig))
            .map_err(|_| LgError::Verify("request signature"))
    }

    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut enc = Enc::default();
        enc.fixed(&self.gid).fixed(&self.p).var(&self.body).fixed(&self.sig);
        enc.finish()
    }

    /// # Errors
    /// Returns an error for a malformed request.
    pub fn decode(bytes: &[u8]) -> Result<Self, LgError> {
        let mut dec = Dec::new(bytes);
        let req = Self {
            gid: dec.fixed()?,
            p: dec.fixed()?,
            body: dec.var(MAX_BODY)?.to_vec(),
            sig: dec.fixed()?,
        };
        dec.finish()?;
        Ok(req)
    }
}

/// Writes a host-visible entry header.
pub fn encode_header(enc: &mut Enc, header: &EntryHeader) {
    enc.u8(header.kind)
        .fixed(&header.post_id)
        .u64(header.key_epoch)
        .u32(header.bucket)
        .fixed(&header.del_secret_hash);
    for tag in &header.tags {
        enc.fixed(tag);
    }
}

/// Reads a host-visible entry header.
///
/// # Errors
/// Returns an error for a truncated header.
pub fn decode_header(dec: &mut Dec<'_>) -> Result<EntryHeader, LgError> {
    let kind = dec.u8()?;
    let post_id = dec.fixed()?;
    let key_epoch = dec.u64()?;
    let bucket = dec.u32()?;
    let del_secret_hash = dec.fixed()?;
    let mut tags = [[0_u8; 16]; TAG_SLOTS];
    for tag in &mut tags {
        *tag = dec.fixed()?;
    }
    Ok(EntryHeader { kind, post_id, key_epoch, bucket, del_secret_hash, tags })
}

/// Key-moving part of an entry (`W`, `W'`, `W'_redeliver`): the signed body, its signer, the joiner
/// list and one sealed slot per joiner in strictly increasing `P` order.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct KeyDelivery {
    /// Admin pseudonym for `W`; absent for member-written entries (device signature is inside).
    pub signer_p: Option<[u8; 32]>,
    pub body_bytes: Vec<u8>,
    /// Admin-`P` signature over `body_bytes` (admin entries only).
    pub body_sig: Option<[u8; 64]>,
    pub joiners: Vec<[u8; 32]>,
    pub slots: Vec<Vec<u8>>,
}

/// Encodes the slot-free part of a key delivery (kept in the log, returned to every reader).
#[must_use]
pub fn kd_meta_encode(kd: &KeyDelivery) -> Vec<u8> {
    let mut enc = Enc::default();
    match (&kd.signer_p, &kd.body_sig) {
        (Some(p), Some(sig)) => enc.u8(1).fixed(p).fixed(sig),
        _ => enc.u8(0),
    };
    enc.var(&kd.body_bytes);
    let count = u32::try_from(kd.joiners.len()).unwrap_or(u32::MAX);
    enc.u32(count);
    for joiner in &kd.joiners {
        enc.fixed(joiner);
    }
    enc.finish()
}

/// # Errors
/// Returns an error for a malformed meta blob.
pub fn kd_meta_decode(bytes: &[u8]) -> Result<KeyDelivery, LgError> {
    let mut dec = Dec::new(bytes);
    let (signer_p, body_sig) = match dec.u8()? {
        0 => (None, None),
        1 => (Some(dec.fixed()?), Some(dec.fixed()?)),
        _ => return Err(LgError::Format("kd signer flag")),
    };
    let body_bytes = dec.var(MAX_KD_META)?.to_vec();
    let count = usize::try_from(dec.u32()?).map_err(|_| LgError::Format("joiner count"))?;
    if count > MAX_SLOTS {
        return Err(LgError::Format("joiner count"));
    }
    let mut joiners = Vec::with_capacity(count);
    for _ in 0..count {
        joiners.push(dec.fixed()?);
    }
    dec.finish()?;
    Ok(KeyDelivery { signer_p, body_bytes, body_sig, joiners, slots: Vec::new() })
}

/// A member-written or admin-written entry submitted to the host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PostEntry {
    pub header: EntryHeader,
    pub ciphertext: Vec<u8>,
    /// 68-byte posting token; empty for admin-signed entries.
    pub token: Vec<u8>,
    pub key: Option<KeyDelivery>,
}

impl PostEntry {
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut enc = Enc::default();
        encode_header(&mut enc, &self.header);
        enc.var(&self.ciphertext).var(&self.token);
        match &self.key {
            Some(kd) => {
                enc.u8(1).var(&kd_meta_encode(kd));
                let count = u32::try_from(kd.slots.len()).unwrap_or(u32::MAX);
                enc.u32(count);
                for slot in &kd.slots {
                    enc.var(slot);
                }
            }
            None => {
                enc.u8(0);
            }
        }
        enc.finish()
    }

    /// # Errors
    /// Returns an error for a malformed entry.
    pub fn decode(bytes: &[u8]) -> Result<Self, LgError> {
        let mut dec = Dec::new(bytes);
        let header = decode_header(&mut dec)?;
        let ciphertext = dec.var(MAX_BUCKET)?.to_vec();
        let token = dec.var(super::TOKEN_LEN)?.to_vec();
        let key = match dec.u8()? {
            0 => None,
            1 => {
                let mut kd = kd_meta_decode(dec.var(MAX_KD_META)?)?;
                let count = usize::try_from(dec.u32()?).map_err(|_| LgError::Format("slots"))?;
                if count > MAX_SLOTS {
                    return Err(LgError::Format("slot count"));
                }
                for _ in 0..count {
                    kd.slots.push(dec.var(MAX_SLOT_CT)?.to_vec());
                }
                Some(kd)
            }
            _ => return Err(LgError::Format("key delivery flag")),
        };
        dec.finish()?;
        Ok(Self { header, ciphertext, token, key })
    }
}

/// The reader's own slot of a key-moving entry with its inclusion proof.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SlotView {
    pub index: u32,
    pub slot_count: u32,
    pub slot_root: [u8; 32],
    pub ct: Vec<u8>,
    pub path: Vec<[u8; 32]>,
}

/// One log entry as delivered to a reader.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogView {
    pub seq: u64,
    pub appended_at_ms: u64,
    pub head: [u8; 32],
    pub host_sig: [u8; 64],
    pub header: EntryHeader,
    pub ciphertext: Vec<u8>,
    pub token: Vec<u8>,
    /// Encoded [`KeyDelivery`] without slots (empty when the entry moves no key).
    pub kd_meta: Vec<u8>,
    pub slot: Option<SlotView>,
}

impl LogView {
    fn encode_into(&self, enc: &mut Enc) {
        enc.u64(self.seq).u64(self.appended_at_ms).fixed(&self.head).fixed(&self.host_sig);
        encode_header(enc, &self.header);
        enc.var(&self.ciphertext).var(&self.token).var(&self.kd_meta);
        match &self.slot {
            Some(slot) => {
                enc.u8(1).u32(slot.index).u32(slot.slot_count).fixed(&slot.slot_root).var(&slot.ct);
                let nodes = u32::try_from(slot.path.len()).unwrap_or(u32::MAX);
                enc.u32(nodes);
                for node in &slot.path {
                    enc.fixed(node);
                }
            }
            None => {
                enc.u8(0);
            }
        }
    }

    fn decode_from(dec: &mut Dec<'_>) -> Result<Self, LgError> {
        let seq = dec.u64()?;
        let appended_at_ms = dec.u64()?;
        let head = dec.fixed()?;
        let host_sig = dec.fixed()?;
        let header = decode_header(dec)?;
        let ciphertext = dec.var(MAX_BUCKET)?.to_vec();
        let token = dec.var(super::TOKEN_LEN)?.to_vec();
        let kd_meta = dec.var(MAX_KD_META)?.to_vec();
        let slot = match dec.u8()? {
            0 => None,
            1 => {
                let index = dec.u32()?;
                let slot_count = dec.u32()?;
                let slot_root = dec.fixed()?;
                let ct = dec.var(MAX_SLOT_CT)?.to_vec();
                let nodes = usize::try_from(dec.u32()?).map_err(|_| LgError::Format("path"))?;
                if nodes > MAX_PATH_NODES {
                    return Err(LgError::Format("path length"));
                }
                let mut path = Vec::with_capacity(nodes);
                for _ in 0..nodes {
                    path.push(dec.fixed()?);
                }
                Some(SlotView { index, slot_count, slot_root, ct, path })
            }
            _ => return Err(LgError::Format("slot flag")),
        };
        Ok(Self { seq, appended_at_ms, head, host_sig, header, ciphertext, token, kd_meta, slot })
    }
}

/// Body of the signed read request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReadRequest {
    pub from_seq: u64,
    pub limit: u32,
}

impl ReadRequest {
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut enc = Enc::default();
        enc.u64(self.from_seq).u32(self.limit);
        enc.finish()
    }

    /// # Errors
    /// Returns an error for a malformed body.
    pub fn decode(bytes: &[u8]) -> Result<Self, LgError> {
        let mut dec = Dec::new(bytes);
        let req = Self { from_seq: dec.u64()?, limit: dec.u32()? };
        dec.finish()?;
        Ok(req)
    }
}

/// Host answer to a read: group counters, the genesis, the admin chain and a page of entries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadReply {
    pub genesis: Vec<u8>,
    pub te: u32,
    pub key_epoch: u64,
    pub epoch_seq: u64,
    pub last_seq: u64,
    pub now_ms: u64,
    pub admin_chain: Vec<Vec<u8>>,
    pub entries: Vec<LogView>,
}

impl ReadReply {
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut enc = Enc::default();
        enc.var(&self.genesis)
            .u32(self.te)
            .u64(self.key_epoch)
            .u64(self.epoch_seq)
            .u64(self.last_seq)
            .u64(self.now_ms);
        enc.u32(u32::try_from(self.admin_chain.len()).unwrap_or(u32::MAX));
        for item in &self.admin_chain {
            enc.var(item);
        }
        enc.u32(u32::try_from(self.entries.len()).unwrap_or(u32::MAX));
        for entry in &self.entries {
            entry.encode_into(&mut enc);
        }
        enc.finish()
    }

    /// # Errors
    /// Returns an error for a malformed reply.
    pub fn decode(bytes: &[u8]) -> Result<Self, LgError> {
        let mut dec = Dec::new(bytes);
        let genesis = dec.var(MAX_BODY)?.to_vec();
        let te = dec.u32()?;
        let key_epoch = dec.u64()?;
        let epoch_seq = dec.u64()?;
        let last_seq = dec.u64()?;
        let now_ms = dec.u64()?;
        let chain = usize::try_from(dec.u32()?).map_err(|_| LgError::Format("chain"))?;
        if chain > MAX_ADMIN_CHAIN {
            return Err(LgError::Format("admin chain length"));
        }
        let mut admin_chain = Vec::with_capacity(chain);
        for _ in 0..chain {
            admin_chain.push(dec.var(MAX_BODY)?.to_vec());
        }
        let count = usize::try_from(dec.u32()?).map_err(|_| LgError::Format("entries"))?;
        if count > MAX_ENTRIES_PER_READ {
            return Err(LgError::Format("entry count"));
        }
        let mut entries = Vec::with_capacity(count);
        for _ in 0..count {
            entries.push(LogView::decode_from(&mut dec)?);
        }
        dec.finish()?;
        Ok(Self { genesis, te, key_epoch, epoch_seq, last_seq, now_ms, admin_chain, entries })
    }
}

/// Admin chain head: hash of the latest chain entry, or the group id (hash of the genesis) when the
/// chain is empty.
#[must_use]
pub fn admin_chain_head(gid: &[u8; 32], chain: &[Vec<u8>]) -> [u8; 32] {
    chain.last().map_or(*gid, |entry| *blake3::hash(entry).as_bytes())
}

// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Row layouts of the `lg_*` tables (deterministic binary, no serde).

use ramflux_crypto::large_group::{EntryHeader, LgReader as Dec, LgWriter as Enc};

use super::store::Refuse;

pub(super) const ROLE_MEMBER: u8 = 0;
pub(super) const ROLE_ADMIN: u8 = 1;
pub(super) const ROLE_OWNER: u8 = 2;
pub(super) const UNKEYED: u64 = u64::MAX;
const MAX_ROW: usize = 16 * 1024;

fn bad<T>(_: T) -> Refuse {
    "corrupt_row"
}

/// Group counters (`lg_state`, tag 0).
#[derive(Clone)]
pub(super) struct Meta {
    pub(super) genesis: Vec<u8>,
    pub(super) te: u32,
    pub(super) te_started_ms: u64,
    pub(super) last_roll_kind: u8,
    pub(super) key_epoch: u64,
    pub(super) epoch_seq: u64,
    pub(super) epoch_prev_seq: u64,
    pub(super) last_seq: u64,
    pub(super) last_head: [u8; 32],
    pub(super) last_appended_ms: u64,
    pub(super) join_pk: [u8; 32],
    pub(super) approval_on: bool,
    pub(super) spent_count: u64,
}

impl Meta {
    pub(super) fn encode(&self) -> Vec<u8> {
        let mut enc = Enc::default();
        enc.var(&self.genesis)
            .u32(self.te)
            .u64(self.te_started_ms)
            .u8(self.last_roll_kind)
            .u64(self.key_epoch)
            .u64(self.epoch_seq)
            .u64(self.epoch_prev_seq)
            .u64(self.last_seq)
            .fixed(&self.last_head)
            .u64(self.last_appended_ms)
            .fixed(&self.join_pk)
            .u8(u8::from(self.approval_on))
            .u64(self.spent_count);
        enc.finish()
    }

    pub(super) fn decode(bytes: &[u8]) -> Result<Self, Refuse> {
        let mut dec = Dec::new(bytes);
        let meta = Self {
            genesis: dec.var(MAX_ROW).map_err(bad)?.to_vec(),
            te: dec.u32().map_err(bad)?,
            te_started_ms: dec.u64().map_err(bad)?,
            last_roll_kind: dec.u8().map_err(bad)?,
            key_epoch: dec.u64().map_err(bad)?,
            epoch_seq: dec.u64().map_err(bad)?,
            epoch_prev_seq: dec.u64().map_err(bad)?,
            last_seq: dec.u64().map_err(bad)?,
            last_head: dec.fixed().map_err(bad)?,
            last_appended_ms: dec.u64().map_err(bad)?,
            join_pk: dec.fixed().map_err(bad)?,
            approval_on: dec.u8().map_err(bad)? == 1,
            spent_count: dec.u64().map_err(bad)?,
        };
        dec.finish().map_err(bad)?;
        Ok(meta)
    }
}

/// One pseudonym (`lg_pseudo`): role, state, join blob and issuance counters. No account data.
#[derive(Clone)]
pub(super) struct Pseudo {
    pub(super) role: u8,
    pub(super) active: bool,
    pub(super) joined_ms: u64,
    pub(super) keyed_epoch: u64,
    pub(super) blob: Vec<u8>,
    pub(super) batches: Vec<u64>,
    pub(super) free: Vec<u64>,
    pub(super) last_free_te: u32,
}

impl Pseudo {
    pub(super) fn encode(&self) -> Vec<u8> {
        let mut enc = Enc::default();
        enc.u8(self.role)
            .u8(u8::from(self.active))
            .u64(self.joined_ms)
            .u64(self.keyed_epoch)
            .var(&self.blob)
            .u32(self.last_free_te);
        for list in [&self.batches, &self.free] {
            enc.u32(u32::try_from(list.len()).unwrap_or(u32::MAX));
            for at in list {
                enc.u64(*at);
            }
        }
        enc.finish()
    }

    pub(super) fn decode(bytes: &[u8]) -> Result<Self, Refuse> {
        let mut dec = Dec::new(bytes);
        let role = dec.u8().map_err(bad)?;
        let active = dec.u8().map_err(bad)? == 1;
        let joined_ms = dec.u64().map_err(bad)?;
        let keyed_epoch = dec.u64().map_err(bad)?;
        let blob = dec.var(MAX_ROW).map_err(bad)?.to_vec();
        let last_free_te = dec.u32().map_err(bad)?;
        let mut lists = [Vec::new(), Vec::new()];
        for list in &mut lists {
            let count = usize::try_from(dec.u32().map_err(bad)?).map_err(bad)?;
            if count > 256 {
                return Err("corrupt_row");
            }
            for _ in 0..count {
                list.push(dec.u64().map_err(bad)?);
            }
        }
        dec.finish().map_err(bad)?;
        let [batches, free] = lists;
        Ok(Self { role, active, joined_ms, keyed_epoch, blob, batches, free, last_free_te })
    }
}

/// An invite (`lg_invite`).
pub(super) struct Invite {
    pub(super) pk: [u8; 32],
    pub(super) role: u8,
    pub(super) max_uses: u32,
    pub(super) uses: u32,
    pub(super) expires_ms: u64,
}

impl Invite {
    pub(super) fn encode(&self) -> Vec<u8> {
        let mut enc = Enc::default();
        enc.fixed(&self.pk).u8(self.role).u32(self.max_uses).u32(self.uses).u64(self.expires_ms);
        enc.finish()
    }

    pub(super) fn decode(bytes: &[u8]) -> Result<Self, Refuse> {
        let mut dec = Dec::new(bytes);
        let invite = Self {
            pk: dec.fixed().map_err(bad)?,
            role: dec.u8().map_err(bad)?,
            max_uses: dec.u32().map_err(bad)?,
            uses: dec.u32().map_err(bad)?,
            expires_ms: dec.u64().map_err(bad)?,
        };
        dec.finish().map_err(bad)?;
        Ok(invite)
    }
}

/// One log row (`lg_log`): the host-visible header and the opaque ciphertext. It has no `P` field.
pub(super) struct LogRow {
    pub(super) header: EntryHeader,
    pub(super) ciphertext: Vec<u8>,
    pub(super) token: Vec<u8>,
    pub(super) kd_meta: Vec<u8>,
    pub(super) appended_ms: u64,
    pub(super) head: [u8; 32],
    pub(super) sig: [u8; 64],
    pub(super) slot_root: [u8; 32],
    pub(super) slot_count: u32,
}

impl LogRow {
    pub(super) fn encode(&self) -> Vec<u8> {
        let mut enc = Enc::default();
        ramflux_crypto::large_group::encode_header(&mut enc, &self.header);
        enc.var(&self.ciphertext)
            .var(&self.token)
            .var(&self.kd_meta)
            .u64(self.appended_ms)
            .fixed(&self.head)
            .fixed(&self.sig)
            .fixed(&self.slot_root)
            .u32(self.slot_count);
        enc.finish()
    }

    pub(super) fn decode(bytes: &[u8]) -> Result<Self, Refuse> {
        let mut dec = Dec::new(bytes);
        let row = Self {
            header: ramflux_crypto::large_group::decode_header(&mut dec).map_err(bad)?,
            ciphertext: dec.var(MAX_ROW).map_err(bad)?.to_vec(),
            token: dec.var(MAX_ROW).map_err(bad)?.to_vec(),
            kd_meta: dec.var(MAX_ROW).map_err(bad)?.to_vec(),
            appended_ms: dec.u64().map_err(bad)?,
            head: dec.fixed().map_err(bad)?,
            sig: dec.fixed().map_err(bad)?,
            slot_root: dec.fixed().map_err(bad)?,
            slot_count: dec.u32().map_err(bad)?,
        };
        dec.finish().map_err(bad)?;
        Ok(row)
    }
}

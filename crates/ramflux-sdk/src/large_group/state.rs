// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Per-group client state. The durable part is stored base64url under the account checkpoint
//! `lg.state.<gid>` (account DB, encrypted); tokens, the roll window and the provisional key live
//! in process memory only (a restart refills tokens and re-verifies a provisional key).

use std::collections::HashMap;
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{LazyLock, Mutex, PoisonError};

use ed25519_dalek::SigningKey;
use ramflux_crypto::large_group::{
    EpochKey, LgReader as Dec, LgWriter as Enc, ProvisionalKey, RollWindow, TokenSecret,
};

use super::{lg_err, lg_msg};
use crate::SdkError;

pub(crate) const ROLE_MEMBER: u8 = 0;
pub(crate) const ROLE_ADMIN: u8 = 1;
pub(crate) const ROLE_OWNER: u8 = 2;
const STATE_DOMAIN: &[u8] = b"rf-lg-client-state-v1";
const MAX_WARNINGS: usize = 32;
const MAX_KEYS: usize = 64;

static CLOCK_OFFSET_MS: AtomicI64 = AtomicI64::new(0);

/// Debug clock offset (hidden `debug.lg.clock`); real runs only.
pub(crate) fn set_clock_offset_ms(offset: i64) {
    CLOCK_OFFSET_MS.store(offset, Ordering::Relaxed);
}

pub(crate) fn now_ms() -> u64 {
    let wall = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX));
    wall.saturating_add_signed(CLOCK_OFFSET_MS.load(Ordering::Relaxed))
}

pub(crate) fn pub_of(seed: &[u8; 32]) -> [u8; 32] {
    SigningKey::from_bytes(seed).verifying_key().to_bytes()
}

/// Durable client state of one group.
pub(crate) struct LgState {
    pub gid: [u8; 32],
    pub genesis: Vec<u8>,
    pub p_seed: [u8; 32],
    pub recv_sk: [u8; 32],
    pub dev_seed: [u8; 32],
    pub role: u8,
    pub join_sk: Option<[u8; 32]>,
    pub keyed: bool,
    pub cur_epoch: u64,
    pub epoch_seq: u64,
    pub keys: Vec<(u64, [u8; 32])>,
    pub cursor: u64,
    pub last_head: [u8; 32],
    pub last_sig: [u8; 64],
    pub last_appended_ms: u64,
    pub te: u32,
    pub roll_a_ms: u64,
    pub roll_u_ms: u64,
    pub warnings: Vec<String>,
}

impl LgState {
    pub(crate) fn key_for(&self, epoch: u64) -> Option<EpochKey> {
        self.keys.iter().find(|(e, _)| *e == epoch).map(|(_, k)| EpochKey::from_bytes(*k))
    }

    pub(crate) fn warn(&mut self, message: &str) {
        if self.warnings.len() >= MAX_WARNINGS {
            self.warnings.remove(0);
        }
        self.warnings.push(message.to_owned());
    }

    pub(crate) fn encode(&self) -> String {
        let mut enc = Enc::new(STATE_DOMAIN);
        enc.fixed(&self.gid).var(&self.genesis).fixed(&self.p_seed).fixed(&self.recv_sk);
        enc.fixed(&self.dev_seed).u8(self.role);
        match &self.join_sk {
            Some(sk) => enc.u8(1).fixed(sk),
            None => enc.u8(0),
        };
        enc.u8(u8::from(self.keyed)).u64(self.cur_epoch).u64(self.epoch_seq);
        enc.u32(u32::try_from(self.keys.len()).unwrap_or(0));
        for (epoch, key) in &self.keys {
            enc.u64(*epoch).fixed(key);
        }
        enc.u64(self.cursor).fixed(&self.last_head).fixed(&self.last_sig);
        enc.u64(self.last_appended_ms).u32(self.te).u64(self.roll_a_ms).u64(self.roll_u_ms);
        enc.u32(u32::try_from(self.warnings.len()).unwrap_or(0));
        for warning in &self.warnings {
            enc.var(warning.as_bytes());
        }
        ramflux_protocol::encode_base64url(enc.finish())
    }

    pub(crate) fn decode(text: &str) -> Result<Self, SdkError> {
        let bytes =
            ramflux_protocol::decode_base64url(text).map_err(|_| lg_msg("state encoding"))?;
        let mut dec = Dec::new(&bytes);
        if dec.var(STATE_DOMAIN.len()).map_err(lg_err)? != STATE_DOMAIN {
            return Err(lg_msg("state domain"));
        }
        let mut state = Self {
            gid: dec.fixed().map_err(lg_err)?,
            genesis: dec.var(4096).map_err(lg_err)?.to_vec(),
            p_seed: dec.fixed().map_err(lg_err)?,
            recv_sk: dec.fixed().map_err(lg_err)?,
            dev_seed: dec.fixed().map_err(lg_err)?,
            role: dec.u8().map_err(lg_err)?,
            join_sk: None,
            keyed: false,
            cur_epoch: 0,
            epoch_seq: 0,
            keys: Vec::new(),
            cursor: 0,
            last_head: [0; 32],
            last_sig: [0; 64],
            last_appended_ms: 0,
            te: 0,
            roll_a_ms: 0,
            roll_u_ms: 0,
            warnings: Vec::new(),
        };
        if dec.u8().map_err(lg_err)? == 1 {
            state.join_sk = Some(dec.fixed().map_err(lg_err)?);
        }
        state.keyed = dec.u8().map_err(lg_err)? == 1;
        state.cur_epoch = dec.u64().map_err(lg_err)?;
        state.epoch_seq = dec.u64().map_err(lg_err)?;
        let count = usize::try_from(dec.u32().map_err(lg_err)?).unwrap_or(usize::MAX);
        if count > MAX_KEYS {
            return Err(lg_msg("state key count"));
        }
        for _ in 0..count {
            state.keys.push((dec.u64().map_err(lg_err)?, dec.fixed().map_err(lg_err)?));
        }
        state.cursor = dec.u64().map_err(lg_err)?;
        state.last_head = dec.fixed().map_err(lg_err)?;
        state.last_sig = dec.fixed().map_err(lg_err)?;
        state.last_appended_ms = dec.u64().map_err(lg_err)?;
        state.te = dec.u32().map_err(lg_err)?;
        state.roll_a_ms = dec.u64().map_err(lg_err)?;
        state.roll_u_ms = dec.u64().map_err(lg_err)?;
        let warnings = usize::try_from(dec.u32().map_err(lg_err)?).unwrap_or(usize::MAX);
        if warnings > MAX_WARNINGS {
            return Err(lg_msg("state warning count"));
        }
        for _ in 0..warnings {
            let raw = dec.var(256).map_err(lg_err)?;
            state.warnings.push(String::from_utf8_lossy(raw).into_owned());
        }
        dec.finish().map_err(lg_err)?;
        Ok(state)
    }
}

/// A spendable token and the time it may first be spent (design 2.3 settling delay).
pub(crate) struct HeldToken {
    pub secret: TokenSecret,
    pub settle_at_ms: u64,
}

/// In-memory runtime of one group on one account.
pub(crate) struct Runtime {
    pub st: LgState,
    pub tokens: Vec<HeldToken>,
    pub rolls: RollWindow,
    pub prov: Option<(u64, ProvisionalKey)>,
    pub refill_due_ms: u64,
    pub heads: HashMap<u64, [u8; 32]>,
    pub admin_chain: Vec<Vec<u8>>,
    pub equivocation: bool,
    /// Roll `A` and the per-epoch uniform draw, by `te`.
    pub epochs: HashMap<u32, (u64, u64)>,
}

impl Runtime {
    pub(crate) fn new(st: LgState) -> Self {
        Self {
            st,
            tokens: Vec::new(),
            rolls: RollWindow::new(),
            prov: None,
            refill_due_ms: 0,
            heads: HashMap::new(),
            admin_chain: Vec::new(),
            equivocation: false,
            epochs: HashMap::new(),
        }
    }
}

static RUNTIMES: LazyLock<Mutex<HashMap<String, Runtime>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

pub(crate) fn runtime_key(account_id: &str, gid: &[u8; 32]) -> String {
    format!("{account_id}/{}", ramflux_protocol::encode_base64url(gid))
}

pub(crate) fn checkpoint_name(gid: &[u8; 32]) -> String {
    format!("lg.state.{}", ramflux_protocol::encode_base64url(gid))
}

/// Takes the runtime out of the process map (the caller puts it back with [`put_runtime`]).
pub(crate) fn take_runtime(key: &str) -> Option<Runtime> {
    RUNTIMES.lock().unwrap_or_else(PoisonError::into_inner).remove(key)
}

pub(crate) fn put_runtime(key: String, runtime: Runtime) {
    RUNTIMES.lock().unwrap_or_else(PoisonError::into_inner).insert(key, runtime);
}

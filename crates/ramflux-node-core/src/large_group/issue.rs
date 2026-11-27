// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Posting-token issuance: fixed batches of 20 under per-pseudonym quotas (design 2.3).

use ramflux_crypto::large_group::{
    BATCH_SIZE, LgReader as Dec, LgWriter as Enc, SignedReq, token_info,
};

use super::host::Op;
use super::store::{Refuse, STATE, key};

const TAG_REPLY: u8 = 3;
const DAY_MS: u64 = 24 * 60 * 60 * 1_000;
const QUOTA_BATCHES: usize = 25;
const FIRST_DAY_BATCHES: usize = 1;
const FREE_BATCHES_PER_DAY: usize = 10;

fn bad<T>(_: T) -> Refuse {
    "bad_request"
}

impl Op<'_> {
    pub(super) fn issue(&mut self, body: &[u8]) -> Result<Vec<u8>, Refuse> {
        let req = SignedReq::decode(body).map_err(bad)?;
        req.verify("issue").map_err(|_| "bad_signature")?;
        let gid = req.gid;
        self.maybe_daily_roll(&gid)?;
        let meta = self.meta(&gid)?;
        let mut row = self.pseudo(&gid, &req.p)?.ok_or("not_found")?;
        if !row.active {
            return Err("pending");
        }
        let cache_key = key(&[&gid, &[TAG_REPLY], blake3::hash(body).as_bytes()]);
        if let Some(cached) = self.tx.get(STATE, &cache_key)? {
            return Ok(cached);
        }
        let mut dec = Dec::new(&req.body);
        let te = dec.u32().map_err(bad)?;
        let _req_id: [u8; 16] = dec.fixed().map_err(bad)?;
        let count = usize::try_from(dec.u32().map_err(bad)?).map_err(bad)?;
        if count != BATCH_SIZE {
            return Err("bad_request");
        }
        let mut blinded = Vec::with_capacity(count);
        for _ in 0..count {
            blinded.push(dec.fixed::<32>().map_err(bad)?);
        }
        dec.finish().map_err(bad)?;
        if te != meta.te {
            return Err("token_epoch_stale");
        }
        let now = self.now;
        row.batches.retain(|at| now.saturating_sub(*at) < DAY_MS);
        row.free.retain(|at| now.saturating_sub(*at) < DAY_MS);
        let first_day = now.saturating_sub(row.joined_ms) < DAY_MS;
        let quota = if first_day { FIRST_DAY_BATCHES } else { QUOTA_BATCHES };
        if row.last_free_te < meta.te && row.free.len() < FREE_BATCHES_PER_DAY {
            row.last_free_te = meta.te;
            row.free.push(now);
        } else if row.batches.len() >= quota {
            return Err("quota");
        } else {
            row.batches.push(now);
        }
        let keys = self.keys(&gid)?;
        let issued =
            keys.root.issue_batch(&blinded, &token_info(&gid, te)).map_err(|_| "internal")?;
        let mut reply = Enc::default();
        for element in &issued.evaluated {
            reply.fixed(element);
        }
        reply.fixed(&issued.proof);
        let reply = reply.finish();
        self.tx.put(STATE, &cache_key, &reply)?;
        self.put_pseudo(&gid, &req.p, &row)?;
        Ok(reply)
    }
}

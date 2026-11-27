// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Hidden fault-injection requests (clock, forced rolls, held reads, alternate heads, wrong slots,
//! garbage key deliveries). They exist only when the node started with `RAMFLUX_LG_DEBUG=1`.

use ramflux_crypto::large_group::{
    EntryHeader, EntryKind, KeyDelivery, LgReader as Dec, LgWriter as Enc, TAG_SLOTS,
    host_head_sign, kd_meta_encode, next_head, random_array,
};

use super::host::{Hold, Op};
use super::store::Refuse;

fn bad<T>(_: T) -> Refuse {
    "bad_request"
}

impl Op<'_> {
    pub(super) fn debug_op(&mut self, op: &str, body: &[u8]) -> Result<Vec<u8>, Refuse> {
        if !self.debug {
            return Err("unknown_op");
        }
        let mut dec = Dec::new(body);
        match op {
            "debug_clock" => {
                let bits = dec.u64().map_err(bad)?;
                self.mem.clock_offset_ms = i64::from_be_bytes(bits.to_be_bytes());
            }
            "debug_roll" => {
                let gid: [u8; 32] = dec.fixed().map_err(bad)?;
                let reason = dec.u8().map_err(bad)?;
                self.write_roll(&gid, reason, &[])?;
            }
            "debug_hold" => {
                let hold = Hold {
                    except: dec.fixed().map_err(bad)?,
                    from_seq: dec.u64().map_err(bad)?,
                    until_ms: dec.u64().map_err(bad)?,
                };
                self.mem.faults.hold = Some(hold);
            }
            "debug_appended" => self.mem.faults.forced_appended_ms = Some(dec.u64().map_err(bad)?),
            "debug_wrong_slot" => self.mem.faults.wrong_slot = Some(dec.fixed().map_err(bad)?),
            "debug_alt_head" => return self.alt_head(&mut dec),
            "debug_garbage_w" => return self.garbage_w(&mut dec),
            _ => return Err("unknown_op"),
        }
        Ok(Vec::new())
    }

    /// A second host-signed head for position `n` (a transferable equivocation proof when used).
    fn alt_head(&mut self, dec: &mut Dec<'_>) -> Result<Vec<u8>, Refuse> {
        let gid: [u8; 32] = dec.fixed().map_err(bad)?;
        let n = dec.u64().map_err(bad)?;
        let meta = self.meta(&gid)?;
        let salt = random_array::<32>().map_err(|_| "internal")?;
        let alt = next_head(&meta.last_head, n, &salt);
        let keys = self.keys(&gid)?;
        let sig = host_head_sign(&keys.key.head_signing_seed(), &gid, n, &alt);
        let mut out = Enc::default();
        out.fixed(&alt).fixed(&sig);
        Ok(out.finish())
    }

    /// A host-minted `W'` with garbage ciphertext at `e+1`: only the host holds the token root key.
    fn garbage_w(&mut self, dec: &mut Dec<'_>) -> Result<Vec<u8>, Refuse> {
        let gid: [u8; 32] = dec.fixed().map_err(bad)?;
        let mut meta = self.meta(&gid)?;
        let joiner = random_array::<32>().map_err(|_| "internal")?;
        let kd = KeyDelivery {
            joiners: vec![joiner],
            body_bytes: random_array::<32>().map_err(|_| "internal")?.to_vec(),
            ..KeyDelivery::default()
        };
        let header = EntryHeader {
            kind: EntryKind::KEY_W_PRIME,
            post_id: random_array::<16>().map_err(|_| "internal")?,
            key_epoch: meta.key_epoch.saturating_add(1),
            bucket: 256,
            del_secret_hash: [0_u8; 32],
            tags: [[0_u8; 16]; TAG_SLOTS],
        };
        let mut junk = vec![0_u8; 256];
        getrandom_fill(&mut junk)?;
        let (seq, _) = self.append_row(
            &gid,
            &mut meta,
            header,
            (junk, Vec::new(), kd_meta_encode(&kd)),
            (&[0; 32], 0),
        )?;
        meta.epoch_prev_seq = meta.epoch_seq;
        meta.epoch_seq = seq;
        meta.key_epoch = meta.key_epoch.saturating_add(1);
        self.put_meta(&gid, &meta)?;
        Ok(seq.to_be_bytes().to_vec())
    }
}

fn getrandom_fill(buf: &mut [u8]) -> Result<(), Refuse> {
    for chunk in buf.chunks_mut(32) {
        let rand = random_array::<32>().map_err(|_| "internal")?;
        for (dst, src) in chunk.iter_mut().zip(rand.iter()) {
            *dst = *src;
        }
    }
    Ok(())
}

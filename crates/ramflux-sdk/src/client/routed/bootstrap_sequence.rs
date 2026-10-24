// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Durable sender allocation and authenticated receive high-water marks survive secret erasure.
use super::{RamfluxClient, SdkDmX3dhHeader, SdkError, invalid};
const MAX_SEQUENCE: u64 = 9_007_199_254_740_991;
pub(crate) fn bootstrap_aad(
    aad: &[u8],
    sequence: Option<u64>,
    version: Option<u32>,
) -> Result<Vec<u8>, SdkError> {
    if !matches!(version, None | Some(2)) {
        return Err(invalid("unsupported bootstrap ordering version"));
    }
    match sequence {
        Some(sequence) if (1..=MAX_SEQUENCE).contains(&sequence) => {
            Ok(ramflux_protocol::canonical_json_bytes(&(
                if version == Some(2) {
                    "ramflux.sdk.bootstrap.hlc.v2"
                } else {
                    "ramflux.sdk.bootstrap.sequence.v1"
                },
                aad,
                sequence,
            ))?)
        }
        Some(_) => Err(invalid("invalid bootstrap sequence")),
        None => Ok(aad.to_vec()),
    }
}
impl RamfluxClient {
    pub(crate) fn allocate_bootstrap_sequence(&self, local: &str) -> Result<u64, SdkError> {
        let db = self.account_db()?;
        db.write_transaction(|| {
            let key = format!("dm-pair/bootstrap-sequence/{local}");
            let sequence = db
                .load_actor_state::<u64>(&key)?
                .unwrap_or(0)
                .checked_add(1)
                .map(|next| next.max(wall_clock_millis()))
                .filter(|n| *n <= MAX_SEQUENCE)
                .ok_or_else(|| invalid("bootstrap sequence exhausted"))?;
            db.persist_actor_state(&key, &sequence)?;
            Ok(sequence)
        })
    }
    pub(super) fn check_bootstrap_sequence(
        &self,
        local: &str,
        remote: &str,
        header: &SdkDmX3dhHeader,
    ) -> Result<u64, SdkError> {
        if header.bootstrap_ordering_version != Some(2) {
            return Err(SdkError::PairRecoveryRequired);
        }
        let sequence = header
            .bootstrap_sequence
            .filter(|n| (1..=MAX_SEQUENCE).contains(n))
            .ok_or(SdkError::PairRecoveryRequired)?;
        let high = self
            .account_db()?
            .load_actor_state::<u64>(&self.bootstrap_high_water_key(local, remote)?)?
            .unwrap_or(0);
        if sequence <= high {
            return Err(SdkError::PairRecoveryRequired);
        }
        Ok(sequence)
    }
    pub(super) fn bootstrap_high_water_key(
        &self,
        local: &str,
        remote: &str,
    ) -> Result<String, SdkError> {
        let remote = self.device_reference(remote)?;
        let remote = remote.as_str();
        let record = self.trusted_device(remote)?;
        let principal = record["principal_id"]
            .as_str()
            .ok_or_else(|| invalid("bootstrap principal missing"))?;
        let commitment = record["principal_commitment"]
            .as_str()
            .ok_or_else(|| invalid("bootstrap commitment missing"))?;
        let pair = self.pair_key(local, remote)?;
        let hash = ramflux_protocol::hash_base64url(
            "ramflux.sdk.bootstrap.owner.v2",
            &ramflux_protocol::canonical_json_bytes(&(principal, commitment, remote))?,
        );
        Ok(format!("{pair}/bootstrap-high-water/{hash}"))
    }
    pub(super) fn bootstrap_high_water(&self, local: &str, remote: &str) -> Result<u64, SdkError> {
        Ok(self
            .account_db()?
            .load_actor_state(&self.bootstrap_high_water_key(local, remote)?)?
            .unwrap_or(0))
    }
    /// Called only after authenticated decryption, in the same transaction as new session commit.
    pub(super) fn commit_bootstrap_sequence(
        &self,
        local: &str,
        remote: &str,
        header: Option<&SdkDmX3dhHeader>,
        id: &str,
    ) -> Result<(), SdkError> {
        let db = self.account_db()?;
        if db.actor_state_exists(&format!("dm-pair/session/{id}"))? {
            return Ok(());
        }
        let header = header.ok_or_else(|| invalid("new session has no sequenced bootstrap"))?;
        let sequence = self.check_bootstrap_sequence(local, remote, header)?;
        db.persist_actor_state(&self.bootstrap_high_water_key(local, remote)?, &sequence)?;
        Ok(())
    }
}

fn wall_clock_millis() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .and_then(|time| u64::try_from(time.as_millis()).ok())
        .unwrap_or(0)
}

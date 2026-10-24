// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Durable sender allocation and authenticated receive high-water marks survive secret erasure.
use super::session::pair_key;
use super::{RamfluxClient, SdkDmX3dhHeader, SdkError, invalid};
const MAX_SEQUENCE: u64 = 9_007_199_254_740_991;
pub(crate) fn bootstrap_aad(aad: &[u8], sequence: Option<u64>) -> Result<Vec<u8>, SdkError> {
    match sequence {
        Some(sequence) if (1..=MAX_SEQUENCE).contains(&sequence) => {
            Ok(ramflux_protocol::canonical_json_bytes(&(
                "ramflux.sdk.bootstrap.sequence.v1",
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
        let sequence = header
            .bootstrap_sequence
            .filter(|n| (1..=MAX_SEQUENCE).contains(n))
            .ok_or_else(|| invalid("unsequenced bootstrap requires manual recovery"))?;
        let high = self
            .account_db()?
            .load_actor_state::<u64>(&format!("{}/bootstrap-high-water", pair_key(local, remote)?))?
            .unwrap_or(0);
        if sequence <= high {
            return Err(SdkError::InboundRejected("bootstrap sequence is retired".into()));
        }
        Ok(sequence)
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
        db.persist_actor_state(
            &format!("{}/bootstrap-high-water", pair_key(local, remote)?),
            &sequence,
        )?;
        Ok(())
    }
}

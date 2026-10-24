// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Bounded, durable observations of foreign root authority, oldest change evicted first.
use crate::NodeCoreError;
use ramflux_protocol::SignedDeviceSetRecord;
use serde::{Deserialize, Deserializer, Serialize};
use std::collections::VecDeque;

pub(crate) const FOREIGN_HEAD_LIMIT: usize = 1024;
pub(crate) const REGISTRATION_PROOF_LIMIT: usize = 4096;

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub(crate) struct ForeignDeviceHeads {
    #[serde(deserialize_with = "load_heads")]
    records: VecDeque<SignedDeviceSetRecord>,
}
fn load_heads<'de, D: Deserializer<'de>>(
    de: D,
) -> Result<VecDeque<SignedDeviceSetRecord>, D::Error> {
    let mut records = VecDeque::deserialize(de)?;
    while records.len() > FOREIGN_HEAD_LIMIT {
        records.pop_front();
    }
    Ok(records)
}
pub(crate) fn load_proofs<'de, D: Deserializer<'de>>(de: D) -> Result<VecDeque<String>, D::Error> {
    // Old snapshots encoded a sorted set, so their original observation order is unavailable.
    // Preserve that deterministic order once; new observations are strictly FIFO.
    let mut proofs = VecDeque::deserialize(de)?;
    while proofs.len() > REGISTRATION_PROOF_LIMIT {
        proofs.pop_front();
    }
    Ok(proofs)
}
impl ForeignDeviceHeads {
    pub(crate) fn check(&self, next: &SignedDeviceSetRecord) -> Result<bool, NodeCoreError> {
        if let Some(old) =
            self.records.iter().find(|r| r.principal_commitment == next.principal_commitment)
        {
            ramflux_crypto::validate_device_set_transition(old, next)
                .map_err(|e| NodeCoreError::ItestHttp(e.to_string()))?;
            return Ok(old != next);
        }
        Ok(true)
    }
    // The caller has already verified the root signature and checked monotonicity.
    pub(crate) fn retain(&mut self, next: SignedDeviceSetRecord) {
        self.records.retain(|old| old.principal_commitment != next.principal_commitment);
        self.records.push_back(next);
        while self.records.len() > FOREIGN_HEAD_LIMIT {
            self.records.pop_front();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn heads_are_bounded_and_preserve_oldest_eviction_after_restart()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut heads = ForeignDeviceHeads::default();
        let root = ramflux_crypto::create_identity_root("test", [9; 32]);
        let record = ramflux_crypto::sign_device_set(
            &root,
            ramflux_crypto::DeviceSetSigningInput {
                principal_kind: ramflux_protocol::PrincipalKind::Human,
                device_set_epoch: 1,
                devices: vec![ramflux_protocol::SignedDeviceSetEntry {
                    device_id: "device".into(),
                    device_epoch: 1,
                    signing_key_commitment: ramflux_crypto::blake3_256_base64url("test", b"sign"),
                    agreement_key_commitment: ramflux_crypto::blake3_256_base64url(
                        "test",
                        b"agreement",
                    ),
                    status: ramflux_protocol::DeviceSetStatus::Active,
                    revoked_at: None,
                }],
            },
        )?;
        for index in 0..=FOREIGN_HEAD_LIMIT {
            let mut next = record.clone();
            next.principal_commitment = format!("root-{}", FOREIGN_HEAD_LIMIT - index);
            heads.retain(next);
        }
        assert_eq!(heads.records.len(), FOREIGN_HEAD_LIMIT);
        assert_eq!(heads.records.front().ok_or("head")?.principal_commitment, "root-1023");
        let mut reopened: ForeignDeviceHeads =
            serde_json::from_slice(&serde_json::to_vec(&heads)?)?;
        let mut next = record;
        next.principal_commitment = "new".into();
        reopened.retain(next);
        assert_eq!(reopened.records.len(), FOREIGN_HEAD_LIMIT);
        assert_eq!(reopened.records.front().ok_or("head")?.principal_commitment, "root-1022");
        Ok(())
    }
    #[test]
    fn legacy_proof_snapshots_are_bounded() -> Result<(), Box<dyn std::error::Error>> {
        #[derive(Deserialize)]
        struct Snapshot {
            #[serde(deserialize_with = "load_proofs")]
            proofs: VecDeque<String>,
        }
        let input = serde_json::json!({"proofs":(0..REGISTRATION_PROOF_LIMIT+3).map(|i|i.to_string()).collect::<Vec<_>>()});
        let snapshot: Snapshot = serde_json::from_value(input)?;
        assert_eq!(snapshot.proofs.len(), REGISTRATION_PROOF_LIMIT);
        assert_eq!(snapshot.proofs.front().map(String::as_str), Some("3"));
        Ok(())
    }
}

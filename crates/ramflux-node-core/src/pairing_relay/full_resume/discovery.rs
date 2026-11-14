// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! A3 proposal pairing stays inside the original pending4 / metadata64KiB / ten-second owner.
use super::{FullNativeAdmission, FullResumeServer, Pending, b32, crypto, wire};
use crate::pairing_relay::PairingRelayError;
use ramflux_crypto::{custody::pairing::verify_full_data_lease, random_32};
use ramflux_protocol::{
    custody::{
        Envelope,
        pairing::{
            PairingWire,
            full_transfer::{
                lease::{BranchKeys, DataLease, ResumeProof},
                relay::{DiscoveryKeys, FullDiscovery, HelloFull, PollFullDiscovery},
            },
        },
    },
    encode_base64url,
};
impl FullResumeServer {
    pub(in crate::pairing_relay) fn verify_discovery_lease(
        lease: &Envelope<DataLease>,
        admission: &FullNativeAdmission<'_>,
        node_key: &str,
        wall: u64,
    ) -> Result<(), PairingRelayError> {
        if admission.node().envelope().body.node_signing_public_key != node_key {
            return Err(PairingRelayError::WrongContext);
        }
        verify_full_data_lease(lease, &lease.body.grant, admission.node(), wall)
            .map_err(|error| crypto(&error))?;
        admission.verify(&lease.body.grant, wall)
    }
    pub(in crate::pairing_relay) fn has_pending(&self, lease_id: &str) -> bool {
        self.pending.iter().any(|item| item.lease.body.lease_id == lease_id)
    }
    pub(in crate::pairing_relay) fn hello(
        &mut self,
        hello: &HelloFull,
        admission: &FullNativeAdmission<'_>,
    ) -> Result<FullDiscovery, PairingRelayError> {
        hello.validate().map_err(|error| wire(&error))?;
        self.prune()?;
        let wall = self.clock.wall_unix_secs()?;
        let mono = self.clock.monotonic_ms();
        Self::verify_discovery_lease(&hello.lease, admission, &self.node_key, wall)?;
        if admission.node().envelope().body.node_id != self.node_id {
            return Err(PairingRelayError::WrongContext);
        }
        if let Some(ready) =
            self.ready.iter().find(|item| item.lease.body.lease_id == hello.lease.body.lease_id)
        {
            return Err(if ready.template.epoch == hello.epoch {
                PairingRelayError::Replay
            } else {
                PairingRelayError::busy(mono)
            });
        }
        if let Some(index) = self
            .pending
            .iter()
            .position(|item| item.lease.body.lease_id == hello.lease.body.lease_id)
        {
            let item = &mut self.pending[index];
            if item.lease != hello.lease || item.epoch != hello.epoch {
                return Err(PairingRelayError::Replay);
            }
            match hello.role.as_str() {
                "initiator" => {
                    if item.source_key != hello.hpke_key {
                        return Err(PairingRelayError::Replay);
                    }
                }
                "responder" => {
                    if let Some(key) = &item.destination_key {
                        if key != &hello.hpke_key {
                            return Err(PairingRelayError::Replay);
                        }
                    } else {
                        let keys = BranchKeys {
                            source: item.source_key.clone(),
                            destination: hello.hpke_key.clone(),
                        };
                        keys.validate().map_err(|error| wire(&error))?;
                        item.template = Some(ResumeProof {
                            schema: "ramflux.pairing.full_transfer.resume_proof.v1".into(),
                            version: 1,
                            lease_id: item.lease.body.lease_id.clone(),
                            boot_id: self.boot_id.clone(),
                            nonce: item.nonce.clone(),
                            role: "initiator".into(),
                            hpke_keys: keys,
                            epoch: item.epoch.clone(),
                        });
                        item.destination_key = Some(hello.hpke_key.clone());
                    }
                }
                _ => return Err(PairingRelayError::WrongRole),
            }
            return Self::discovery(item, mono);
        }
        if hello.role != "initiator" {
            return Err(PairingRelayError::WrongContext);
        }
        self.check_cooldown(&hello.lease.body.grant.source_ref.account_anchor, mono)?;
        if self.pending.len() == 4
            || self.pending.iter().any(|item| {
                item.lease.body.grant.source_ref.account_anchor
                    == hello.lease.body.grant.source_ref.account_anchor
            })
        {
            return Err(PairingRelayError::busy(mono));
        }
        b32(&hello.hpke_key)?;
        let metadata = self.budget.reserve_metadata(8192, mono)?;
        let pending = Pending {
            lease: hello.lease.clone(),
            template: None,
            source_key: hello.hpke_key.clone(),
            destination_key: None,
            epoch: hello.epoch.clone(),
            nonce: encode_base64url(
                random_32().map_err(|_| PairingRelayError::invalid("entropy"))?,
            ),
            discovery_credit: [1000; 2],
            discovery_updated: [mono; 2],
            proofs: [None, None],
            deadline: mono.saturating_add(10_000),
            _metadata: metadata,
        };
        let reply = Self::discovery(&pending, mono)?;
        self.pending.push(pending);
        Ok(reply)
    }
    fn discovery(pending: &Pending, mono: u64) -> Result<FullDiscovery, PairingRelayError> {
        let reply = FullDiscovery {
            epoch: pending.epoch.clone(),
            expires_in_ms: ramflux_protocol::custody::pairing::full_transfer::U64(
                pending.deadline.saturating_sub(mono),
            ),
            hpke_keys: DiscoveryKeys {
                source: pending.source_key.clone(),
                destination: pending.destination_key.clone(),
            },
            kind: "full_discovery".into(),
            lease_id: pending.lease.body.lease_id.clone(),
            profile: ramflux_protocol::custody::pairing::full_transfer::PROFILE.into(),
            template: pending.template.clone(),
        };
        reply.validate().map_err(|error| wire(&error))?;
        Ok(reply)
    }
    pub(in crate::pairing_relay) fn poll_discovery(
        &mut self,
        poll: &PollFullDiscovery,
        admission: &FullNativeAdmission<'_>,
    ) -> Result<FullDiscovery, PairingRelayError> {
        poll.validate().map_err(|error| wire(&error))?;
        self.prune()?;
        Self::verify_discovery_lease(
            &poll.lease,
            admission,
            &self.node_key,
            self.clock.wall_unix_secs()?,
        )?;
        let item = self
            .pending
            .iter_mut()
            .find(|item| item.lease.body.lease_id == poll.lease.body.lease_id)
            .ok_or(PairingRelayError::NotFound)?;
        if item.lease != poll.lease {
            return Err(PairingRelayError::Replay);
        }
        let mono = self.clock.monotonic_ms();
        let signer = usize::from(poll.role != "initiator");
        let credit = item.discovery_credit[signer]
            .saturating_add(mono.saturating_sub(item.discovery_updated[signer]))
            .min(1000);
        if credit < 500 {
            return Err(PairingRelayError::busy(mono));
        }
        item.discovery_credit[signer] = credit - 500;
        item.discovery_updated[signer] = item.discovery_updated[signer].max(mono);
        Self::discovery(item, mono)
    }
}

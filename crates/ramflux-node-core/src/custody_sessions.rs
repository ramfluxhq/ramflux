// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Process-local, bounded leases. Restart loses every challenge/session; none is backed up.

use ramflux_protocol::custody::{
    BindingMode, BranchChallenge, CustodyRefusal, CustodySession, DeviceRef,
};
use std::{
    collections::{BTreeMap, BTreeSet},
    time::{Duration, Instant},
};

const GLOBAL_LIMIT: usize = 4096;
const SOURCE_LIMIT: usize = 64;
const REQUEST_LIMIT: usize = 256;
const CHALLENGE_SECONDS: u64 = 300;
const RETAIN_SECONDS: u64 = 600;

fn random() -> Result<String, CustodyRefusal> {
    ramflux_crypto::random_32()
        .map(ramflux_protocol::encode_base64url)
        .map_err(|_| CustodyRefusal::PersistenceUnavailable)
}
pub(crate) struct ChallengeIntent {
    pub device: DeviceRef,
    pub action_hash: String,
    pub holder: String,
    pub source: String,
    pub audience: String,
    pub mode: BindingMode,
}
#[derive(Clone)]
pub(crate) struct ChallengeLease {
    pub challenge: BranchChallenge,
    pub device: DeviceRef,
    pub action_hash: String,
    pub holder: String,
    source: String,
    deadline: Instant,
    retain_until: Instant,
    consumed: bool,
}
#[derive(Clone)]
pub(crate) struct SessionLease {
    pub session: CustodySession,
    holder: String,
    deadline: Instant,
    nonces: BTreeSet<String>,
}
#[derive(Default)]
pub(crate) struct CustodyLeases {
    challenges: BTreeMap<String, ChallengeLease>,
    proofs: BTreeMap<String, Instant>,
    sessions: BTreeMap<String, SessionLease>,
}
impl CustodyLeases {
    fn prune(&mut self, tick: Instant) {
        self.challenges.retain(|_, c| c.retain_until >= tick);
        self.proofs.retain(|_, until| *until >= tick);
        self.sessions.retain(|_, s| s.deadline >= tick);
    }
    pub fn issue(
        &mut self,
        intent: ChallengeIntent,
        now: u64,
        tick: Instant,
    ) -> Result<BranchChallenge, CustodyRefusal> {
        let ChallengeIntent { device, action_hash, holder, source, audience, mode } = intent;
        if device.device_epoch == 0
            || device.device_epoch > ramflux_protocol::MAX_SAFE_JSON_INTEGER
            || ramflux_protocol::validate_device_name(&device.device_id).is_err()
            || !ramflux_protocol::decode_base64url(&device.account_anchor).is_ok_and(|bytes| {
                bytes.len() == 32
                    && ramflux_protocol::encode_base64url(bytes) == device.account_anchor
            })
        {
            return Err(CustodyRefusal::InvalidInput);
        }
        self.prune(tick);
        if holder.len() > 512
            || source.len() > 256
            || self.challenges.len() >= GLOBAL_LIMIT
            || self.challenges.values().filter(|c| c.source == source).count() >= SOURCE_LIMIT
        {
            return Err(CustodyRefusal::Capacity);
        }
        let challenge = BranchChallenge {
            challenge_nonce: random()?,
            audience,
            binding_mode: mode,
            issued_at: now,
            expires_at: now.checked_add(CHALLENGE_SECONDS).ok_or(CustodyRefusal::InvalidInput)?,
        };
        self.challenges.insert(
            challenge.challenge_nonce.clone(),
            ChallengeLease {
                challenge: challenge.clone(),
                device,
                action_hash,
                holder,
                source,
                deadline: tick + Duration::from_secs(CHALLENGE_SECONDS),
                retain_until: tick + Duration::from_secs(RETAIN_SECONDS),
                consumed: false,
            },
        );
        Ok(challenge)
    }
    pub fn challenge(&self, nonce: &str, tick: Instant) -> Result<ChallengeLease, CustodyRefusal> {
        let c = self.challenges.get(nonce).ok_or(CustodyRefusal::ChallengeUnknown)?;
        if c.consumed {
            return Err(CustodyRefusal::Replay);
        }
        if c.deadline < tick {
            return Err(CustodyRefusal::ChallengeExpired);
        }
        Ok(c.clone())
    }
    /// Called only after cryptographic validation. One mutex serializes competing consumers.
    pub fn consume(
        &mut self,
        nonce: &str,
        proof_id: &str,
        tick: Instant,
    ) -> Result<(), CustodyRefusal> {
        self.prune(tick);
        let c = self.challenge(nonce, tick)?;
        if self.proofs.contains_key(proof_id) {
            return Err(CustodyRefusal::Replay);
        }
        if self.proofs.len() >= GLOBAL_LIMIT {
            return Err(CustodyRefusal::Capacity);
        }
        self.proofs.insert(proof_id.into(), c.retain_until);
        if let Some(c) = self.challenges.get_mut(nonce) {
            c.consumed = true;
        }
        Ok(())
    }
    pub fn open(
        &mut self,
        mut session: CustodySession,
        holder: String,
        now: u64,
        tick: Instant,
    ) -> Result<CustodySession, CustodyRefusal> {
        self.prune(tick);
        if self.sessions.len() >= GLOBAL_LIMIT {
            return Err(CustodyRefusal::Capacity);
        }
        session.session_id = random()?;
        let seconds = session.expires_at.saturating_sub(now).min(CHALLENGE_SECONDS);
        if seconds == 0 {
            return Err(CustodyRefusal::SessionExpired);
        }
        self.sessions.insert(
            session.session_id.clone(),
            SessionLease {
                session: session.clone(),
                holder,
                deadline: tick + Duration::from_secs(seconds),
                nonces: BTreeSet::new(),
            },
        );
        Ok(session)
    }
    pub fn session(
        &mut self,
        id: &str,
        holder: &str,
        now: u64,
        tick: Instant,
    ) -> Result<CustodySession, CustodyRefusal> {
        self.prune(tick);
        let lease = self.sessions.get(id).ok_or(CustodyRefusal::SessionRequired)?;
        if lease.holder != holder {
            return Err(CustodyRefusal::BindingRefused);
        }
        if now > lease.session.expires_at {
            return Err(CustodyRefusal::SessionExpired);
        }
        Ok(lease.session.clone())
    }
    pub fn request(&mut self, id: &str, nonce: &str) -> Result<(), CustodyRefusal> {
        if !ramflux_protocol::decode_base64url(nonce).is_ok_and(|bytes| {
            bytes.len() == 32 && ramflux_protocol::encode_base64url(bytes) == nonce
        }) {
            return Err(CustodyRefusal::InvalidInput);
        }
        let lease = self.sessions.get_mut(id).ok_or(CustodyRefusal::SessionRequired)?;
        if lease.nonces.contains(nonce) {
            return Err(CustodyRefusal::Replay);
        }
        if lease.nonces.len() >= REQUEST_LIMIT {
            return Err(CustodyRefusal::Capacity);
        }
        lease.nonces.insert(nonce.into());
        Ok(())
    }
    pub fn close(&mut self, id: &str) {
        self.sessions.remove(id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;
    fn issue(pool: &mut CustodyLeases, tick: Instant) -> Result<BranchChallenge> {
        Ok(pool.issue(
            ChallengeIntent {
                device: DeviceRef {
                    account_anchor: ramflux_protocol::encode_base64url([1; 32]),
                    device_id: "phone".into(),
                    device_epoch: 1,
                },
                action_hash: "action".into(),
                holder: "connection".into(),
                source: "source".into(),
                audience: "router".into(),
                mode: BindingMode::HomeRelayReceipt,
            },
            100,
            tick,
        )?)
    }
    #[test]
    fn challenge_consumption_expiry_and_lost_holder_fail_closed() -> Result {
        let tick = Instant::now();
        let mut pool = CustodyLeases::default();
        let challenge = issue(&mut pool, tick)?;
        assert!(pool.challenge(&challenge.challenge_nonce, tick).is_ok());
        pool.consume(&challenge.challenge_nonce, "proof", tick)?;
        assert_eq!(
            pool.consume(&challenge.challenge_nonce, "proof", tick),
            Err(CustodyRefusal::Replay)
        );
        let next = issue(&mut pool, tick)?;
        assert_eq!(pool.consume(&next.challenge_nonce, "proof", tick), Err(CustodyRefusal::Replay));
        assert!(matches!(
            pool.challenge(&next.challenge_nonce, tick + Duration::from_secs(301)),
            Err(CustodyRefusal::ChallengeExpired)
        ));
        assert!(matches!(
            CustodyLeases::default().challenge(&challenge.challenge_nonce, tick),
            Err(CustodyRefusal::ChallengeUnknown)
        ));
        // Wall-clock rollback cannot extend a monotonic deadline.
        assert_eq!(
            pool.consume(&next.challenge_nonce, "unused", tick + Duration::from_secs(301)),
            Err(CustodyRefusal::ChallengeExpired)
        );
        Ok(())
    }
    #[test]
    fn bounded_source_budget_never_evicts_an_unexpired_challenge() -> Result {
        let tick = Instant::now();
        let mut pool = CustodyLeases::default();
        let first = issue(&mut pool, tick)?;
        for _ in 1..SOURCE_LIMIT {
            issue(&mut pool, tick)?;
        }
        assert!(issue(&mut pool, tick).is_err());
        assert!(pool.challenge(&first.challenge_nonce, tick).is_ok());
        assert!(issue(&mut pool, tick + Duration::from_secs(601)).is_ok());
        Ok(())
    }
}

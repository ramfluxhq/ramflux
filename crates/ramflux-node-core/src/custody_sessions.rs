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
// More than eleven 1024/minute issuance windows covering the 600-second replay horizon.
const REPLAY_LIMIT: usize = 12_288;
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
    pub source: String,
    deadline: Instant,
    retain_until: Instant,
    consumed: bool,
    issued: Instant,
    prefixes: Vec<String>,
    outstanding: bool,
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
    sources: crate::custody_ingress::CustodySourceBudget,
    pending_count: usize,
    by_holder: BTreeMap<String, BTreeSet<String>>,
    by_prefix: BTreeMap<String, BTreeSet<(Instant, String)>>,
}
impl CustodyLeases {
    fn prune(&mut self, tick: Instant) {
        let expired: Vec<_> = self
            .challenges
            .iter()
            .filter(|(_, c)| c.outstanding && c.deadline < tick)
            .map(|(nonce, _)| nonce.clone())
            .collect();
        for nonce in expired {
            self.untrack(&nonce);
        }
        self.challenges
            .retain(|_, c| if c.consumed { c.retain_until >= tick } else { c.deadline >= tick });
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
        let source_ip: std::net::IpAddr =
            source.parse().map_err(|_| CustodyRefusal::InvalidInput)?;
        let prefixes = crate::custody_source_prefixes(source_ip);
        if holder.len() > 512
            || self.by_holder.get(&holder).is_some_and(|entries| entries.len() >= 4)
            || prefixes.iter().any(|key| {
                self.by_prefix.get(key).is_some_and(|entries| entries.len() >= SOURCE_LIMIT)
            })
        {
            return Err(CustodyRefusal::Capacity);
        }
        if self.pending_count >= GLOBAL_LIMIT {
            return Err(CustodyRefusal::Busy);
        }
        self.sources.admit(source_ip, tick).ok_or(CustodyRefusal::Busy)?;
        let challenge = BranchChallenge {
            challenge_nonce: random()?,
            action_hash: action_hash.clone(),
            audience,
            binding_mode: mode,
            issued_at: now,
            expires_at: now.checked_add(CHALLENGE_SECONDS).ok_or(CustodyRefusal::InvalidInput)?,
        };
        self.pending_count += 1;
        self.by_holder.entry(holder.clone()).or_default().insert(challenge.challenge_nonce.clone());
        for prefix in &prefixes {
            self.by_prefix
                .entry(prefix.clone())
                .or_default()
                .insert((tick, challenge.challenge_nonce.clone()));
        }
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
                issued: tick,
                prefixes,
                outstanding: true,
            },
        );
        Ok(challenge)
    }
    fn untrack(&mut self, nonce: &str) {
        let Some(lease) = self.challenges.get_mut(nonce) else { return };
        if !lease.outstanding {
            return;
        }
        lease.outstanding = false;
        self.pending_count = self.pending_count.saturating_sub(1);
        if let Some(entries) = self.by_holder.get_mut(&lease.holder) {
            entries.remove(nonce);
            if entries.is_empty() {
                self.by_holder.remove(&lease.holder);
            }
        }
        for prefix in &lease.prefixes {
            if let Some(entries) = self.by_prefix.get_mut(prefix) {
                entries.remove(&(lease.issued, nonce.into()));
                if entries.is_empty() {
                    self.by_prefix.remove(prefix);
                }
            }
        }
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
        let expired = self.challenges.get(nonce).is_some_and(|c| !c.consumed && c.deadline < tick);
        self.prune(tick);
        if expired {
            return Err(CustodyRefusal::ChallengeExpired);
        }
        let c = self.challenge(nonce, tick)?;
        if self.proofs.contains_key(proof_id) {
            return Err(CustodyRefusal::Replay);
        }
        if self.proofs.len() >= REPLAY_LIMIT {
            return Err(CustodyRefusal::Capacity);
        }
        self.proofs.insert(proof_id.into(), c.retain_until);
        self.untrack(nonce);
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
        self.sessions.retain(|_, lease| lease.holder != holder);
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
    pub fn reject(&mut self, nonce: &str) {
        if self.challenges.get(nonce).is_some_and(|lease| !lease.consumed) {
            self.untrack(nonce);
            self.challenges.remove(nonce);
        }
    }
    pub fn disconnect(&mut self, holder: &str) {
        let nonces: Vec<_> = self
            .by_holder
            .get(holder)
            .map(|entries| entries.iter().cloned().collect())
            .unwrap_or_default();
        for nonce in nonces {
            self.untrack(&nonce);
            self.challenges.remove(&nonce);
        }
        self.sessions.retain(|_, s| s.holder != holder);
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
                source: "192.0.2.1".into(),
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
    fn connection_budget_limits_outstanding_challenges_and_releases_on_disconnect() -> Result {
        let tick = Instant::now();
        let mut pool = CustodyLeases::default();
        let first = issue(&mut pool, tick)?;
        for _ in 1..4 {
            issue(&mut pool, tick)?;
        }
        assert!(issue(&mut pool, tick).is_err());
        assert!(pool.challenge(&first.challenge_nonce, tick).is_ok());
        pool.consume(&first.challenge_nonce, "proof", tick)?;
        pool.disconnect("connection");
        assert_eq!(
            pool.challenge(&first.challenge_nonce, tick).err(),
            Some(CustodyRefusal::Replay)
        );
        assert_eq!(pool.challenges.len(), 1);
        assert!(issue(&mut pool, tick).is_ok());
        assert!(issue(&mut pool, tick + Duration::from_secs(601)).is_ok());
        Ok(())
    }
    fn intent(source: String, holder: String) -> ChallengeIntent {
        ChallengeIntent {
            device: DeviceRef {
                account_anchor: ramflux_protocol::encode_base64url([1; 32]),
                device_id: "phone".into(),
                device_epoch: 1,
            },
            action_hash: ramflux_protocol::encode_base64url([2; 32]),
            holder,
            source,
            audience: "node".into(),
            mode: BindingMode::HomeRelayReceipt,
        }
    }
    #[test]
    fn sixty_four_ipv6_addresses_cannot_lock_out_another_prefix() {
        let tick = Instant::now();
        let mut pool = CustodyLeases::default();
        let mut issued = 0;
        for address in 1..=64 {
            for request in 0..64 {
                let source =
                    std::net::Ipv6Addr::new(0x2001, 0xdb8, 1, 2, 0, 0, 0, address).to_string();
                if pool
                    .issue(intent(source, format!("attacker-{address}-{request}")), 100, tick)
                    .is_ok()
                {
                    issued += 1;
                }
            }
        }
        assert!(issued <= SOURCE_LIMIT);
        assert!(pool.issue(intent("203.0.113.1".into(), "honest".into()), 100, tick).is_ok());
    }
    #[test]
    fn challenge_floor_survives_new_prefix_churn() -> Result {
        let tick = Instant::now();
        let mut pool = CustodyLeases::default();
        let first = pool.issue(intent("192.0.2.1".into(), "honest".into()), 100, tick)?;
        for n in 0..2000 {
            let _ =
                pool.issue(intent(format!("2001:db8:{n:x}::1"), format!("churn-{n}")), 100, tick);
        }
        assert!(pool.challenge(&first.challenge_nonce, tick).is_ok());
        let second = pool.issue(intent("192.0.2.1".into(), "honest".into()), 100, tick)?;
        assert!(pool.challenge(&second.challenge_nonce, tick).is_ok());
        assert_eq!(pool.pending_count, 513);
        Ok(())
    }
    #[test]
    fn full_pending_pool_refuses_without_retiring_challenges_or_replay() -> Result {
        let tick = Instant::now();
        let mut pool = CustodyLeases::default();
        let consumed = pool.issue(intent("192.0.2.1".into(), "used".into()), 100, tick)?;
        pool.consume(&consumed.challenge_nonce, "proof-id", tick)?;
        let mut first = None;
        for n in 0..GLOBAL_LIMIT {
            let c = pool.issue(
                intent(format!("2001:db8:{:x}::1", n / 2), format!("holder-{n}")),
                100,
                tick + Duration::from_secs((n as u64 / 1000) * 61),
            )?;
            first.get_or_insert(c);
        }
        assert_eq!(pool.pending_count, GLOBAL_LIMIT);
        assert_eq!(
            pool.issue(
                intent("203.0.113.1".into(), "new".into()),
                100,
                tick + Duration::from_secs(248)
            )
            .err(),
            Some(CustodyRefusal::Busy)
        );
        assert!(pool.challenge(&first.ok_or("first")?.challenge_nonce, tick).is_ok());
        assert!(pool.proofs.contains_key("proof-id"));
        Ok(())
    }
}

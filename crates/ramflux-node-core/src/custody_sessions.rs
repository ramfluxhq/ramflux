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

const PENDING_CHALLENGE_LIMIT: usize = 4096;
// More than eleven 1024/minute issuance windows covering the 600-second replay horizon.
const REPLAY_LIMIT: usize = 12_288;
const SOURCE_LIMIT: usize = 64;
const HOLDER_LIMIT: usize = 4;
const REQUEST_LIMIT: usize = 256;
const CHALLENGE_SECONDS: u64 = 300;
const RETAIN_SECONDS: u64 = 600;

use crate::custody_budget_log::{CustodyAdmissionRefusal, node_retry, refuse, source_retry};

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
pub(crate) struct MigrationGrant {
    pub purpose: ramflux_protocol::custody::MigrationPurpose,
    pub source: std::net::IpAddr,
    pub control_hash: String,
    pub publication: ramflux_protocol::custody::Publication,
}
#[derive(Clone)]
pub(crate) struct SessionLease {
    pub session: CustodySession,
    holder: String,
    deadline: Instant,
    nonces: BTreeSet<String>,
    migration: Option<MigrationGrant>,
}
#[derive(Default)]
pub(crate) struct CustodyLeases {
    challenges: BTreeMap<String, ChallengeLease>,
    proofs: BTreeMap<String, Instant>,
    sessions: crate::custody_population_map::PopulationMap<String, SessionLease>,
    sources: crate::custody_ingress::CustodySourceBudget,
    session_deadlines: BTreeSet<(Instant, String)>,
    session_by_holder: BTreeMap<String, String>,
    pending_count: usize,
    by_holder: BTreeMap<String, BTreeSet<String>>,
    by_prefix: BTreeMap<String, BTreeSet<(Instant, String)>>,
}
impl CustodyLeases {
    pub(crate) fn with_issuance_settings(settings: crate::CustodyIssuanceSettings) -> Self {
        Self {
            sources: crate::custody_ingress::CustodySourceBudget::with_settings(settings),
            ..Self::default()
        }
    }
    #[cfg(feature = "itest-http")]
    pub(crate) fn budget_snapshot(&mut self) -> serde_json::Value {
        self.prune(Instant::now());
        serde_json::json!({
            "outstanding": self.pending_count,
            "holders": self.by_holder.values().map(BTreeSet::len).collect::<Vec<_>>(),
            "prefixes": self.by_prefix.iter().filter(|(key, _)| key.contains('/'))
                .map(|(key, entries)| (key.clone(), entries.len())).collect::<BTreeMap<_, _>>(),
            "replay": self.proofs.len(),
            "sessions": self.sessions.len(),
        })
    }
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
        while let Some((deadline, id)) = self.session_deadlines.first() {
            if *deadline >= tick {
                break;
            }
            let id = id.clone();
            self.session_deadlines.pop_first();
            self.remove_session(&id);
        }
    }
    pub fn issue(
        &mut self,
        intent: ChallengeIntent,
        now: u64,
        tick: Instant,
    ) -> Result<BranchChallenge, CustodyAdmissionRefusal> {
        let ChallengeIntent { device, action_hash, holder, source, audience, mode } = intent;
        if device.device_epoch == 0
            || device.device_epoch > ramflux_protocol::MAX_SAFE_JSON_INTEGER
            || ramflux_protocol::validate_device_name(&device.device_id).is_err()
            || !ramflux_protocol::decode_base64url(&device.account_anchor).is_ok_and(|bytes| {
                bytes.len() == 32
                    && ramflux_protocol::encode_base64url(bytes) == device.account_anchor
            })
        {
            return Err(CustodyRefusal::InvalidInput.into());
        }
        self.prune(tick);
        let source_ip: std::net::IpAddr =
            source.parse().map_err(|_| CustodyRefusal::InvalidInput)?;
        let prefixes = crate::custody_source_prefixes(source_ip);
        if holder.len() > 512 {
            return Err(refuse(
                "holder_bytes",
                holder.len(),
                512,
                CustodyRefusal::Capacity,
                Some(source_retry()),
            ));
        }
        let holder_count = self.by_holder.get(&holder).map_or(0, BTreeSet::len);
        if holder_count >= HOLDER_LIMIT {
            return Err(refuse(
                "holder",
                holder_count,
                HOLDER_LIMIT,
                CustodyRefusal::Capacity,
                Some(source_retry()),
            ));
        }
        for key in &prefixes {
            let count = self.by_prefix.get(key).map_or(0, BTreeSet::len);
            if count >= SOURCE_LIMIT {
                return Err(refuse(
                    "prefix",
                    count,
                    SOURCE_LIMIT,
                    CustodyRefusal::Capacity,
                    Some(source_retry()),
                ));
            }
        }
        if self.pending_count >= PENDING_CHALLENGE_LIMIT {
            return Err(refuse(
                "global",
                self.pending_count,
                PENDING_CHALLENGE_LIMIT,
                CustodyRefusal::Busy,
                Some(node_retry()),
            ));
        }
        self.sources.admit(source_ip, tick)?;
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
    ) -> Result<(), CustodyAdmissionRefusal> {
        let expired = self.challenges.get(nonce).is_some_and(|c| !c.consumed && c.deadline < tick);
        self.prune(tick);
        if expired {
            return Err(CustodyRefusal::ChallengeExpired.into());
        }
        let c = self.challenge(nonce, tick)?;
        if self.proofs.contains_key(proof_id) {
            return Err(CustodyRefusal::Replay.into());
        }
        if self.proofs.len() >= REPLAY_LIMIT {
            return Err(refuse(
                "replay",
                self.proofs.len(),
                REPLAY_LIMIT,
                CustodyRefusal::Capacity,
                Some(node_retry()),
            ));
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
        session: CustodySession,
        holder: String,
        now: u64,
        tick: Instant,
    ) -> Result<CustodySession, CustodyRefusal> {
        self.open_scoped(session, holder, now, tick, None)
    }
    pub fn open_migration(
        &mut self,
        session: CustodySession,
        holder: String,
        now: u64,
        tick: Instant,
        grant: MigrationGrant,
    ) -> Result<CustodySession, CustodyRefusal> {
        self.prune(tick);
        if !ramflux_protocol::decode_base64url(&grant.control_hash).is_ok_and(|bytes| {
            bytes.len() == 32 && ramflux_protocol::encode_base64url(bytes) == grant.control_hash
        }) {
            return Err(CustodyRefusal::InvalidInput);
        }
        if self.sessions.values().filter(|s| s.migration.is_some()).count() >= 16
            || ramflux_protocol::canonical_json_bytes(&grant.publication)
                .map_err(|_| CustodyRefusal::InvalidInput)?
                .len()
                > ramflux_protocol::custody::MAX_CUSTODY_FRAME_BYTES
        {
            return Err(CustodyRefusal::Capacity);
        }
        self.open_scoped(session, holder, now, tick, Some(grant))
    }
    fn open_scoped(
        &mut self,
        mut session: CustodySession,
        holder: String,
        now: u64,
        tick: Instant,
        migration: Option<MigrationGrant>,
    ) -> Result<CustodySession, CustodyAdmissionRefusal> {
        self.prune(tick);
        if let Some(id) = self.session_by_holder.get(&holder).cloned() {
            self.remove_session(&id);
        }
        session.session_id = random()?;
        let seconds = session.expires_at.saturating_sub(now).min(CHALLENGE_SECONDS);
        if seconds == 0 {
            return Err(CustodyRefusal::SessionExpired.into());
        }
        self.session_by_holder.insert(holder.clone(), session.session_id.clone());
        self.session_deadlines
            .insert((tick + Duration::from_secs(seconds), session.session_id.clone()));
        self.sessions.insert(
            session.session_id.clone(),
            SessionLease {
                session: session.clone(),
                holder,
                deadline: tick + Duration::from_secs(seconds),
                nonces: BTreeSet::new(),
                migration,
            },
        );
        Ok(session)
    }
    pub fn migration_grant(&self, id: &str) -> Result<Option<MigrationGrant>, CustodyRefusal> {
        self.sessions.get(id).map(|s| s.migration.clone()).ok_or(CustodyRefusal::SessionRequired)
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
            return Err(refuse(
                "request",
                lease.nonces.len(),
                REQUEST_LIMIT,
                CustodyRefusal::Capacity,
                None,
            )
            .code);
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
        if let Some(id) = self.session_by_holder.get(holder).cloned() {
            self.remove_session(&id);
        }
    }
    fn remove_session(&mut self, id: &str) {
        if let Some(lease) = self.sessions.remove(id) {
            self.session_deadlines.remove(&(lease.deadline, id.to_owned()));
            if self.session_by_holder.get(&lease.holder).is_some_and(|current| current == id) {
                self.session_by_holder.remove(&lease.holder);
            }
        }
    }
    pub fn close(&mut self, id: &str) {
        self.remove_session(id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;
    pub(super) fn issue(pool: &mut CustodyLeases, tick: Instant) -> Result<BranchChallenge> {
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
            pool.consume(&challenge.challenge_nonce, "proof", tick).map_err(|e| e.code),
            Err(CustodyRefusal::Replay)
        );
        let next = issue(&mut pool, tick)?;
        assert_eq!(
            pool.consume(&next.challenge_nonce, "proof", tick).map_err(|e| e.code),
            Err(CustodyRefusal::Replay)
        );
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
            pool.consume(&next.challenge_nonce, "unused", tick + Duration::from_secs(301))
                .map_err(|e| e.code),
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
    pub(super) fn intent(source: String, holder: String) -> ChallengeIntent {
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
    fn eight_attacking_prefixes_leave_fresh_challenges_available_for_ten_minutes() -> Result {
        for ipv6 in [true, false] {
            let mut pool = CustodyLeases::default();
            let started = Instant::now();
            for minute in 0..10 {
                let tick = started + Duration::from_secs(minute * 60);
                let mut issued = 0;
                for share in 1..=8 {
                    for request in 0..256 {
                        let source = if ipv6 {
                            format!("2001:db8:{share:x}:{:x}::{:x}", request / 128, request % 8 + 1)
                        } else {
                            format!("192.0.{share}.{}", request % 8 + 1)
                        };
                        let holder = format!("attacker-{share}-{request}");
                        match pool.issue(intent(source, holder.clone()), 100 + minute * 60, tick) {
                            Ok(_) => {
                                issued += 1;
                                pool.disconnect(&holder);
                            }
                            Err(code) => assert_eq!(code.code, CustodyRefusal::Busy),
                        }
                    }
                }
                assert_eq!(issued, 8 * 32);
                // Three operations for native publication, registration and session opening.
                for request in 0..3 {
                    let holder = format!("honest-{minute}-{request}");
                    pool.issue(
                        intent("203.0.113.1".into(), holder.clone()),
                        100 + minute * 60,
                        tick,
                    )?;
                    pool.disconnect(&holder);
                }
            }
        }
        Ok(())
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
        for n in 0..PENDING_CHALLENGE_LIMIT {
            let c = pool.issue(
                intent(format!("2001:db8:{:x}::1", n / 2), format!("holder-{n}")),
                100,
                tick + Duration::from_secs((n as u64 / 1000) * 61),
            )?;
            first.get_or_insert(c);
        }
        assert_eq!(pool.pending_count, PENDING_CHALLENGE_LIMIT);
        assert_eq!(
            pool.issue(
                intent("203.0.113.1".into(), "new".into()),
                100,
                tick + Duration::from_secs(248)
            )
            .err()
            .map(|e| e.code),
            Some(CustodyRefusal::Busy)
        );
        assert!(pool.challenge(&first.ok_or("first")?.challenge_nonce, tick).is_ok());
        assert!(pool.proofs.contains_key("proof-id"));
        Ok(())
    }
}

#[cfg(test)]
#[path = "custody_sessions/budget_tests.rs"]
mod budget_tests;

#[cfg(test)]
pub(crate) mod hint_tests;
#[cfg(test)]
mod population_tests;

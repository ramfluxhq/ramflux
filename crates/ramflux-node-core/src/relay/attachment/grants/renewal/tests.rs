// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain
#![allow(clippy::unwrap_used, clippy::too_many_lines)]
use super::super::{
    AttachmentAuthority, AttachmentReplayProof, GrantPublicationLease, RetirementOutcome,
    ScopedGrantRegistry, fixture::RetirementFixture, hex,
};
use super::*;
use crate::{RelayRedbStore, relay::attachment::AttachmentPolicy};
use ed25519_dalek::SigningKey;
use ramflux_protocol::large_attachment::body_digest;
use redb::ReadableTable as _;
use std::sync::{Arc, Barrier};

mod mint_tests;
mod predicate_tests;

pub(super) const RELAY: &str = "https://relay.example";
pub(super) const ISSUER: &str = "https://gateway.owner.example";

pub(super) fn path(name: &str) -> ramflux_test_support::TestPath {
    ramflux_test_support::TestPath::new().expect("test: allocate fixture directory").child(format!(
        "rf-renewal-{name}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
    ))
}
pub(super) fn authority() -> AttachmentAuthority {
    AttachmentAuthority {
        source: "node-a".into(),
        generation: 4,
        signing_public_key: SigningKey::from_bytes(&[77; 32]).verifying_key().to_bytes(),
    }
}
pub(super) fn wide() -> Caps {
    Caps { global: 4096, per_home: 64, per_requester: 100 }
}
pub(super) fn refusal<T>(r: Result<T, RenewalRefusal>) -> RenewalRefusal {
    r.err().unwrap()
}
pub(super) struct Env {
    pub f: RetirementFixture,
    pub policy: RenewalPolicy,
    pub cap: Vec<u8>,
    pub now: u64,
    pub path: ramflux_test_support::TestPath,
}
impl Env {
    pub fn new(name: &str) -> Self {
        let path = path(name);
        let now = crate::now_unix_seconds();
        let f = RetirementFixture::new_at(&path, now);
        let cap = capability(&f.registry, f.grant.grant().grant_id);
        let policy = RenewalPolicy { relay_audience: RELAY.into(), token_issuer: ISSUER.into() };
        Self { f, policy, cap, now, path }
    }
    pub fn g(&self) -> &ScopedAttachmentGrant {
        self.f.grant.grant()
    }
    pub fn target(&self, length: u64) -> AttachmentOperation {
        operation(self.g(), 1, length)
    }
    pub fn verdict(&self, at: u64) -> HomeVerdict {
        HomeVerdict {
            account_anchor: self.g().grantee.account_anchor.clone(),
            home_node: self.g().grantee.home_node_id.clone(),
            home_node_key: SigningKey::from_bytes(&[0x40; 32]).verifying_key().to_bytes(),
            home_epoch: 1,
            home_record_hash: [3; 32],
            checked_at: at,
        }
    }
    pub fn mint_req<'a>(
        &'a self,
        op: &'a [u8],
        verdict: &'a HomeVerdict,
        cap: &'a [u8],
    ) -> ChallengeMint<'a> {
        ChallengeMint {
            capability: cap,
            target_operation: op,
            requester: &self.g().grantee,
            home_node: &self.g().grantee.home_node_id,
            peer_node: &self.g().grantee.home_node_id,
            verdict,
        }
    }
    pub fn mint(
        &self,
        byte: u8,
        op: &AttachmentOperation,
        at: u64,
    ) -> Result<RenewalChallenge, RenewalRefusal> {
        let bytes = op.canonical_bytes().unwrap();
        let verdict = self.verdict(at);
        self.f.registry.mint_with(
            &self.policy,
            &self.mint_req(&bytes, &verdict, &self.cap),
            [byte; 32],
            at,
            wide(),
        )
    }
    pub fn admission<'a>(
        &'a self,
        challenge: u8,
        op: &AttachmentOperation,
        proof: &'a AttachmentReplayProof,
        w_expires_at: u64,
    ) -> RenewalAdmission<'a> {
        RenewalAdmission {
            grant: &self.f.grant,
            challenge: [challenge; 32],
            target_hash: op.hash().unwrap(),
            requester: &self.g().grantee,
            home_node: &self.g().grantee.home_node_id,
            home_epoch: 1,
            payload_generation: op.payload_generation,
            authority_generation: 4,
            w_issued_at: self.now,
            w_expires_at,
            verdict_checked_at: self.now,
            proof,
        }
    }
    pub fn admit(
        &self,
        challenge: u8,
        op: &AttachmentOperation,
        nonce: u8,
        at: u64,
    ) -> Result<GrantPublicationLease, RenewalRefusal> {
        let proof = AttachmentReplayProof {
            nonce: [nonce; 32],
            issued_at: self.now,
            expires_at: self.now + 30,
        };
        self.f.registry.admit_renewal_after_authentication(
            &self.admission(challenge, op, &proof, self.now + 30),
            &|| at,
        )
    }
}
pub(super) fn capability(registry: &ScopedGrantRegistry, id: [u8; 32]) -> Vec<u8> {
    ramflux_protocol::decode_base64url(&registry.lookup(&id).unwrap().unwrap().capability).unwrap()
}
pub(super) fn operation(g: &ScopedAttachmentGrant, op: u32, length: u64) -> AttachmentOperation {
    let object = format!("/attachments/{}/{}", hex(&g.object_id), hex(&g.manifest_hash));
    let (method, path, length) = match op {
        1 => ("GET", format!("{object}/segments/0"), length),
        2 => ("HEAD", format!("{object}/segments/0"), 0),
        _ => ("POST", format!("{object}/missing"), length),
    };
    AttachmentOperation {
        op,
        method: method.into(),
        path,
        audience: RELAY.into(),
        object_id: g.object_id,
        manifest_hash: g.manifest_hash,
        grant_id: g.grant_id,
        grant_epoch: g.epoch,
        authority_generation: 4,
        operation_id: [0xa1; 32],
        payload_generation: 1,
        segment_index: 0,
        offset: 0,
        length,
        body_digest: body_digest(&[]),
    }
}

#[test]
fn large_renewal_challenge_single_use_and_atomic_with_nonce() {
    let e = Env::new("atomic");
    let t = e.target(16);
    let now = e.now;
    // Fault after the challenge update: everything rolls back, the challenge stays usable.
    e.mint(1, &t, now).unwrap();
    FAIL_AFTER_CHALLENGE.with(|f| f.set(true));
    assert_eq!(refusal(e.admit(1, &t, 1, now)), RenewalRefusal::ReplayProtectionCapacity);
    drop(e.admit(1, &t, 2, now).unwrap());
    // The faulted nonce was never consumed: it admits on a second, fresh challenge.
    e.mint(2, &t, now).unwrap();
    drop(e.admit(2, &t, 1, now).unwrap());
    // An identical resend is Replay (nonce pre-check), never ChallengeConsumed.
    assert_eq!(refusal(e.admit(2, &t, 1, now)), RenewalRefusal::Replay);
    // A distinct nonce on the consumed challenge is ChallengeConsumed.
    assert_eq!(refusal(e.admit(2, &t, 3, now)), RenewalRefusal::ChallengeConsumed);
    // Distinct nonces racing one challenge: exactly one Issued, one ChallengeConsumed.
    e.mint(3, &t, now).unwrap();
    let barrier = Arc::new(Barrier::new(3));
    let mut tasks = Vec::new();
    for nonce in [10_u8, 11] {
        let registry = e.f.registry.clone();
        let grant = e.f.grant.clone();
        let barrier = barrier.clone();
        let target = t.clone();
        tasks.push(std::thread::spawn(move || {
            let proof =
                AttachmentReplayProof { nonce: [nonce; 32], issued_at: now, expires_at: now + 30 };
            let adm = RenewalAdmission {
                grant: &grant,
                challenge: [3; 32],
                target_hash: target.hash().unwrap(),
                requester: &grant.grant().grantee,
                home_node: &grant.grant().grantee.home_node_id,
                home_epoch: 1,
                payload_generation: 1,
                authority_generation: 4,
                w_issued_at: now,
                w_expires_at: now + 30,
                verdict_checked_at: now,
                proof: &proof,
            };
            barrier.wait();
            registry.admit_renewal_after_authentication(&adm, &|| now).map(drop)
        }));
    }
    barrier.wait();
    let results = tasks.into_iter().map(|t| t.join().unwrap()).collect::<Vec<_>>();
    assert_eq!(results.iter().filter(|r| r.is_ok()).count(), 1);
    assert_eq!(results.iter().filter(|r| *r == &Err(RenewalRefusal::ChallengeConsumed)).count(), 1);
}

#[test]
fn renewal_challenge_state_survives_restart() {
    let e = Env::new("restart");
    let (t, now) = (e.target(16), e.now);
    for c in [1, 2, 3] {
        e.mint(c, &t, now).unwrap();
    }
    drop(e.admit(2, &t, 1, now).unwrap());
    let grant = e.f.grant.clone();
    let (path, policy) = (e.path.clone(), e.policy.clone());
    let cap = e.cap.clone();
    drop(e);
    let ledger = RelayRedbStore::open_at(&path, now)
        .unwrap()
        .attachment_ledger(AttachmentPolicy::default())
        .unwrap();
    let registry = ledger.scoped_grants(authority()).unwrap();
    assert!(!cap.is_empty() && policy.relay_audience == RELAY);
    let admit = |c: u8, n: u8, at: u64| {
        let proof = AttachmentReplayProof { nonce: [n; 32], issued_at: now, expires_at: now + 30 };
        registry
            .admit_renewal_after_authentication(
                &RenewalAdmission {
                    grant: &grant,
                    challenge: [c; 32],
                    target_hash: t.hash().unwrap(),
                    requester: &grant.grant().grantee,
                    home_node: &grant.grant().grantee.home_node_id,
                    home_epoch: 1,
                    payload_generation: 1,
                    authority_generation: 4,
                    w_issued_at: now,
                    w_expires_at: now + 30,
                    verdict_checked_at: now,
                    proof: &proof,
                },
                &|| at,
            )
            .map(drop)
    };
    assert_eq!(admit(2, 7, now + 1), Err(RenewalRefusal::ChallengeConsumed));
    assert_eq!(admit(1, 8, now + 29), Ok(()));
    assert_eq!(admit(3, 9, now + 30), Err(RenewalRefusal::ChallengeExpired));
    assert_eq!(admit(9, 9, now + 30), Err(RenewalRefusal::ChallengeUnknown));
}

#[test]
fn renewal_challenge_delayed_positive_expiry_and_substitutions() {
    let e = Env::new("delayed");
    let (t, now) = (e.target(16), e.now);
    for c in 1..=6 {
        e.mint(c, &t, now).unwrap();
    }
    assert_eq!(e.mint(1, &t, now), Err(RenewalRefusal::Busy));
    // W expiry beyond the challenge expiry is refused and consumes nothing.
    let proof = AttachmentReplayProof { nonce: [5; 32], issued_at: now, expires_at: now + 30 };
    let long = e.admission(5, &t, &proof, now + 31);
    assert_eq!(
        refusal(e.f.registry.admit_renewal_after_authentication(&long, &|| now + 1)),
        RenewalRefusal::ChallengeMismatch
    );
    // Substitutions: each refused, the challenge stays unconsumed.
    let other_range = e.target(17);
    assert_eq!(refusal(e.admit(5, &other_range, 5, now + 1)), RenewalRefusal::ChallengeMismatch);
    let mut head = operation(e.g(), 2, 0);
    head.operation_id = t.operation_id;
    assert_eq!(refusal(e.admit(5, &head, 5, now + 1)), RenewalRefusal::ChallengeMismatch);
    let stranger = QualifiedOwner { device_id: "other".into(), ..e.g().grantee.clone() };
    let mut adm = e.admission(5, &t, &proof, now + 30);
    adm.requester = &stranger;
    assert_eq!(
        refusal(e.f.registry.admit_renewal_after_authentication(&adm, &|| now + 1)),
        RenewalRefusal::ChallengeMismatch
    );
    let mut adm = e.admission(5, &t, &proof, now + 30);
    adm.home_node = "node-c";
    assert_eq!(
        refusal(e.f.registry.admit_renewal_after_authentication(&adm, &|| now + 1)),
        RenewalRefusal::ChallengeMismatch
    );
    let mut adm = e.admission(5, &t, &proof, now + 30);
    adm.home_epoch = 0;
    assert_eq!(
        refusal(e.f.registry.admit_renewal_after_authentication(&adm, &|| now + 1)),
        RenewalRefusal::ChallengeMismatch
    );
    let second = e.f.register_edited(|g| g.grant_id = [0x77; 32]);
    let mut adm = e.admission(5, &t, &proof, now + 30);
    adm.grant = &second;
    assert_eq!(
        refusal(e.f.registry.admit_renewal_after_authentication(&adm, &|| now + 1)),
        RenewalRefusal::ChallengeMismatch
    );
    let mut adm = e.admission(5, &t, &proof, now + 30);
    adm.authority_generation = 5;
    assert_eq!(
        refusal(e.f.registry.admit_renewal_after_authentication(&adm, &|| now + 1)),
        RenewalRefusal::AuthorityGenerationMismatch
    );
    let mut adm = e.admission(5, &t, &proof, now + 30);
    adm.payload_generation = 2;
    assert_eq!(
        refusal(e.f.registry.admit_renewal_after_authentication(&adm, &|| now + 1)),
        RenewalRefusal::PayloadGenerationMismatch
    );
    // Challenge 5 admits once its substitutions are all refused (they consumed nothing).
    drop(
        e.f.registry
            .admit_renewal_after_authentication(&e.admission(5, &t, &proof, now + 30), &|| now + 1)
            .unwrap(),
    );
    assert_eq!(refusal(e.admit(5, &t, 6, now + 1)), RenewalRefusal::ChallengeConsumed);
    // Delayed positive: mint at t, renew at t+25.
    drop(e.admit(1, &t, 1, now + 25).unwrap());
    // Inclusive boundary: the last second of the lifetime still admits; t+30 is expired.
    drop(e.admit(2, &t, 2, now + 29).unwrap());
    assert_eq!(refusal(e.admit(3, &t, 3, now + 30)), RenewalRefusal::ChallengeExpired);
    assert_eq!(refusal(e.admit(4, &t, 4, now + 31)), RenewalRefusal::ChallengeExpired);
}

#[test]
fn renewal_admission_refuses_retired_grant_without_consuming() {
    let e = Env::new("retired");
    let (t, now) = (e.target(16), e.now);
    e.mint(6, &t, now).unwrap();
    // Retire after validation, before the admission commit: nothing is consumed.
    assert_eq!(e.f.retire(&e.f.request()).unwrap(), RetirementOutcome::Retired);
    assert_eq!(refusal(e.admit(6, &t, 7, now)), RenewalRefusal::GrantNotActive);
    assert!(!challenge_consumed(&e.f.registry, 6));
    assert!(!nonce_consumed(&e, 7));
}

fn challenge_consumed(registry: &ScopedGrantRegistry, byte: u8) -> bool {
    let tx = registry.ledger.db.begin_write().unwrap();
    let table = tx.open_table(CHALLENGES).unwrap();
    let value = table.get([byte; 32].as_slice()).unwrap().unwrap();
    let row: ChallengeRow = decode(value.value()).unwrap();
    row.consumed
}
fn nonce_consumed(e: &Env, byte: u8) -> bool {
    let tx = e.f.registry.ledger.db.begin_write().unwrap();
    replay::nonce_consumed(&tx, "node-a", &e.g().grantee, &[byte; 32]).unwrap()
}

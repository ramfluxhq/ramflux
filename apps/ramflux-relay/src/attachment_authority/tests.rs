// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain
#![allow(
    clippy::unwrap_used,
    clippy::too_many_lines,
    clippy::many_single_char_names,
    clippy::similar_names,
    clippy::too_many_arguments,
    clippy::panic,
    clippy::assert_is_empty,
    clippy::items_after_statements,
    clippy::type_complexity
)]
use super::*;
use ramflux_node_core::{
    RelayRedbStore,
    attachment::{
        AttachmentAuthority, AttachmentPolicy, RetirementOutcome,
        fixture::{FixtureSpec, RetirementFixture},
    },
};
use ramflux_protocol::large_attachment::{ScopedAttachmentGrant, body_digest};
use std::cell::Cell;

mod listener;
mod quic;
mod rows;

const RELAY: &str = "https://relay.example";
const ISSUER: &str = "https://gateway.owner.example";
const T0: u64 = 1_700_000_001;

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    bytes.iter().fold(String::new(), |mut s, b| {
        write!(s, "{b:02x}").unwrap();
        s
    })
}
fn unhex(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}
fn path(name: &str) -> ramflux_test_support::TestPath {
    ramflux_test_support::TestPath::new().expect("test: allocate fixture directory").child(format!(
        "rf-authority-{name}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
    ))
}
fn policy() -> RenewalPolicy {
    RenewalPolicy { relay_audience: RELAY.into(), token_issuer: ISSUER.into() }
}
fn seed(first: u8) -> [u8; 32] {
    std::array::from_fn(|i| first + u8::try_from(i).unwrap())
}
/// The r4 vector identities: case 1, source `node-owner` generation 3, issuer seed 0x60...
fn spec() -> FixtureSpec {
    FixtureSpec { case: 1, source: "node-owner".into(), generation: 3, signer_seed: seed(0x60) }
}
fn home_key() -> SigningKey {
    SigningKey::from_bytes(&seed(0x40))
}
fn grantee_key() -> SigningKey {
    SigningKey::from_bytes(&seed(0x20))
}
fn operation(g: &ScopedAttachmentGrant, op: u32, length: u64) -> AttachmentOperation {
    let object = format!("/attachments/{}/{}", hex(&g.object_id), hex(&g.manifest_hash));
    let (method, path, length) = match op {
        1 => ("GET", format!("{object}/segments/0"), length),
        _ => ("HEAD", format!("{object}/segments/0"), 0),
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
        authority_generation: 3,
        operation_id: [0xa1; 32],
        payload_generation: 1,
        segment_index: 0,
        offset: 0,
        length,
        body_digest: body_digest(&[]),
    }
}
fn capability(f: &RetirementFixture, id: [u8; 32]) -> Vec<u8> {
    ramflux_protocol::decode_base64url(&f.registry.lookup(&id).unwrap().unwrap().capability)
        .unwrap()
}
fn lp(parts: &[&[u8]]) -> Vec<u8> {
    let mut out = Vec::new();
    for p in parts {
        out.extend(u32::try_from(p.len()).unwrap().to_be_bytes());
        out.extend(*p);
    }
    out
}
fn vectors() -> serde_json::Value {
    serde_json::from_str::<serde_json::Value>(include_str!(
        "../../../../crates/ramflux-protocol/tests/fixtures/large_attachment_renewal_v1.json"
    ))
    .unwrap()["renewal"]
        .clone()
}
fn field(v: &serde_json::Value, path: &[&str]) -> Vec<u8> {
    let mut cur = v;
    for p in path {
        cur = &cur[*p];
    }
    unhex(cur.as_str().unwrap())
}

/// W and Prenew construction, with per-field tweaks applied BEFORE signing so dependent
/// digests and signatures stay correct. Only the named field or signer differs.
struct Tweak<'a> {
    w: &'a dyn Fn(&mut ForwardAttestation),
    p: &'a dyn Fn(&mut RequesterPop),
    home: SigningKey,
    grantee: SigningKey,
}
impl Tweak<'_> {
    fn none() -> Tweak<'static> {
        Tweak { w: &|_| {}, p: &|_| {}, home: home_key(), grantee: grantee_key() }
    }
}

struct Env {
    f: RetirementFixture,
    issuer: SourceIssuer,
    cap: Vec<u8>,
    now: u64,
    _directory: ramflux_test_support::TestPath,
}
impl Env {
    fn new(name: &str) -> Self {
        Self::at(name, T0)
    }
    fn at(name: &str, now: u64) -> Self {
        let directory = path(name);
        let f = RetirementFixture::new_with(&directory, now, &spec());
        let issuer = SourceIssuer::new(f.registry.clone(), f.source_signer(), policy()).unwrap();
        let cap = capability(&f, f.grant.grant().grant_id);
        Self { f, issuer, cap, now, _directory: directory }
    }
    fn g(&self) -> &ScopedAttachmentGrant {
        self.f.grant.grant()
    }
    fn target(&self) -> AttachmentOperation {
        operation(self.g(), 1, 16)
    }
    fn verdict(&self) -> HomeVerdict {
        HomeVerdict {
            account_anchor: self.g().grantee.account_anchor.clone(),
            home_node: self.g().grantee.home_node_id.clone(),
            home_node_key: home_key().verifying_key().to_bytes(),
            home_epoch: 1,
            home_record_hash: [3; 32],
            checked_at: self.now,
        }
    }
    fn mint(&self, g: &ScopedAttachmentGrant, cap: &[u8], t: &AttachmentOperation) -> [u8; 32] {
        let op = t.canonical_bytes().unwrap();
        let verdict = self.verdict();
        self.issuer
            .challenge(
                &ChallengeMint {
                    capability: cap,
                    target_operation: &op,
                    requester: &g.grantee,
                    home_node: &g.grantee.home_node_id,
                    peer_node: &g.grantee.home_node_id,
                    verdict: &verdict,
                },
                self.now,
            )
            .unwrap()
            .challenge
    }
    fn build(
        &self,
        g: &ScopedAttachmentGrant,
        cap: &[u8],
        t: &AttachmentOperation,
        challenge: [u8; 32],
        nonce: u8,
    ) -> RenewAdmitRequest {
        let request = RenewalRequest::new(t, ISSUER, [0xb2; 32]).unwrap();
        self.forge(g, cap, &request, challenge, nonce, &Tweak::none())
    }
    fn forge(
        &self,
        g: &ScopedAttachmentGrant,
        cap: &[u8],
        request: &RenewalRequest,
        challenge: [u8; 32],
        nonce: u8,
        tweak: &Tweak<'_>,
    ) -> RenewAdmitRequest {
        let renew_hash = request.target().unwrap().0.hash().unwrap();
        let mut w = ForwardAttestation {
            requester: g.grantee.clone(),
            grant_hash: g.hash().unwrap(),
            grant_id: g.grant_id,
            grant_epoch: g.epoch,
            source_issuer: ISSUER.into(),
            home_issuer: g.grantee.home_node_id.clone(),
            challenge,
            operation_hash: renew_hash,
            issued_at: self.now,
            expires_at: self.now + 30,
        };
        (tweak.w)(&mut w);
        let mut pop = RequesterPop {
            operation_hash: renew_hash,
            requester_digest: requester_digest(&g.grantee).unwrap(),
            nonce: [nonce; 32],
            issued_at: self.now,
            expires_at: self.now + 30,
            forward_digest: w.hash().unwrap(),
        };
        (tweak.p)(&mut pop);
        RenewAdmitRequest {
            operation: request.operation.clone(),
            body: request.body.clone(),
            attestation: w.canonical_bytes().unwrap(),
            home_signature: tweak.home.sign(&w.signing_bytes().unwrap()).to_bytes().to_vec(),
            proof: pop.canonical_bytes().unwrap(),
            requester_signature: tweak
                .grantee
                .sign(&pop.signing_bytes().unwrap())
                .to_bytes()
                .to_vec(),
            grant: cap.to_vec(),
            peer_node: w.home_issuer.clone(),
            home_verdict: self.verdict(),
        }
    }
    fn run_at(&self, r: &RenewAdmitRequest, at: u64) -> Result<Vec<u8>, IssueError> {
        let mut sink = VecSink::default();
        self.issuer.renew(r, &|| at, &mut sink, &IssueHooks::none())?;
        Ok(sink.bytes)
    }
    fn run(&self, r: &RenewAdmitRequest) -> Result<Vec<u8>, IssueError> {
        self.run_at(r, self.now)
    }
    fn refused(&self, r: &RenewAdmitRequest) -> RenewalRefusal {
        match self.run(r) {
            Err(IssueError::Refused(code)) => code,
            other => panic!("expected a refusal, got {other:?}"),
        }
    }
}

#[test]
fn large_source_issuer_renews_foreign_grant_without_sender_device() {
    let e = Env::new("issue");
    let j = vectors();
    let frozen_target = field(&j, &["target_operation_hex"]);
    let t = AttachmentOperation::decode(&frozen_target).unwrap();
    // The registered fixture carries the r4 vector identities.
    assert_eq!(t.grant_id, e.g().grant_id);
    assert_eq!(t.manifest_hash, e.g().manifest_hash);
    assert_eq!(hex(&t.hash().unwrap()), j["target_ohash_hex"].as_str().unwrap());
    let verdict = e.verdict();
    let challenge =
        e.f.registry
            .mint_renewal_challenge_with(
                &policy(),
                &ChallengeMint {
                    capability: &e.cap,
                    target_operation: &frozen_target,
                    requester: &e.g().grantee,
                    home_node: &e.g().grantee.home_node_id,
                    peer_node: &e.g().grantee.home_node_id,
                    verdict: &verdict,
                },
                [0xc1; 32],
                T0,
            )
            .unwrap();
    assert_eq!(challenge.challenge, [0xc1; 32]);
    let good = RenewAdmitRequest {
        operation: field(&j, &["renewal_operation_hex"]),
        body: field(&j, &["renewal_body_hex"]),
        attestation: field(&j, &["home", "bytes_hex"]),
        home_signature: field(&j, &["home", "signature_hex"]),
        proof: field(&j, &["renewal_pop", "bytes_hex"]),
        requester_signature: field(&j, &["renewal_pop", "signature_hex"]),
        grant: e.cap.clone(),
        peer_node: e.g().grantee.home_node_id.clone(),
        home_verdict: verdict,
    };
    // Received-byte round trips: decode then encode is byte-identical.
    assert_eq!(
        AttachmentOperation::decode(&good.operation).unwrap().canonical_bytes().unwrap(),
        good.operation
    );
    assert_eq!(
        ForwardAttestation::decode(&good.attestation).unwrap().canonical_bytes().unwrap(),
        good.attestation
    );
    assert_eq!(RequesterPop::decode(&good.proof).unwrap().canonical_bytes().unwrap(), good.proof);

    // r4 rejected range, audience and HEAD vectors under the retained signatures.
    let rejected = j["rejected_target_operations_hex"].as_array().unwrap();
    let expected = [
        RenewalRefusal::ChallengeMismatch,
        RenewalRefusal::TargetInvalid,
        RenewalRefusal::ChallengeMismatch,
    ];
    for (hexed, expect) in rejected.iter().zip(expected) {
        let sub = AttachmentOperation::decode(&unhex(hexed.as_str().unwrap())).unwrap();
        assert_ne!(sub.hash().unwrap(), t.hash().unwrap());
        let swapped = RenewalRequest::new(&sub, ISSUER, [0xb2; 32]).unwrap();
        let mut body_only = good.clone();
        body_only.body = swapped.body.clone();
        assert_eq!(e.refused(&body_only), RenewalRefusal::TargetInvalid);
        let mut rebuilt = good.clone();
        (rebuilt.operation, rebuilt.body) = (swapped.operation, swapped.body);
        assert_eq!(e.refused(&rebuilt), expect, "vector {hexed}");
    }

    // Frozen issuance: emitted T and its signature equal the vector byte for byte.
    let token = e.run(&good).unwrap();
    let frozen_token =
        lp(&[&field(&j, &["token", "bytes_hex"]), &field(&j, &["token", "signature_hex"])]);
    assert_eq!(token, frozen_token);
    let key = e.f.source_signer().verifying_key().to_bytes();
    let verified = AttachmentToken::decode_signed(&token, &key).unwrap();
    assert_eq!(verified.token().canonical_bytes().unwrap(), field(&j, &["token", "bytes_hex"]));
    assert_eq!(verified.signed_bytes().unwrap(), token);
    assert_eq!(verified.token().target_hash, t.hash().unwrap());

    // Identical resend: Replay. Distinct nonce on the consumed challenge: ChallengeConsumed.
    assert_eq!(e.refused(&good), RenewalRefusal::Replay);
    let again = e.build(e.g(), &e.cap, &t, [0xc1; 32], 2);
    assert_eq!(e.refused(&again), RenewalRefusal::ChallengeConsumed);
    let unknown = e.build(e.g(), &e.cap, &t, [0xee; 32], 3);
    assert_eq!(e.refused(&unknown), RenewalRefusal::ChallengeUnknown);

    // A challenge minted before retirement: retirement refuses the fresh request, while
    // the already consumed request stays Replay.
    let challenge2 = e.mint(e.g(), &e.cap, &t);
    assert_eq!(e.f.retire(&e.f.request()).unwrap(), RetirementOutcome::Retired);
    assert_eq!(e.refused(&good), RenewalRefusal::Replay);
    let late = e.build(e.g(), &e.cap, &t, challenge2, 4);
    assert_eq!(e.refused(&late), RenewalRefusal::GrantNotActive);
}

#[test]
fn token_expiry_is_clamped_to_grant_and_receipt_inclusively() {
    let e = Env::new("clamp");
    for (id, expires, want) in
        [(0x71_u8, T0 + 300, T0 + 300), (0x72, T0 + 100, T0 + 100), (0x73, T0 + 301, T0 + 300)]
    {
        let g = e.f.register_edited(|g| {
            g.grant_id = [id; 32];
            g.expires_at = expires;
        });
        let cap = capability(&e.f, [id; 32]);
        let t = operation(g.grant(), 1, 16);
        let challenge = e.mint(g.grant(), &cap, &t);
        let token = e.run(&e.build(g.grant(), &cap, &t, challenge, id)).unwrap();
        let key = e.f.source_signer().verifying_key().to_bytes();
        assert_eq!(AttachmentToken::decode_signed(&token, &key).unwrap().token().expires_at, want);
    }
}

fn retire(f: &RetirementFixture) -> RetirementOutcome {
    f.retire(&f.request()).unwrap()
}

/// Sink that records what the transport saw and lets a test act mid-write.
struct ProbeSink<'a> {
    bytes: Vec<u8>,
    reset: bool,
    during_write: &'a dyn Fn(),
}
impl TokenSink for ProbeSink<'_> {
    fn write_token(&mut self, bytes: &[u8], _: Duration) -> io::Result<()> {
        (self.during_write)();
        self.bytes.extend_from_slice(bytes);
        Ok(())
    }
    fn reset(&mut self) {
        self.reset = true;
    }
}

#[test]
fn retire_between_validation_and_commit_refuses_with_no_token() {
    let e = Env::new("race-pre");
    let t = e.target();
    let challenge = e.mint(e.g(), &e.cap, &t);
    let good = e.build(e.g(), &e.cap, &t, challenge, 1);
    let mut sink = VecSink::default();
    let hooks = IssueHooks {
        before_admission: &|| assert_eq!(retire(&e.f), RetirementOutcome::Retired),
        ..IssueHooks::none()
    };
    assert_eq!(
        e.issuer.renew(&good, &|| e.now, &mut sink, &hooks),
        Err(IssueError::Refused(RenewalRefusal::GrantNotActive))
    );
    assert_eq!(sink.bytes.len(), 0);
}

#[test]
fn retire_after_commit_before_signing_cancels_and_joins_the_lease() {
    let e = Env::new("race-post");
    let t = e.target();
    let challenge = e.mint(e.g(), &e.cap, &t);
    let good = e.build(e.g(), &e.cap, &t, challenge, 1);
    let mut sink = VecSink::default();
    let hooks = IssueHooks {
        after_commit: &|| {
            assert_eq!(retire(&e.f), RetirementOutcome::RevocationPending);
            false
        },
        ..IssueHooks::none()
    };
    assert_eq!(e.issuer.renew(&good, &|| e.now, &mut sink, &hooks), Err(IssueError::Cancelled));
    assert!(sink.bytes.is_empty() && sink.reset);
    assert_eq!(retire(&e.f), RetirementOutcome::Retired);
    // Fail closed: the consumed request stays Replay, even after retirement.
    assert_eq!(e.refused(&good), RenewalRefusal::Replay);
}

#[test]
fn large_source_issuer_final_check_writes_zero_token_bytes_after_retirement() {
    let e = Env::new("race-final");
    let t = e.target();
    let challenge = e.mint(e.g(), &e.cap, &t);
    let good = e.build(e.g(), &e.cap, &t, challenge, 1);
    let mut sink = VecSink::default();
    let held = Cell::new(false);
    let hooks = IssueHooks {
        before_final_token_check: &|| {
            // T is signed and the lease is held: retirement can only fence, not ACK.
            assert_eq!(retire(&e.f), RetirementOutcome::RevocationPending);
            held.set(true);
        },
        ..IssueHooks::none()
    };
    assert_eq!(e.issuer.renew(&good, &|| e.now, &mut sink, &hooks), Err(IssueError::Cancelled));
    assert!(held.get());
    assert_eq!(sink.bytes.len(), 0, "token bytes escaped after retirement");
    assert!(sink.reset);
    assert_eq!(retire(&e.f), RetirementOutcome::Retired);
}

#[test]
fn adapter_holds_the_lease_through_the_actual_transport_write() {
    let e = Env::new("adapter");
    let t = e.target();
    let challenge = e.mint(e.g(), &e.cap, &t);
    let good = e.build(e.g(), &e.cap, &t, challenge, 1);
    // Retirement during the write cannot ACK: the lease outlives the transport send.
    let during = || assert_eq!(retire(&e.f), RetirementOutcome::RevocationPending);
    let mut sink = ProbeSink { bytes: Vec::new(), reset: false, during_write: &during };
    let outcome = e.issuer.respond(&good, &|| e.now, &mut sink, &IssueHooks::none());
    assert_eq!(outcome, Ok(Outcome::Issued));
    let frame: RenewAdmitResponse = serde_json::from_slice(&sink.bytes).unwrap();
    assert!(matches!(frame, RenewAdmitResponse::Issued { ref token } if !token.is_empty()));
    // Only after the write returned did the lease drop.
    assert_eq!(retire(&e.f), RetirementOutcome::Retired);

    // Retirement at the adapter's final check: zero bytes of the frame reach the transport.
    let e = Env::new("adapter-final");
    let t = e.target();
    let challenge = e.mint(e.g(), &e.cap, &t);
    let good = e.build(e.g(), &e.cap, &t, challenge, 1);
    let hooks = IssueHooks {
        before_final_token_check: &|| {
            assert_eq!(retire(&e.f), RetirementOutcome::RevocationPending);
        },
        ..IssueHooks::none()
    };
    let nothing = || panic!("a frame reached the transport after retirement");
    let mut sink = ProbeSink { bytes: Vec::new(), reset: false, during_write: &nothing };
    assert_eq!(e.issuer.respond(&good, &|| e.now, &mut sink, &hooks), Err(IssueError::Cancelled));
    assert!(sink.bytes.is_empty() && sink.reset);
    assert_eq!(retire(&e.f), RetirementOutcome::Retired);

    // Typed refusals are framed and written too.
    let e = Env::new("adapter-refused");
    let mut sink = VecSink::default();
    let t = e.target();
    let unknown = e.build(e.g(), &e.cap, &t, [0xee; 32], 1);
    let outcome = e.issuer.respond(&unknown, &|| e.now, &mut sink, &IssueHooks::none());
    assert_eq!(outcome, Ok(Outcome::Refused(RenewalRefusal::ChallengeUnknown)));
    assert_eq!(
        serde_json::from_slice::<RenewAdmitResponse>(&sink.bytes).unwrap(),
        RenewAdmitResponse::Refused { code: RenewalRefusal::ChallengeUnknown }
    );
    assert_eq!(
        serde_json::from_slice::<RenewAdmitRequest>(&serde_json::to_vec(&unknown).unwrap())
            .unwrap(),
        unknown
    );
}

#[test]
fn admission_time_is_reread_so_a_stalled_request_is_refused_and_consumes_nothing() {
    let e = Env::new("stalled");
    let t = e.target();
    let challenge = e.mint(e.g(), &e.cap, &t);
    let good = e.build(e.g(), &e.cap, &t, challenge, 1);
    // Validated at expiry-1, resumed at expiry+1 (the challenge lives 30 s from mint).
    let clock = Cell::new(e.now + 29);
    let hooks = IssueHooks { before_admission: &|| clock.set(e.now + 31), ..IssueHooks::none() };
    let mut sink = VecSink::default();
    let r = e.issuer.renew(&good, &|| clock.get(), &mut sink, &hooks);
    assert_eq!(r, Err(IssueError::Refused(RenewalRefusal::ChallengeExpired)));
    assert!(sink.bytes.is_empty());
    // Nothing was consumed: the same bytes issue at a valid time.
    assert!(e.run_at(&good, e.now + 29).is_ok());
}

#[test]
fn crash_after_commit_emits_no_token_and_restart_resend_is_replay() {
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
    let signer = SigningKey::from_bytes(&spec().signer_seed);
    let root = path("crash-root");
    let f = RetirementFixture::new_with(&root, now, &spec());
    let e = Env {
        issuer: SourceIssuer::new(f.registry.clone(), signer.clone(), policy()).unwrap(),
        cap: capability(&f, f.grant.grant().grant_id),
        f,
        now,
        _directory: root.clone(),
    };
    let t = e.target();
    let challenge = e.mint(e.g(), &e.cap, &t);
    let good = e.build(e.g(), &e.cap, &t, challenge, 1);
    let mut sink = VecSink::default();
    let hooks = IssueHooks { after_commit: &|| true, ..IssueHooks::none() };
    assert_eq!(e.issuer.renew(&good, &|| now, &mut sink, &hooks), Err(IssueError::Interrupted));
    assert!(sink.bytes.is_empty() && !sink.reset);
    drop(e);
    let ledger = RelayRedbStore::open(&root)
        .unwrap()
        .attachment_ledger(AttachmentPolicy::default())
        .unwrap();
    let registry = ledger
        .scoped_grants(AttachmentAuthority {
            source: "node-owner".into(),
            generation: 3,
            signing_public_key: signer.verifying_key().to_bytes(),
        })
        .unwrap();
    let issuer = SourceIssuer::new(registry, signer, policy()).unwrap();
    let mut sink = VecSink::default();
    let outcome = issuer.respond(&good, &|| now, &mut sink, &IssueHooks::none());
    assert_eq!(outcome, Ok(Outcome::Refused(RenewalRefusal::Replay)));
    assert!(matches!(
        serde_json::from_slice::<RenewAdmitResponse>(&sink.bytes).unwrap(),
        RenewAdmitResponse::Refused { code: RenewalRefusal::Replay }
    ));
}

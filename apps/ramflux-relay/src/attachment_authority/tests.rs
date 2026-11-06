// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain
#![allow(
    clippy::unwrap_used,
    clippy::too_many_lines,
    clippy::many_single_char_names,
    clippy::similar_names,
    clippy::too_many_arguments,
    clippy::panic
)]
use super::*;
use ramflux_node_core::{
    RelayRedbStore,
    attachment::{
        AttachmentAuthority, AttachmentPolicy, RetirementOutcome, fixture::RetirementFixture,
    },
};
use ramflux_protocol::large_attachment::{ScopedAttachmentGrant, body_digest};
use std::cell::Cell;

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
fn path(name: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!(
        "rf-authority-{name}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
    ))
}
fn policy() -> RenewalPolicy {
    RenewalPolicy { relay_audience: RELAY.into(), token_issuer: ISSUER.into() }
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
        authority_generation: 4,
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
fn home_key() -> SigningKey {
    SigningKey::from_bytes(&[0x40; 32])
}
fn grantee_key() -> SigningKey {
    SigningKey::from_bytes(&std::array::from_fn(|i| 0x20 + u8::try_from(i).unwrap()))
}

struct Env {
    f: RetirementFixture,
    issuer: SourceIssuer,
    cap: Vec<u8>,
    now: u64,
}
impl Env {
    fn new(name: &str) -> Self {
        Self::at(name, T0)
    }
    fn at(name: &str, now: u64) -> Self {
        let f = RetirementFixture::new_at(&path(name), now);
        let issuer = SourceIssuer::new(f.registry.clone(), f.source_signer(), policy()).unwrap();
        let cap = capability(&f, f.grant.grant().grant_id);
        Self { f, issuer, cap, now }
    }
    fn g(&self) -> &ScopedAttachmentGrant {
        self.f.grant.grant()
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
    /// Builds and signs W and Prenew over the renewal request, like gateway B and device Q.
    fn build(
        &self,
        g: &ScopedAttachmentGrant,
        cap: &[u8],
        t: &AttachmentOperation,
        challenge: [u8; 32],
        nonce: u8,
    ) -> RenewAdmitRequest {
        let request = RenewalRequest::new(t, ISSUER, [0xb2; 32]).unwrap();
        self.sign(g, cap, &request, challenge, nonce, &home_key())
    }
    fn sign(
        &self,
        g: &ScopedAttachmentGrant,
        cap: &[u8],
        request: &RenewalRequest,
        challenge: [u8; 32],
        nonce: u8,
        home: &SigningKey,
    ) -> RenewAdmitRequest {
        let renew_hash = request.target().unwrap().0.hash().unwrap();
        let w = ForwardAttestation {
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
        let pop = RequesterPop {
            operation_hash: renew_hash,
            requester_digest: requester_digest(&g.grantee).unwrap(),
            nonce: [nonce; 32],
            issued_at: self.now,
            expires_at: self.now + 30,
            forward_digest: w.hash().unwrap(),
        };
        RenewAdmitRequest {
            operation: request.operation.clone(),
            body: request.body.clone(),
            attestation: w.canonical_bytes().unwrap(),
            home_signature: home.sign(&w.signing_bytes().unwrap()).to_bytes().to_vec(),
            proof: pop.canonical_bytes().unwrap(),
            requester_signature: grantee_key()
                .sign(&pop.signing_bytes().unwrap())
                .to_bytes()
                .to_vec(),
            grant: cap.to_vec(),
            peer_node: g.grantee.home_node_id.clone(),
            home_verdict: self.verdict(),
        }
    }
    fn run(&self, r: &RenewAdmitRequest) -> Result<Vec<u8>, IssueError> {
        let mut sink = VecSink::default();
        self.issuer.renew(r, &|| self.now, &mut sink, &IssueHooks::none())?;
        Ok(sink.bytes)
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
    let t = operation(e.g(), 1, 16);
    let challenge = e.mint(e.g(), &e.cap, &t);
    let good = e.build(e.g(), &e.cap, &t, challenge, 1);

    // r4 vector link: the frozen Htarget still matches the codec output.
    let j: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../crates/ramflux-protocol/tests/fixtures/large_attachment_renewal_v1.json"
    ))
    .unwrap();
    let r = &j["renewal"];
    let frozen =
        AttachmentOperation::decode(&unhex(r["target_operation_hex"].as_str().unwrap())).unwrap();
    assert_eq!(hex(&frozen.hash().unwrap()), r["target_ohash_hex"].as_str().unwrap());

    // r4 rejected range, audience and HEAD vectors, under retained signatures.
    let rejected = r["rejected_target_operations_hex"].as_array().unwrap();
    assert_eq!(rejected.len(), 3);
    let expected = [
        RenewalRefusal::ChallengeMismatch,
        RenewalRefusal::TargetInvalid,
        RenewalRefusal::ChallengeMismatch,
    ];
    for (hexed, expect) in rejected.iter().zip(expected) {
        let mut sub = AttachmentOperation::decode(&unhex(hexed.as_str().unwrap())).unwrap();
        assert_ne!(sub.hash().unwrap(), frozen.hash().unwrap());
        // Rebind the vector (case 1 identities) to this fixture grant; keep the mutation.
        (sub.object_id, sub.manifest_hash, sub.grant_id) =
            (e.g().object_id, e.g().manifest_hash, e.g().grant_id);
        sub.authority_generation = 4;
        sub.path = sub.path.replace(&hex(&frozen.object_id), &hex(&sub.object_id));
        sub.path = sub.path.replace(&hex(&frozen.manifest_hash), &hex(&sub.manifest_hash));
        // (a) body swapped under the retained Orenew: the committed body digest fails.
        let swapped = RenewalRequest::new(&sub, ISSUER, [0xb2; 32]).unwrap();
        let mut r1 = good.clone();
        r1.body = swapped.body.clone();
        assert_eq!(e.refused(&r1), RenewalRefusal::TargetInvalid);
        // (b) Orenew and body rebuilt, signatures W and Prenew retained.
        let mut r2 = good.clone();
        r2.operation = swapped.operation;
        r2.body = swapped.body;
        assert_eq!(e.refused(&r2), expect, "vector {hexed}");
    }

    // Rights: the target right is required in addition to Renew.
    let narrow = e.f.register_edited(|g| {
        g.grant_id = [0x78; 32];
        g.rights = 1 | 8;
    });
    let narrow_cap = capability(&e.f, narrow.grant().grant_id);
    let head = operation(narrow.grant(), 2, 0);
    let r3 = e.build(narrow.grant(), &narrow_cap, &head, [7; 32], 1);
    assert_eq!(e.refused(&r3), RenewalRefusal::RightsInsufficient);

    // W signed by a key that is not the verdict home key.
    let request = RenewalRequest::new(&t, ISSUER, [0xb2; 32]).unwrap();
    let other = SigningKey::from_bytes(&[0x99; 32]);
    let r4 = e.sign(e.g(), &e.cap, &request, challenge, 1, &other);
    assert_eq!(e.refused(&r4), RenewalRefusal::HomeMismatch);
    // Verdict home key unusable, or verdict stale.
    let mut r5 = good.clone();
    r5.home_verdict.home_node_key =
        (0..=255_u8).map(|b| [b; 32]).find(|k| VerifyingKey::from_bytes(k).is_err()).unwrap();
    assert_eq!(e.refused(&r5), RenewalRefusal::HomeTrustUnavailable);
    let mut r6 = good.clone();
    r6.home_verdict.checked_at = e.now - 61;
    assert_eq!(e.refused(&r6), RenewalRefusal::HomeTrustUnavailable);
    let mut r7 = good.clone();
    r7.peer_node = "node-c".into();
    assert_eq!(e.refused(&r7), RenewalRefusal::HomeMismatch);

    // Owner/source key absent: an issuer without the pinned source key cannot exist.
    assert!(matches!(
        SourceIssuer::new(e.f.registry.clone(), SigningKey::from_bytes(&[1; 32]), policy()),
        Err(RenewalRefusal::CapabilityUnavailable)
    ));
    // A valid capability that differs from the registered row (shorter receipt).
    let g = e.g();
    let receipt = AttachmentRegistrationReceipt {
        grant_hash: g.hash().unwrap(),
        grant_epoch: g.epoch,
        source_authority: "node-a".into(),
        authority_generation: 4,
        expires_at: g.expires_at - 1,
    };
    let signer = e.f.source_signer();
    let sig = signer.sign(&receipt.signing_bytes().unwrap()).to_bytes();
    let forged = receipt.capability(&e.f.grant, &sig, &signer.verifying_key().to_bytes()).unwrap();
    assert_ne!(forged, e.cap);
    let mut r8 = good.clone();
    r8.grant = forged;
    assert_eq!(e.refused(&r8), RenewalRefusal::CapabilityInvalid);
    let mut r9 = good.clone();
    r9.grant.truncate(r9.grant.len() - 1);
    assert_eq!(e.refused(&r9), RenewalRefusal::CapabilityInvalid);
    // Oversized request.
    let mut r10 = good.clone();
    r10.body = vec![0; 17 * 1024];
    assert_eq!(e.refused(&r10), RenewalRefusal::Invalid);
    // Prenew signed by a different device key.
    let mut r11 = good.clone();
    r11.requester_signature = home_key().sign(&r11.proof).to_bytes().to_vec();
    assert_eq!(e.refused(&r11), RenewalRefusal::Invalid);

    // Every refusal above left the challenge and nonce untouched: the genuine request issues.
    let token = e.run(&good).unwrap();
    let issuer_key = e.f.source_signer().verifying_key().to_bytes();
    let verified = AttachmentToken::decode_signed(&token, &issuer_key).unwrap();
    let signed = verified.token();
    assert_eq!(signed.target_hash, t.hash().unwrap());
    assert_ne!(
        signed.target_hash,
        RenewalRequest::new(&t, ISSUER, [0xb2; 32]).unwrap().target().unwrap().0.hash().unwrap()
    );
    assert_eq!(signed.grant_hash, g.hash().unwrap());
    assert_eq!(signed.requester_digest, requester_digest(&g.grantee).unwrap());
    assert_eq!((signed.rights, signed.source_authority.as_str()), (1, "node-a"));
    assert_eq!((signed.authority_generation, signed.token_issuer.as_str()), (4, ISSUER));
    assert_eq!((signed.issued_at, signed.expires_at), (e.now, e.now + 300));
    assert_eq!(token, signed_bytes_again(&verified));

    // Identical resend: Replay. A distinct nonce on the consumed challenge: ChallengeConsumed.
    assert_eq!(e.refused(&good), RenewalRefusal::Replay);
    let again = e.build(e.g(), &e.cap, &t, challenge, 2);
    assert_eq!(e.refused(&again), RenewalRefusal::ChallengeConsumed);
    // An unknown challenge.
    let unknown = e.build(e.g(), &e.cap, &t, [0xee; 32], 3);
    assert_eq!(e.refused(&unknown), RenewalRefusal::ChallengeUnknown);

    // Retired grant: the challenge was minted earlier, issuance is refused.
    let challenge2 = e.mint(e.g(), &e.cap, &t);
    assert_eq!(e.f.retire(&e.f.request()).unwrap(), RetirementOutcome::Retired);
    let late = e.build(e.g(), &e.cap, &t, challenge2, 4);
    assert_eq!(e.refused(&late), RenewalRefusal::GrantNotActive);
}

fn signed_bytes_again(v: &ramflux_protocol::large_attachment::VerifiedAttachmentToken) -> Vec<u8> {
    v.signed_bytes().unwrap()
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

#[test]
fn respond_maps_every_outcome_to_a_typed_response() {
    let e = Env::new("respond");
    let t = operation(e.g(), 1, 16);
    let challenge = e.mint(e.g(), &e.cap, &t);
    let good = e.build(e.g(), &e.cap, &t, challenge, 1);
    let first = e.issuer.respond(&good, &|| e.now);
    assert!(matches!(first, RenewAdmitResponse::Issued { ref token } if !token.is_empty()));
    assert_eq!(
        e.issuer.respond(&good, &|| e.now),
        RenewAdmitResponse::Refused { code: RenewalRefusal::Replay }
    );
    let json = serde_json::to_vec(&good).unwrap();
    assert_eq!(serde_json::from_slice::<RenewAdmitRequest>(&json).unwrap(), good);
}

fn retire(f: &RetirementFixture) -> RetirementOutcome {
    f.retire(&f.request()).unwrap()
}

#[test]
fn retire_between_validation_and_commit_refuses_with_no_token() {
    let e = Env::new("race-pre");
    let t = operation(e.g(), 1, 16);
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
    let t = operation(e.g(), 1, 16);
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
    // The lease is gone now: the join completes and retirement ACKs.
    assert_eq!(retire(&e.f), RetirementOutcome::Retired);
    // Nonce and challenge stay consumed: fail closed.
    assert_eq!(e.refused(&good), RenewalRefusal::GrantNotActive);
}

#[test]
fn large_source_issuer_final_check_writes_zero_token_bytes_after_retirement() {
    let e = Env::new("race-final");
    let t = operation(e.g(), 1, 16);
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
    assert!(sink.bytes.is_empty(), "token bytes escaped after retirement");
    assert!(sink.reset);
    assert_eq!(retire(&e.f), RetirementOutcome::Retired);
}

#[test]
fn crash_after_commit_emits_no_token_and_restart_resend_is_replay() {
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
    let root = path("crash");
    let f = RetirementFixture::new_at(&root, now);
    let signer = f.source_signer();
    let e = Env {
        issuer: SourceIssuer::new(f.registry.clone(), signer.clone(), policy()).unwrap(),
        cap: capability(&f, f.grant.grant().grant_id),
        f,
        now,
    };
    let t = operation(e.g(), 1, 16);
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
            source: "node-a".into(),
            generation: 4,
            signing_public_key: signer.verifying_key().to_bytes(),
        })
        .unwrap();
    let issuer = SourceIssuer::new(registry, signer, policy()).unwrap();
    assert_eq!(
        issuer.respond(&good, &|| now),
        RenewAdmitResponse::Refused { code: RenewalRefusal::Replay }
    );
}

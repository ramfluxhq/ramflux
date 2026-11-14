// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain
use super::*;
use crate::pairing_relay::{FullNativeAdmission, FullResumeProgress, PairingRelayError};
use ramflux_protocol::canonical_json_bytes;
use ramflux_protocol::custody::{
    Envelope,
    pairing::full_transfer::{
        PROFILE,
        lease::{DataLease, ResumeProof},
        relay::{HelloFull, PollFullDiscovery, ResumeTokenFull},
    },
};
struct Endpoint {
    driver: custody_sessions::Driver,
    current: ramflux_crypto::custody::VerifiedRecord,
    lease: Envelope<DataLease>,
    prefix: u8,
}
impl Endpoint {
    fn new(seed: u8) -> TestResult<Self> {
        let driver = custody_sessions::Driver::new(&format!("owner-{seed}"), seed)?;
        let current =
            ramflux_crypto::custody::verify_record(&driver.publication.record, NOW, None, None)?;
        let grant = DataGrant {
            schema: "ramflux.pairing.full_transfer.data_grant.v1".into(),
            version: 1,
            transfer_id: encode_base64url([seed; 32]),
            node_id: driver.node.envelope().body.node_id.clone(),
            source_ref: driver.reference.clone(),
            destination_ref: DeviceRef {
                account_anchor: driver.reference.account_anchor.clone(),
                device_id: "target".into(),
                device_epoch: 1,
            },
            branch_keys: BranchKeys {
                source: driver.publication.record.body.devices[0]
                    .branch_certificate
                    .as_ref()
                    .ok_or("branch")?
                    .body
                    .branch_signing_public_key
                    .clone(),
                destination: ramflux_crypto::public_key_base64url_from_seed([37; 32]),
            },
            opaque_commitment: encode_base64url([seed + 1; 32]),
            expires_at: WALL + 604_800,
        };
        let body = DataLease {
            schema: "ramflux.pairing.full_transfer.data_lease.v1".into(),
            version: 1,
            lease_id: encode_base64url([seed + 2; 32]),
            grant,
            issued_at: WALL,
            expires_at: WALL + 604_800,
        };
        let lease = Envelope {
            signature: ramflux_crypto::sign_canonical_bytes_with_seed(
                &body.signing_bytes()?,
                [8; 32],
            ),
            body,
        };
        Ok(Self { driver, current, lease, prefix: seed })
    }
    fn admission(&self) -> FullNativeAdmission<'_> {
        FullNativeAdmission::for_current(&self.driver.node, &self.current, &self.lease.body.grant)
    }
    fn source(&self) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(198, 51, self.prefix, 1))
    }
    fn hello(&self) -> HelloFull {
        HelloFull {
            epoch: encode_base64url([90; 32]),
            hpke_key: encode_base64url(ramflux_crypto::X25519KeyPair::from_seed([51; 32]).public),
            kind: "hello_full".into(),
            lease: self.lease.clone(),
            profile: PROFILE.into(),
            role: "initiator".into(),
        }
    }
    fn poll(&self) -> PollFullDiscovery {
        PollFullDiscovery {
            kind: "poll_full_discovery".into(),
            lease: self.lease.clone(),
            profile: PROFILE.into(),
            role: "responder".into(),
        }
    }
}
fn store(clock: &Arc<TestPairingClock>) -> TestResult<PairingRelayStore> {
    Ok(PairingRelayStore::new(PairingRelayConfig {
        clock: Arc::clone(clock) as Arc<dyn PairingClock>,
        node_seed: [8; 32],
        public_origin: ORIGIN.into(),
    })?)
}
#[test]
fn pairing_full_resume_one_pending_per_account() -> TestResult {
    let clock = TestPairingClock::new(WALL);
    let mut store = store(&clock)?;
    let owner = Endpoint::new(10)?;
    let first = owner.hello();
    store.hello_full(owner.source(), &first, &owner.admission())?;
    let before = store.full_resume_stats()?.ok_or("stats")?;
    let mut second = first.clone();
    second.lease.body.lease_id = encode_base64url([99; 32]);
    second.lease.signature = ramflux_crypto::sign_canonical_bytes_with_seed(
        &second.lease.body.signing_bytes()?,
        [8; 32],
    );
    assert!(matches!(
        store.hello_full(owner.source(), &second, &owner.admission()),
        Err(PairingRelayError::Busy { .. })
    ));
    let after = store.full_resume_stats()?.ok_or("stats")?;
    assert_eq!(after.pending_challenges, 1);
    assert_eq!(after.body_budget, before.body_budget);
    assert_eq!(after.connections, 0);
    Ok(())
}
#[test]
fn pairing_full_resume_discovery_freezes_roles_deadline_and_returns_exact_peer_proof() -> TestResult
{
    let clock = TestPairingClock::new(WALL);
    let mut store = store(&clock)?;
    let owner = Endpoint::new(10)?;
    let mut first = owner.hello();
    let mut b = first.clone();
    b.role = "responder".into();
    b.hpke_key = encode_base64url(ramflux_crypto::X25519KeyPair::from_seed([52; 32]).public);
    let original = store.accounted_bytes();
    assert!(matches!(
        store.hello_full(owner.source(), &b, &owner.admission()),
        Err(PairingRelayError::WrongContext)
    ));
    assert_eq!(store.accounted_bytes(), original);
    assert!(matches!(
        store.poll_full_discovery(owner.source(), &owner.poll(), &owner.admission()),
        Err(PairingRelayError::NotFound)
    ));
    assert_eq!(store.accounted_bytes(), original);
    let initial = store.hello_full(owner.source(), &first, &owner.admission())?;
    assert!(initial.template.is_none());
    assert!(initial.hpke_keys.destination.is_none());
    assert_eq!(initial.expires_in_ms.0, 10_000);
    clock.advance_secs(1);
    let retry = store.hello_full(owner.source(), &first, &owner.admission())?;
    assert_eq!(retry.expires_in_ms.0, 9000);
    first.hpke_key = encode_base64url(ramflux_crypto::X25519KeyPair::from_seed([53; 32]).public);
    assert!(matches!(
        store.hello_full(owner.source(), &first, &owner.admission()),
        Err(PairingRelayError::Replay)
    ));
    let frozen = store.hello_full(owner.source(), &b, &owner.admission())?;
    assert_eq!(frozen.expires_in_ms.0, 9000);
    let template = frozen.template.ok_or("both keys did not freeze")?;
    assert_eq!(template.hpke_keys.source, initial.hpke_keys.source);
    assert_eq!(template.hpke_keys.destination, b.hpke_key);
    b.hpke_key = first.hpke_key;
    assert!(matches!(
        store.hello_full(owner.source(), &b, &owner.admission()),
        Err(PairingRelayError::Replay)
    ));
    let sign = |role: &str, seed| -> TestResult<Envelope<ResumeProof>> {
        let mut body = template.clone();
        body.role = role.into();
        Ok(Envelope {
            signature: ramflux_crypto::sign_canonical_bytes_with_seed(
                &body.signing_bytes()?,
                [seed; 32],
            ),
            body,
        })
    };
    let a = sign("initiator", 12)?;
    let b = sign("responder", 37)?;
    assert!(matches!(
        store.submit_full_resume(&a, &owner.admission())?,
        FullResumeProgress::Pending
    ));
    let mut altered = a.clone();
    altered.body.nonce = encode_base64url([98; 32]);
    altered.signature =
        ramflux_crypto::sign_canonical_bytes_with_seed(&altered.body.signing_bytes()?, [12; 32]);
    assert!(matches!(
        store.submit_full_resume(&altered, &owner.admission()),
        Err(PairingRelayError::Replay)
    ));
    let FullResumeProgress::Ready(bt) = store.submit_full_resume(&b, &owner.admission())? else {
        return Err("B token missing".into());
    };
    let FullResumeProgress::Ready(at) = store.submit_full_resume(&a, &owner.admission())? else {
        return Err("A token missing".into());
    };
    let wire = at.encode_secret()?;
    let reply = ResumeTokenFull::from_wire_bytes(&wire)?;
    assert_eq!(canonical_json_bytes(&reply.peer_proof)?, canonical_json_bytes(&b)?);
    let forbidden = zeroize::Zeroizing::new(encode_base64url(bt.token.as_ref()));
    assert!(!std::str::from_utf8(&wire)?.contains(forbidden.as_str()));
    clock.advance_secs(9);
    assert!(store.submit_full_resume(&a, &owner.admission()).is_err());
    Ok(())
}
#[test]
fn pairing_full_resume_expired_pending_backs_off() -> TestResult {
    let clock = TestPairingClock::new(WALL);
    let mut store = store(&clock)?;
    let owners = (0..5).map(|n| Endpoint::new(10 + n * 10)).collect::<TestResult<Vec<_>>>()?;
    for owner in owners.iter().take(4) {
        store.hello_full(owner.source(), &owner.hello(), &owner.admission())?;
    }
    let waiting = &owners[4];
    assert!(matches!(
        store.hello_full(waiting.source(), &waiting.hello(), &waiting.admission()),
        Err(PairingRelayError::Busy { .. })
    ));
    clock.advance_secs(10);
    for owner in owners.iter().take(4) {
        let mut next = owner.hello();
        next.epoch = encode_base64url([91; 32]);
        assert!(matches!(
            store.hello_full(owner.source(), &next, &owner.admission()),
            Err(PairingRelayError::Busy { .. })
        ));
    }
    store.hello_full(waiting.source(), &waiting.hello(), &waiting.admission())?;
    let stats = store.full_resume_stats()?.ok_or("stats")?;
    assert_eq!(stats.pending_challenges, 1);
    assert_eq!(stats.cooldown_accounts, 4);
    assert!(stats.body_budget.metadata_bound_bytes <= 65_536);
    Ok(())
}

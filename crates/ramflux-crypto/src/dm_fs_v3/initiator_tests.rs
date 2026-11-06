// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use super::*;
use ramflux_protocol::{dm_fs_v3 as p, domain};
use serde_json::Value;
use std::{
    cell::RefCell,
    collections::{BTreeMap, BTreeSet},
};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;
type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;
fn crypto() -> Result<Value> {
    Ok(serde_json::from_str(include_str!(
        "../../../ramflux-protocol/fixtures/dm_fs_v3/crypto_vectors.json"
    ))?)
}
fn raw(name: &str) -> Result<Vec<u8>> {
    let w: Value = serde_json::from_str(include_str!(
        "../../../ramflux-protocol/fixtures/dm_fs_v3/wire_vectors.json"
    ))?;
    let v = w["positive"]
        .as_array()
        .ok_or("positive")?
        .iter()
        .find(|v| v["name"] == name)
        .ok_or("vector")?;
    Ok(hex::decode(v["bytes"].as_str().ok_or("bytes")?)?)
}
fn fixed<const N: usize>(value: &Value) -> Result<[u8; N]> {
    hex::decode(value.as_str().ok_or("hex")?)?.try_into().map_err(|_| "width".into())
}
struct FixtureRng {
    seeds: [[u8; 32]; 2],
    cursor: usize,
    fail_at: Option<usize>,
}
impl FixtureRng {
    fn new(vector: &Value) -> Result<Self> {
        Ok(Self {
            seeds: [fixed(&vector["seeds"]["ephemeral"])?, fixed(&vector["seeds"]["ratchet"])?],
            cursor: 0,
            fail_at: None,
        })
    }
}
impl NativeBootstrapRng for FixtureRng {
    fn fill_seed(
        &mut self,
        output: &mut [u8; 32],
    ) -> std::result::Result<(), NativeBootstrapError> {
        if self.fail_at == Some(self.cursor) {
            output[..8].fill(0x5a);
            return Err(NativeBootstrapError::Entropy);
        }
        output.copy_from_slice(self.seeds.get(self.cursor).ok_or(NativeBootstrapError::Entropy)?);
        self.cursor += 1;
        Ok(())
    }
}
struct Observation {
    expected: Vec<[u8; 32]>,
    seen: BTreeSet<usize>,
    wipes: BTreeMap<&'static str, usize>,
}
thread_local! {static OBS:RefCell<Option<Observation>>=const{RefCell::new(None)};}
pub(super) fn observe_dh(index: usize, bytes: &[u8; 32]) {
    OBS.with(|obs| {
        if let Some(obs) = obs.borrow_mut().as_mut() {
            assert!(
                obs.expected.get(index).is_some_and(|v| v == bytes),
                "independent DH mismatch at {index}"
            );
            assert!(obs.seen.insert(index));
        }
    });
}
pub(super) fn observe_wiped(slot: &'static str, bytes: &[u8]) {
    assert!(bytes.iter().all(|b| *b == 0), "bootstrap slot not erased: {slot}");
    OBS.with(|obs| {
        if let Some(obs) = obs.borrow_mut().as_mut() {
            *obs.wipes.entry(slot).or_insert(0) += 1;
        }
    });
}
struct Scope;
impl Drop for Scope {
    fn drop(&mut self) {
        OBS.with(|obs| {
            obs.replace(None);
        });
    }
}
fn assert_wipes(expected: &[&'static str], run: impl FnOnce() -> Result) -> Result {
    OBS.with(|obs| {
        assert!(obs.borrow().is_none());
        obs.replace(Some(Observation {
            expected: Vec::new(),
            seen: BTreeSet::new(),
            wipes: BTreeMap::new(),
        }));
    });
    let scope = Scope;
    run()?;
    let state = OBS.with(RefCell::take).ok_or("wipe observations")?;
    assert!(state.seen.is_empty(), "failed bootstrap reached successful DH handoff");
    assert_eq!(state.wipes, expected.iter().map(|slot| (*slot, 1)).collect());
    drop(scope);
    Ok(())
}
fn parts(
    vector: &Value,
) -> Result<(p::PrekeyLeaseResult, p::BootstrapTranscript, Zeroizing<[u8; 32]>)> {
    let mode = vector["mode"].as_str().ok_or("mode")?;
    let lease = p::PrekeyLeaseResult::from_bytes(&raw(&format!("lease_{mode}"))?)?;
    let transcript = p::BootstrapTranscript::from_bytes(&raw(&format!("transcript_{mode}"))?)?;
    let identity = StaticSecret::from(fixed::<32>(&vector["seeds"]["initiator_identity"])?);
    let dh1 =
        Zeroizing::new(identity.diffie_hellman(&PublicKey::from(lease.base.spk_key)).to_bytes());
    assert!(*dh1 == fixed::<32>(&vector["dh"][0])?, "agreement DH1 mismatch");
    Ok((lease, transcript, dh1))
}
fn input<'a>(
    lease: &'a p::PrekeyLeaseResult,
    t: &p::BootstrapTranscript,
    key: &'a [u8; 32],
    dh1: &'a Zeroizing<[u8; 32]>,
) -> NativeInitiatorInput<'a> {
    NativeInitiatorInput {
        lease,
        header: t.header.clone(),
        node_key: key,
        agreement_dh1: dh1,
        envelope_created_at: t.envelope_created_at,
        envelope_ttl: t.envelope_ttl,
        now: lease.issued_at,
    }
}
fn node_key() -> [u8; 32] {
    ed25519_dalek::SigningKey::from_bytes(&[60; 32]).verifying_key().to_bytes()
}
/// Shared independent output contract; recipient tests extend this same suite in the next part.
pub(super) fn native_bootstrap_contract(
    mut derive: impl FnMut(&Value) -> Result<NativeHkdfOutput<32>>,
) -> Result {
    let c = crypto()?;
    let mut count = 0;
    for vector in c["bootstrap"].as_array().ok_or("bootstrap")? {
        let output = derive(vector)?;
        let golden = fixed::<32>(&vector["kdf"]["output"])?;
        assert!(output.as_ref() == golden, "independent native SK mismatch");
        count += 1;
    }
    assert_eq!(count, 2);
    Ok(())
}
#[test]
fn dm_fs_v3_x3dh_opk_and_spk_only_golden() -> Result {
    native_bootstrap_contract(|vector| {
        let (lease, t, dh1) = parts(vector)?;
        let key = node_key();
        let mut rng = FixtureRng::new(vector)?;
        let expected = vector["dh"]
            .as_array()
            .ok_or("DH")?
            .iter()
            .map(fixed)
            .collect::<Result<Vec<[u8; 32]>>>()?;
        OBS.with(|obs| {
            obs.replace(Some(Observation {
                expected,
                seen: BTreeSet::new(),
                wipes: BTreeMap::new(),
            }));
        });
        let scope = Scope;
        let output = native_initiator(input(&lease, &t, &key, &dh1), &mut rng)?;
        assert_eq!(rng.cursor, 2);
        assert_eq!(output.public.transcript.to_bytes()?, t.to_bytes()?);
        assert_eq!(output.public.bundle_hash, t.header.bundle_hash);
        let info = hex::decode(vector["kdf"]["info"].as_str().ok_or("info")?)?;
        assert_eq!(output.public.transcript_hash.as_slice(), &info[info.len() - 32..]);
        let encoded = output.public.transcript.to_bytes()?;
        for forbidden in [
            fixed::<32>(&vector["seeds"]["ephemeral"])?,
            fixed(&vector["seeds"]["ratchet"])?,
            fixed(&vector["kdf"]["output"])?,
        ] {
            assert!(
                !encoded.windows(32).any(|part| part == forbidden),
                "private material in public projection"
            );
        }
        let NativeInitiatorHandoff { initial_sk, public: _, ratchet_seed } = output;
        drop(ratchet_seed);
        let state = OBS.with(RefCell::take).ok_or("observations")?;
        assert_eq!(state.seen.len(), if lease.opk.is_some() { 4 } else { 3 });
        let mut expected =
            BTreeMap::from([("e_seed", 1), ("r0_seed", 1), ("dh2", 1), ("dh3", 1), ("ikm", 1)]);
        if lease.opk.is_some() {
            expected.insert("dh4", 1);
        }
        assert_eq!(state.wipes, expected);
        drop(scope);
        assert!(*dh1 == fixed::<32>(&vector["dh"][0])?, "borrowed DH1 changed");
        Ok(initial_sk)
    })
}
fn native_rng_contract(rng: &mut dyn NativeBootstrapRng) -> Result {
    let mut first = Zeroizing::new([0; 32]);
    let mut second = Zeroizing::new([0; 32]);
    rng.fill_seed(&mut first)?;
    rng.fill_seed(&mut second)?;
    assert!(*first != *second, "RNG draw independence");
    assert!(
        PublicKey::from(&StaticSecret::from(*first))
            != PublicKey::from(&StaticSecret::from(*second)),
        "RNG effective key independence"
    );
    Ok(())
}
#[test]
fn dm_fs_v3_initiator_uses_independent_e_and_r0() -> Result {
    let c = crypto()?;
    for vector in c["bootstrap"].as_array().ok_or("bootstrap")? {
        independence_case(vector)?;
    }
    Ok(())
}
fn independence_case(v: &Value) -> Result {
    let (lease, t, dh1) = parts(v)?;
    let key = node_key();
    native_rng_contract(&mut FixtureRng::new(v)?)?;
    native_rng_contract(&mut NativeOsRng)?;
    let mut rng = FixtureRng::new(v)?;
    let result = native_initiator(input(&lease, &t, &key, &dh1), &mut rng);
    assert!(result.is_ok(), "independent E/R0 handoff must succeed");
    let result = result?;
    assert_ne!(
        result.public.transcript.header.ephemeral_key,
        result.public.transcript.header.ratchet_key
    );
    assert_eq!(rng.cursor, 2);
    // Retained R0 plus DH1/public data cannot reconstruct the captured E bootstrap.
    let mut retained_seed = Zeroizing::new([0; 32]);
    retained_seed.copy_from_slice(result.ratchet_seed.as_ref());
    let retained = StaticSecret::from(*retained_seed);
    let mut ikm = Zeroizing::new([0u8; 160]);
    ikm[..32].fill(0xff);
    ikm[32..64].copy_from_slice(&*dh1);
    ikm[64..96].copy_from_slice(
        retained.diffie_hellman(&PublicKey::from(lease.target.agreement_key)).as_bytes(),
    );
    ikm[96..128]
        .copy_from_slice(retained.diffie_hellman(&PublicKey::from(lease.base.spk_key)).as_bytes());
    let len = if let Some(opk) = &lease.opk {
        ikm[128..]
            .copy_from_slice(retained.diffie_hellman(&PublicKey::from(opk.opk_key)).as_bytes());
        160
    } else {
        128
    };
    let mut info = domain::DM_FS_V3_X3DH_ROOT.as_bytes().to_vec();
    info.extend_from_slice(&result.public.transcript_hash);
    let wrong = native_hkdf::<32>(&ikm[..len], &result.public.bundle_hash, &info)?;
    assert!(
        wrong.as_ref() != result.initial_sk.as_ref(),
        "retained ratchet secret reconstructed old bootstrap"
    );
    let one = native_initiator(input(&lease, &t, &key, &dh1), &mut NativeOsRng)?;
    let two = native_initiator(input(&lease, &t, &key, &dh1), &mut NativeOsRng)?;
    assert_ne!(
        one.public.transcript.header.ephemeral_key,
        two.public.transcript.header.ephemeral_key
    );
    assert_ne!(one.public.transcript.header.ratchet_key, two.public.transcript.header.ratchet_key);
    assert!(one.initial_sk.as_ref() != two.initial_sk.as_ref(), "fresh bootstrap repeated SK");
    Ok(())
}
#[test]
fn dm_fs_v3_all_zero_dh_rejected() -> Result {
    let c = crypto()?;
    for fixture in c["dh_refusals"].as_array().ok_or("DH refusals")? {
        let secret = StaticSecret::from(fixed::<32>(&fixture["private_seed"])?);
        let peer = fixed(&fixture["peer_public"])?;
        assert!(!secret.diffie_hellman(&PublicKey::from(peer)).was_contributory());
        assert!(matches!(
            super::bootstrap::checked_dh(&secret, &peer, "refusal_dh"),
            Err(NativeBootstrapError::NonContributory)
        ));
        assert_eq!(fixed::<32>(&fixture["shared_secret"])?, [0; 32]);
        assert_eq!(fixture["reject"], true);
    }
    let v = &c["bootstrap"][0];
    let (lease, t, _) = parts(v)?;
    let key = node_key();
    let zero = Zeroizing::new([0; 32]);
    let mut rng = FixtureRng::new(v)?;
    assert!(matches!(
        native_initiator(input(&lease, &t, &key, &zero), &mut rng),
        Err(NativeBootstrapError::NonContributory)
    ));
    assert_eq!(rng.cursor, 0);
    Ok(())
}
#[test]
fn dm_fs_v3_initiator_failure_and_limits() -> Result {
    let c = crypto()?;
    let v = &c["bootstrap"][0];
    let (lease, t, dh1) = parts(v)?;
    let key = node_key();
    for failed_draw in [0, 1] {
        OBS.with(|obs| {
            obs.replace(Some(Observation {
                expected: Vec::new(),
                seen: BTreeSet::new(),
                wipes: BTreeMap::new(),
            }));
        });
        let scope = Scope;
        let mut rng = FixtureRng::new(v)?;
        rng.fail_at = Some(failed_draw);
        assert!(matches!(
            native_initiator(input(&lease, &t, &key, &dh1), &mut rng),
            Err(NativeBootstrapError::Entropy)
        ));
        let state = OBS.with(RefCell::take).ok_or("wipes")?;
        let mut expected = BTreeMap::from([("e_seed", 1)]);
        if failed_draw == 1 {
            expected.insert("r0_seed", 1);
        }
        assert_eq!(state.wipes, expected);
        drop(scope);
    }
    let mut rng = FixtureRng::new(v)?;
    rng.seeds[1] = rng.seeds[0];
    assert_wipes(&["e_seed", "r0_seed"], || {
        assert!(matches!(
            native_initiator(input(&lease, &t, &key, &dh1), &mut rng),
            Err(NativeBootstrapError::RepeatedKey)
        ));
        Ok(())
    })?;
    let mut bad = t.clone();
    bad.header.routed_ad = vec![0; 4097];
    let mut rng = FixtureRng::new(v)?;
    assert!(matches!(
        native_initiator(input(&lease, &bad, &key, &dh1), &mut rng),
        Err(NativeBootstrapError::Decode(p::DecodeError::FieldCeiling))
    ));
    assert_eq!(rng.cursor, 0);
    let mut expired = input(&lease, &t, &key, &dh1);
    expired.now = t.header.deadline;
    assert!(matches!(
        native_initiator(expired, &mut rng),
        Err(NativeBootstrapError::Deadline(p::DeadlineError::Expired))
    ));
    let mut broken = lease.clone();
    broken.signature[0] ^= 1;
    assert!(matches!(
        native_initiator(input(&broken, &t, &key, &dh1), &mut rng),
        Err(NativeBootstrapError::Proof(NativePrekeyError::Signature))
    ));
    Ok(())
}

fn signed_noncontributory_peer(vector: &Value, peer: [u8; 32], which: &str) -> Result {
    let (mut lease, mut transcript, dh1) = parts(vector)?;
    if which == "opk" && lease.opk.is_none() {
        return Ok(());
    }
    let branch = crate::DeviceBranch {
        principal_id: "fixture-target".into(),
        device_id: "fixture-target-device".into(),
        device_epoch: 1,
        signing_key: ed25519_dalek::SigningKey::from_bytes(&[14; 32]),
    };
    let node = crate::DeviceBranch {
        principal_id: "fixture-node".into(),
        device_id: "fixture-node-device".into(),
        device_epoch: 1,
        signing_key: ed25519_dalek::SigningKey::from_bytes(&[60; 32]),
    };
    match which {
        "agreement" => {
            lease.target.agreement_key = peer;
            lease.base.branch = lease.target.clone();
        }
        "spk" => lease.base.spk_key = peer,
        "opk" => lease.opk.as_mut().ok_or("OPK")?.opk_key = peer,
        _ => return Err("peer field".into()),
    }
    lease.base = sign_base(lease.base, &branch)?;
    if let Some(mut opk) = lease.opk.take() {
        opk.branch_binding = branch_binding(&lease.target)?;
        lease.opk = Some(sign_opk(opk, &branch, &lease.target)?);
    }
    lease = sign_lease_result(lease, &node)?;
    transcript.header.target = lease.target.clone();
    transcript.header.base = lease.base.clone();
    transcript.header.base_hash = base_hash(&lease.base)?;
    transcript.header.bundle_hash = bundle_hash(&lease)?;
    transcript.header.opk_key = lease.opk.as_ref().map(|opk| opk.opk_key);
    let key = node.public_key();
    let mut rng = FixtureRng::new(vector)?;
    let mut expected = vec!["e_seed", "r0_seed", "dh2"];
    if which != "agreement" {
        expected.push("dh3");
    }
    if which == "opk" {
        expected.push("dh4");
    }
    assert_wipes(&expected, || {
        assert!(
            matches!(
                native_initiator(input(&lease, &transcript, &key, &dh1), &mut rng),
                Err(NativeBootstrapError::NonContributory)
            ),
            "signed non-contributory {which}"
        );
        Ok(())
    })?;
    Ok(())
}
#[test]
fn dm_fs_v3_initiator_signed_zero_peers_rejected() -> Result {
    let c = crypto()?;
    for vector in c["bootstrap"].as_array().ok_or("bootstrap")? {
        for fixture in c["dh_refusals"].as_array().ok_or("refusals")? {
            for which in ["agreement", "spk", "opk"] {
                signed_noncontributory_peer(vector, fixed(&fixture["peer_public"])?, which)?;
            }
        }
    }
    Ok(())
}

#[test]
fn dm_fs_v3_initiator_transcript_failure_erases_seeds() -> Result {
    let c = crypto()?;
    for v in c["bootstrap"].as_array().ok_or("bootstrap")? {
        let (lease, mut t, dh1) = parts(v)?;
        t.header.operation_id[0] ^= 1;
        let key = node_key();
        let mut rng = FixtureRng::new(v)?;
        assert_wipes(&["e_seed", "r0_seed"], || {
            assert!(matches!(
                native_initiator(input(&lease, &t, &key, &dh1), &mut rng),
                Err(NativeBootstrapError::Proof(NativePrekeyError::Binding))
            ));
            Ok(())
        })?;
        assert_eq!(rng.cursor, 2);
    }
    Ok(())
}
#[derive(Clone, Copy)]
enum DeadlineBound {
    IssuedAt,
    LeasedAt,
    SpkExpiry,
    EnvelopeTime,
    EnvelopeTtl,
    TtlPolicy,
    FutureLease,
    SpkValidity,
}
fn reseal_deadline(lease: &mut p::PrekeyLeaseResult, t: &mut p::BootstrapTranscript) -> Result {
    let branch = crate::DeviceBranch {
        principal_id: "fixture-target".into(),
        device_id: "fixture-device".into(),
        device_epoch: 1,
        signing_key: ed25519_dalek::SigningKey::from_bytes(&[14; 32]),
    };
    let node = crate::DeviceBranch {
        principal_id: "fixture-node".into(),
        device_id: "fixture-device".into(),
        device_epoch: 1,
        signing_key: ed25519_dalek::SigningKey::from_bytes(&[60; 32]),
    };
    lease.base = sign_base(lease.base.clone(), &branch)?;
    *lease = sign_lease_result(lease.clone(), &node)?;
    t.header.base = lease.base.clone();
    t.header.base_hash = base_hash(&lease.base)?;
    t.header.bundle_hash = bundle_hash(lease)?;
    t.header.issued_at = lease.issued_at;
    t.header.leased_at = lease.leased_at;
    t.header.deadline = lease.deadline;
    Ok(())
}
// Each baseline passes with every competing bound slack; change one independent
// input, then update only its dependent signed/header/hash representations.
fn deadline_negative(mode: &str, bound: DeadlineBound, error: p::DeadlineError) -> Result {
    let c = crypto()?;
    let v = c["bootstrap"]
        .as_array()
        .ok_or("bootstrap")?
        .iter()
        .find(|v| v["mode"] == mode)
        .ok_or("mode")?;
    let (mut lease, mut t, dh1) = parts(v)?;
    let horizon = u64::try_from(ramflux_protocol::MAX_ENVELOPE_TTL_SECONDS)?;
    let start = 2_000_000;
    lease.base.issued_at = start;
    lease.base.expires_at = start + 2 * horizon;
    lease.issued_at = start + 10;
    lease.leased_at = start + 10;
    lease.deadline = start + horizon + 1;
    t.envelope_created_at = start + 11;
    t.envelope_ttl = horizon;
    let now = match bound {
        DeadlineBound::IssuedAt => {
            lease.issued_at = start + 2;
            start + 10
        }
        DeadlineBound::LeasedAt => {
            lease.leased_at = start + 2;
            start + 10
        }
        DeadlineBound::SpkExpiry => {
            lease.base.expires_at = start + horizon + 2;
            lease.issued_at = start + horizon + 10;
            lease.leased_at = lease.issued_at;
            lease.deadline = start + 2 * horizon + 1;
            t.envelope_created_at = lease.issued_at + 10;
            lease.issued_at
        }
        DeadlineBound::EnvelopeTime => {
            lease.deadline = start + horizon / 2 + 1;
            t.envelope_ttl = horizon / 2;
            start + 10
        }
        DeadlineBound::EnvelopeTtl => {
            lease.deadline = start + horizon / 2 + 1;
            t.envelope_created_at = start;
            t.envelope_ttl = horizon / 2 + 10;
            start + 10
        }
        DeadlineBound::TtlPolicy | DeadlineBound::FutureLease | DeadlineBound::SpkValidity => {
            start + 10
        }
    };
    reseal_deadline(&mut lease, &mut t)?;
    let key = node_key();
    let mut baseline = input(&lease, &t, &key, &dh1);
    baseline.now = now;
    assert!(
        native_initiator(baseline, &mut FixtureRng::new(v)?).is_ok(),
        "deadline baseline must pass"
    );
    match bound {
        DeadlineBound::IssuedAt => lease.issued_at = start,
        DeadlineBound::LeasedAt => lease.leased_at = start,
        DeadlineBound::SpkExpiry => lease.base.expires_at = start + horizon,
        DeadlineBound::EnvelopeTime => t.envelope_created_at = start,
        DeadlineBound::EnvelopeTtl => t.envelope_ttl = horizon / 2,
        DeadlineBound::TtlPolicy => t.envelope_ttl = horizon + 1,
        DeadlineBound::FutureLease => {
            lease.leased_at = now + ramflux_protocol::custody::CLOCK_SKEW_SECONDS + 1;
        }
        DeadlineBound::SpkValidity => lease.base.issued_at = start - 1,
    }
    reseal_deadline(&mut lease, &mut t)?;
    let mut negative = input(&lease, &t, &key, &dh1);
    negative.now = now;
    let mut rng = FixtureRng::new(v)?;
    let result = native_initiator(negative, &mut rng);
    assert!(result.is_err(), "deadline bound must reject");
    if let Err(actual) = result {
        assert_eq!(actual, NativeBootstrapError::Deadline(error));
    }
    assert_eq!(rng.cursor, 0, "deadline rejects before entropy");
    Ok(())
}
#[test]
fn dm_fs_v3_initiator_deadline_spk_only_start() -> Result {
    deadline_negative("spk_only", DeadlineBound::IssuedAt, p::DeadlineError::ExceedsBound)
}
#[test]
fn dm_fs_v3_initiator_deadline_opk_start() -> Result {
    deadline_negative("opk", DeadlineBound::LeasedAt, p::DeadlineError::ExceedsBound)
}
#[test]
fn dm_fs_v3_initiator_deadline_spk_expiry() -> Result {
    for mode in ["opk", "spk_only"] {
        deadline_negative(mode, DeadlineBound::SpkExpiry, p::DeadlineError::ExceedsBound)?;
    }
    Ok(())
}
#[test]
fn dm_fs_v3_initiator_deadline_envelope_time() -> Result {
    for mode in ["opk", "spk_only"] {
        deadline_negative(mode, DeadlineBound::EnvelopeTime, p::DeadlineError::ExceedsBound)?;
    }
    Ok(())
}
#[test]
fn dm_fs_v3_initiator_deadline_envelope_ttl() -> Result {
    for mode in ["opk", "spk_only"] {
        deadline_negative(mode, DeadlineBound::EnvelopeTtl, p::DeadlineError::ExceedsBound)?;
    }
    Ok(())
}
#[test]
fn dm_fs_v3_initiator_deadline_ttl_policy() -> Result {
    for mode in ["opk", "spk_only"] {
        deadline_negative(mode, DeadlineBound::TtlPolicy, p::DeadlineError::Policy)?;
    }
    Ok(())
}
#[test]
fn dm_fs_v3_initiator_deadline_future_lease() -> Result {
    for mode in ["opk", "spk_only"] {
        deadline_negative(mode, DeadlineBound::FutureLease, p::DeadlineError::FutureLease)?;
    }
    Ok(())
}
#[test]
fn dm_fs_v3_initiator_deadline_spk_validity() -> Result {
    for mode in ["opk", "spk_only"] {
        deadline_negative(mode, DeadlineBound::SpkValidity, p::DeadlineError::Policy)?;
    }
    Ok(())
}
#[test]
fn dm_fs_v3_initiator_deadline_accepts_d_minus_one() -> Result {
    let c = crypto()?;
    for v in c["bootstrap"].as_array().ok_or("bootstrap")? {
        let (lease, t, dh1) = parts(v)?;
        let key = node_key();
        let mut accepted = input(&lease, &t, &key, &dh1);
        accepted.now = t.header.deadline - 1;
        let output = native_initiator(accepted, &mut FixtureRng::new(v)?)?;
        assert!(
            output.initial_sk.as_ref() == fixed::<32>(&v["kdf"]["output"])?,
            "D-1 golden mismatch"
        );
    }
    Ok(())
}

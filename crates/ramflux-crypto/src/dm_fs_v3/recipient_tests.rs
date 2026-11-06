// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use super::*;
use ramflux_protocol::dm_fs_v3 as p;
use serde_json::Value;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;
pub(super) type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;
pub(super) fn vectors() -> Result<Value> {
    Ok(serde_json::from_str(include_str!(
        "../../../ramflux-protocol/fixtures/dm_fs_v3/crypto_vectors.json"
    ))?)
}
fn raw(name: &str) -> Result<Vec<u8>> {
    let w: Value = serde_json::from_str(include_str!(
        "../../../ramflux-protocol/fixtures/dm_fs_v3/wire_vectors.json"
    ))?;
    let row = w["positive"]
        .as_array()
        .ok_or("positive")?
        .iter()
        .find(|v| v["name"] == name)
        .ok_or("vector")?;
    Ok(hex::decode(row["bytes"].as_str().ok_or("bytes")?)?)
}
pub(super) fn fixed(value: &Value) -> Result<[u8; 32]> {
    hex::decode(value.as_str().ok_or("hex")?)?.try_into().map_err(|_| "width".into())
}
pub(super) struct Case {
    pub lease: p::PrekeyLeaseResult,
    pub t: p::BootstrapTranscript,
    pub node: [u8; 32],
    pub spk: Zeroizing<[u8; 32]>,
    pub opk: Zeroizing<[u8; 32]>,
    pub dh2: Zeroizing<[u8; 32]>,
}
impl Case {
    pub fn new(v: &Value) -> Result<Self> {
        let mode = v["mode"].as_str().ok_or("mode")?;
        let lease = p::PrekeyLeaseResult::from_bytes(&raw(&format!("lease_{mode}"))?)?;
        let t = p::BootstrapTranscript::from_bytes(&raw(&format!("transcript_{mode}"))?)?;
        let identity = StaticSecret::from(fixed(&v["seeds"]["recipient_identity"])?);
        let dh2 = Zeroizing::new(
            identity.diffie_hellman(&PublicKey::from(t.header.ephemeral_key)).to_bytes(),
        );
        assert!(*dh2 == fixed(&v["dh"][1])?, "recipient DH2 oracle");
        Ok(Self {
            lease,
            t,
            node: ed25519_dalek::SigningKey::from_bytes(&[60; 32]).verifying_key().to_bytes(),
            spk: Zeroizing::new(fixed(&v["seeds"]["spk"])?),
            opk: Zeroizing::new(fixed(&v["seeds"]["opk"])?),
            dh2,
        })
    }
    pub fn input(&self) -> NativeRecipientInput<'_> {
        NativeRecipientInput {
            lease: &self.lease,
            transcript: &self.t,
            received_header: &self.t.header,
            node_key: &self.node,
            agreement_dh2: &self.dh2,
            spk: NativeSelectedSpk {
                spk_id: self.lease.base.spk_id,
                spk_serial: self.lease.base.spk_serial,
                generation: self.lease.base.generation,
                seed: &self.spk,
            },
            opk: self
                .lease
                .opk
                .as_ref()
                .map(|opk| NativeSelectedOpk { opk_id: opk.opk_id, seed: &self.opk }),
            envelope_created_at: self.t.envelope_created_at,
            envelope_ttl: self.t.envelope_ttl,
            routed_ad: &self.t.routed_ad,
            now: self.lease.issued_at,
        }
    }
}
pub(super) fn rejected(
    input: NativeRecipientInput<'_>,
    expected: NativeBootstrapError,
    name: &str,
) {
    let result = native_recipient(input);
    assert!(result.is_err(), "recipient accepted {name}");
    if let Err(actual) = result {
        assert_eq!(actual, expected, "{name}");
    }
}
fn binding() -> NativeBootstrapError {
    NativePrekeyError::Binding.into()
}
#[test]
fn dm_fs_v3_recipient_matches_independent_vectors() -> Result {
    super::initiator_tests::native_bootstrap_contract(|v| {
        let c = Case::new(v)?;
        let output = native_recipient(c.input())?;
        assert_eq!(output.public.transcript.to_bytes()?, c.t.to_bytes()?);
        assert_eq!(output.public.bundle_hash, c.t.header.bundle_hash);
        assert_eq!(output.public.transcript_hash, transcript_hash(&c.t)?);
        assert!(*c.dh2 == fixed(&v["dh"][1])?, "borrowed DH2 mutated");
        let public = output.public.transcript.to_bytes()?;
        for seed in v["seeds"]
            .as_object()
            .ok_or("seeds")?
            .values()
            .chain(std::iter::once(&v["kdf"]["output"]))
        {
            let secret = fixed(seed)?;
            assert!(
                !public.windows(32).any(|window| window == secret),
                "secret in recipient public projection"
            );
        }
        Ok(output.initial_sk)
    })
}
struct Seeds {
    e: Zeroizing<[u8; 32]>,
    r0: Zeroizing<[u8; 32]>,
    cursor: usize,
}
impl NativeBootstrapRng for Seeds {
    fn fill_seed(&mut self, out: &mut [u8; 32]) -> std::result::Result<(), NativeBootstrapError> {
        match self.cursor {
            0 => out.copy_from_slice(&*self.e),
            1 => out.copy_from_slice(&*self.r0),
            _ => return Err(NativeBootstrapError::Entropy),
        }
        self.cursor += 1;
        Ok(())
    }
}
#[test]
fn dm_fs_v3_recipient_round_trip_opk_and_spk_only() -> Result {
    let v = vectors()?;
    for v in v["bootstrap"].as_array().ok_or("bootstrap")? {
        let mut c = Case::new(v)?;
        let identity = StaticSecret::from(fixed(&v["seeds"]["initiator_identity"])?);
        let dh1 = Zeroizing::new(
            identity.diffie_hellman(&PublicKey::from(c.lease.base.spk_key)).to_bytes(),
        );
        let mut rng = Seeds {
            e: Zeroizing::new(fixed(&v["seeds"]["ephemeral"])?),
            r0: Zeroizing::new(fixed(&v["seeds"]["ratchet"])?),
            cursor: 0,
        };
        let initiator = native_initiator(
            NativeInitiatorInput {
                lease: &c.lease,
                header: c.t.header.clone(),
                node_key: &c.node,
                agreement_dh1: &dh1,
                envelope_created_at: c.t.envelope_created_at,
                envelope_ttl: c.t.envelope_ttl,
                now: c.lease.issued_at,
            },
            &mut rng,
        )?;
        c.t = initiator.public.transcript.clone();
        let recipient = native_recipient(c.input())?;
        assert!(
            recipient.initial_sk.as_ref() == initiator.initial_sk.as_ref(),
            "recipient round trip"
        );
        assert!(recipient.initial_sk.as_ref() == fixed(&v["kdf"]["output"])?, "recipient golden");
    }
    Ok(())
}
type Mutation = (&'static str, fn(&mut p::BootstrapHeader));
fn header_mutations() -> [Mutation; 22] {
    [
        ("profile", |h| h.profile.push('x')),
        ("source", |h| h.source.record_hash[0] ^= 1),
        ("target", |h| h.target.record_hash[0] ^= 1),
        ("base", |h| h.base.signature[0] ^= 1),
        ("base_hash", |h| h.base_hash[0] ^= 1),
        ("bundle_hash", |h| h.bundle_hash[0] ^= 1),
        ("spk_id", |h| h.spk_id[0] ^= 1),
        ("spk_serial", |h| h.spk_serial += 1),
        ("generation", |h| h.generation += 1),
        ("opk_id", |h| h.opk_id = Some([0; 32])),
        ("opk_key", |h| h.opk_key = Some([0; 32])),
        ("ephemeral", |h| h.ephemeral_key[0] ^= 1),
        ("ratchet", |h| h.ratchet_key[0] ^= 1),
        ("operation_id", |h| h.operation_id[0] ^= 1),
        ("issued_at", |h| h.issued_at += 1),
        ("leased_at", |h| h.leased_at += 1),
        ("conversation_id", |h| h.conversation_id[0] ^= 1),
        ("session_id", |h| h.session_id.push('x')),
        ("sequence", |h| h.sequence += 1),
        ("sequence_version", |h| h.sequence_version += 1),
        ("deadline", |h| h.deadline += 1),
        ("routed_ad", |h| h.routed_ad[0] ^= 1),
    ]
}
#[test]
fn dm_fs_v3_recipient_rejects_each_bound_field_exactly() -> Result {
    let v = vectors()?;
    let mut count = 0;
    for v in v["bootstrap"].as_array().ok_or("bootstrap")? {
        let c = Case::new(v)?;
        for (name, mutate) in header_mutations() {
            let mut t = c.t.clone();
            mutate(&mut t.header);
            let mut input = c.input();
            input.transcript = &t;
            let expected = if name == "profile"
                || (c.lease.opk.is_none() && matches!(name, "opk_id" | "opk_key"))
            {
                NativePrekeyError::Decode(p::DecodeError::Value).into()
            } else {
                binding()
            };
            rejected(input, expected, name);
            count += 1;
            // Lease-bound rows must fail even when the received header agrees.
            if matches!(
                name,
                "source"
                    | "target"
                    | "base"
                    | "base_hash"
                    | "bundle_hash"
                    | "spk_id"
                    | "spk_serial"
                    | "generation"
                    | "opk_id"
                    | "opk_key"
                    | "operation_id"
                    | "issued_at"
                    | "leased_at"
                    | "deadline"
                    | "routed_ad"
            ) {
                let mut input = c.input();
                input.transcript = &t;
                input.received_header = &t.header;
                rejected(input, expected, &format!("lease {name}"));
                count += 1;
            }
        }
        let mut paired = c.t.clone();
        if c.lease.opk.is_some() {
            paired.header.opk_id = None;
            paired.header.opk_key = None;
        } else {
            paired.header.opk_id = Some([0; 32]);
            paired.header.opk_key = Some([0; 32]);
        }
        let mut input = c.input();
        input.transcript = &paired;
        input.received_header = &paired.header;
        rejected(input, binding(), "OPK paired presence");
        for name in ["profile", "created_at", "ttl", "ad"] {
            let mut t = c.t.clone();
            match name {
                "profile" => t.profile.push('x'),
                "created_at" => t.envelope_created_at += 1,
                "ttl" => t.envelope_ttl += 1,
                _ => t.routed_ad[0] ^= 1,
            }
            let mut input = c.input();
            input.transcript = &t;
            rejected(
                input,
                if name == "profile" {
                    NativePrekeyError::Decode(p::DecodeError::Value).into()
                } else {
                    binding()
                },
                name,
            );
            count += 1;
        }
        reject_context_and_selection(&c)?;
    }
    assert_eq!(count, 82);
    Ok(())
}
fn reject_context_and_selection(c: &Case) -> Result {
    // Individually bind the separately supplied envelope context too.
    let mut input = c.input();
    input.envelope_created_at += 1;
    rejected(input, binding(), "received creation");
    let mut input = c.input();
    input.envelope_ttl += 1;
    rejected(input, binding(), "received ttl");
    let ad = [0u8; 4];
    let mut input = c.input();
    input.routed_ad = &ad;
    rejected(input, binding(), "received ad");
    let mut input = c.input();
    input.spk.spk_id[0] ^= 1;
    rejected(input, binding(), "selected SPK id");
    let mut input = c.input();
    input.spk.spk_serial += 1;
    rejected(input, binding(), "selected SPK serial");
    let mut input = c.input();
    input.spk.generation += 1;
    rejected(input, binding(), "selected SPK generation");
    let wrong = Zeroizing::new([42; 32]);
    let mut input = c.input();
    input.spk.seed = &wrong;
    rejected(input, binding(), "selected SPK key");
    if c.lease.opk.is_some() {
        let mut input = c.input();
        input.opk.as_mut().ok_or("OPK")?.opk_id[0] ^= 1;
        rejected(input, binding(), "selected OPK id");
        let mut input = c.input();
        input.opk.as_mut().ok_or("OPK")?.seed = &wrong;
        rejected(input, binding(), "selected OPK key");
        let mut input = c.input();
        input.opk = None;
        rejected(input, binding(), "missing selected OPK");
    } else {
        let mut input = c.input();
        input.opk = Some(NativeSelectedOpk { opk_id: [0; 32], seed: &wrong });
        rejected(input, binding(), "extra selected OPK");
    }
    let mut input = c.input();
    input.now = c.t.header.deadline;
    rejected(input, p::DeadlineError::Expired.into(), "deadline equality");
    let mut lease = c.lease.clone();
    lease.signature[0] ^= 1;
    let mut input = c.input();
    input.lease = &lease;
    rejected(input, NativePrekeyError::Signature.into(), "lease signature");
    let node = [0; 32];
    let mut input = c.input();
    input.node_key = &node;
    rejected(input, NativePrekeyError::Signature.into(), "node key");
    Ok(())
}
#[test]
fn dm_fs_v3_recipient_zero_dh_and_decoder_limits() -> Result {
    let v = vectors()?;
    for v in v["bootstrap"].as_array().ok_or("bootstrap")? {
        let c = Case::new(v)?;
        let zero = Zeroizing::new([0; 32]);
        let mut input = c.input();
        input.agreement_dh2 = &zero;
        rejected(input, NativeBootstrapError::NonContributory, "DH2");
        for fixture in vectors()?["dh_refusals"].as_array().ok_or("refusals")? {
            let peer = fixed(&fixture["peer_public"])?;
            let mut t = c.t.clone();
            t.header.ephemeral_key = peer;
            let mut input = c.input();
            input.transcript = &t;
            input.received_header = &t.header;
            rejected(input, NativeBootstrapError::NonContributory, "ephemeral low order");
        }
        let mut t = c.t.clone();
        t.header.routed_ad = vec![0; 4097];
        let mut input = c.input();
        input.transcript = &t;
        rejected(input, NativePrekeyError::Decode(p::DecodeError::FieldCeiling).into(), "AD cap+1");
    }
    for (name, kind) in [
        ("header_opk", p::WireType::BootstrapHeader),
        ("transcript_opk", p::WireType::BootstrapTranscript),
    ] {
        let mut bytes = raw(name)?;
        bytes.resize(kind.ceiling() + 1, 0);
        if kind == p::WireType::BootstrapHeader {
            assert_eq!(p::BootstrapHeader::from_bytes(&bytes), Err(p::DecodeError::TypeCeiling));
        } else {
            assert_eq!(
                p::BootstrapTranscript::from_bytes(&bytes),
                Err(p::DecodeError::TypeCeiling)
            );
        }
    }
    Ok(())
}

/// Publicly valid node proof with a noncontributory source agreement key.
pub(super) fn signed_source_peer(
    c: &Case,
    peer: [u8; 32],
) -> Result<(p::PrekeyLeaseResult, p::BootstrapTranscript)> {
    let node = crate::DeviceBranch {
        principal_id: "fixture-node".into(),
        device_id: "fixture-device".into(),
        device_epoch: 1,
        signing_key: ed25519_dalek::SigningKey::from_bytes(&[60; 32]),
    };
    let mut lease = c.lease.clone();
    lease.requester.agreement_key = peer;
    lease = sign_lease_result(lease, &node)?;
    let mut t = c.t.clone();
    t.header.source = lease.requester.clone();
    t.header.bundle_hash = bundle_hash(&lease)?;
    Ok((lease, t))
}
#[test]
fn dm_fs_v3_recipient_signed_zero_source_rejected() -> Result {
    let all = vectors()?;
    for v in all["bootstrap"].as_array().ok_or("bootstrap")? {
        let c = Case::new(v)?;
        for fixture in all["dh_refusals"].as_array().ok_or("refusals")? {
            let (lease, t) = signed_source_peer(&c, fixed(&fixture["peer_public"])?)?;
            let mut input = c.input();
            input.lease = &lease;
            input.transcript = &t;
            input.received_header = &t.header;
            rejected(input, NativeBootstrapError::NonContributory, "signed zero DH1");
        }
    }
    Ok(())
}

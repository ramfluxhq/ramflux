// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Dormant initiator: caller-owned agreement DH1, independent E/R0 and scoped SK.
use super::{
    NativeHkdfError, NativeHkdfOutput, NativePrekeyError, bootstrap_transcript, bundle_hash,
    native_hkdf, transcript_hash, verify_bootstrap_transcript, verify_lease_result,
};
use ramflux_protocol::{dm_fs_v3 as p, domain};
use x25519_dalek::{PublicKey, SharedSecret, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// Component failures contain no secret or untrusted input values.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum NativeBootstrapError {
    #[error(transparent)]
    Proof(#[from] NativePrekeyError),
    #[error(transparent)]
    Decode(#[from] p::DecodeError),
    #[error(transparent)]
    Deadline(#[from] p::DeadlineError),
    #[error(transparent)]
    Hkdf(#[from] NativeHkdfError),
    #[error("native bootstrap entropy unavailable")]
    Entropy,
    #[error("native bootstrap non-contributory agreement")]
    NonContributory,
    #[error("native bootstrap repeated E/R0 key")]
    RepeatedKey,
}
type Result<T> = std::result::Result<T, NativeBootstrapError>;
/// Entropy capability: each fill must supply a fresh independent cryptographic draw.
pub trait NativeBootstrapRng {
    /// Fill caller-owned guarded storage, without retaining or logging its bytes.
    /// # Errors
    /// Returns an entropy failure; the caller erases partial writes on every exit.
    fn fill_seed(&mut self, output: &mut [u8; 32]) -> Result<()>;
}
/// OS entropy implementation; no credential/provider material is retained.
pub struct NativeOsRng;
impl NativeBootstrapRng for NativeOsRng {
    fn fill_seed(&mut self, output: &mut [u8; 32]) -> Result<()> {
        getrandom::fill(output).map_err(|_| NativeBootstrapError::Entropy)
    }
}
/// Scoped caller-buffer owner, without Clone, Debug or serialization.
pub struct NativeBootstrapSecret<const N: usize> {
    bytes: [u8; N],
    slot: &'static str,
}
impl<const N: usize> NativeBootstrapSecret<N> {
    fn new(slot: &'static str) -> Self {
        Self { bytes: [0; N], slot }
    }
}
impl<const N: usize> std::ops::Deref for NativeBootstrapSecret<N> {
    type Target = [u8; N];
    fn deref(&self) -> &Self::Target {
        &self.bytes
    }
}
impl<const N: usize> Zeroize for NativeBootstrapSecret<N> {
    fn zeroize(&mut self) {
        self.bytes.zeroize();
    }
}
impl<const N: usize> Drop for NativeBootstrapSecret<N> {
    fn drop(&mut self) {
        self.zeroize();
        observe_wiped(self.slot, &self.bytes);
    }
}
impl<const N: usize> ZeroizeOnDrop for NativeBootstrapSecret<N> {}
struct ScopedKey {
    key: StaticSecret,
    slot: &'static str,
}
impl ScopedKey {
    fn new(seed: &[u8; 32], slot: &'static str) -> Self {
        Self { key: StaticSecret::from(*seed), slot }
    }
    fn public(&self) -> [u8; 32] {
        PublicKey::from(&self.key).to_bytes()
    }
}
impl Drop for ScopedKey {
    fn drop(&mut self) {
        self.key.zeroize();
        observe_wiped(self.slot, &self.key.to_bytes());
    }
}
pub(super) struct ScopedDh {
    value: SharedSecret,
    slot: &'static str,
}
impl ScopedDh {
    pub(super) fn as_bytes(&self) -> &[u8; 32] {
        self.value.as_bytes()
    }
}
impl Drop for ScopedDh {
    fn drop(&mut self) {
        self.value.zeroize();
        observe_wiped(self.slot, self.value.as_bytes());
    }
}
pub(super) fn checked_dh(
    secret: &StaticSecret,
    peer: &[u8; 32],
    slot: &'static str,
) -> Result<ScopedDh> {
    let value = ScopedDh { value: secret.diffie_hellman(&PublicKey::from(*peer)), slot };
    if !value.value.was_contributory() {
        return Err(NativeBootstrapError::NonContributory);
    }
    Ok(value)
}
/// Public inputs and borrowed DH1 supplied by the scoped agreement provider.
/// The caller binds DH1 to this source branch and the selected signed SPK.
/// Current authority and monotone-clock trust remain consumer-owned.
pub struct NativeInitiatorInput<'a> {
    pub lease: &'a p::PrekeyLeaseResult,
    pub header: p::BootstrapHeader,
    pub node_key: &'a [u8; 32],
    pub agreement_dh1: &'a Zeroizing<[u8; 32]>,
    pub envelope_created_at: u64,
    pub envelope_ttl: u64,
    pub now: u64,
}
/// Public projection cannot serialize the ephemeral seed or initial SK.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NativeBootstrapPublic {
    pub transcript: p::BootstrapTranscript,
    pub bundle_hash: [u8; 32],
    pub transcript_hash: [u8; 32],
}
/// Temporary secret handoff only; deliberately no Clone/Debug/serde or snapshot API.
pub struct NativeInitiatorHandoff {
    pub public: NativeBootstrapPublic,
    pub initial_sk: NativeHkdfOutput<32>,
    pub ratchet_seed: NativeBootstrapSecret<32>,
}
/// Derive the fixed native X3DH transcript and initial secret with fresh E and R0.
/// # Errors
/// Rejects proof/encoding/time failures, entropy failures, repeated keys and zero DH.
pub fn native_initiator(
    mut input: NativeInitiatorInput<'_>,
    rng: &mut dyn NativeBootstrapRng,
) -> Result<NativeInitiatorHandoff> {
    verify_lease_result(input.lease, input.node_key)?;
    input.header.to_bytes()?;
    let validity = input
        .lease
        .base
        .expires_at
        .checked_sub(input.lease.base.issued_at)
        .ok_or(p::DeadlineError::Policy)?;
    p::validate_bootstrap_deadline(&p::DeadlineInputs {
        mode: if input.lease.opk.is_some() {
            p::BootstrapMode::Opk
        } else {
            p::BootstrapMode::SpkOnly
        },
        now: input.now,
        deadline: input.header.deadline,
        ttl: input.envelope_ttl,
        spk_validity_seconds: validity,
        leased_at: input.lease.leased_at,
        issued_at: input.lease.issued_at,
        spk_expires_at: input.lease.base.expires_at,
        envelope_created_at: input.envelope_created_at,
    })?;
    if input.agreement_dh1.iter().fold(0u8, |sum, b| sum | b) == 0 {
        return Err(NativeBootstrapError::NonContributory);
    }
    let mut e_seed = NativeBootstrapSecret::<32>::new("e_seed");
    rng.fill_seed(&mut e_seed.bytes)?;
    let mut r0_seed = NativeBootstrapSecret::<32>::new("r0_seed");
    rng.fill_seed(&mut r0_seed.bytes)?;
    let ephemeral = ScopedKey::new(&e_seed, "ephemeral_key");
    let ratchet = ScopedKey::new(&r0_seed, "ratchet_key");
    if ephemeral.public() == ratchet.public() {
        return Err(NativeBootstrapError::RepeatedKey);
    }
    input.header.ephemeral_key = ephemeral.public();
    input.header.ratchet_key = ratchet.public();
    let routed_ad = input.header.routed_ad.clone();
    let transcript = bootstrap_transcript(
        input.header,
        input.envelope_created_at,
        input.envelope_ttl,
        routed_ad,
    )?;
    verify_bootstrap_transcript(&transcript, input.lease, input.node_key)?;
    let bundle = bundle_hash(input.lease)?;
    let hash = transcript_hash(&transcript)?;
    let dh2 = checked_dh(&ephemeral.key, &input.lease.target.agreement_key, "dh2")?;
    let dh3 = checked_dh(&ephemeral.key, &input.lease.base.spk_key, "dh3")?;
    let dh4 = input
        .lease
        .opk
        .as_ref()
        .map(|opk| checked_dh(&ephemeral.key, &opk.opk_key, "dh4"))
        .transpose()?;
    observe_dh(0, input.agreement_dh1);
    observe_dh(1, dh2.as_bytes());
    observe_dh(2, dh3.as_bytes());
    let mut ikm = NativeBootstrapSecret::<160>::new("ikm");
    ikm.bytes[..32].fill(0xff);
    ikm.bytes[32..64].copy_from_slice(&**input.agreement_dh1);
    ikm.bytes[64..96].copy_from_slice(dh2.as_bytes());
    ikm.bytes[96..128].copy_from_slice(dh3.as_bytes());
    let length = if let Some(dh4) = &dh4 {
        observe_dh(3, dh4.as_bytes());
        ikm.bytes[128..].copy_from_slice(dh4.as_bytes());
        160
    } else {
        128
    };
    let mut info = domain::DM_FS_V3_X3DH_ROOT.as_bytes().to_vec();
    info.extend_from_slice(&hash);
    let initial_sk = native_hkdf::<32>(&ikm.bytes[..length], &bundle, &info)?;
    Ok(NativeInitiatorHandoff {
        public: NativeBootstrapPublic { transcript, bundle_hash: bundle, transcript_hash: hash },
        initial_sk,
        ratchet_seed: r0_seed,
    })
}
#[cfg(test)]
fn observe_dh(index: usize, bytes: &[u8; 32]) {
    super::initiator_tests::observe_dh(index, bytes);
}
#[cfg(not(test))]
fn observe_dh(_index: usize, _bytes: &[u8; 32]) {}
#[cfg(test)]
fn observe_wiped(slot: &'static str, bytes: &[u8]) {
    super::initiator_tests::observe_wiped(slot, bytes);
}
#[cfg(not(test))]
fn observe_wiped(_slot: &'static str, _bytes: &[u8]) {}

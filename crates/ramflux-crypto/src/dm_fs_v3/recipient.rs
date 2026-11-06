// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Scoped recipient component. No provider, persistence, admission or payload decryption.
use super::{
    NativeBootstrapError, NativeBootstrapPublic, NativeHkdfOutput, NativePrekeyError, bundle_hash,
    native_hkdf, transcript_hash, verify_bootstrap_transcript,
};
use ramflux_protocol::{dm_fs_v3 as p, domain};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};
type Result<T> = std::result::Result<T, NativeBootstrapError>;

/// A named, borrowed SPK selected by the caller's current key provider.
/// The component verifies the name and derived public key against the signed base.
pub struct NativeSelectedSpk<'a> {
    pub spk_id: [u8; 32],
    pub spk_serial: u64,
    pub generation: u64,
    pub seed: &'a Zeroizing<[u8; 32]>,
}
/// A named borrowed OPK. Presence must match the authenticated lease exactly.
pub struct NativeSelectedOpk<'a> {
    pub opk_id: [u8; 32],
    pub seed: &'a Zeroizing<[u8; 32]>,
}
/// Received envelope inputs, separate from the proposed transcript.
/// The caller supplies the actual parsed header and independently routed metadata;
/// payload authentication, authority, monotone time and key retirement remain caller-owned.
pub struct NativeRecipientInput<'a> {
    pub lease: &'a p::PrekeyLeaseResult,
    pub transcript: &'a p::BootstrapTranscript,
    pub received_header: &'a p::BootstrapHeader,
    pub node_key: &'a [u8; 32],
    /// Provider-owned agreement DH2, bound to the target branch and received E.
    pub agreement_dh2: &'a Zeroizing<[u8; 32]>,
    pub spk: NativeSelectedSpk<'a>,
    pub opk: Option<NativeSelectedOpk<'a>>,
    pub envelope_created_at: u64,
    pub envelope_ttl: u64,
    pub routed_ad: &'a [u8],
    pub now: u64,
}
/// Temporary SK handoff, without Clone, Debug, serialization or a snapshot API.
pub struct NativeRecipientHandoff {
    pub public: NativeBootstrapPublic,
    pub initial_sk: NativeHkdfOutput<32>,
}
struct Secret<const N: usize> {
    bytes: [u8; N],
    slot: &'static str,
}
impl<const N: usize> Secret<N> {
    fn new(slot: &'static str) -> Self {
        Self { bytes: [0; N], slot }
    }
}
impl<const N: usize> Drop for Secret<N> {
    fn drop(&mut self) {
        self.bytes.zeroize();
        observe(self.slot, &self.bytes);
    }
}
impl<const N: usize> ZeroizeOnDrop for Secret<N> {}
fn dh(key: &StaticSecret, peer: &[u8; 32], slot: &'static str) -> Result<Secret<32>> {
    // Dalek's concrete secret/shared-secret owners erase their arrays at Drop.
    let shared = key.diffie_hellman(&PublicKey::from(*peer));
    let mut owned = Secret::new(slot);
    owned.bytes.copy_from_slice(shared.as_bytes());
    if !shared.was_contributory() {
        return Err(NativeBootstrapError::NonContributory);
    }
    Ok(owned)
}
fn binding() -> NativeBootstrapError {
    NativePrekeyError::Binding.into()
}
fn validate(input: &NativeRecipientInput<'_>) -> Result<()> {
    let t = input.transcript;
    verify_bootstrap_transcript(t, input.lease, input.node_key)?;
    if t.header != *input.received_header
        || t.profile != t.header.profile
        || t.envelope_created_at != input.envelope_created_at
        || t.envelope_ttl != input.envelope_ttl
        || t.routed_ad != input.routed_ad
    {
        return Err(binding());
    }
    let base = &input.lease.base;
    let validity = base.expires_at.checked_sub(base.issued_at).ok_or(p::DeadlineError::Policy)?;
    p::validate_bootstrap_deadline(&p::DeadlineInputs {
        mode: if input.lease.opk.is_some() {
            p::BootstrapMode::Opk
        } else {
            p::BootstrapMode::SpkOnly
        },
        now: input.now,
        deadline: t.header.deadline,
        ttl: input.envelope_ttl,
        spk_validity_seconds: validity,
        leased_at: input.lease.leased_at,
        issued_at: input.lease.issued_at,
        spk_expires_at: base.expires_at,
        envelope_created_at: input.envelope_created_at,
    })?;
    if input.spk.spk_id != base.spk_id
        || input.spk.spk_serial != base.spk_serial
        || input.spk.generation != base.generation
        || input.opk.is_some() != input.lease.opk.is_some()
    {
        return Err(binding());
    }
    if input.agreement_dh2.iter().all(|b| *b == 0) {
        return Err(NativeBootstrapError::NonContributory);
    }
    Ok(())
}
/// Verify all public bindings and derive the native recipient's scoped initial SK.
/// This synchronous operation never suspends; dropping its containing operation
/// erases returned SK, and every early return drops all allocated transient owners.
/// # Errors
/// Rejects canonical/proof/time failures, named-key mismatches and noncontributory DH.
pub fn native_recipient(input: NativeRecipientInput<'_>) -> Result<NativeRecipientHandoff> {
    validate(&input)?;
    let t = input.transcript;
    let base = &input.lease.base;
    #[cfg(test)]
    checkpoint("validated")?;
    let mut spk_seed = Secret::<32>::new("recipient_spk_seed");
    spk_seed.bytes.copy_from_slice(&**input.spk.seed);
    let spk = StaticSecret::from(spk_seed.bytes);
    if PublicKey::from(&spk).to_bytes() != base.spk_key {
        return Err(binding());
    }
    #[cfg(test)]
    checkpoint("spk")?;
    let dh1 = dh(&spk, &t.header.source.agreement_key, "recipient_dh1")?;
    #[cfg(test)]
    checkpoint("dh1")?;
    let dh3 = dh(&spk, &t.header.ephemeral_key, "recipient_dh3")?;
    #[cfg(test)]
    checkpoint("dh3")?;
    let dh4 = match (input.opk, &input.lease.opk) {
        (Some(selected), Some(public)) => {
            if selected.opk_id != public.opk_id {
                return Err(binding());
            }
            let mut seed = Secret::<32>::new("recipient_opk_seed");
            seed.bytes.copy_from_slice(&**selected.seed);
            let key = StaticSecret::from(seed.bytes);
            if PublicKey::from(&key).to_bytes() != public.opk_key {
                return Err(binding());
            }
            #[cfg(test)]
            checkpoint("opk")?;
            Some(dh(&key, &t.header.ephemeral_key, "recipient_dh4")?)
        }
        (None, None) => None,
        _ => return Err(binding()),
    };
    #[cfg(test)]
    checkpoint("dh4")?;
    let mut ikm = Secret::<160>::new("recipient_ikm");
    ikm.bytes[..32].fill(0xff);
    ikm.bytes[32..64].copy_from_slice(&dh1.bytes);
    ikm.bytes[64..96].copy_from_slice(&**input.agreement_dh2);
    ikm.bytes[96..128].copy_from_slice(&dh3.bytes);
    let length = if let Some(dh4) = &dh4 {
        ikm.bytes[128..].copy_from_slice(&dh4.bytes);
        160
    } else {
        128
    };
    #[cfg(test)]
    checkpoint("ikm")?;
    let bundle = bundle_hash(input.lease)?;
    let hash = transcript_hash(t)?;
    let mut info = domain::DM_FS_V3_X3DH_ROOT.as_bytes().to_vec();
    info.extend_from_slice(&hash);
    let initial_sk = native_hkdf::<32>(&ikm.bytes[..length], &bundle, &info)?;
    #[cfg(test)]
    checkpoint("derived")?;
    Ok(NativeRecipientHandoff {
        public: NativeBootstrapPublic {
            transcript: t.clone(),
            bundle_hash: bundle,
            transcript_hash: hash,
        },
        initial_sk,
    })
}
#[cfg(test)]
fn observe(slot: &'static str, bytes: &[u8]) {
    super::secret_tests::observe(slot, bytes);
}
#[cfg(not(test))]
fn observe(_slot: &'static str, _bytes: &[u8]) {}
#[cfg(test)]
fn checkpoint(stage: &'static str) -> Result<()> {
    super::secret_tests::checkpoint(stage)
}

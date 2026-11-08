// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! RFC 9180 Auth HPKE for cooperative transfer. Unwired: one Seal/Open at sequence 0.
//! Owned X25519 seeds are taken by move ([`HpkeSecrets`]) and wiped at the end of every
//! setup, success or error. hpke still holds KEM DH, HKDF PRK and AEAD key-schedule
//! copies inside `AeadCtx` until drop; aes-gcm 0.11 `zeroize` wipes AES round keys and
//! GHASH on that drop. Encapped-key bytes and the CSPRNG seed owned here are Zeroizing.

use super::cleanup::HpkeSecrets;
use crate::CryptoError;
use aes_gcm_hpke as _;
use chacha20::cipher::{KeyIvInit, StreamCipher};
use hpke::aead::{AeadCtxR, AeadCtxS, AesGcm256};
use hpke::kdf::HkdfSha256;
use hpke::kem::X25519HkdfSha256;
use hpke::rand_core::{TryCryptoRng, TryRng};
use hpke::{
    Deserializable, Kem, OpModeR, OpModeS, Serializable, setup_receiver, setup_sender_with_rng,
};
use ramflux_protocol::{MAX_SAFE_JSON_INTEGER, canonical_json_bytes, domain, encode_base64url};
use serde::Serialize;
use std::convert::Infallible;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::{Zeroize, Zeroizing};

type SuiteKem = X25519HkdfSha256;
type SuiteKdf = HkdfSha256;
type SuiteAead = AesGcm256;
type KemSk = <SuiteKem as Kem>::PrivateKey;
type KemPk = <SuiteKem as Kem>::PublicKey;
type KemEnc = <SuiteKem as Kem>::EncappedKey;
type SenderCtx = AeadCtxS<SuiteAead, SuiteKdf, SuiteKem>;
type ReceiverCtx = AeadCtxR<SuiteAead, SuiteKdf, SuiteKem>;

/// Simultaneous conservative handover plaintext bound (plan D6). Isolated by max / max+1.
pub const MAX_HPKE_PLAINTEXT: usize = 464_384;
/// AES-GCM tag length. Open rejects ciphertext longer than plaintext max plus this.
pub const MAX_HPKE_AEAD_TAG: usize = 16;
const INFO_LEN_LIMIT: usize = 65_530;

/// Transfer AAD fields bound into every Seal/Open.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TransferHpkeAad {
    pub transfer_id: [u8; 32],
    pub current_record_hash: [u8; 32],
    pub device_set_epoch: u64,
}

/// Sender Auth context. Exactly one Seal, then destroy. The X25519 seed is not retained.
pub struct HpkeSender {
    enc: [u8; 32],
    aad: Vec<u8>,
    used: bool,
    ctx: Option<SenderCtx>,
}

/// Recipient Auth context. Exactly one Open, then destroy. The X25519 seed is not retained.
pub struct HpkeReceiver {
    aad: Vec<u8>,
    used: bool,
    ctx: Option<ReceiverCtx>,
}

struct SeededCsPrng {
    cipher: chacha20::ChaCha20,
}

#[derive(Serialize)]
struct AadWire<'a> {
    current_record_hash: &'a str,
    device_set_epoch: u64,
    schema: &'a str,
    transfer_id: &'a str,
    version: u32,
}

impl SeededCsPrng {
    fn from_seed(seed: &[u8; 32]) -> Self {
        let nonce = chacha20::Nonce::from([0_u8; 12]);
        Self { cipher: chacha20::ChaCha20::new(seed.into(), &nonce) }
    }
}

impl TryRng for SeededCsPrng {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Infallible> {
        let mut bytes = [0_u8; 4];
        self.try_fill_bytes(&mut bytes)?;
        Ok(u32::from_le_bytes(bytes))
    }

    fn try_next_u64(&mut self) -> Result<u64, Infallible> {
        let mut bytes = [0_u8; 8];
        self.try_fill_bytes(&mut bytes)?;
        Ok(u64::from_le_bytes(bytes))
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Infallible> {
        dst.fill(0);
        self.cipher.apply_keystream(dst);
        Ok(())
    }
}

impl TryCryptoRng for SeededCsPrng {}

impl HpkeSender {
    /// Setup Auth sender: fresh transfer-only `sender_sk` taken by move, recipient HPKE public, framed info.
    ///
    /// # Errors
    /// Rejects all-zero/reflected keys, oversize info, missing entropy, or KEM setup failure.
    pub fn setup(
        mut sender_sk: HpkeSecrets,
        recipient_pk: &[u8; 32],
        transcript_hash: &[u8; 32],
        aad: &TransferHpkeAad,
    ) -> Result<Self, CryptoError> {
        let result = setup_sender_body(sender_sk.as_bytes(), recipient_pk, transcript_hash, aad);
        sender_sk.cleanup();
        result
    }

    #[must_use]
    pub fn enc(&self) -> [u8; 32] {
        self.enc
    }

    /// Seal once at sequence 0. Further Seal calls fail and wipe.
    ///
    /// # Errors
    /// Rejects oversize plaintext, a used context, or AEAD failure.
    pub fn seal(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        if plaintext.len() > MAX_HPKE_PLAINTEXT {
            return self.fail("payload_size");
        }
        if self.used {
            return self.fail("already_used");
        }
        let Some(mut ctx) = self.ctx.take() else {
            return self.fail("already_used");
        };
        let sealed = ctx.seal(plaintext, &self.aad).map_err(|_| CryptoError::Pairing("hpke_aead"));
        self.used = true;
        drop(ctx);
        sealed
    }

    /// Drop the AEAD context. The X25519 seed was already wiped at setup.
    pub fn cleanup(&mut self) {
        self.ctx = None;
        self.used = true;
    }

    fn fail<T>(&mut self, reason: &'static str) -> Result<T, CryptoError> {
        self.cleanup();
        Err(CryptoError::Pairing(reason))
    }
}

impl HpkeReceiver {
    /// Setup Auth receiver with the sender's transfer-only public key and encapsulated key.
    ///
    /// # Errors
    /// Rejects all-zero/reflected keys, oversize info, or KEM decap failure.
    pub fn setup(
        mut recipient_sk: HpkeSecrets,
        sender_pk: &[u8; 32],
        enc: &[u8; 32],
        transcript_hash: &[u8; 32],
        aad: &TransferHpkeAad,
    ) -> Result<Self, CryptoError> {
        let result =
            setup_receiver_body(recipient_sk.as_bytes(), sender_pk, enc, transcript_hash, aad);
        recipient_sk.cleanup();
        result
    }

    /// Open once at sequence 0. Further Open calls fail and wipe.
    ///
    /// # Errors
    /// Rejects a used context or AEAD authentication failure (wrong sender/info/AAD).
    pub fn open(&mut self, ciphertext: &[u8]) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
        if ciphertext.len() > MAX_HPKE_PLAINTEXT + MAX_HPKE_AEAD_TAG {
            return self.fail("payload_size");
        }
        if self.used {
            return self.fail("already_used");
        }
        let Some(mut ctx) = self.ctx.take() else {
            return self.fail("already_used");
        };
        let opened = ctx.open(ciphertext, &self.aad).map_err(|_| CryptoError::Pairing("hpke_open"));
        self.used = true;
        drop(ctx);
        Ok(Zeroizing::new(opened?))
    }

    /// Drop the AEAD context. The X25519 seed was already wiped at setup.
    pub fn cleanup(&mut self) {
        self.ctx = None;
        self.used = true;
    }

    fn fail<T>(&mut self, reason: &'static str) -> Result<T, CryptoError> {
        self.cleanup();
        Err(CryptoError::Pairing(reason))
    }
}

fn setup_sender_body(
    sender_sk: &[u8; 32],
    recipient_pk: &[u8; 32],
    transcript_hash: &[u8; 32],
    aad: &TransferHpkeAad,
) -> Result<HpkeSender, CryptoError> {
    let keys = local_and_peer(sender_sk, recipient_pk)?;
    let info = framed_info(transcript_hash)?;
    let aad_bytes = aad_bytes(aad)?;
    let mut seed = Zeroizing::new([0_u8; 32]);
    getrandom::fill(&mut *seed)
        .map_err(|error| CryptoError::RandomUnavailable(error.to_string()))?;
    let mut rng = SeededCsPrng::from_seed(&seed);
    seed.zeroize();
    let (encapped, ctx) = setup_sender_with_rng::<SuiteAead, SuiteKdf, SuiteKem>(
        &OpModeS::Auth((keys.local_sk, keys.local_pk)),
        &keys.peer_pk,
        &info,
        &mut rng,
    )
    .map_err(|_| CryptoError::Pairing("hpke_setup"))?;
    Ok(HpkeSender { enc: enc_bytes(&encapped)?, aad: aad_bytes, used: false, ctx: Some(ctx) })
}

fn setup_receiver_body(
    recipient_sk: &[u8; 32],
    sender_pk: &[u8; 32],
    enc: &[u8; 32],
    transcript_hash: &[u8; 32],
    aad: &TransferHpkeAad,
) -> Result<HpkeReceiver, CryptoError> {
    let keys = local_and_peer(recipient_sk, sender_pk)?;
    let info = framed_info(transcript_hash)?;
    let aad_bytes = aad_bytes(aad)?;
    let encapped = KemEnc::from_bytes(enc).map_err(|_| CryptoError::Pairing("enc"))?;
    let ctx = setup_receiver::<SuiteAead, SuiteKdf, SuiteKem>(
        &auth_receiver_mode(keys.peer_pk),
        &keys.local_sk,
        &encapped,
        &info,
    )
    .map_err(|_| CryptoError::Pairing("hpke_setup"))?;
    Ok(HpkeReceiver { aad: aad_bytes, used: false, ctx: Some(ctx) })
}

struct LocalPeerKeys {
    local_sk: KemSk,
    local_pk: KemPk,
    peer_pk: KemPk,
}

fn local_and_peer(secret: &[u8; 32], peer_pk: &[u8; 32]) -> Result<LocalPeerKeys, CryptoError> {
    if secret.iter().all(|byte| *byte == 0) || peer_pk.iter().all(|byte| *byte == 0) {
        return Err(CryptoError::Pairing("all_zero_hpke_key"));
    }
    let local_pk = PublicKey::from(&StaticSecret::from(*secret)).to_bytes();
    if local_pk == *peer_pk {
        return Err(CryptoError::Pairing("reflection"));
    }
    Ok(LocalPeerKeys {
        local_sk: KemSk::from_bytes(secret).map_err(|_| CryptoError::Pairing("hpke_key"))?,
        local_pk: KemPk::from_bytes(&local_pk).map_err(|_| CryptoError::Pairing("hpke_key"))?,
        peer_pk: KemPk::from_bytes(peer_pk).map_err(|_| CryptoError::Pairing("hpke_key"))?,
    })
}

fn auth_receiver_mode(sender_pk: KemPk) -> OpModeR<'static, SuiteKem> {
    OpModeR::Auth(sender_pk)
}

pub(super) fn framed_info(transcript_hash: &[u8; 32]) -> Result<Vec<u8>, CryptoError> {
    let label = domain::CUSTODY_TRANSFER_HPKE_INFO.as_bytes();
    let mut info = Vec::with_capacity(label.len() + 1 + transcript_hash.len());
    info.extend_from_slice(label);
    info.push(0);
    info.extend_from_slice(transcript_hash);
    if info.len() > INFO_LEN_LIMIT {
        return Err(CryptoError::Pairing("info"));
    }
    Ok(info)
}

pub(super) fn aad_bytes(aad: &TransferHpkeAad) -> Result<Vec<u8>, CryptoError> {
    if aad.device_set_epoch > MAX_SAFE_JSON_INTEGER {
        return Err(CryptoError::Pairing("device_set_epoch"));
    }
    let transfer_id = encode_base64url(aad.transfer_id);
    let current_record_hash = encode_base64url(aad.current_record_hash);
    canonical_json_bytes(&AadWire {
        current_record_hash: &current_record_hash,
        device_set_epoch: aad.device_set_epoch,
        schema: domain::CUSTODY_TRANSFER_AAD,
        transfer_id: &transfer_id,
        version: 1,
    })
    .map_err(Into::into)
}

fn enc_bytes(encapped: &KemEnc) -> Result<[u8; 32], CryptoError> {
    <[u8; 32]>::try_from(encapped.to_bytes().as_slice()).map_err(|_| CryptoError::Pairing("enc"))
}

#[cfg(test)]
pub(super) fn open_rfc9180_auth_vector(
    recipient_sk: &[u8; 32],
    sender_pk: &[u8; 32],
    enc: &[u8; 32],
    info: &[u8],
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    if info.len() > INFO_LEN_LIMIT {
        return Err(CryptoError::Pairing("info"));
    }
    let sk = KemSk::from_bytes(recipient_sk).map_err(|_| CryptoError::Pairing("hpke_key"))?;
    let pk = KemPk::from_bytes(sender_pk).map_err(|_| CryptoError::Pairing("hpke_key"))?;
    let encapped = KemEnc::from_bytes(enc).map_err(|_| CryptoError::Pairing("enc"))?;
    let mut ctx = setup_receiver::<SuiteAead, SuiteKdf, SuiteKem>(
        &auth_receiver_mode(pk),
        &sk,
        &encapped,
        info,
    )
    .map_err(|_| CryptoError::Pairing("hpke_setup"))?;
    let plaintext = ctx.open(ciphertext, aad).map_err(|_| CryptoError::Pairing("hpke_open"))?;
    Ok(Zeroizing::new(plaintext))
}

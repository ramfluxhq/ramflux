// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Authenticated key slots (design section 2.4.1): HPKE base mode (RFC 9180) with
//! `info = "rf-lg-slot-v1" ‖ group_id ‖ I2OSP(key_epoch, 8) ‖ I2OSP(prev_key_seq, 8) ‖ P` (93 B).

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use hpke::aead::ChaCha20Poly1305;
use hpke::kdf::HkdfSha256;
use hpke::kem::{Kem, X25519HkdfSha256};
use hpke::{Deserializable, OpModeR, OpModeS, Serializable, setup_receiver, setup_sender_with_rng};
use zeroize::Zeroizing;

use super::codec::{Dec, Enc};
use super::rng::SeedRng;
use super::{EpochKey, LgError, random_array};

type SuiteKem = X25519HkdfSha256;
type SuiteKdf = HkdfSha256;
type SuiteAead = ChaCha20Poly1305;

const SLOT_INFO_PREFIX: &[u8; 13] = b"rf-lg-slot-v1";
const BODY_DOMAIN: &[u8] = b"rf-lg-keybody-v1";
const SLOT_PLAIN_DOMAIN: &[u8] = b"rf-lg-slotplain-v1";
const ENCAP_LEN: usize = 32;
const MAX_CERT: usize = 2048;
const MAX_ROSTER_HEAD: usize = 1024;
const MAX_ADMIN_CHAIN: usize = 16 * 1024;
const MAX_SLOT_PLAIN: usize = 24 * 1024;

/// The signed body of every entry that moves the content key (`W`, `W'`, `W'_redeliver`, `R`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedKeyBody {
    pub group_id: [u8; 32],
    pub kind: u8,
    pub key_epoch: u64,
    pub prev_key_seq: u64,
    pub slot_root: [u8; 32],
    pub slot_count: u32,
    pub kc: [u8; 32],
    pub admin_chain_head: [u8; 32],
    pub join_pk_new: Option<[u8; 32]>,
}

impl SignedKeyBody {
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut enc = Enc::new(BODY_DOMAIN);
        enc.fixed(&self.group_id)
            .u8(self.kind)
            .u64(self.key_epoch)
            .u64(self.prev_key_seq)
            .fixed(&self.slot_root)
            .u32(self.slot_count)
            .fixed(&self.kc)
            .fixed(&self.admin_chain_head);
        match &self.join_pk_new {
            Some(key) => enc.u8(1).fixed(key),
            None => enc.u8(0),
        };
        enc.finish()
    }

    fn decode_from(dec: &mut Dec<'_>) -> Result<Self, LgError> {
        if dec.var(BODY_DOMAIN.len())? != BODY_DOMAIN {
            return Err(LgError::Format("key body domain"));
        }
        let group_id = dec.fixed()?;
        let kind = dec.u8()?;
        let key_epoch = dec.u64()?;
        let prev_key_seq = dec.u64()?;
        let slot_root = dec.fixed()?;
        let slot_count = dec.u32()?;
        let kc = dec.fixed()?;
        let admin_chain_head = dec.fixed()?;
        let join_pk_new = match dec.u8()? {
            0 => None,
            1 => Some(dec.fixed()?),
            _ => return Err(LgError::Format("join key flag")),
        };
        Ok(Self {
            group_id,
            kind,
            key_epoch,
            prev_key_seq,
            slot_root,
            slot_count,
            kc,
            admin_chain_head,
            join_pk_new,
        })
    }

    /// Ed25519 signature (admin `P` or the writing member's device key) over the encoded body.
    #[must_use]
    pub fn sign(&self, signing_seed: &[u8; 32]) -> [u8; 64] {
        SigningKey::from_bytes(signing_seed).sign(&self.encode()).to_bytes()
    }

    /// # Errors
    /// Refuses a malformed key or a bad signature.
    pub fn verify(&self, signer_pub: &[u8; 32], signature: &[u8; 64]) -> Result<(), LgError> {
        let key =
            VerifyingKey::from_bytes(signer_pub).map_err(|_| LgError::Verify("signer key"))?;
        key.verify(&self.encode(), &Signature::from_bytes(signature))
            .map_err(|_| LgError::Verify("key body signature"))
    }
}

/// What a joiner's slot carries (R2-M1 (i)): the key, the signed body and its signature, the
/// signer public key and certificate, the roster head and the delivered admin chain.
pub struct SlotOpened {
    pub key: EpochKey,
    pub body: SignedKeyBody,
    pub signature: [u8; 64],
    pub signer_pub: [u8; 32],
    pub signer_cert: Vec<u8>,
    pub roster_head: Vec<u8>,
    pub admin_chain: Vec<u8>,
}

/// The 93-byte HPKE `info` of a slot.
#[must_use]
pub fn slot_info(group_id: &[u8; 32], key_epoch: u64, prev_key_seq: u64, p: &[u8; 32]) -> [u8; 93] {
    let mut out = [0_u8; 93];
    let mut at = 0_usize;
    for part in [
        SLOT_INFO_PREFIX.as_slice(),
        group_id.as_slice(),
        key_epoch.to_be_bytes().as_slice(),
        prev_key_seq.to_be_bytes().as_slice(),
        p.as_slice(),
    ] {
        if let Some(dst) = out.get_mut(at..at + part.len()) {
            dst.copy_from_slice(part);
        }
        at += part.len();
    }
    out
}

/// A fresh X25519 receive keypair `(secret, public)`.
///
/// # Errors
/// Returns [`LgError::Random`] when the OS refuses randomness.
pub fn generate_recv_keypair() -> Result<(Zeroizing<[u8; 32]>, [u8; 32]), LgError> {
    let ikm = Zeroizing::new(random_array::<32>()?);
    let (secret, public) = <SuiteKem as Kem>::derive_keypair(ikm.as_slice());
    let mut sk = [0_u8; 32];
    sk.copy_from_slice(secret.to_bytes().as_slice());
    let mut pk = [0_u8; 32];
    pk.copy_from_slice(public.to_bytes().as_slice());
    Ok((Zeroizing::new(sk), pk))
}

fn encode_plain(opened: &SlotOpened) -> Vec<u8> {
    let mut enc = Enc::new(SLOT_PLAIN_DOMAIN);
    enc.fixed(opened.key.expose())
        .var(&opened.body.encode())
        .fixed(&opened.signature)
        .fixed(&opened.signer_pub)
        .var(&opened.signer_cert)
        .var(&opened.roster_head)
        .var(&opened.admin_chain);
    enc.finish()
}

/// Wraps one member's slot: `enc (32) ‖ AEAD(plaintext)`.
///
/// # Errors
/// Refuses oversized inputs or an HPKE failure.
pub fn seal_slot(recv_pk: &[u8; 32], p: &[u8; 32], plain: &SlotOpened) -> Result<Vec<u8>, LgError> {
    let info = slot_info(&plain.body.group_id, plain.body.key_epoch, plain.body.prev_key_seq, p);
    let public = <SuiteKem as Kem>::PublicKey::from_bytes(recv_pk)
        .map_err(|_| LgError::Crypto("recv public key"))?;
    let seed = Zeroizing::new(random_array::<32>()?);
    let mut rng = SeedRng::new(&seed);
    let (encapped, mut context) = setup_sender_with_rng::<SuiteAead, SuiteKdf, SuiteKem>(
        &OpModeS::Base,
        &public,
        &info,
        &mut rng,
    )
    .map_err(|_| LgError::Crypto("hpke setup"))?;
    let plaintext = Zeroizing::new(encode_plain(plain));
    if plaintext.len() > MAX_SLOT_PLAIN {
        return Err(LgError::Format("slot plaintext too large"));
    }
    let sealed = context.seal(&plaintext, &[]).map_err(|_| LgError::Crypto("hpke seal"))?;
    let enc = encapped.to_bytes();
    let mut out = Vec::with_capacity(ENCAP_LEN + sealed.len());
    out.extend_from_slice(enc.as_slice());
    out.extend_from_slice(&sealed);
    Ok(out)
}

/// Opens a slot for the member holding `recv_sk`.
///
/// # Errors
/// Refuses a malformed slot, an HPKE/AEAD failure (wrong `info`, wrong position) or bad plaintext.
pub fn open_slot(
    recv_sk: &[u8; 32],
    group_id: &[u8; 32],
    key_epoch: u64,
    prev_key_seq: u64,
    p: &[u8; 32],
    slot_ct: &[u8],
) -> Result<SlotOpened, LgError> {
    let (enc, ct) = slot_ct.split_at_checked(ENCAP_LEN).ok_or(LgError::Format("slot length"))?;
    let secret = <SuiteKem as Kem>::PrivateKey::from_bytes(recv_sk)
        .map_err(|_| LgError::Crypto("recv secret key"))?;
    let encapped = <SuiteKem as Kem>::EncappedKey::from_bytes(enc)
        .map_err(|_| LgError::Format("slot encap"))?;
    let info = slot_info(group_id, key_epoch, prev_key_seq, p);
    let mut context =
        setup_receiver::<SuiteAead, SuiteKdf, SuiteKem>(&OpModeR::Base, &secret, &encapped, &info)
            .map_err(|_| LgError::Verify("slot hpke"))?;
    let plain = Zeroizing::new(context.open(ct, &[]).map_err(|_| LgError::Verify("slot aead"))?);
    let mut dec = Dec::new(&plain);
    if dec.var(SLOT_PLAIN_DOMAIN.len())? != SLOT_PLAIN_DOMAIN {
        return Err(LgError::Format("slot plaintext domain"));
    }
    let key = EpochKey::from_bytes(dec.fixed()?);
    let body_bytes = dec.var(1024)?;
    let mut body_dec = Dec::new(body_bytes);
    let body = SignedKeyBody::decode_from(&mut body_dec)?;
    body_dec.finish()?;
    let opened = SlotOpened {
        key,
        body,
        signature: dec.fixed()?,
        signer_pub: dec.fixed()?,
        signer_cert: dec.var(MAX_CERT)?.to_vec(),
        roster_head: dec.var(MAX_ROSTER_HEAD)?.to_vec(),
        admin_chain: dec.var(MAX_ADMIN_CHAIN)?.to_vec(),
    };
    dec.finish()?;
    Ok(opened)
}

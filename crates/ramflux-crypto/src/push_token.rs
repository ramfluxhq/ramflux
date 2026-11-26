// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Sealing of a raw provider push token to the centre's active push key (central push, `sv = 1`).
//!
//! Suite: HPKE base mode (RFC 9180), DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, ChaCha20-Poly1305.
//! Wire: `sealed = 0x01 || klen:u8 || kid || enc[32] || ct`, `aad` empty,
//! `info = "rfc-push-token" || 0x00 || 0x01 || u16be len(centre_id) || centre_id || klen || kid`.
//! The plaintext is a closed JSON object with the member order `tv, p, tok, app, env, nk, rt, iat, cap`.

use crate::CryptoError;
use chacha20::cipher::{KeyIvInit, StreamCipher};
use hpke::aead::{AeadCtxS, ChaCha20Poly1305};
use hpke::kdf::HkdfSha256;
use hpke::kem::X25519HkdfSha256;
use hpke::rand_core::{TryCryptoRng, TryRng};
use hpke::{Deserializable, Kem, OpModeS, Serializable, setup_sender_with_rng};
use ramflux_protocol::encode_base64url;
use serde::Serialize;
use std::convert::Infallible;
use zeroize::{Zeroize, Zeroizing};

type SuiteKem = X25519HkdfSha256;
type SuiteKdf = HkdfSha256;
type SuiteAead = ChaCha20Poly1305;

/// Domain of the HPKE info, including its NUL terminator.
const INFO_DOMAIN: &[u8] = b"rfc-push-token\0";
/// Format version of the sealed token and of its plaintext.
pub const PUSH_TOKEN_VERSION: u8 = 1;
/// Maximum serialised plaintext length.
pub const MAX_PUSH_TOKEN_PLAINTEXT: usize = 1024;
/// Length of a route tag in bytes.
pub const ROUTE_TAG_LEN: usize = 16;
const KEM_ENC_LEN: usize = 32;
const MAX_KID_LEN: usize = 32;
const MAX_CENTRE_ID_LEN: usize = u16::MAX as usize;
const MAX_APP_LEN: usize = 155;

/// Provider of a sealed route.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PushTokenProvider {
    Apns,
    ApnsVoip,
    Fcm,
}

/// Closed plaintext of a sealed push token (`sv = 1`).
#[derive(Clone, Debug, Serialize)]
pub struct PushTokenPlaintext {
    pub tv: u8,
    pub p: PushTokenProvider,
    pub tok: String,
    pub app: String,
    pub env: &'static str,
    /// Unpadded base64url of the pinned home node identity key (32 bytes).
    pub nk: String,
    /// Unpadded base64url of the route tag (16 bytes).
    pub rt: String,
    /// Device clock, Unix milliseconds, at sealing.
    pub iat: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cap: Option<&'static str>,
}

/// Inputs of one seal.
pub struct SealInput<'a> {
    pub centre_id: &'a str,
    pub kid: &'a str,
    pub recipient_pk: &'a [u8; 32],
    pub plaintext: &'a PushTokenPlaintext,
}

impl PushTokenPlaintext {
    /// Checks the closed rules the centre enforces on the plaintext.
    ///
    /// # Errors
    /// Returns [`CryptoError::PushToken`] for any member outside its rule.
    pub fn validate(&self) -> Result<(), CryptoError> {
        if self.tv != PUSH_TOKEN_VERSION {
            return Err(CryptoError::PushToken("tv"));
        }
        match self.p {
            PushTokenProvider::Apns | PushTokenProvider::ApnsVoip => {
                let hex_ok = (64..=200).contains(&self.tok.len())
                    && self.tok.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
                if !hex_ok {
                    return Err(CryptoError::PushToken("apns_token"));
                }
            }
            PushTokenProvider::Fcm => {
                let ok = (1..=512).contains(&self.tok.len())
                    && self.tok.bytes().all(|b| {
                        b.is_ascii_alphanumeric() || matches!(b, b'_' | b':' | b'.' | b'-')
                    });
                if !ok {
                    return Err(CryptoError::PushToken("fcm_token"));
                }
            }
        }
        if !app_id_ok(&self.app) {
            return Err(CryptoError::PushToken("app"));
        }
        match (self.p, self.env, self.cap) {
            (PushTokenProvider::Fcm, "production", None)
            | (
                PushTokenProvider::Apns | PushTokenProvider::ApnsVoip,
                "sandbox" | "production",
                None | Some("alert" | "filtered"),
            ) => {}
            _ => return Err(CryptoError::PushToken("env_or_cap")),
        }
        if self.cap.is_some() && self.p != PushTokenProvider::Apns {
            return Err(CryptoError::PushToken("cap"));
        }
        decode_fixed::<32>(&self.nk).ok_or(CryptoError::PushToken("nk"))?;
        decode_fixed::<ROUTE_TAG_LEN>(&self.rt).ok_or(CryptoError::PushToken("rt"))?;
        Ok(())
    }
}

fn app_id_ok(app: &str) -> bool {
    let bytes = app.as_bytes();
    if bytes.is_empty() || bytes.len() > MAX_APP_LEN {
        return false;
    }
    bytes[0].is_ascii_alphanumeric()
        && bytes.iter().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

fn decode_fixed<const N: usize>(input: &str) -> Option<[u8; N]> {
    let bytes = ramflux_protocol::decode_base64url(input).ok()?;
    <[u8; N]>::try_from(bytes.as_slice()).ok()
}

/// Seals a push token. The returned bytes are the `st` value before base64url encoding.
///
/// # Errors
/// Returns [`CryptoError::PushToken`] for invalid input, or a setup or AEAD failure.
pub fn seal_push_token(input: &SealInput<'_>) -> Result<Vec<u8>, CryptoError> {
    let kid = input.kid.as_bytes();
    if kid.is_empty()
        || kid.len() > MAX_KID_LEN
        || !kid.iter().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'-')
    {
        return Err(CryptoError::PushToken("kid"));
    }
    if input.centre_id.is_empty() || input.centre_id.len() > MAX_CENTRE_ID_LEN {
        return Err(CryptoError::PushToken("centre_id"));
    }
    input.plaintext.validate()?;
    let plaintext = Zeroizing::new(
        serde_json::to_vec(input.plaintext).map_err(|_| CryptoError::PushToken("encode"))?,
    );
    if plaintext.len() > MAX_PUSH_TOKEN_PLAINTEXT {
        return Err(CryptoError::PushToken("plaintext_size"));
    }
    let info = info_bytes(input.centre_id, input.kid);
    let recipient = <SuiteKem as Kem>::PublicKey::from_bytes(input.recipient_pk)
        .map_err(|_| CryptoError::PushToken("recipient_key"))?;
    let mut seed = Zeroizing::new([0_u8; 32]);
    getrandom::fill(&mut *seed)
        .map_err(|error| CryptoError::RandomUnavailable(error.to_string()))?;
    let mut rng = SeededCsPrng::from_seed(&seed);
    seed.zeroize();
    let (encapped, mut ctx): (
        <SuiteKem as Kem>::EncappedKey,
        AeadCtxS<SuiteAead, SuiteKdf, SuiteKem>,
    ) = setup_sender_with_rng::<SuiteAead, SuiteKdf, SuiteKem>(
        &OpModeS::Base,
        &recipient,
        &info,
        &mut rng,
    )
    .map_err(|_| CryptoError::PushToken("setup"))?;
    let enc = encapped.to_bytes();
    let ct = ctx.seal(&plaintext, &[]).map_err(|_| CryptoError::AeadFailed)?;
    drop(ctx);
    let mut sealed = Vec::with_capacity(1 + 1 + kid.len() + KEM_ENC_LEN + ct.len());
    sealed.push(PUSH_TOKEN_VERSION);
    sealed.push(u8::try_from(kid.len()).map_err(|_| CryptoError::PushToken("kid"))?);
    sealed.extend_from_slice(kid);
    sealed.extend_from_slice(enc.as_slice());
    sealed.extend_from_slice(&ct);
    Ok(sealed)
}

/// Encodes sealed bytes as the wire `st` value (unpadded base64url).
#[must_use]
pub fn encode_sealed_token(sealed: &[u8]) -> String {
    encode_base64url(sealed)
}

fn info_bytes(centre_id: &str, kid: &str) -> Vec<u8> {
    let mut info = Vec::with_capacity(INFO_DOMAIN.len() + 1 + 2 + centre_id.len() + 1 + kid.len());
    info.extend_from_slice(INFO_DOMAIN);
    info.push(PUSH_TOKEN_VERSION);
    info.extend_from_slice(&u16::try_from(centre_id.len()).unwrap_or(u16::MAX).to_be_bytes());
    info.extend_from_slice(centre_id.as_bytes());
    info.push(u8::try_from(kid.len()).unwrap_or(u8::MAX));
    info.extend_from_slice(kid.as_bytes());
    info
}

struct SeededCsPrng {
    cipher: chacha20::ChaCha20,
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

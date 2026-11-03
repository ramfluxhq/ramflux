// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Public test vectors from RFC 8291 section 5 / Appendix A and RFC 5903 section 8.1.
use super::{encrypt_webpush_aes128gcm, encrypt_webpush_aes128gcm_with};
use aes_gcm::aead::{Aead, KeyInit};
use p256::elliptic_curve::sec1::ToSec1Point;

const RECEIVER_PRIVATE: &str = "q1dXpw3UpT5VOmu_cf_v6ih07Aems3njxI-JWgLcM94";
const RECEIVER_PUBLIC: &str = concat!(
    "BCVxsr7N_eNgVRqvHtD0zTZsEc6-VV-JvLexhqUzORcx",
    "aOzi6-AYWXvTBHm4bjyPjs7Vd8pZGH6SRpkNtoIAiw4"
);
const SENDER_PRIVATE: &str = "yfWPiYE-n46HLnH0KqZOF1fJJU3MYrct3AELtAQ-oRw";
const SENDER_PUBLIC: &str = concat!(
    "BP4z9KsN6nGRTbVYI_c7VJSPQTBtkgcy27mlmlMoZIIg",
    "Dll6e3vCYLocInmYWAmS6TlzAC8wEqKK6PBru3jl7A8"
);
const AUTH_SECRET: &str = "BTBZMqHH6r4Tts7J_aSIgg";
const PLAINTEXT: &[u8] = b"When I grow up, I want to be a watermelon";

#[test]
fn rfc8291_section5_webpush_body_is_byte_exact() -> Result<(), Box<dyn std::error::Error>> {
    // https://www.rfc-editor.org/rfc/rfc8291#section-5
    let receiver =
        p256::SecretKey::from_slice(&ramflux_protocol::decode_base64url(RECEIVER_PRIVATE)?)?;
    let sender = p256::SecretKey::from_slice(&ramflux_protocol::decode_base64url(SENDER_PRIVATE)?)?;
    assert_eq!(
        ramflux_protocol::encode_base64url(receiver.public_key().to_sec1_point(false).as_bytes()),
        RECEIVER_PUBLIC
    );
    assert_eq!(
        ramflux_protocol::encode_base64url(sender.public_key().to_sec1_point(false).as_bytes()),
        SENDER_PUBLIC
    );
    let shared =
        p256::ecdh::diffie_hellman(sender.to_nonzero_scalar(), receiver.public_key().as_affine());
    assert_eq!(
        ramflux_protocol::encode_base64url(shared.raw_secret_bytes()),
        "kyrL1jIIOHEzg3sM2ZWRHDRB62YACZhhSlknJ672kSs"
    );
    let salt: [u8; 16] = ramflux_protocol::decode_base64url("DGv6ra1nlYgDCS1FRnbzlw")?
        .try_into()
        .map_err(|_| "invalid RFC salt length")?;
    let body =
        encrypt_webpush_aes128gcm_with(&sender, salt, RECEIVER_PUBLIC, AUTH_SECRET, PLAINTEXT)?;
    let expected = ramflux_protocol::decode_base64url(concat!(
        "DGv6ra1nlYgDCS1FRnbzlwAAEABBBP4z9KsN6nGRTbVYI_c7VJSPQTBtkgcy27ml",
        "mlMoZIIgDll6e3vCYLocInmYWAmS6TlzAC8wEqKK6PBru3jl7A_yl95bQpu6cVPT",
        "pK4Mqgkf1CXztLVBSt2Ks3oZwbuwXPXLWyouBWLVWGNWQexSgSxsj_Qulcy4a-fN"
    ))?;
    // RFC 8291 reported erratum 5230: 86 header + 42 record + 16 tag bytes.
    assert_eq!(body.len(), 144);
    assert_eq!(body, expected);
    assert_eq!(decrypt_webpush_body(&body, &receiver)?, PLAINTEXT);
    Ok(())
}

#[test]
fn production_webpush_wrapper_round_trips_and_authenticates()
-> Result<(), Box<dyn std::error::Error>> {
    let receiver =
        p256::SecretKey::from_slice(&ramflux_protocol::decode_base64url(RECEIVER_PRIVATE)?)?;
    let first = encrypt_webpush_aes128gcm(RECEIVER_PUBLIC, AUTH_SECRET, PLAINTEXT)?;
    let second = encrypt_webpush_aes128gcm(RECEIVER_PUBLIC, AUTH_SECRET, PLAINTEXT)?;
    assert_ne!(first, second);
    assert_eq!(decrypt_webpush_body(&first, &receiver)?, PLAINTEXT);
    assert_eq!(decrypt_webpush_body(&second, &receiver)?, PLAINTEXT);
    let mut tampered = first;
    let tag = tampered.last_mut().ok_or("missing Web Push authentication tag")?;
    *tag ^= 1;
    assert!(decrypt_webpush_body(&tampered, &receiver).is_err());
    Ok(())
}

#[test]
fn p256_ecdh_matches_rfc5903_section8_1() -> Result<(), Box<dyn std::error::Error>> {
    // https://www.rfc-editor.org/rfc/rfc5903#section-8.1
    let initiator = p256::SecretKey::from_slice(&decode_hex(concat!(
        "C88F01F510D9AC3F70A292DAA2316DE5",
        "44E9AAB8AFE84049C62A9C57862D1433"
    ))?)?;
    let responder = p256::PublicKey::from_sec1_bytes(&decode_hex(concat!(
        "04",
        "D12DFB5289C8D4F81208B70270398C342296970A0BCCB74C736FC7554494BF63",
        "56FBF3CA366CC23E8157854C13C58D6AAC23F046ADA30F8353E74F33039872AB"
    ))?)?;
    let shared = p256::ecdh::diffie_hellman(initiator.to_nonzero_scalar(), responder.as_affine());
    assert_eq!(
        shared.raw_secret_bytes().as_slice(),
        decode_hex(concat!(
            "D6840F6B42F6EDAFD13116E0E1256520",
            "2FEF8E9ECE7DCE03812464D04B9442DE"
        ))?
    );
    Ok(())
}

fn decode_hex(value: &str) -> Result<Vec<u8>, std::num::ParseIntError> {
    (0..value.len()).step_by(2).map(|i| u8::from_str_radix(&value[i..i + 2], 16)).collect()
}

fn decrypt_webpush_body(
    body: &[u8],
    receiver: &p256::SecretKey,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let header = body.get(..86).ok_or("truncated Web Push header")?;
    let salt: [u8; 16] = header[..16].try_into()?;
    let record_size = u32::from_be_bytes(header[16..20].try_into()?);
    if record_size != 4096 || header[20] != 65 {
        return Err("unexpected Web Push record header".into());
    }
    let sender = p256::PublicKey::from_sec1_bytes(&header[21..])?;
    let shared = p256::ecdh::diffie_hellman(receiver.to_nonzero_scalar(), sender.as_affine());
    let auth = ramflux_protocol::decode_base64url(AUTH_SECRET)?;
    let mut info = b"WebPush: info\0".to_vec();
    info.extend_from_slice(receiver.public_key().to_sec1_point(false).as_bytes());
    info.extend_from_slice(&header[21..]);
    let key_hkdf = hkdf::Hkdf::<sha2::Sha256>::new(Some(&auth), shared.raw_secret_bytes());
    let mut ikm = [0_u8; 32];
    key_hkdf.expand(&info, &mut ikm).map_err(|_| "receiver key derivation failed")?;
    let content_hkdf = hkdf::Hkdf::<sha2::Sha256>::new(Some(&salt), &ikm);
    let mut cek = [0_u8; 16];
    let mut nonce = [0_u8; 12];
    content_hkdf
        .expand(b"Content-Encoding: aes128gcm\0", &mut cek)
        .map_err(|_| "receiver content key derivation failed")?;
    content_hkdf
        .expand(b"Content-Encoding: nonce\0", &mut nonce)
        .map_err(|_| "receiver nonce derivation failed")?;
    let cipher = aes_gcm::Aes128Gcm::new_from_slice(&cek).map_err(|_| "invalid content key")?;
    let mut plaintext = cipher
        .decrypt(aes_gcm::Nonce::from_slice(&nonce), &body[86..])
        .map_err(|_| "Web Push authentication failed")?;
    if plaintext.pop() != Some(0x02) {
        return Err("missing final Web Push delimiter".into());
    }
    Ok(plaintext)
}

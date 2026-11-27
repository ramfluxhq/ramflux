// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! RFC 9420 section 5 crypto-basics known-answer runner over the process `RustCrypto`.
//!
//! The runner re-derives `RefHash`, `ExpandWithLabel`, `DeriveSecret`, `DeriveTreeSecret`,
//! `SignWithLabel` and `EncryptWithLabel` from the RFC's definitions using only the provider's
//! primitives, and compares them with the vector file (`crypto-basics.json` of the openmls
//! repository). Only suite 1 entries are run. The vector file is input from outside: its size is
//! bounded before parsing.

use openmls_rust_crypto::RustCrypto;
use openmls_traits::crypto::OpenMlsCrypto;
use openmls_traits::types::{
    HashType, HpkeAeadType, HpkeCiphertext, HpkeConfig, HpkeKdfType, HpkeKemType, SignatureScheme,
};
use serde::Deserialize;
use tls_codec::{Serialize as _, VLBytes};

use crate::MlsError;

/// Largest accepted vector file.
const MAX_KAT_BYTES: usize = 4 * 1024 * 1024;
/// Label prefix of every labelled operation (RFC 9420 section 5.1).
const LABEL_PREFIX: &str = "MLS 1.0 ";
/// Hash output length of suite 1 (SHA-256).
const HASH_LENGTH: usize = 32;

/// Outcome of a run.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct KatReport {
    /// Checks executed.
    pub run: usize,
    /// Checks that matched.
    pub passed: usize,
    /// Names of the checks that did not match (`<operation>#<entry>`).
    pub failed: Vec<String>,
}

#[derive(Deserialize)]
struct RefHash {
    label: String,
    value: String,
    out: String,
}

#[derive(Deserialize)]
struct ExpandWithLabel {
    secret: String,
    label: String,
    context: String,
    length: u16,
    out: String,
}

#[derive(Deserialize)]
struct DeriveSecret {
    secret: String,
    label: String,
    out: String,
}

#[derive(Deserialize)]
struct DeriveTreeSecret {
    secret: String,
    label: String,
    generation: u32,
    length: u16,
    out: String,
}

#[derive(Deserialize)]
struct SignWithLabel {
    r#priv: String,
    r#pub: String,
    content: String,
    label: String,
    signature: String,
}

#[derive(Deserialize)]
struct EncryptWithLabel {
    r#priv: String,
    r#pub: String,
    label: String,
    context: String,
    plaintext: String,
    kem_output: String,
    ciphertext: String,
}

#[derive(Deserialize)]
struct CryptoBasicsCase {
    cipher_suite: u16,
    ref_hash: RefHash,
    expand_with_label: ExpandWithLabel,
    derive_secret: DeriveSecret,
    derive_tree_secret: DeriveTreeSecret,
    sign_with_label: SignWithLabel,
    encrypt_with_label: EncryptWithLabel,
}

fn parse_cases(json: &[u8]) -> Result<Vec<CryptoBasicsCase>, MlsError> {
    if json.len() > MAX_KAT_BYTES {
        return Err(MlsError::TooLarge(format!(
            "vector file of {} bytes, limit {MAX_KAT_BYTES}",
            json.len()
        )));
    }
    serde_json::from_slice(json).map_err(|error| MlsError::Mls(format!("vector file: {error}")))
}

fn hex_bytes(text: &str) -> Result<Vec<u8>, String> {
    hex::decode(text).map_err(|error| format!("hex: {error}"))
}

fn vl(bytes: &[u8]) -> Result<Vec<u8>, String> {
    VLBytes::from(bytes.to_vec()).tls_serialize_detached().map_err(|error| format!("tls: {error}"))
}

fn crypto_error(error: impl std::fmt::Debug) -> String {
    format!("crypto: {error:?}")
}

fn labelled(label: &str) -> Vec<u8> {
    format!("{LABEL_PREFIX}{label}").into_bytes()
}

fn expect_equal(name: &str, got: &[u8], want: &[u8]) -> Result<(), String> {
    if got == want { Ok(()) } else { Err(format!("{name}: output differs")) }
}

fn ref_hash(crypto: &RustCrypto, label: &[u8], value: &[u8]) -> Result<Vec<u8>, String> {
    let mut input = vl(label)?;
    input.extend_from_slice(&vl(value)?);
    crypto.hash(HashType::Sha2_256, &input).map_err(crypto_error)
}

fn expand_with_label(
    crypto: &RustCrypto,
    secret: &[u8],
    label: &str,
    context: &[u8],
    length: u16,
) -> Result<Vec<u8>, String> {
    let mut info = length.to_be_bytes().to_vec();
    info.extend_from_slice(&vl(&labelled(label))?);
    info.extend_from_slice(&vl(context)?);
    let out = crypto
        .hkdf_expand(HashType::Sha2_256, secret, &info, usize::from(length))
        .map_err(crypto_error)?;
    Ok(out.as_slice().to_vec())
}

fn sign_content(label: &str, content: &[u8]) -> Result<Vec<u8>, String> {
    let mut payload = vl(&labelled(label))?;
    payload.extend_from_slice(&vl(content)?);
    Ok(payload)
}

fn hpke_config() -> HpkeConfig {
    HpkeConfig(HpkeKemType::DhKem25519, HpkeKdfType::HkdfSha256, HpkeAeadType::AesGcm128)
}

fn encrypt_context(label: &str, context: &[u8]) -> Result<Vec<u8>, String> {
    let mut info = vl(&labelled(label))?;
    info.extend_from_slice(&vl(context)?);
    Ok(info)
}

fn check_ref_hash(crypto: &RustCrypto, case: &RefHash) -> Result<(), String> {
    let got = ref_hash(crypto, case.label.as_bytes(), &hex_bytes(&case.value)?)?;
    expect_equal("ref_hash", &got, &hex_bytes(&case.out)?)
}

fn check_expand(crypto: &RustCrypto, case: &ExpandWithLabel) -> Result<(), String> {
    let got = expand_with_label(
        crypto,
        &hex_bytes(&case.secret)?,
        &case.label,
        &hex_bytes(&case.context)?,
        case.length,
    )?;
    expect_equal("expand_with_label", &got, &hex_bytes(&case.out)?)
}

fn check_derive_secret(crypto: &RustCrypto, case: &DeriveSecret) -> Result<(), String> {
    let length = u16::try_from(HASH_LENGTH).map_err(|_| "hash length".to_owned())?;
    let got = expand_with_label(crypto, &hex_bytes(&case.secret)?, &case.label, &[], length)?;
    expect_equal("derive_secret", &got, &hex_bytes(&case.out)?)
}

fn check_derive_tree_secret(crypto: &RustCrypto, case: &DeriveTreeSecret) -> Result<(), String> {
    let got = expand_with_label(
        crypto,
        &hex_bytes(&case.secret)?,
        &case.label,
        &case.generation.to_be_bytes(),
        case.length,
    )?;
    expect_equal("derive_tree_secret", &got, &hex_bytes(&case.out)?)
}

fn check_sign(crypto: &RustCrypto, case: &SignWithLabel) -> Result<(), String> {
    let payload = sign_content(&case.label, &hex_bytes(&case.content)?)?;
    let public = hex_bytes(&case.r#pub)?;
    crypto
        .verify_signature(SignatureScheme::ED25519, &payload, &public, &hex_bytes(&case.signature)?)
        .map_err(|error| format!("sign_with_label: vector signature does not verify: {error:?}"))?;
    let own = crypto
        .sign(SignatureScheme::ED25519, &payload, &hex_bytes(&case.r#priv)?)
        .map_err(crypto_error)?;
    crypto
        .verify_signature(SignatureScheme::ED25519, &payload, &public, &own)
        .map_err(|error| format!("sign_with_label: own signature does not verify: {error:?}"))
}

fn check_encrypt(crypto: &RustCrypto, case: &EncryptWithLabel) -> Result<(), String> {
    let info = encrypt_context(&case.label, &hex_bytes(&case.context)?)?;
    let secret = hex_bytes(&case.r#priv)?;
    let plaintext = hex_bytes(&case.plaintext)?;
    let vector = HpkeCiphertext {
        kem_output: hex_bytes(&case.kem_output)?.into(),
        ciphertext: hex_bytes(&case.ciphertext)?.into(),
    };
    let opened =
        crypto.hpke_open(hpke_config(), &vector, &secret, &info, &[]).map_err(crypto_error)?;
    expect_equal("encrypt_with_label (vector)", &opened, &plaintext)?;
    let sealed = crypto
        .hpke_seal(hpke_config(), &hex_bytes(&case.r#pub)?, &info, &[], &plaintext)
        .map_err(crypto_error)?;
    let reopened =
        crypto.hpke_open(hpke_config(), &sealed, &secret, &info, &[]).map_err(crypto_error)?;
    expect_equal("encrypt_with_label (own)", &reopened, &plaintext)
}

fn record(report: &mut KatReport, name: &str, index: usize, outcome: Result<(), String>) {
    report.run += 1;
    match outcome {
        Ok(()) => report.passed += 1,
        Err(reason) => report.failed.push(format!("{name}#{index}: {reason}")),
    }
}

/// Run every suite 1 entry of a `crypto-basics.json` file.
///
/// # Errors
/// The file is too large or not a vector file; mismatching entries are reported, not errors.
pub fn run_crypto_basics(crypto: &RustCrypto, json: &[u8]) -> Result<KatReport, MlsError> {
    let mut report = KatReport::default();
    for (index, case) in
        parse_cases(json)?.iter().enumerate().filter(|(_, case)| case.cipher_suite == 1)
    {
        record(&mut report, "ref_hash", index, check_ref_hash(crypto, &case.ref_hash));
        record(
            &mut report,
            "expand_with_label",
            index,
            check_expand(crypto, &case.expand_with_label),
        );
        record(
            &mut report,
            "derive_secret",
            index,
            check_derive_secret(crypto, &case.derive_secret),
        );
        record(
            &mut report,
            "derive_tree_secret",
            index,
            check_derive_tree_secret(crypto, &case.derive_tree_secret),
        );
        record(&mut report, "sign_with_label", index, check_sign(crypto, &case.sign_with_label));
        record(
            &mut report,
            "encrypt_with_label",
            index,
            check_encrypt(crypto, &case.encrypt_with_label),
        );
    }
    Ok(report)
}

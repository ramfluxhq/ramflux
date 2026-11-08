// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use super::{
    EstablishedSas, PairingRole, PendingSas, SAS_EMOJI, commit, emoji_from_indices, sas::sha256,
    take_pairing_secret_cleanups,
};
use crate::{CryptoError, X25519KeyPair};
use hmac::{Hmac, KeyInit, Mac};
use ramflux_protocol::custody::pairing::{
    PairingWire, RoleContext, Transcript, context_commitment_preimage, transcript_preimage,
};
use ramflux_protocol::{canonical_json_bytes, domain, encode_base64url};
use sha2::{Digest, Sha256};

type Result<T = ()> = std::result::Result<T, CryptoError>;

const INIT_SECRET: [u8; 32] = [7; 32];
const RESP_SECRET: [u8; 32] = [8; 32];
const INIT_SALT: [u8; 32] = [11; 32];
const RESP_SALT: [u8; 32] = [12; 32];

fn fixture_json() -> Result<serde_json::Value> {
    serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../ramflux-protocol/fixtures/pairing_v2/vectors.json"
    )))
    .map_err(|_| CryptoError::Pairing("json"))
}

fn fixture_transcript() -> Result<Transcript> {
    let json = fixture_json()?;
    let bytes =
        canonical_json_bytes(&json["transcript"]).map_err(|_| CryptoError::Pairing("json"))?;
    Transcript::from_wire_bytes(&bytes).map_err(Into::into)
}

fn bound_transcript() -> Result<Transcript> {
    let mut transcript = fixture_transcript()?;
    transcript.initiator.sas_key = encode_base64url(X25519KeyPair::from_seed(INIT_SECRET).public);
    transcript.responder.sas_key = encode_base64url(X25519KeyPair::from_seed(RESP_SECRET).public);
    transcript.validate().map_err(CryptoError::from)?;
    Ok(transcript)
}

fn pending(
    role: PairingRole,
    context: &RoleContext,
    secret: &[u8; 32],
    salt: &[u8; 32],
) -> Result<PendingSas> {
    commit(role, context, secret, salt)
}

fn handshake() -> Result<(EstablishedSas, EstablishedSas)> {
    let transcript = bound_transcript()?;
    let mut initiator =
        pending(PairingRole::Initiator, &transcript.initiator, &INIT_SECRET, &INIT_SALT)?;
    let mut responder =
        pending(PairingRole::Responder, &transcript.responder, &RESP_SECRET, &RESP_SALT)?;
    initiator.store_peer_commitment(PairingRole::Responder, responder.commitment())?;
    responder.store_peer_commitment(PairingRole::Initiator, initiator.commitment())?;
    let initiator = initiator.establish(&transcript.responder, &RESP_SALT)?;
    let responder = responder.establish(&transcript.initiator, &INIT_SALT)?;
    Ok((initiator, responder))
}

fn confirmed() -> Result<(EstablishedSas, EstablishedSas)> {
    let (mut initiator, mut responder) = handshake()?;
    let th = initiator.transcript_hash();
    let init_mac = initiator.confirm_local(&th, true)?;
    let resp_mac = responder.confirm_local(&th, true)?;
    initiator.accept_peer_mac(&resp_mac)?;
    responder.accept_peer_mac(&init_mac)?;
    Ok((initiator, responder))
}

fn hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    bytes
        .iter()
        .flat_map(|value| {
            [char::from(HEX[usize::from(value >> 4)]), char::from(HEX[usize::from(value & 15)])]
        })
        .collect()
}

fn decode_hex(value: &str) -> Result<Vec<u8>> {
    hex::decode(value).map_err(|_| CryptoError::Pairing("hex"))
}

fn expect_pairing<T>(result: Result<T>, reason: &'static str) -> Result {
    match result {
        Err(CryptoError::Pairing(found)) if found == reason => Ok(()),
        Err(error) => Err(error),
        Ok(_) => Err(CryptoError::Pairing("unexpected_ok")),
    }
}

fn independent_hkdf<const N: usize>(ikm: &[u8], salt: &[u8], info: &[u8]) -> Result<[u8; N]> {
    let kdf = hkdf::Hkdf::<Sha256>::new(Some(salt), ikm);
    let mut out = [0_u8; N];
    kdf.expand(info, &mut out).map_err(|_| CryptoError::HkdfFailed)?;
    Ok(out)
}

#[test]
fn pairing_sas_transcript_role_and_human_confirmation() -> Result {
    fixture_hashes()?;
    role_binding()?;
    human_confirmation_and_macs()?;
    full_context_negatives()?;
    two_leg_ordering()?;
    independent_derivation()?;
    Ok(())
}

fn fixture_hashes() -> Result {
    let json = fixture_json()?;
    let transcript = fixture_transcript()?;
    assert_eq!(
        hex(&sha256(&transcript_preimage(&transcript)?)),
        json["sha256"]["transcript"].as_str().ok_or(CryptoError::Pairing("json"))?
    );
    assert_eq!(
        hex(&sha256(&context_commitment_preimage(&transcript.initiator, &INIT_SALT)?)),
        json["sha256"]["initiator"].as_str().ok_or(CryptoError::Pairing("json"))?
    );
    assert_eq!(
        hex(&sha256(&context_commitment_preimage(&transcript.responder, &RESP_SALT)?)),
        json["sha256"]["responder"].as_str().ok_or(CryptoError::Pairing("json"))?
    );
    let old = decode_hex(
        json["preimages_hex"]["old_commitment"].as_str().ok_or(CryptoError::Pairing("json"))?,
    )?;
    assert_eq!(
        hex(&sha256(&old)),
        json["sha256"]["old_commitment"].as_str().ok_or(CryptoError::Pairing("json"))?
    );
    Ok(())
}

fn role_binding() -> Result {
    let transcript = fixture_transcript()?;
    let mut responder_role = transcript.initiator.clone();
    responder_role.role = "responder".into();
    let initiator_commit = sha256(&context_commitment_preimage(&transcript.initiator, &INIT_SALT)?);
    let responder_commit = sha256(&context_commitment_preimage(&responder_role, &INIT_SALT)?);
    assert_ne!(initiator_commit, responder_commit);
    let bound = bound_transcript()?;
    let pending = pending(PairingRole::Initiator, &bound.initiator, &INIT_SECRET, &INIT_SALT)?;
    assert_eq!(
        pending.commitment(),
        sha256(&context_commitment_preimage(&bound.initiator, &INIT_SALT)?)
    );
    let (initiator, responder) = handshake()?;
    assert_eq!(initiator.transcript_hash(), responder.transcript_hash());
    assert_eq!(initiator.transcript_hash(), sha256(&transcript_preimage(&bound)?));
    let sas_only: [u8; 32] =
        Sha256::digest(format!("{}{}", bound.initiator.sas_key, bound.responder.sas_key)).into();
    assert_ne!(initiator.transcript_hash(), sas_only);
    Ok(())
}

fn human_confirmation_and_macs() -> Result {
    let (mut initiator, responder) = handshake()?;
    expect_pairing(initiator.seal(b"early").map(|_| ()), "human_confirmation_required")?;
    assert_eq!(initiator.transcript_hash(), responder.transcript_hash());
    assert_eq!(initiator.emoji_indices(), responder.emoji_indices());
    let (mut initiator, _responder) = handshake()?;
    expect_pairing(initiator.confirm_local(&[0; 32], true).map(|_| ()), "transcript_hash")?;
    let (mut initiator, _responder) = handshake()?;
    let th = initiator.transcript_hash();
    let init_mac = initiator.confirm_local(&th, true)?;
    expect_pairing(initiator.accept_peer_mac(&init_mac), "confirm_mac")?;
    let (mut initiator, _responder) = handshake()?;
    let th = initiator.transcript_hash();
    expect_pairing(initiator.confirm_local(&th, false).map(|_| ()), "sas_mismatch")?;
    let (mut initiator, mut responder) = confirmed()?;
    let (counter, ciphertext) = initiator.seal(b"channel-body")?;
    let opened = responder.open(counter, &ciphertext)?;
    assert_eq!(&opened[..], b"channel-body");
    let (back_counter, back) = responder.seal(b"reply")?;
    let reply = initiator.open(back_counter, &back)?;
    assert_eq!(&reply[..], b"reply");
    expect_pairing(responder.open(counter, &ciphertext).map(|_| ()), "channel_counter")?;
    Ok(())
}

fn full_context_negatives() -> Result {
    let transcript = bound_transcript()?;
    expect_pairing(
        commit(PairingRole::Responder, &transcript.initiator, &INIT_SECRET, &INIT_SALT).map(|_| ()),
        "role_mismatch",
    )?;
    expect_pairing(
        commit(PairingRole::Initiator, &transcript.initiator, &RESP_SECRET, &INIT_SALT).map(|_| ()),
        "sas_key_mismatch",
    )?;
    for (mutate, reason) in [
        (mutate_display as fn(&mut RoleContext), "commitment_mismatch"),
        (mutate_branch, "commitment_mismatch"),
        (mutate_agreement, "commitment_mismatch"),
        (mutate_device, "commitment_mismatch"),
        (mutate_purpose, "transfer_context"),
    ] {
        let mut peer = transcript.responder.clone();
        mutate(&mut peer);
        let mut session =
            pending(PairingRole::Initiator, &transcript.initiator, &INIT_SECRET, &INIT_SALT)?;
        let honest =
            pending(PairingRole::Responder, &transcript.responder, &RESP_SECRET, &RESP_SALT)?;
        session.store_peer_commitment(PairingRole::Responder, honest.commitment())?;
        expect_pairing(session.establish(&peer, &RESP_SALT).map(|_| ()), reason)?;
    }
    noncontributory_peer()?;
    Ok(())
}

fn noncontributory_peer() -> Result {
    let transcript = bound_transcript()?;
    let mut initiator =
        pending(PairingRole::Initiator, &transcript.initiator, &INIT_SECRET, &INIT_SALT)?;
    let mut peer = transcript.responder.clone();
    let mut low_order = [0_u8; 32];
    low_order[0] = 1;
    peer.sas_key = encode_base64url(low_order);
    let frozen = sha256(&context_commitment_preimage(&peer, &RESP_SALT)?);
    initiator.store_peer_commitment(PairingRole::Responder, frozen)?;
    expect_pairing(initiator.establish(&peer, &RESP_SALT).map(|_| ()), "noncontributory")
}

fn mutate_display(context: &mut RoleContext) {
    context.display_name = "mutated".into();
}
fn mutate_branch(context: &mut RoleContext) {
    context.branch_key = encode_base64url([9; 32]);
}
fn mutate_agreement(context: &mut RoleContext) {
    context.agreement_key = encode_base64url([10; 32]);
}
fn mutate_device(context: &mut RoleContext) {
    context.device_ref.device_id = "mutated-device".into();
}
fn mutate_purpose(context: &mut RoleContext) {
    context.common.purpose = "primary_transfer".into();
}

fn two_leg_ordering() -> Result {
    let transcript = bound_transcript()?;
    let initiator =
        pending(PairingRole::Initiator, &transcript.initiator, &INIT_SECRET, &INIT_SALT)?;
    let responder =
        pending(PairingRole::Responder, &transcript.responder, &RESP_SECRET, &RESP_SALT)?;
    expect_pairing(
        initiator.establish(&transcript.responder, &RESP_SALT).map(|_| ()),
        "peer_commit_missing",
    )?;
    let mut initiator =
        pending(PairingRole::Initiator, &transcript.initiator, &INIT_SECRET, &INIT_SALT)?;
    initiator.store_peer_commitment(PairingRole::Responder, responder.commitment())?;
    let mut changed = transcript.responder.clone();
    changed.agreement_key = encode_base64url([13; 32]);
    expect_pairing(initiator.establish(&changed, &RESP_SALT).map(|_| ()), "commitment_mismatch")?;
    Ok(())
}

fn independent_derivation() -> Result {
    let (initiator, responder) = handshake()?;
    let ikm = x25519_dalek::StaticSecret::from(INIT_SECRET).diffie_hellman(
        &x25519_dalek::PublicKey::from(X25519KeyPair::from_seed(RESP_SECRET).public),
    );
    let th = initiator.transcript_hash();
    let sas = independent_hkdf::<6>(ikm.as_bytes(), &th, domain::CUSTODY_PAIRING_SAS.as_bytes())?;
    let packed = u64::from_be_bytes([0, 0, sas[0], sas[1], sas[2], sas[3], sas[4], sas[5]]) >> 6;
    let indices: [u8; 7] =
        core::array::from_fn(|index| ((packed >> (36 - 6 * index)) & 0x3f) as u8);
    assert_eq!(initiator.emoji_indices(), indices);
    assert_eq!(responder.emoji_indices(), indices);
    let emoji = emoji_from_indices(indices);
    assert_eq!(emoji[0].name, SAS_EMOJI[usize::from(indices[0])].1);
    assert_eq!(SAS_EMOJI[0], ("🐶", "Dog"));
    assert_eq!(SAS_EMOJI[15], ("🌷", "Flower"));
    let confirm_i = independent_hkdf::<32>(
        ikm.as_bytes(),
        &th,
        domain::CUSTODY_PAIRING_CONFIRM_INITIATOR.as_bytes(),
    )?;
    let mut mac =
        Hmac::<Sha256>::new_from_slice(&confirm_i).map_err(|_| CryptoError::HmacFailed)?;
    mac.update(&th);
    let produced: [u8; 32] = mac.finalize().into_bytes().into();
    let mut initiator = initiator;
    let local = initiator.confirm_local(&th, true)?;
    assert_eq!(local, produced);
    Ok(())
}

#[test]
fn pairing_owned_secret_cleanup_all_exits() -> Result {
    let _ = take_pairing_secret_cleanups();
    cancel_exit()?;
    assert_eq!(take_pairing_secret_cleanups(), 1, "cancel");
    commitment_mismatch_exit()?;
    assert_eq!(take_pairing_secret_cleanups(), 1, "commitment_mismatch");
    missing_peer_commit_exit()?;
    assert_eq!(take_pairing_secret_cleanups(), 1, "peer_commit_missing");
    mismatch_confirm_exit()?;
    assert_eq!(take_pairing_secret_cleanups(), 3, "sas_mismatch");
    success_exit()?;
    assert_eq!(take_pairing_secret_cleanups(), 4, "success");
    Ok(())
}

fn cancel_exit() -> Result {
    let transcript = bound_transcript()?;
    let mut pending =
        pending(PairingRole::Initiator, &transcript.initiator, &INIT_SECRET, &INIT_SALT)?;
    pending.cleanup();
    Ok(())
}

fn commitment_mismatch_exit() -> Result {
    let transcript = bound_transcript()?;
    let mut initiator =
        pending(PairingRole::Initiator, &transcript.initiator, &INIT_SECRET, &INIT_SALT)?;
    let responder =
        pending(PairingRole::Responder, &transcript.responder, &RESP_SECRET, &RESP_SALT)?;
    initiator.store_peer_commitment(PairingRole::Responder, responder.commitment())?;
    let mut changed = transcript.responder.clone();
    changed.display_name = "other".into();
    expect_pairing(initiator.establish(&changed, &RESP_SALT).map(|_| ()), "commitment_mismatch")
}

fn missing_peer_commit_exit() -> Result {
    let transcript = bound_transcript()?;
    let initiator =
        pending(PairingRole::Initiator, &transcript.initiator, &INIT_SECRET, &INIT_SALT)?;
    expect_pairing(
        initiator.establish(&transcript.responder, &RESP_SALT).map(|_| ()),
        "peer_commit_missing",
    )
}

fn mismatch_confirm_exit() -> Result {
    let (mut initiator, _responder) = handshake()?;
    expect_pairing(
        initiator.confirm_local(&initiator.transcript_hash(), false).map(|_| ()),
        "sas_mismatch",
    )
}

fn success_exit() -> Result {
    let (mut initiator, mut responder) = confirmed()?;
    let (counter, ciphertext) = initiator.seal(b"ok")?;
    drop(responder.open(counter, &ciphertext)?);
    initiator.cleanup();
    responder.cleanup();
    Ok(())
}

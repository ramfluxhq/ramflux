// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use super::{
    EstablishedSas, PairingRole, PendingSas, SAS_EMOJI, commit, emoji_from_indices,
    last_wiped_pairing_bytes, sas::sha256, take_pairing_secret_cleanups,
};
use crate::{CryptoError, X25519KeyPair};
use hmac::{Hmac, KeyInit, Mac};
use ramflux_protocol::custody::pairing::{
    DataSelection, PairingWire, RoleContext, Transcript, context_commitment_preimage,
    transcript_preimage,
};
use ramflux_protocol::{canonical_json_bytes, domain, encode_base64url};
use sha2::{Digest, Sha256};

type Result<T = ()> = std::result::Result<T, CryptoError>;

const INIT_SECRET: [u8; 32] = [7; 32];
const RESP_SECRET: [u8; 32] = [8; 32];
const INIT_SALT: [u8; 32] = [11; 32];
const RESP_SALT: [u8; 32] = [12; 32];

/// Independent Matrix SAS table (glyph, English name, scalar code points including VS16).
const INDEPENDENT_SAS_EMOJI: [(&str, &str, &[u32]); 64] = [
    ("🐶", "Dog", &[0x1F436]),
    ("🐱", "Cat", &[0x1F431]),
    ("🦁", "Lion", &[0x1F981]),
    ("🐴", "Horse", &[0x1F434]),
    ("🦄", "Unicorn", &[0x1F984]),
    ("🐷", "Pig", &[0x1F437]),
    ("🐘", "Elephant", &[0x1F418]),
    ("🐰", "Rabbit", &[0x1F430]),
    ("🐼", "Panda", &[0x1F43C]),
    ("🐓", "Rooster", &[0x1F413]),
    ("🐧", "Penguin", &[0x1F427]),
    ("🐢", "Turtle", &[0x1F422]),
    ("🐟", "Fish", &[0x1F41F]),
    ("🐙", "Octopus", &[0x1F419]),
    ("🦋", "Butterfly", &[0x1F98B]),
    ("🌷", "Flower", &[0x1F337]),
    ("🌳", "Tree", &[0x1F333]),
    ("🌵", "Cactus", &[0x1F335]),
    ("🍄", "Mushroom", &[0x1F344]),
    ("🌏", "Globe", &[0x1F30F]),
    ("🌙", "Moon", &[0x1F319]),
    ("☁️", "Cloud", &[0x2601, 0xFE0F]),
    ("🔥", "Fire", &[0x1F525]),
    ("🍌", "Banana", &[0x1F34C]),
    ("🍎", "Apple", &[0x1F34E]),
    ("🍓", "Strawberry", &[0x1F353]),
    ("🌽", "Corn", &[0x1F33D]),
    ("🍕", "Pizza", &[0x1F355]),
    ("🎂", "Cake", &[0x1F382]),
    ("❤️", "Heart", &[0x2764, 0xFE0F]),
    ("😀", "Smiley", &[0x1F600]),
    ("🤖", "Robot", &[0x1F916]),
    ("🎩", "Hat", &[0x1F3A9]),
    ("👓", "Glasses", &[0x1F453]),
    ("🔧", "Spanner", &[0x1F527]),
    ("🎅", "Santa", &[0x1F385]),
    ("👍", "Thumbs Up", &[0x1F44D]),
    ("☂️", "Umbrella", &[0x2602, 0xFE0F]),
    ("⌛", "Hourglass", &[0x231B]),
    ("⏰", "Clock", &[0x23F0]),
    ("🎁", "Gift", &[0x1F381]),
    ("💡", "Light Bulb", &[0x1F4A1]),
    ("📕", "Book", &[0x1F4D5]),
    ("✏️", "Pencil", &[0x270F, 0xFE0F]),
    ("📎", "Paperclip", &[0x1F4CE]),
    ("✂️", "Scissors", &[0x2702, 0xFE0F]),
    ("🔒", "Lock", &[0x1F512]),
    ("🔑", "Key", &[0x1F511]),
    ("🔨", "Hammer", &[0x1F528]),
    ("☎️", "Telephone", &[0x260E, 0xFE0F]),
    ("🏁", "Flag", &[0x1F3C1]),
    ("🚂", "Train", &[0x1F682]),
    ("🚲", "Bicycle", &[0x1F6B2]),
    ("✈️", "Aeroplane", &[0x2708, 0xFE0F]),
    ("🚀", "Rocket", &[0x1F680]),
    ("🏆", "Trophy", &[0x1F3C6]),
    ("⚽", "Ball", &[0x26BD]),
    ("🎸", "Guitar", &[0x1F3B8]),
    ("🎺", "Trumpet", &[0x1F3BA]),
    ("🔔", "Bell", &[0x1F514]),
    ("⚓", "Anchor", &[0x2693]),
    ("🎧", "Headphones", &[0x1F3A7]),
    ("📁", "Folder", &[0x1F4C1]),
    ("📌", "Pin", &[0x1F4CC]),
];

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

fn transfer_transcript() -> Result<Transcript> {
    let mut transcript = bound_transcript()?;
    let transfer_id = encode_base64url([23; 32]);
    transcript.initiator.common.purpose = "primary_transfer".into();
    transcript.initiator.common.requested_role = "primary".into();
    transcript.initiator.common.hpke_suite = Some(domain::CUSTODY_TRANSFER_HPKE_SUITE.into());
    transcript.initiator.common.transfer_id = Some(transfer_id);
    transcript.initiator.common.data_selection =
        vec![DataSelection { key_id: "hist".into(), purpose: "history".into() }];
    transcript.responder.common = transcript.initiator.common.clone();
    transcript.initiator.hpke_key = Some(encode_base64url([21; 32]));
    transcript.responder.hpke_key = Some(encode_base64url([22; 32]));
    transcript.validate().map_err(CryptoError::from)?;
    Ok(transcript)
}

fn transfer_existing_transcript() -> Result<Transcript> {
    let mut transcript = transfer_transcript()?;
    let dest = transcript.responder.device_ref.clone();
    transcript.initiator.common.recipient_mode = "existing".into();
    transcript.initiator.common.destination_ref = Some(dest.clone());
    transcript.responder.common = transcript.initiator.common.clone();
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
    let _ = initiator.reveal()?;
    let _ = responder.reveal()?;
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

fn assert_wiped_bytes() {
    assert!(last_wiped_pairing_bytes().iter().all(|byte| *byte == 0), "pairing secrets not zeroed");
}

fn independent_hkdf<const N: usize>(ikm: &[u8], salt: &[u8], info: &[u8]) -> Result<[u8; N]> {
    let kdf = hkdf::Hkdf::<Sha256>::new(Some(salt), ikm);
    let mut out = [0_u8; N];
    kdf.expand(info, &mut out).map_err(|_| CryptoError::HkdfFailed)?;
    Ok(out)
}

fn expect_commit_mismatch(
    transcript: &Transcript,
    peer_role: PairingRole,
    mutate: impl FnOnce(&mut RoleContext),
) -> Result {
    let (local_role, local_ctx, local_secret, local_salt, peer_ctx, peer_secret, peer_salt) =
        match peer_role {
            PairingRole::Responder => (
                PairingRole::Initiator,
                &transcript.initiator,
                &INIT_SECRET,
                &INIT_SALT,
                &transcript.responder,
                &RESP_SECRET,
                &RESP_SALT,
            ),
            PairingRole::Initiator => (
                PairingRole::Responder,
                &transcript.responder,
                &RESP_SECRET,
                &RESP_SALT,
                &transcript.initiator,
                &INIT_SECRET,
                &INIT_SALT,
            ),
        };
    let mut peer = peer_ctx.clone();
    mutate(&mut peer);
    let mut session = pending(local_role, local_ctx, local_secret, local_salt)?;
    let honest = pending(peer_role, peer_ctx, peer_secret, peer_salt)?;
    session.store_peer_commitment(peer_role, honest.commitment())?;
    expect_pairing(session.establish(&peer, peer_salt).map(|_| ()), "commitment_mismatch")
}

#[test]
fn pairing_sas_transcript_role_and_human_confirmation() -> Result {
    fixture_hashes()?;
    role_binding()?;
    human_confirmation_and_macs()?;
    commit_before_reveal()?;
    session_dead_after_cleanup()?;
    full_context_negatives()?;
    two_leg_ordering()?;
    independent_derivation()?;
    pin_independent_emoji_table();
    emoji_index_out_of_range()?;
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

fn commit_before_reveal() -> Result {
    let transcript = bound_transcript()?;
    let mut initiator =
        pending(PairingRole::Initiator, &transcript.initiator, &INIT_SECRET, &INIT_SALT)?;
    expect_pairing(initiator.salt().map(|_| ()), "peer_commit_missing")?;
    expect_pairing(initiator.context().map(|_| ()), "peer_commit_missing")?;
    expect_pairing(initiator.reveal().map(|_| ()), "peer_commit_missing")?;
    let responder =
        pending(PairingRole::Responder, &transcript.responder, &RESP_SECRET, &RESP_SALT)?;
    initiator.store_peer_commitment(PairingRole::Responder, responder.commitment())?;
    assert_eq!(initiator.salt()?, INIT_SALT);
    assert_eq!(initiator.context()?.sas_key, transcript.initiator.sas_key);
    let (salt, context) = initiator.reveal()?;
    assert_eq!(salt, INIT_SALT);
    assert_eq!(context.display_name, transcript.initiator.display_name);
    Ok(())
}

fn session_dead_after_cleanup() -> Result {
    let transcript = bound_transcript()?;
    let mut session =
        pending(PairingRole::Initiator, &transcript.initiator, &INIT_SECRET, &INIT_SALT)?;
    session.cleanup();
    assert!(session.secrets_are_cleared());
    expect_pairing(session.salt().map(|_| ()), "cleaned")?;
    expect_pairing(session.context().map(|_| ()), "cleaned")?;
    expect_pairing(session.reveal().map(|_| ()), "cleaned")?;
    expect_pairing(session.store_peer_commitment(PairingRole::Responder, [1; 32]), "cleaned")?;
    expect_pairing(session.establish(&transcript.responder, &RESP_SALT).map(|_| ()), "cleaned")?;
    let mut session =
        pending(PairingRole::Initiator, &transcript.initiator, &INIT_SECRET, &INIT_SALT)?;
    let honest = pending(PairingRole::Responder, &transcript.responder, &RESP_SECRET, &RESP_SALT)?;
    session.store_peer_commitment(PairingRole::Responder, honest.commitment())?;
    expect_pairing(
        session.store_peer_commitment(PairingRole::Responder, [9; 32]),
        "duplicate_commit",
    )?;
    assert!(session.secrets_are_cleared());
    expect_pairing(session.salt().map(|_| ()), "cleaned")?;
    expect_pairing(session.establish(&transcript.responder, &RESP_SALT).map(|_| ()), "cleaned")?;
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
    enroll_field_negatives(&transcript)?;
    transfer_field_negatives()?;
    noncontributory_peer()?;
    reflection_peer()?;
    Ok(())
}

fn enroll_field_negatives(transcript: &Transcript) -> Result {
    expect_commit_mismatch(transcript, PairingRole::Responder, |peer| {
        peer.display_name = "mutated".into();
    })?;
    expect_commit_mismatch(transcript, PairingRole::Responder, |peer| {
        peer.branch_key = encode_base64url([9; 32]);
    })?;
    expect_commit_mismatch(transcript, PairingRole::Responder, |peer| {
        peer.agreement_key = encode_base64url([10; 32]);
    })?;
    expect_commit_mismatch(transcript, PairingRole::Responder, |peer| {
        peer.sas_key = encode_base64url(X25519KeyPair::from_seed([9; 32]).public);
    })?;
    expect_commit_mismatch(transcript, PairingRole::Responder, |peer| {
        peer.device_ref.device_id = "mutated-device".into();
    })?;
    expect_commit_mismatch(transcript, PairingRole::Responder, |peer| {
        peer.device_ref.device_epoch = 2;
    })?;
    expect_commit_mismatch(transcript, PairingRole::Responder, |peer| {
        let anchor = encode_base64url([14; 32]);
        peer.common.account_anchor = anchor.clone();
        peer.device_ref.account_anchor = anchor;
    })?;
    expect_commit_mismatch(transcript, PairingRole::Responder, |peer| {
        peer.common.invitation_id = encode_base64url([31; 32]);
    })?;
    expect_commit_mismatch(transcript, PairingRole::Responder, |peer| {
        peer.common.issuer_seq = 2;
    })?;
    expect_commit_mismatch(transcript, PairingRole::Responder, |peer| {
        peer.common.master_public_key = encode_base64url([15; 32]);
    })?;
    expect_commit_mismatch(transcript, PairingRole::Responder, |peer| {
        peer.common.record_hash = encode_base64url([16; 32]);
    })?;
    expect_commit_mismatch(transcript, PairingRole::Responder, |peer| {
        peer.common.device_set_epoch = 4_294_967_298;
    })?;
    expect_commit_mismatch(transcript, PairingRole::Responder, |peer| {
        peer.common.capabilities =
            vec!["call".into(), "group".into(), "message".into(), "register".into()];
    })?;
    expect_commit_mismatch(transcript, PairingRole::Responder, |peer| {
        peer.common.lease_not_before = 1_700_000_001;
    })?;
    expect_commit_mismatch(transcript, PairingRole::Responder, |peer| {
        peer.common.lease_expires_at = 1_702_591_999;
    })?;
    expect_commit_mismatch(transcript, PairingRole::Responder, |peer| {
        peer.common.expires_at = 1_700_000_301;
    })?;
    Ok(())
}

fn transfer_field_negatives() -> Result {
    let transcript = transfer_transcript()?;
    expect_commit_mismatch(&transcript, PairingRole::Responder, |peer| {
        peer.hpke_key = Some(encode_base64url([24; 32]));
    })?;
    expect_commit_mismatch(&transcript, PairingRole::Responder, |peer| {
        peer.common.transfer_id = Some(encode_base64url([25; 32]));
    })?;
    expect_commit_mismatch(&transcript, PairingRole::Responder, |peer| {
        peer.common.data_selection[0].key_id = "hist2".into();
    })?;
    expect_commit_mismatch(&transcript, PairingRole::Responder, |peer| {
        peer.common.data_selection[0].purpose = "attachment".into();
    })?;
    let existing = transfer_existing_transcript()?;
    expect_commit_mismatch(&existing, PairingRole::Initiator, |peer| {
        if let Some(dest) = &mut peer.common.destination_ref {
            dest.device_id = "other-primary".into();
        }
    })?;
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

fn reflection_peer() -> Result {
    let transcript = bound_transcript()?;
    let mut initiator =
        pending(PairingRole::Initiator, &transcript.initiator, &INIT_SECRET, &INIT_SALT)?;
    let mut peer = transcript.responder.clone();
    peer.sas_key = transcript.initiator.sas_key.clone();
    let frozen = sha256(&context_commitment_preimage(&peer, &RESP_SALT)?);
    initiator.store_peer_commitment(PairingRole::Responder, frozen)?;
    expect_pairing(initiator.establish(&peer, &RESP_SALT).map(|_| ()), "reflection")
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
    let transfer = transfer_transcript()?;
    expect_commit_mismatch(&transfer, PairingRole::Responder, |peer| {
        peer.hpke_key = Some(encode_base64url([26; 32]));
    })?;
    expect_commit_mismatch(&transfer, PairingRole::Responder, |peer| {
        peer.common.lease_not_before = 1_700_000_002;
    })?;
    expect_commit_mismatch(&transfer, PairingRole::Responder, |peer| {
        peer.common.capabilities = vec!["call".into(), "message".into(), "sync".into()];
    })?;
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
    let emoji = emoji_from_indices(indices)?;
    assert_eq!(emoji[0].name, SAS_EMOJI[usize::from(indices[0])].1);
    assert_eq!(SAS_EMOJI[0], ("🐶", "Dog"));
    assert_eq!(SAS_EMOJI[3], ("🐴", "Horse"));
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

fn pin_independent_emoji_table() {
    assert_eq!(SAS_EMOJI.len(), 64);
    assert_eq!(INDEPENDENT_SAS_EMOJI.len(), 64);
    for (index, ((glyph, name), (want_glyph, want_name, units))) in
        SAS_EMOJI.iter().zip(INDEPENDENT_SAS_EMOJI).enumerate()
    {
        assert_eq!(*glyph, want_glyph, "glyph {index}");
        assert_eq!(*name, want_name, "name {index}");
        let got: Vec<u32> = glyph.chars().map(u32::from).collect();
        assert_eq!(got, units, "code point {index}");
    }
    assert_eq!(SAS_EMOJI[3].0.chars().next(), Some('\u{1F434}'));
}

fn emoji_index_out_of_range() -> Result {
    expect_pairing(emoji_from_indices([64, 0, 0, 0, 0, 0, 0]).map(|_| ()), "emoji_index")?;
    expect_pairing(emoji_from_indices([0, 0, 0, 0, 0, 0, 255]).map(|_| ()), "emoji_index")
}

#[test]
fn pairing_owned_secret_cleanup_all_exits() -> Result {
    let _ = take_pairing_secret_cleanups();
    cancel_exit()?;
    assert_eq!(take_pairing_secret_cleanups(), 1, "cancel");
    assert_wiped_bytes();
    commitment_mismatch_exit()?;
    assert_eq!(take_pairing_secret_cleanups(), 1, "commitment_mismatch");
    assert_wiped_bytes();
    missing_peer_commit_exit()?;
    assert_eq!(take_pairing_secret_cleanups(), 1, "peer_commit_missing");
    assert_wiped_bytes();
    mismatch_confirm_exit()?;
    assert_eq!(take_pairing_secret_cleanups(), 3, "sas_mismatch");
    assert_wiped_bytes();
    success_exit()?;
    assert_eq!(take_pairing_secret_cleanups(), 4, "success");
    assert_wiped_bytes();
    store_role_mismatch_exit()?;
    assert_eq!(take_pairing_secret_cleanups(), 1, "store_role_mismatch");
    assert_wiped_bytes();
    duplicate_commit_exit()?;
    assert_eq!(take_pairing_secret_cleanups(), 1, "duplicate_commit");
    assert_wiped_bytes();
    confirm_mac_exit()?;
    assert_eq!(take_pairing_secret_cleanups(), 3, "confirm_mac");
    assert_wiped_bytes();
    transcript_hash_exit()?;
    assert_eq!(take_pairing_secret_cleanups(), 3, "transcript_hash");
    assert_wiped_bytes();
    noncontributory_exit()?;
    assert_eq!(take_pairing_secret_cleanups(), 1, "noncontributory");
    assert_wiped_bytes();
    reflection_exit()?;
    assert_eq!(take_pairing_secret_cleanups(), 1, "reflection");
    assert_wiped_bytes();
    channel_counter_exit()?;
    assert_eq!(take_pairing_secret_cleanups(), 1, "channel_counter");
    assert_wiped_bytes();
    channel_aead_exit()?;
    assert_eq!(take_pairing_secret_cleanups(), 1, "channel_aead");
    assert_wiped_bytes();
    Ok(())
}

fn cancel_exit() -> Result {
    let transcript = bound_transcript()?;
    let mut pending =
        pending(PairingRole::Initiator, &transcript.initiator, &INIT_SECRET, &INIT_SALT)?;
    pending.cleanup();
    assert!(pending.secrets_are_cleared());
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
    assert!(initiator.secrets_are_cleared());
    assert!(responder.secrets_are_cleared());
    Ok(())
}

fn store_role_mismatch_exit() -> Result {
    let transcript = bound_transcript()?;
    let mut initiator =
        pending(PairingRole::Initiator, &transcript.initiator, &INIT_SECRET, &INIT_SALT)?;
    expect_pairing(
        initiator.store_peer_commitment(PairingRole::Initiator, [2; 32]),
        "role_mismatch",
    )?;
    assert!(initiator.secrets_are_cleared());
    Ok(())
}

fn duplicate_commit_exit() -> Result {
    let transcript = bound_transcript()?;
    let mut session =
        pending(PairingRole::Initiator, &transcript.initiator, &INIT_SECRET, &INIT_SALT)?;
    let honest = pending(PairingRole::Responder, &transcript.responder, &RESP_SECRET, &RESP_SALT)?;
    session.store_peer_commitment(PairingRole::Responder, honest.commitment())?;
    expect_pairing(
        session.store_peer_commitment(PairingRole::Responder, [9; 32]),
        "duplicate_commit",
    )?;
    assert!(session.secrets_are_cleared());
    Ok(())
}

fn confirm_mac_exit() -> Result {
    let (mut initiator, _responder) = handshake()?;
    expect_pairing(initiator.accept_peer_mac(&[3; 32]), "confirm_mac")?;
    assert!(initiator.secrets_are_cleared());
    Ok(())
}

fn transcript_hash_exit() -> Result {
    let (mut initiator, _responder) = handshake()?;
    expect_pairing(initiator.confirm_local(&[0; 32], true).map(|_| ()), "transcript_hash")?;
    assert!(initiator.secrets_are_cleared());
    Ok(())
}

fn noncontributory_exit() -> Result {
    noncontributory_peer()
}

fn reflection_exit() -> Result {
    reflection_peer()
}

fn channel_counter_exit() -> Result {
    let (mut initiator, mut responder) = confirmed()?;
    let _ = take_pairing_secret_cleanups();
    let (counter, ciphertext) = initiator.seal(b"ok")?;
    drop(responder.open(counter, &ciphertext)?);
    expect_pairing(responder.open(counter, &ciphertext).map(|_| ()), "channel_counter")?;
    assert!(responder.secrets_are_cleared());
    Ok(())
}

fn channel_aead_exit() -> Result {
    let (_initiator, mut responder) = confirmed()?;
    let _ = take_pairing_secret_cleanups();
    expect_pairing(responder.open(0, b"not-aead").map(|_| ()), "channel_aead")?;
    assert!(responder.secrets_are_cleared());
    Ok(())
}

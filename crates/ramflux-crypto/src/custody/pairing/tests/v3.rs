// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain
use super::*;
use ramflux_protocol::custody::pairing::context_v3::{RoleContextV3, TranscriptV3};
use serde_json::json;

fn full_transcript() -> Result<TranscriptV3> {
    let mut value = serde_json::to_value(transfer_transcript()?)
        .map_err(|_| CryptoError::Pairing("fixture"))?;
    value["schema"] = json!("ramflux.pairing.Transcript.v3");
    value["version"] = json!(3);
    for name in ["initiator", "responder"] {
        value[name]["schema"] = json!("ramflux.pairing.RoleContext.v3");
        value[name]["version"] = json!(3);
        value[name]["common"]["schema"] = json!("ramflux.pairing.Common.v3");
        value[name]["common"]["version"] = json!(3);
        value[name]["common"]["data_selection"] = json!({"full_account_data_v1":{}});
        value[name]["transfer_profile"] = json!("full_account_data_v1");
    }
    Ok(TranscriptV3::from_wire_bytes(&canonical_json_bytes(&value)?)?)
}

#[test]
fn pairing_v3_real_sas_agrees_and_opens_only_after_both_confirmations() -> Result {
    let transcript = full_transcript()?;
    let mut a = commit(PairingRole::Initiator, &transcript.initiator, &INIT_SECRET, &INIT_SALT)?;
    let mut b = commit(PairingRole::Responder, &transcript.responder, &RESP_SECRET, &RESP_SALT)?;
    a.store_peer_commitment(PairingRole::Responder, b.commitment())?;
    b.store_peer_commitment(PairingRole::Initiator, a.commitment())?;
    let mut a = a.establish_wire(&transcript.responder.to_wire_bytes()?, &RESP_SALT)?;
    let mut b = b.establish_wire(&transcript.initiator.to_wire_bytes()?, &INIT_SALT)?;
    assert_eq!(a.transcript_hash(), b.transcript_hash());
    assert_eq!(a.emoji_indices(), b.emoji_indices());
    let am = a.confirm_local(&a.transcript_hash(), true)?;
    let bm = b.confirm_local(&b.transcript_hash(), true)?;
    a.accept_peer_mac(&bm)?;
    b.accept_peer_mac(&am)?;
    let (counter, encrypted) = a.seal(b"full profile confirmed")?;
    assert_eq!(b.open(counter, &encrypted)?.as_slice(), b"full profile confirmed");
    Ok(())
}

#[test]
fn pairing_v3_commit_refuses_v2_reply_without_downgrade() -> Result {
    let transcript = full_transcript()?;
    let mut a = commit(PairingRole::Initiator, &transcript.initiator, &INIT_SECRET, &INIT_SALT)?;
    let old = transfer_transcript()?;
    let b = commit(PairingRole::Responder, &old.responder, &RESP_SECRET, &RESP_SALT)?;
    a.store_peer_commitment(PairingRole::Responder, b.commitment())?;
    assert!(matches!(
        a.establish_wire(&old.responder.to_wire_bytes()?, &RESP_SALT),
        Err(CryptoError::Pairing("UpdateRequired"))
    ));
    Ok(())
}

#[test]
fn pairing_v3_sas_commitment_covers_transfer_profile_and_full_selection() -> Result {
    let transcript = full_transcript()?;
    let b = commit(PairingRole::Responder, &transcript.responder, &RESP_SECRET, &RESP_SALT)?;
    let mut independently_framed = b"ramflux.identity.pairing.context_commitment.v3\0".to_vec();
    independently_framed.push(1);
    independently_framed.extend_from_slice(&RESP_SALT);
    independently_framed.extend(canonical_json_bytes(&transcript.responder)?);
    assert_eq!(b.commitment(), <[u8; 32]>::from(Sha256::digest(&independently_framed)));
    let mut changed: RoleContextV3 = transcript.responder.clone();
    changed.transfer_profile = None;
    let mut altered = b"ramflux.identity.pairing.context_commitment.v3\0".to_vec();
    altered.push(1);
    altered.extend_from_slice(&RESP_SALT);
    altered.extend(canonical_json_bytes(&changed)?);
    assert_ne!(b.commitment(), <[u8; 32]>::from(Sha256::digest(&altered)));
    let mut a = commit(PairingRole::Initiator, &transcript.initiator, &INIT_SECRET, &INIT_SALT)?;
    a.store_peer_commitment(PairingRole::Responder, b.commitment())?;
    assert!(a.establish_wire(&canonical_json_bytes(&changed)?, &RESP_SALT).is_err());
    Ok(())
}

#[test]
fn pairing_v3_rejects_and_retires_channel_before_human_confirmation() -> Result {
    let transcript = full_transcript()?;
    let mut a = commit(PairingRole::Initiator, &transcript.initiator, &INIT_SECRET, &INIT_SALT)?;
    let b = commit(PairingRole::Responder, &transcript.responder, &RESP_SECRET, &RESP_SALT)?;
    a.store_peer_commitment(PairingRole::Responder, b.commitment())?;
    let mut a = a.establish_wire(&transcript.responder.to_wire_bytes()?, &RESP_SALT)?;
    assert!(matches!(
        a.seal(b"not confirmed"),
        Err(CryptoError::Pairing("human_confirmation_required"))
    ));
    assert!(a.confirm_local(&a.transcript_hash(), true).is_err());
    Ok(())
}

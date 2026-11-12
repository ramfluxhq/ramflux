// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Actual SDK bootstrap/proofs/HPKE/Ready. No HTTP, complete-manifest or application claim.
use super::*;
type ResultOf<T = ()> = Result<T, Box<dyn std::error::Error>>;
fn h(n: u8) -> String {
    encode_base64url([n; 32])
}
fn manifest(hash: &str) -> DataPacket {
    DataPacket::Manifest {
        manifest_hash: hash.into(),
        offset: U64(0),
        total: U64(1),
        bytes: SecretBase64::from_bytes(b"x"),
    }
}
#[tokio::test]
async fn pairing_full_sdk_epoch_ready_consumes_r0_and_positions_both_manifest_directions()
-> ResultOf {
    let (a, b) = super::super::tests::epochs().await?;
    let (mut a, control) = a.source_control()?;
    let mut b = b.destination_control(&control)?;
    let ready = b.seal_ready()?;
    assert_eq!(ready.counter.0, 0);
    assert_eq!(ready.role, "responder");
    a.accept_ready(&ready)?;
    let current = h(80); // Reconnect may be streaming a child, never infer its acceptance here.
    let forward = a.seal_packet(&manifest(&current))?;
    assert_eq!(forward.counter.0, 0);
    assert!(
        matches!(b.open_packet(&forward)?,Some(DataPacket::Manifest {manifest_hash,..}) if manifest_hash==current)
    );
    let reverse = b.seal_packet(&manifest(&h(81)))?;
    assert_eq!(reverse.counter.0, 1, "Ready reset responder data counters");
    assert!(matches!(a.open_packet(&reverse)?, Some(DataPacket::Manifest { .. })));
    assert_eq!(a.last_received, Some(1));
    assert_eq!(b.last_received, Some(0));
    Ok(())
}
#[tokio::test]
async fn pairing_full_sdk_epoch_wrong_ready_base_hash_retires_token_and_cipher() -> ResultOf {
    let (a, mut b) = super::super::tests::epochs().await?;
    let (mut a, control) = a.source_control()?;
    // Hostile B has the correct exporter keys but deliberately emits another Ready hash.
    let keys = b.verified.open_control(&control, &b.binding)?;
    let mut malicious = FullConfirmedChannel::resume(PairingRole::Responder, keys, h(99))?;
    let (counter, bytes) = malicious.seal_ready()?;
    let ready = EncryptedPacket {
        counter: U64(counter),
        ciphertext: encode_base64url(bytes),
        epoch: b.epoch,
        lease_id: b.lease_id,
        role: "responder".into(),
    };
    assert!(a.accept_ready(&ready).is_err(), "wrong base manifest Ready accepted");
    assert!(a.channel.is_none() && a.token.is_none(), "failed Ready retained crypto/token");
    assert!(a.seal_packet(&manifest(&h(80))).is_err());
    Ok(())
}
#[tokio::test]
async fn pairing_full_sdk_epoch_foreign_control_and_packet_scope_refused() -> ResultOf {
    let (a, b) = super::super::tests::epochs().await?;
    let (mut a, mut control) = a.source_control()?;
    control.epoch = h(98);
    assert!(b.destination_control(&control).is_err(), "foreign control opened with local HPKE key");
    let foreign = EncryptedPacket {
        counter: U64(0),
        ciphertext: encode_base64url([0; 16]),
        epoch: h(98),
        lease_id: a.lease_id.clone(),
        role: "responder".into(),
    };
    assert!(a.accept_ready(&foreign).is_err());
    assert!(a.token.is_none() && a.channel.is_none());
    Ok(())
}
#[tokio::test]
async fn pairing_full_sdk_epoch_expired_lease_retires_existing_packet_keys() -> ResultOf {
    let (a, b) = super::super::tests::epochs().await?;
    let (mut a, control) = a.source_control()?;
    let mut b = b.destination_control(&control)?;
    a.accept_ready(&b.seal_ready()?)?;
    a.expires_at = crate::custody::network_now()?;
    assert!(matches!(a.seal_packet(&manifest(&h(80))), Err(SdkError::PairingCode("LeaseExpired"))));
    assert!(a.channel.is_none() && a.token.is_none());
    Ok(())
}

#[tokio::test]
async fn pairing_full_sdk_manifest_framing_failure_retires_authenticated_epoch() -> ResultOf {
    let (a, b) = super::super::tests::epochs().await?;
    let (mut a, control) = a.source_control()?;
    let mut b = b.destination_control(&control)?;
    a.accept_ready(&b.seal_ready()?)?;
    let part = a.seal_packet(&manifest(&h(80)))?;
    let mut assembler =
        ramflux_protocol::custody::pairing::full_transfer::ManifestAssembler::default();
    assert!(
        b.open_manifest_part(&part, &mut assembler).is_err(),
        "authenticated invalid manifest reached staging"
    );
    assert!(b.channel.is_none() && b.token.is_none(), "manifest refusal retained channel/token");
    assert!(b.open_manifest_part(&part, &mut assembler).is_err(), "refused epoch revived");
    Ok(())
}

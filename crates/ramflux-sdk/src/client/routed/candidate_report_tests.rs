// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use super::*;
use ramflux_crypto::CryptoError;

fn resign(sender: &Fixture, envelope: &mut ramflux_protocol::Envelope) -> Result<(), SdkError> {
    envelope.signed.signature = ramflux_crypto::sign_protocol_object_with_device_branch(
        sender.client.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?,
        envelope,
    )?;
    Ok(())
}

fn report_mismatch(result: Result<Opened, SdkError>) -> Result<(), SdkError> {
    match result {
        Err(SdkError::Crypto(CryptoError::ReportCommitmentMismatch)) => {
            assert_eq!(
                SdkError::Crypto(CryptoError::ReportCommitmentMismatch).to_string(),
                "crypto error: report opening commitment mismatch"
            );
            Ok(())
        }
        Err(error) => Err(invalid(&format!("exact report commitment mismatch, got {error}"))),
        Ok(_) => Err(invalid("exact report commitment mismatch, got Ok")),
    }
}

#[test]
fn direct_seal_writes_tag_and_commitment_and_opens() -> Result<(), SdkError> {
    let _gate = ramflux_protocol::schema_profile::SchemaV1LiveGuard::enter();
    let (_a, b, entry) = {
        let a = Fixture::new("alice", 141)?;
        let b = Fixture::new("bob", 142)?;
        let entry = seal(&a, &b, message("report-ok", "c"), b"report-body")?;
        (a, b, entry)
    };
    let tag = ramflux_protocol::decode_base64url(
        entry.envelope.collapse_tag.as_deref().ok_or_else(|| invalid("collapse_tag"))?,
    )
    .map_err(|_| invalid("collapse_tag"))?;
    let commitment = ramflux_protocol::decode_base64url(
        entry.envelope.report_commitment.as_deref().ok_or_else(|| invalid("report_commitment"))?,
    )
    .map_err(|_| invalid("report_commitment"))?;
    assert_eq!(tag.len(), 32);
    assert_eq!(commitment.len(), 32);
    assert_eq!(entry.envelope.delivery_mode.as_deref(), Some("durable"));
    let opened = b.client.open_routed(&entry, "bob")?;
    assert_eq!(opened.body.as_slice(), b"report-body");
    Ok(())
}

#[test]
fn tampered_opening_refused_and_next_message_opens() -> Result<(), SdkError> {
    let _gate = ramflux_protocol::schema_profile::SchemaV1LiveGuard::enter();
    let a = Fixture::new("alice", 143)?;
    let b = Fixture::new("bob", 144)?;
    let entry = seal(&a, &b, message("report-tamper", "c"), b"tamper-body")?;
    let mut tampered = entry.clone();
    tampered.envelope.report_commitment = Some(ramflux_protocol::encode_base64url([0x00_u8; 32]));
    resign(&a, &mut tampered.envelope)?;
    report_mismatch(b.client.open_routed(&tampered, "bob"))?;
    let next = seal(&a, &b, message("report-next", "c"), b"next-body")?;
    let opened = b.client.open_routed(&next, "bob")?;
    assert_eq!(opened.body.as_slice(), b"next-body");
    Ok(())
}

#[test]
fn two_direct_sends_produce_fresh_commitments() -> Result<(), SdkError> {
    let _gate = ramflux_protocol::schema_profile::SchemaV1LiveGuard::enter();
    let a = Fixture::new("alice", 145)?;
    let b = Fixture::new("bob", 146)?;
    let first = seal(&a, &b, message("report-fresh-1", "c"), b"one")?;
    let second = seal(&a, &b, message("report-fresh-2", "c"), b"two")?;
    let first_c = first.envelope.report_commitment.as_deref().ok_or_else(|| invalid("first C"))?;
    let second_c =
        second.envelope.report_commitment.as_deref().ok_or_else(|| invalid("second C"))?;
    assert_ne!(first_c, second_c);
    let first_open = b.client.open_routed(&first, "bob")?;
    let second_open = b.client.open_routed(&second, "bob")?;
    assert_eq!(first_open.body.as_slice(), b"one");
    assert_eq!(second_open.body.as_slice(), b"two");
    let first_kf = ramflux_crypto::parse_report_plaintext(&first_open.decrypted.plaintext)?;
    let second_kf = ramflux_crypto::parse_report_plaintext(&second_open.decrypted.plaintext)?;
    assert_ne!(first_kf.opening(), second_kf.opening());
    Ok(())
}

#[test]
fn gate_off_omits_report_fields_and_legacy_bytes_open() -> Result<(), SdkError> {
    assert!(!ramflux_protocol::schema_profile::schema_v1_live());
    let a = Fixture::new("alice", 147)?;
    let b = Fixture::new("bob", 148)?;
    let entry = seal(&a, &b, message("report-legacy", "c"), b"legacy-body")?;
    assert_eq!(entry.envelope.collapse_tag, None);
    assert_eq!(entry.envelope.report_commitment, None);
    let json = serde_json::to_vec(&entry.envelope)?;
    assert!(!json.windows(b"report_commitment".len()).any(|w| w == b"report_commitment"));
    assert!(!json.windows(b"collapse_tag".len()).any(|w| w == b"collapse_tag"));
    let opened = b.client.open_routed(&entry, "bob")?;
    assert_eq!(opened.body.as_slice(), b"legacy-body");
    Ok(())
}

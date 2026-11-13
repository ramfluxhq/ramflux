// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Framing/correlation unit scope; actual daemon/TTY handoff is tested by its consumers.
use super::{
    CredentialOutcome, CredentialRequest, PrivateCredentialReply, PrivateCredentialScope,
    PrivateCredentialSlot, SdkError, SecretUtf8, encode_reply, invalid, read_reply,
};
fn request(account: &str, requested: &str) -> CredentialRequest {
    CredentialRequest {
        local_account_id: account.into(),
        reservation_id: ramflux_protocol::encode_base64url([1; 32]),
        frontend_generation: 1,
        action: requested.into(),
    }
}
fn secret() -> Result<CredentialOutcome, SdkError> {
    Ok(CredentialOutcome::Provided {
        passphrase: SecretUtf8::from_bytes(b"private-canary")?,
        confirmation: None,
    })
}
fn reply(generation: u64) -> Result<PrivateCredentialReply, SdkError> {
    let bytes = encode_reply(generation, "unlock", &secret()?)?;
    read_reply(&mut bytes.as_slice(), "unlock")
}
#[test]
fn pairing_private_binary_reply_binds_connection_and_nonreused_scope() -> Result<(), SdkError> {
    let a = PrivateCredentialScope::data(request("a", "unlock"), None)?;
    let b = PrivateCredentialScope::data(request("b", "unlock"), None)?;
    let mut slot = PrivateCredentialSlot::new(7);
    let old = slot.issue(a.clone())?;
    slot.retire();
    let new = slot.issue(b.clone())?;
    assert_ne!(old, new, "equal frontend generation reused a private request generation");
    assert!(
        slot.consume(7, &b, reply(old)?).is_err(),
        "stale private reply reached a different account"
    );
    let wrong_connection = slot.issue(a.clone())?;
    assert!(slot.consume(8, &a, reply(wrong_connection)?).is_err());
    let changed_scope = slot.issue(a.clone())?;
    assert!(slot.consume(7, &b, reply(changed_scope)?).is_err());
    let mut other = PrivateCredentialSlot::new(8);
    let own = slot.issue(a.clone())?;
    let foreign = other.issue(b.clone())?;
    assert_ne!(own, foreign, "different connections shared a raw reply generation");
    assert!(
        other.consume(8, &b, reply(own)?).is_err(),
        "another connection's raw reply satisfied this account"
    );
    slot.retire();
    let valid = slot.issue(b.clone())?;
    let CredentialOutcome::Provided { passphrase, confirmation } =
        slot.consume(7, &b, reply(valid)?)?
    else {
        return Err(invalid());
    };
    assert_eq!(passphrase.as_bytes(), b"private-canary");
    assert!(confirmation.is_none());
    assert!(slot.consume(7, &b, reply(valid)?).is_err(), "a second private reply was accepted");
    Ok(())
}
#[test]
fn pairing_private_binary_reply_refuses_malformed_and_phrase_confirmation() -> Result<(), SdkError>
{
    let valid = encode_reply(9, "unlock", &secret()?)?;
    let mut malformed = valid.clone();
    malformed[4] = b'{';
    assert!(read_reply(&mut malformed.as_slice(), "unlock").is_err());
    malformed = valid.clone();
    malformed[..4].copy_from_slice(&2065_u32.to_be_bytes());
    assert!(read_reply(&mut malformed.as_slice(), "unlock").is_err());
    malformed = valid.clone();
    malformed[13] = 2;
    assert!(read_reply(&mut malformed.as_slice(), "unlock").is_err());
    malformed = valid.clone();
    let truncated = malformed.len() - 1;
    malformed.truncate(truncated);
    assert!(read_reply(&mut malformed.as_slice(), "unlock").is_err());
    malformed = valid.clone();
    malformed.push(0);
    let total = u32::try_from(malformed.len() - 4).map_err(|_| invalid())?;
    malformed[..4].copy_from_slice(&total.to_be_bytes());
    assert!(read_reply(&mut malformed.as_slice(), "unlock").is_err());
    malformed = valid.clone();
    malformed[13] = 0;
    assert!(
        read_reply(&mut malformed.as_slice(), "unlock").is_err(),
        "refusal carried secret bytes"
    );
    let setup = CredentialOutcome::Provided {
        passphrase: SecretUtf8::from_bytes(b"private-canary")?,
        confirmation: Some(SecretUtf8::from_bytes(b"private-canary")?),
    };
    assert!(encode_reply(9, "phrase", &setup).is_err());
    let setup_bytes = encode_reply(9, "setup", &setup)?;
    assert!(read_reply(&mut setup_bytes.as_slice(), "phrase").is_err());
    require_provided_arm("setup", &setup)?;
    require_provided_arm("phrase", &secret()?)?;
    let bounded = CredentialOutcome::Provided {
        passphrase: SecretUtf8::from_bytes(&[b'a'; 1024])?,
        confirmation: Some(SecretUtf8::from_bytes(&[b'a'; 1024])?),
    };
    require_provided_arm("setup", &bounded)?;
    let refused = encode_reply(9, "phrase", &CredentialOutcome::Refused)?;
    assert!(matches!(
        read_reply(&mut refused.as_slice(), "phrase")?.outcome,
        CredentialOutcome::Refused
    ));
    let id = ramflux_protocol::encode_base64url([2; 32]);
    assert!(
        PrivateCredentialScope::phrase(
            request("a", "phrase"),
            id.clone(),
            None,
            "initiator",
            "awaiting_prepare"
        )
        .is_err()
    );
    assert!(
        PrivateCredentialScope::phrase(
            request("a", "phrase"),
            id.clone(),
            None,
            "responder",
            "prepared"
        )
        .is_err()
    );
    PrivateCredentialScope::phrase(
        request("a", "phrase"),
        id,
        None,
        "responder",
        "awaiting_prepare",
    )?;
    Ok(())
}

fn require_provided_arm(action: &str, value: &CredentialOutcome) -> Result<(), SdkError> {
    let frame = encode_reply(9, action, value)?;
    let decoded = read_reply(&mut frame.as_slice(), action)?;
    let CredentialOutcome::Provided { passphrase, confirmation } = decoded.outcome else {
        return Err(invalid());
    };
    let CredentialOutcome::Provided { passphrase: expected, confirmation: expected_confirmation } =
        value
    else {
        return Err(invalid());
    };
    assert!(passphrase.as_bytes() == expected.as_bytes(), "private provided bytes changed");
    assert_eq!(confirmation.is_some(), expected_confirmation.is_some());
    if let (Some(actual), Some(expected)) = (confirmation, expected_confirmation) {
        assert!(actual.as_bytes() == expected.as_bytes(), "private confirmation bytes changed");
    }
    Ok(())
}

// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Actual connection reader and attended-call ownership, without generic secret frames.
use super::*;
use crate::custody::pairing::{
    CredentialOutcome, PersistedReservation, SecretUtf8, persist_reservation,
    private_credential::{PrivateCredentialScope, encode_reply, provider_for_account},
};
use ramflux_protocol::custody::pairing::local_dto::CredentialRequest;
type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
fn reservation(root: &Path, account: &str) -> Result<CredentialRequest, SdkError> {
    let stored = PersistedReservation {
        account_id: account.into(),
        reservation_id: ramflux_protocol::encode_base64url([3; 32]),
        frontend_generation: 1,
    };
    persist_reservation(root, &stored)?;
    Ok(CredentialRequest {
        local_account_id: account.into(),
        reservation_id: stored.reservation_id,
        frontend_generation: 1,
        action: "unlock".into(),
    })
}
fn raw(generation: u64) -> Result<zeroize::Zeroizing<Vec<u8>>, SdkError> {
    encode_reply(
        generation,
        "unlock",
        &CredentialOutcome::Provided {
            passphrase: SecretUtf8::from_bytes(b"socket-private-canary")?,
            confirmation: None,
        },
    )
}
fn generation(frame: &LocalBusFrame) -> TestResult<u64> {
    Ok(frame.frame_id.strip_prefix("credential-").ok_or("missing generation")?.parse()?)
}
#[tokio::test]
async fn pairing_private_socket_reader_delivers_only_to_attended_call() -> TestResult {
    let root = tempfile::tempdir()?;
    let expected = reservation(root.path(), "a")?;
    let (outbound, mut prompts) = mpsc::channel(4);
    let input = connection(root.path().into(), 17, outbound);
    let channel = input.channel();
    let _call = bind_call(
        root.path(),
        "a",
        "parent-a".into(),
        PrivateCredentialCallKind::Unlock,
        channel.clone(),
    )?;
    let provider = provider_for_account(root.path(), "a".into())?;
    let worker = tokio::task::spawn_blocking(move || provider.provide(&expected));
    let prompt = prompts.recv().await.ok_or("missing private prompt")?;
    assert_eq!(prompt.request_id, "parent-a");
    assert_eq!(prompt.method, "device.credential.request");
    assert!(!serde_json::to_vec(&prompt)?.windows(21).any(|b| b == b"socket-private-canary"));
    let bytes = raw(generation(&prompt)?)?;
    assert!(read_frame(&mut bytes.as_slice(), &channel, 17).await?.is_none());
    let CredentialOutcome::Provided { passphrase, .. } = worker.await?? else {
        return Err("attended private reply refused".into());
    };
    assert!(passphrase.as_bytes() == b"socket-private-canary", "private socket bytes changed");
    assert!(
        read_frame(&mut bytes.as_slice(), &channel, 17).await.is_err(),
        "second binary reply reached generic routing"
    );
    Ok(())
}
#[tokio::test]
async fn pairing_private_socket_refuses_json_before_private_payload() -> TestResult {
    let root = tempfile::tempdir()?;
    let expected = reservation(root.path(), "a")?;
    let (outbound, mut prompts) = mpsc::channel(4);
    let input = connection(root.path().into(), 18, outbound);
    let channel = input.channel();
    let call = bind_call(
        root.path(),
        "a",
        "parent-a".into(),
        PrivateCredentialCallKind::Unlock,
        channel.clone(),
    )?;
    let provider = provider_for_account(root.path(), "a".into())?;
    let worker = tokio::task::spawn_blocking(move || provider.provide(&expected));
    prompts.recv().await.ok_or("missing private prompt")?;
    let payload = br#"{"passphrase":"socket-private-canary"}"#;
    let mut bytes = Vec::from(u32::try_from(payload.len())?.to_be_bytes());
    bytes.extend_from_slice(payload);
    let mut reader = bytes.as_slice();
    assert!(read_frame(&mut reader, &channel, 18).await.is_err());
    assert_eq!(reader.len(), bytes.len() - 5, "JSON private payload reached generic parser");
    drop(call);
    assert!(matches!(worker.await??, CredentialOutcome::Refused));
    Ok(())
}
#[tokio::test]
async fn pairing_private_call_drop_and_operation_scope_fence_late_input() -> TestResult {
    let root = tempfile::tempdir()?;
    let mut expected = reservation(root.path(), "b")?;
    expected.action = "phrase".into();
    let operation = ramflux_protocol::encode_base64url([4; 32]);
    let scope = PrivateCredentialScope::phrase(
        expected.clone(),
        operation.clone(),
        None,
        "responder",
        "awaiting_prepare",
    )?;
    let (outbound, mut prompts) = mpsc::channel(4);
    let input = connection(root.path().into(), 19, outbound);
    let channel = input.channel();
    let call = bind_call(
        root.path(),
        "b",
        "prepare-b".into(),
        PrivateCredentialCallKind::Prepare { operation_id: operation },
        channel.clone(),
    )?;
    let provider = provider_for_account(root.path(), "b".into())?;
    let worker = tokio::task::spawn_blocking(move || provider.provide_scoped(&expected, &scope));
    let prompt = prompts.recv().await.ok_or("missing phrase prompt")?;
    assert_eq!(prompt.request_id, "prepare-b");
    drop(call);
    assert!(matches!(worker.await??, CredentialOutcome::Refused));
    let bytes = raw(generation(&prompt)?)?;
    let mut reader = bytes.as_slice();
    assert!(read_frame(&mut reader, &channel, 19).await.is_err());
    assert_eq!(reader.len(), bytes.len() - 5, "late private bytes reached JSON");
    let _call =
        bind_call(root.path(), "b", "unlock-b".into(), PrivateCredentialCallKind::Unlock, channel)?;
    let mut phrase = reservation(root.path(), "b")?;
    phrase.action = "phrase".into();
    let scope = PrivateCredentialScope::phrase(
        phrase.clone(),
        ramflux_protocol::encode_base64url([4; 32]),
        None,
        "responder",
        "awaiting_prepare",
    )?;
    assert!(
        provider_for_account(root.path(), "b".into())?.provide_scoped(&phrase, &scope).is_err(),
        "ordinary unlock initiated a phrase prompt"
    );
    Ok(())
}

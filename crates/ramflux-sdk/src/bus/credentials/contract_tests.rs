// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Shared required-name contract: cross-account/connection/cancel and raw malformed inputs.
use super::*;
use crate::custody::pairing::{
    CredentialOutcome, PersistedReservation, SecretUtf8, persist_reservation,
    private_credential::{encode_reply, provider_for_account, read_reply},
};
use tokio::sync::mpsc;
type TestResult = Result<(), Box<dyn std::error::Error>>;
fn reply(generation: u64) -> Result<zeroize::Zeroizing<Vec<u8>>, SdkError> {
    encode_reply(
        generation,
        "unlock",
        &CredentialOutcome::Provided {
            passphrase: SecretUtf8::from_bytes(b"contract-private-canary")?,
            confirmation: None,
        },
    )
}
fn malformed() -> TestResult {
    let valid = reply(1)?;
    let mut overlong = valid.clone();
    overlong[14..16].copy_from_slice(&1025_u16.to_be_bytes());
    assert!(
        read_reply(&mut overlong.as_slice(), "unlock").is_err(),
        "test: malformed or crossed private input escaped its owned callback gate"
    );
    let mut short = &valid[..valid.len() - 1];
    assert!(
        read_reply(&mut short, "unlock").is_err(),
        "test: malformed or crossed private input escaped its owned callback gate"
    );
    let mut trailing = valid.clone();
    trailing.push(0);
    let len = u32::try_from(trailing.len() - 4)?;
    trailing[..4].copy_from_slice(&len.to_be_bytes());
    assert!(
        read_reply(&mut trailing.as_slice(), "unlock").is_err(),
        "test: malformed or crossed private input escaped its owned callback gate"
    );
    let mut unknown = valid.clone();
    unknown[13] = 2;
    assert!(
        read_reply(&mut unknown.as_slice(), "unlock").is_err(),
        "test: malformed or crossed private input escaped its owned callback gate"
    );
    let mut refused = valid;
    refused[13] = 0;
    assert!(
        read_reply(&mut refused.as_slice(), "unlock").is_err(),
        "test: malformed or crossed private input escaped its owned callback gate"
    );
    Ok(())
}
pub(crate) async fn required_demux_cases() -> TestResult {
    malformed()?;
    let root = tempfile::tempdir()?;
    for account in ["a", "b"] {
        persist_reservation(
            root.path(),
            &PersistedReservation {
                account_id: account.into(),
                reservation_id: ramflux_protocol::encode_base64url([8; 32]),
                frontend_generation: 1,
            },
        )?;
    }
    let metadata =
        |account: &str| ramflux_protocol::custody::pairing::local_dto::CredentialRequest {
            local_account_id: account.into(),
            reservation_id: ramflux_protocol::encode_base64url([8; 32]),
            frontend_generation: 1,
            action: "unlock".into(),
        };
    let (txa, mut a) = mpsc::channel(4);
    let (txb, mut b) = mpsc::channel(4);
    let ia = connection(root.path().into(), 81, txa);
    let ib = connection(root.path().into(), 82, txb);
    let ca = ia.channel();
    let cb = ib.channel();
    let call =
        bind_call(root.path(), "a", "old-a".into(), PrivateCredentialCallKind::Unlock, ca.clone())?;
    let _b =
        bind_call(root.path(), "b", "b".into(), PrivateCredentialCallKind::Unlock, cb.clone())?;
    let pa = provider_for_account(root.path(), "a".into())?;
    let pb = provider_for_account(root.path(), "b".into())?;
    let ma = metadata("a");
    let mb = metadata("b");
    let wa = tokio::task::spawn_blocking(move || pa.provide(&ma));
    let wb = tokio::task::spawn_blocking(move || pb.provide(&mb));
    let old = a.recv().await.ok_or("A prompt")?;
    let target = b.recv().await.ok_or("B prompt")?;
    drop(call);
    assert!(
        matches!(wa.await??, CredentialOutcome::Refused),
        "test: malformed or crossed private input escaped its owned callback gate"
    );
    let _fresh = bind_call(
        root.path(),
        "a",
        "fresh-a".into(),
        PrivateCredentialCallKind::Unlock,
        ca.clone(),
    )?;
    let pa = provider_for_account(root.path(), "a".into())?;
    let ma = metadata("a");
    let fresh = tokio::task::spawn_blocking(move || pa.provide(&ma));
    let current = a.recv().await.ok_or("new A prompt")?;
    assert_ne!(old.frame_id, current.frame_id, "cancel/new action reused request generation");
    assert_ne!(target.frame_id, current.frame_id, "equal frontend generation crossed connections");
    let generation = |frame: &LocalBusFrame| -> Result<u64, Box<dyn std::error::Error>> {
        Ok(frame.frame_id.strip_prefix("credential-").ok_or("generation")?.parse()?)
    };
    let stale = reply(generation(&old)?)?;
    let mut reader = stale.as_slice();
    assert!(
        read_frame(&mut reader, &ca, 81).await.is_err(),
        "test: malformed or crossed private input escaped its owned callback gate"
    );
    assert_eq!(reader.len(), stale.len() - 16, "stale generation consumed private payload");
    let crossed = reply(generation(&target)?)?;
    let mut reader = crossed.as_slice();
    assert!(
        read_frame(&mut reader, &ca, 81).await.is_err(),
        "test: malformed or crossed private input escaped its owned callback gate"
    );
    assert_eq!(reader.len(), crossed.len() - 16, "wrong connection consumed private payload");
    let payload = br#"{"passphrase":"contract-private-canary"}"#;
    let mut json = zeroize::Zeroizing::new(Vec::from(u32::try_from(payload.len())?.to_be_bytes()));
    json.extend_from_slice(payload);
    let mut reader = json.as_slice();
    assert!(
        read_frame(&mut reader, &ca, 81).await.is_err(),
        "test: malformed or crossed private input escaped its owned callback gate"
    );
    assert_eq!(reader.len(), json.len() - 5, "private JSON reached generic capture");
    ia.close();
    assert!(
        matches!(fresh.await??, CredentialOutcome::Refused),
        "test: malformed or crossed private input escaped its owned callback gate"
    );
    assert!(
        read_frame(&mut crossed.as_slice(), &cb, 82).await?.is_none(),
        "test: malformed or crossed private input escaped its owned callback gate"
    );
    let CredentialOutcome::Provided { passphrase, .. } = wb.await?? else {
        return Err("B reply refused".into());
    };
    assert!(passphrase.as_bytes() == b"contract-private-canary", "A callback took B bytes");
    Ok(())
}

pub(crate) async fn deadline<T>(
    work: impl std::future::Future<Output = Result<T, Box<dyn std::error::Error>>>,
) -> Result<T, Box<dyn std::error::Error>> {
    tokio::time::timeout(std::time::Duration::from_secs(60), work)
        .await
        .map_err(|_| "test: private pairing input deadline exceeded")?
}

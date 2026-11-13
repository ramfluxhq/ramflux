// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Worker/channel ownership proof; socket and frontend integration are separate consumers.
use super::{
    CredentialOutcome, CredentialRequest, PrivateCredentialChannel, PrivateCredentialScope,
    SecretUtf8, encode_reply,
};
use crate::SdkError;
use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
    mpsc,
};
type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
struct Retire(Arc<PrivateCredentialChannel>);
impl Drop for Retire {
    fn drop(&mut self) {
        self.0.retire();
    }
}
fn request(account: &str) -> CredentialRequest {
    CredentialRequest {
        local_account_id: account.into(),
        reservation_id: ramflux_protocol::encode_base64url([1; 32]),
        frontend_generation: 1,
        action: "unlock".into(),
    }
}
fn fixture() -> (Arc<PrivateCredentialChannel>, mpsc::Receiver<(u64, CredentialRequest)>) {
    let (sender, receiver) = mpsc::channel();
    let channel = Arc::new(PrivateCredentialChannel::new(
        7,
        Arc::new(move |generation, request| {
            sender.send((generation, request.clone())).map_err(|_| SdkError::PairingCode("Retired"))
        }),
    ));
    (channel, receiver)
}
fn scope(request: &CredentialRequest) -> Result<PrivateCredentialScope, SdkError> {
    PrivateCredentialScope::data(request.clone(), None)
}
fn reply(generation: u64) -> Result<zeroize::Zeroizing<Vec<u8>>, SdkError> {
    encode_reply(
        generation,
        "unlock",
        &CredentialOutcome::Provided {
            passphrase: SecretUtf8::from_bytes(b"channel-secret-canary")?,
            confirmation: None,
        },
    )
}
#[test]
fn pairing_private_provider_channel_revalidates_after_input() -> TestResult {
    let (channel, prompts) = fixture();
    let epoch = Arc::new(AtomicU64::new(1));
    let current = epoch.clone();
    let provider = channel.provider(
        "a".into(),
        Arc::new(move |request| {
            let mut bound = request.clone();
            bound.frontend_generation = current.load(Ordering::Acquire);
            PrivateCredentialScope::data(bound, None)
        }),
    );
    std::thread::scope(|threads| -> TestResult {
        let _retire = Retire(channel.clone());
        let worker = threads.spawn(|| provider.provide(&request("a")));
        let (generation, metadata) = prompts.recv()?;
        assert_eq!(metadata.local_account_id, "a");
        epoch.store(2, Ordering::Release); // The actual local callback scope changes while UI waits.
        let bytes = reply(generation)?;
        channel.deliver(7, &mut bytes.as_slice())?;
        assert!(
            worker.join().map_err(|_| "private provider panicked")?.is_err(),
            "stale local scope consumed a secret"
        );
        assert!(!channel.expects_reply());
        Ok(())
    })?;
    let provider = channel.provider("a".into(), Arc::new(scope));
    std::thread::scope(|threads| -> TestResult {
        let _retire = Retire(channel.clone());
        let worker = threads.spawn(|| provider.provide(&request("a")));
        let (generation, _) = prompts.recv()?;
        channel.deliver(7, &mut reply(generation)?.as_slice())?;
        let CredentialOutcome::Provided { passphrase, confirmation } =
            worker.join().map_err(|_| "private provider panicked")??
        else {
            return Err("private provider refused a valid reply".into());
        };
        assert!(passphrase.as_bytes() == b"channel-secret-canary", "private reply bytes changed");
        assert!(confirmation.is_none());
        assert!(
            channel.deliver(7, &mut reply(generation)?.as_slice()).is_err(),
            "second reply satisfied a retired callback"
        );
        Ok(())
    })
}
#[test]
fn pairing_private_provider_cancel_does_not_retire_a_later_account() -> TestResult {
    let (channel, prompts) = fixture();
    let a = channel.provider("a".into(), Arc::new(scope));
    let b = channel.provider("b".into(), Arc::new(scope));
    std::thread::scope(|threads| -> TestResult {
        let _retire = Retire(channel.clone());
        let old = threads.spawn(|| a.provide(&request("a")));
        let (old_generation, _) = prompts.recv()?;
        a.cancel();
        let later = threads.spawn(|| b.provide(&request("b")));
        let (later_generation, _) = prompts.recv()?;
        assert!(matches!(
            old.join().map_err(|_| "cancelled provider panicked")??,
            CredentialOutcome::Refused
        ));
        assert_ne!(old_generation, later_generation);
        a.cancel(); // A's late cancel must not touch B's independently bound pending request.
        assert!(channel.expects_reply());
        let stale = reply(old_generation)?;
        let mut raw = stale.as_slice();
        assert!(channel.deliver(7, &mut raw).is_err());
        assert_eq!(raw.len(), stale.len() - 16, "stale generation consumed private payload bytes");
        assert!(matches!(
            later.join().map_err(|_| "later provider panicked")??,
            CredentialOutcome::Refused
        ));
        Ok(())
    })?;
    std::thread::scope(|threads| -> TestResult {
        let _retire = Retire(channel.clone());
        let worker = threads.spawn(|| b.provide(&request("b")));
        let (generation, _) = prompts.recv()?;
        channel.deliver(7, &mut reply(generation)?.as_slice())?;
        assert!(matches!(
            worker.join().map_err(|_| "fresh provider panicked")??,
            CredentialOutcome::Provided { .. }
        ));
        Ok(())
    })?;
    let fresh_a = channel.provider("a".into(), Arc::new(scope));
    std::thread::scope(|threads| -> TestResult {
        let _retire = Retire(channel.clone());
        let worker = threads.spawn(|| fresh_a.provide(&request("a")));
        let (generation, _) = prompts.recv()?;
        a.cancel(); // A retired provider cannot cancel a later A action either.
        assert!(channel.expects_reply());
        channel.deliver(7, &mut reply(generation)?.as_slice())?;
        assert!(matches!(
            worker.join().map_err(|_| "new A provider panicked")??,
            CredentialOutcome::Provided { .. }
        ));
        Ok(())
    })?;
    channel.close();
    assert!(
        fresh_a.provide(&request("a")).is_err(),
        "closed connection recreated a private request"
    );
    Ok(())
}

#[tokio::test]
async fn pairing_private_async_reader_checks_generation_before_secret_payload() -> TestResult {
    use tokio::io::AsyncReadExt;
    let bytes = reply(23)?;
    let mut raw = bytes.as_slice();
    let mut prefix = [0; 4];
    raw.read_exact(&mut prefix).await?;
    let mut tag = [0; 1];
    raw.read_exact(&mut tag).await?;
    assert!(
        super::read_reply_after_discriminator(&mut raw, prefix, tag[0], "unlock", 24)
            .await
            .is_err()
    );
    assert_eq!(raw.len(), bytes.len() - 16, "wrong async generation consumed private payload");
    let scope = PrivateCredentialScope::data(request("a"), None)?;
    let mut slot = super::PrivateCredentialSlot::new(7);
    let generation = slot.issue(scope.clone())?;
    let fresh = reply(generation)?;
    let mut raw = fresh.as_slice();
    raw.read_exact(&mut prefix).await?;
    raw.read_exact(&mut tag).await?;
    let decoded =
        super::read_reply_after_discriminator(&mut raw, prefix, tag[0], "unlock", generation)
            .await?;
    let CredentialOutcome::Provided { passphrase, .. } = slot.consume(7, &scope, decoded)? else {
        return Err("valid async reply was refused".into());
    };
    assert!(passphrase.as_bytes() == b"channel-secret-canary", "async secret bytes changed");
    Ok(())
}

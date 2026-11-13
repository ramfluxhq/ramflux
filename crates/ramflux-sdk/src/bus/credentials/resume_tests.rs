// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Actual attended socket and connection broker keep cold-resume unlock input out of JSON.
use super::*;
use crate::custody::pairing::{
    CredentialOutcome, LocalCredentialProvider, PersistedReservation, SecretUtf8,
    persist_reservation,
    private_credential::{PairingBusClient, PrivateCredentialScope, provider_for_account},
};
use crate::platform::listener::BusListener as _;
use std::sync::atomic::{AtomicUsize, Ordering};
type TestResult = Result<(), Box<dyn std::error::Error>>;
struct Provider(AtomicUsize);
impl LocalCredentialProvider for Provider {
    fn provide(
        &self,
        _: &ramflux_protocol::custody::pairing::local_dto::CredentialRequest,
    ) -> Result<CredentialOutcome, SdkError> {
        self.0.fetch_add(1, Ordering::Relaxed);
        Ok(CredentialOutcome::Provided {
            passphrase: SecretUtf8::from_bytes(b"cold-resume-private-canary")?,
            confirmation: None,
        })
    }
}
#[tokio::test]
async fn pairing_cold_status_unlock_uses_exact_operation_and_same_connection_raw_reply()
-> TestResult {
    super::contract_tests::deadline(run()).await
}
async fn run() -> TestResult {
    let root = tempfile::tempdir()?;
    let metadata = ramflux_protocol::custody::pairing::local_dto::CredentialRequest {
        local_account_id: "cold-b".into(),
        reservation_id: ramflux_protocol::encode_base64url([31; 32]),
        frontend_generation: 2,
        action: "unlock".into(),
    };
    persist_reservation(
        root.path(),
        &PersistedReservation {
            account_id: "cold-b".into(),
            reservation_id: metadata.reservation_id.clone(),
            frontend_generation: 2,
        },
    )?;
    let socket = root.path().join("resume.sock");
    let listener = crate::platform::listener::bind(&socket)?;
    let provider = Arc::new(Provider(AtomicUsize::new(0)));
    let frontend = async {
        let mut client = PairingBusClient::connect(&socket, provider.clone()).await?;
        let response = client.request(Some("cold-b".into()), "device", "device.transfer.status",
            serde_json::json!({"schema":"ramflux.pairing.StatusRequest.v2","version":2,"operation_id":ramflux_protocol::encode_base64url([32;32]),"generation":4})).await?;
        assert_eq!(
            response,
            serde_json::json!({"resumed":true}),
            "test: private input altered public resume result"
        );
        TestResult::Ok(())
    };
    let daemon = async {
        let mut stream = listener.accept().await?;
        let parent = crate::bus::io::read_local_bus_frame(&mut stream).await?;
        let public = ramflux_protocol::canonical_json_bytes(&parent)?;
        assert!(
            !public
                .windows(b"cold-resume-private-canary".len())
                .any(|bytes| bytes == b"cold-resume-private-canary"),
            "test: resume public JSON contained the private credential"
        );
        serve(root.path(), &mut stream, parent, metadata, serde_json::json!({"resumed":true})).await
    };
    let (frontend, daemon) = tokio::join!(frontend, daemon);
    frontend?;
    daemon?;
    assert_eq!(
        provider.0.load(Ordering::Relaxed),
        1,
        "test: resume invoked a duplicate or missing private callback"
    );
    Ok(())
}
pub(crate) async fn serve(
    root: &Path,
    stream: &mut crate::platform::fs::LocalSocketStream,
    parent: LocalBusFrame,
    metadata: ramflux_protocol::custody::pairing::local_dto::CredentialRequest,
    response: serde_json::Value,
) -> TestResult {
    let (outbound, mut prompts) = mpsc::channel(1);
    let input = connection(root.into(), 91, outbound.clone());
    let channel = input.channel();
    let mut state = LocalBusConnectionState::new(91, outbound);
    state.credential_channel = Some(channel.clone());
    let _call = call(root, &parent, &state)?.ok_or("test: status lacked private call owner")?;
    let provider = provider_for_account(root, "cold-b".into())?;
    let foreign = PrivateCredentialScope::data(
        metadata.clone(),
        Some(ramflux_protocol::encode_base64url([33; 32])),
    )?;
    assert!(
        provider.provide_scoped(&metadata, &foreign).is_err(),
        "test: resume input accepted another operation"
    );
    assert!(prompts.try_recv().is_err(), "test: wrong operation reached the UI prompt");
    let scope = PrivateCredentialScope::data(
        metadata.clone(),
        Some(ramflux_protocol::encode_base64url([32; 32])),
    )?;
    let worker = tokio::task::spawn_blocking(move || provider.provide_scoped(&metadata, &scope));
    let prompt = prompts.recv().await.ok_or("test: missing exact resume prompt")?;
    crate::bus::io::write_local_bus_frame(stream, &prompt).await?;
    assert!(
        read_frame(stream, &channel, 91).await?.is_none(),
        "test: resume secret became a public bus frame"
    );
    let CredentialOutcome::Provided { passphrase, confirmation } = worker.await?? else {
        return Err("test: resume private callback refused the same-connection reply".into());
    };
    assert_eq!(
        passphrase.as_bytes(),
        b"cold-resume-private-canary",
        "test: resume credential crossed its private owner"
    );
    assert!(confirmation.is_none(), "test: unlock received setup confirmation");
    drop(passphrase);
    crate::bus::io::write_local_bus_frame(
        stream,
        &LocalBusFrame { kind: crate::LocalBusFrameKind::Response, body: response, ..parent },
    )
    .await?;
    Ok(())
}

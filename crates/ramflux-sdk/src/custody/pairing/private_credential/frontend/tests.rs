// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use super::*;
use crate::custody::pairing::{
    SecretUtf8,
    private_credential::{
        PrivateCredentialScope, PrivateCredentialSlot, read_reply_after_discriminator,
    },
};
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::io::AsyncReadExt;
type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
struct Provider(AtomicUsize, AtomicUsize);
impl LocalCredentialProvider for Provider {
    fn cancel(&self) {
        self.1.fetch_add(1, Ordering::Relaxed);
    }
    fn provide(&self, _: &CredentialRequest) -> Result<CredentialOutcome, SdkError> {
        self.0.fetch_add(1, Ordering::Relaxed);
        Ok(CredentialOutcome::Provided {
            passphrase: SecretUtf8::from_bytes(b"frontend-secret-canary")?,
            confirmation: None,
        })
    }
}
fn request() -> LocalBusFrame {
    LocalBusFrame::request(
        "attended-1",
        Some("a".into()),
        "account",
        "account.unlock",
        serde_json::json!({}),
    )
}
fn metadata() -> CredentialRequest {
    CredentialRequest {
        local_account_id: "a".into(),
        reservation_id: ramflux_protocol::encode_base64url([7; 32]),
        frontend_generation: 1,
        action: "unlock".into(),
    }
}
fn prompt_frame(generation: u64) -> Result<LocalBusFrame, SdkError> {
    Ok(LocalBusFrame {
        frame_id: format!("credential-{generation}"),
        method: "device.credential.request".into(),
        sdk_api: "device".into(),
        body: serde_json::to_value(metadata())?,
        ..request()
    })
}
#[tokio::test]
async fn pairing_private_frontend_answers_raw_and_returns_only_public_result() -> TestResult {
    crate::bus::credentials::contract_tests::deadline(async {
        let (mut frontend, mut daemon) = tokio::io::duplex(4096);
        let provider = Arc::new(Provider(AtomicUsize::new(0), AtomicUsize::new(0)));
        let callback = provider.clone();
        let server = async {
            let parent = crate::bus::io::read_local_bus_frame(&mut daemon).await?;
            assert_eq!(
                parent.body,
                serde_json::json!({}),
                "test: frontend private correlation or public response contract changed"
            );
            let scope = PrivateCredentialScope::data(metadata(), None)?;
            let mut slot = PrivateCredentialSlot::new(27);
            let generation = slot.issue(scope.clone())?;
            crate::bus::io::write_local_bus_frame(&mut daemon, &prompt_frame(generation)?).await?;
            let mut prefix = [0; 4];
            daemon.read_exact(&mut prefix).await?;
            let tag = daemon.read_u8().await?;
            let reply =
                read_reply_after_discriminator(&mut daemon, prefix, tag, "unlock", generation)
                    .await?;
            let CredentialOutcome::Provided { passphrase, confirmation } =
                slot.consume(27, &scope, reply)?
            else {
                return Err("frontend refused private reply".into());
            };
            assert!(passphrase.as_bytes() == b"frontend-secret-canary", "frontend secret changed");
            assert!(
                confirmation.is_none(),
                "test: frontend private correlation or public response contract changed"
            );
            drop(passphrase);
            let response = LocalBusFrame {
                kind: LocalBusFrameKind::Response,
                body: serde_json::json!({"unlocked":true}),
                ..parent
            };
            crate::bus::io::write_local_bus_frame(&mut daemon, &response).await?;
            TestResult::Ok(())
        };
        let request = request();
        let client = exchange(&mut frontend, &request, callback);
        let (server, result) = tokio::join!(server, client);
        server?;
        assert_eq!(
            result?.body,
            serde_json::json!({"unlocked":true}),
            "test: frontend private correlation or public response contract changed"
        );
        assert_eq!(
            provider.1.load(Ordering::Relaxed),
            0,
            "test: completed frontend callback retired its reusable provider"
        );
        assert_eq!(
            provider.0.load(Ordering::Relaxed),
            1,
            "test: frontend private correlation or public response contract changed"
        );
        Ok(())
    })
    .await
}
#[tokio::test]
async fn pairing_private_frontend_refuses_crossed_parent_and_wrong_action() -> TestResult {
    crate::bus::credentials::contract_tests::deadline(async {
        let provider = Arc::new(Provider(AtomicUsize::new(0), AtomicUsize::new(0)));
        for wrong in ["parent", "account", "action"] {
            let (mut frontend, mut daemon) = tokio::io::duplex(4096);
            let mut frame = prompt_frame(3)?;
            match wrong {
                "parent" => frame.request_id = "different-call".into(),
                "account" => frame.account_id = Some("b".into()),
                _ => frame.body["action"] = "phrase".into(),
            }
            let server = async {
                crate::bus::io::read_local_bus_frame(&mut daemon).await?;
                crate::bus::io::write_local_bus_frame(&mut daemon, &frame).await
            };
            let request = request();
            let (sent, result) =
                tokio::join!(server, exchange(&mut frontend, &request, provider.clone()));
            sent?;
            assert!(result.is_err(), "invalid private prompt was accepted");
        }
        assert_eq!(provider.0.load(Ordering::Relaxed), 0, "invalid prompt reached local UI");
        Ok(())
    })
    .await
}

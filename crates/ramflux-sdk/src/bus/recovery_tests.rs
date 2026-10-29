// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Actual local-bus phrase entry stays connection-bound and bypasses ordinary journals.
use crate::{
    LocalBusClient, LocalBusConfig, LocalBusFrame, LocalBusRecoveryClient, RamfluxClient, SdkError,
    custody::{
        CreationState,
        tests::{Root, TestVault, create_with_phrase},
    },
};
use std::{path::Path, sync::Arc, time::Duration};
use tokio::sync::watch;
use zeroize::Zeroizing;
type TestResult = Result<(), Box<dyn std::error::Error>>;
struct Stop(watch::Sender<bool>);
impl Drop for Stop {
    fn drop(&mut self) {
        let _ = self.0.send(true);
    }
}
async fn connect(socket: &Path) -> Result<LocalBusRecoveryClient, SdkError> {
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            match LocalBusRecoveryClient::connect(socket).await {
                Ok(client) => return Ok(client),
                Err(SdkError::Io(error))
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::NotFound | std::io::ErrorKind::ConnectionRefused
                    ) => {}
                Err(error) => return Err(error),
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .map_err(|_| SdkError::CustodySetupInvalid)?
}
fn assert_phrase_absent(root: &Path, phrase: &[u8]) -> TestResult {
    for entry in std::fs::read_dir(root)? {
        let entry = entry?;
        if entry.file_type()?.is_dir() {
            assert_phrase_absent(&entry.path(), phrase)?;
        } else if entry.file_type()?.is_file() {
            assert!(
                !std::fs::read(entry.path())?.windows(phrase.len()).any(|part| part == phrase),
                "phrase persisted in a bus artifact"
            );
        }
    }
    Ok(())
}
#[tokio::test]
async fn ordinary_phrase_recovery_is_explicit_connection_local_and_refuses_wrong_phrase_without_changes()
-> TestResult {
    let root = Root::new()?;
    let vault = Arc::new(TestVault::default());
    let (account, phrase) =
        create_with_phrase(&root.0, "recoverable", vault.as_ref(), crate::custody::network_now()?)?;
    let mut data = RamfluxClient::new();
    data.open_account_index(&root.0)?;
    data.seal_new_account_data(
        "recoverable",
        &account.record().body.account_anchor,
        b"local recovery data secret",
    )?;
    drop(data);
    let socket = root.0.join("bus.sock");
    let mut config = LocalBusConfig::new(&socket, &root.0);
    config.custody_vault = Some(vault.clone());
    let (stop, receiver) = watch::channel(false);
    let flow = async {
        let _stop = Stop(stop);
        let mut client = connect(&socket).await?;
        let pending = client.begin("recoverable").await?;
        assert_eq!(pending.account_anchor, account.record().body.account_anchor);
        assert!(pending.warning.contains("revokes all other devices"));
        let before = std::fs::read(root.0.join("custody_accounts/recoverable/authority.json"))?;
        let entries = vault.entry_count()?;
        let secret = Zeroizing::new("local recovery data secret".into());
        let wrong =
            ramflux_crypto::custody::RecoveryPhrase::from_entropy(&[1; 32])?.display_words();
        assert!(matches!(
            client.confirm(&wrong, &secret, &pending.account_anchor).await,
            Err(SdkError::CustodyConfirmationFailed)
        ));
        assert_eq!(
            std::fs::read(root.0.join("custody_accounts/recoverable/authority.json"))?,
            before
        );
        assert_eq!(vault.entry_count()?, entries);
        let mut other = connect(&socket).await?;
        assert!(matches!(
            other.confirm(&phrase, &secret, &pending.account_anchor).await,
            Err(SdkError::CustodySetupInvalid)
        ));
        client.begin("recoverable").await?;
        let recovered = client.confirm(&phrase, &secret, &pending.account_anchor).await?;
        assert_eq!(recovered.account_id, "recoverable");
        assert_eq!(recovered.networking, CreationState::NetworkingPending);
        assert!(client.confirm(&phrase, &secret, &pending.account_anchor).await.is_err());
        client.cancel().await?;
        client.cancel().await?;
        let ordinary = LocalBusClient::connect(&socket).await?;
        assert!(matches!(
            ordinary
                .request_frame_response(LocalBusFrame::request(
                    "generic",
                    None,
                    "account",
                    "account.recover.begin",
                    serde_json::json!({"account_id":"recoverable"})
                ))
                .await,
            Err(SdkError::CustodySetupInvalid)
        ));
        assert_phrase_absent(&root.0, phrase.as_bytes())?;
        Ok::<_, Box<dyn std::error::Error>>(())
    };
    let (server, flow) = tokio::join!(crate::serve_local_bus_until(config, receiver), flow);
    server?;
    flow?;
    Ok(())
}

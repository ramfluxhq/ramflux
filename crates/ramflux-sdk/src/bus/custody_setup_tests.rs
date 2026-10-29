// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Real same-user Unix-socket ceremony with an in-memory test vault; no remote services.
use crate::custody::tests::{Root, TestVault, input, words};
use crate::{
    custody::{CreationState, CustodyBusClient},
    *,
};
use std::sync::Arc;
use tokio::sync::watch;
struct Shutdown(watch::Sender<bool>);
impl Drop for Shutdown {
    fn drop(&mut self) {
        let _ = self.0.send(true);
    }
}
type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;
async fn connect(path: &std::path::Path) -> Result<CustodyBusClient> {
    // Binding creates the socket path before listener readiness; restart may also leave
    // the previous socket present briefly. Retry only these transient startup errors.
    for _ in 0..500 {
        match CustodyBusClient::connect(path).await {
            Ok(client) => return Ok(client),
            Err(SdkError::Io(error))
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::NotFound | std::io::ErrorKind::ConnectionRefused
                ) => {}
            Err(error) => return Err(error.into()),
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    Err("socket did not appear".into())
}
#[tokio::test]
async fn custody_bus_show_once_confirm_restart_and_legacy_fallback_refusal() -> Result {
    let root = Root::new()?;
    let socket = root.0.join("bus.sock");
    let mut config = LocalBusConfig::new(&socket, &root.0);
    config.enable_born_v3_creation = true;
    config.custody_vault = Some(Arc::new(TestVault::default()));
    let (stop, receiver) = watch::channel(false);
    let flow = async {
        let _shutdown = Shutdown(stop.clone());
        let mut bus = connect(&socket).await?;
        let anchor = bus.begin(&input("birth")).await?;
        let phrase = bus.show_once().await?;
        let positions = bus.hidden_challenge().await?;
        let confirmed = bus.confirm(&words(&phrase, positions)?).await?;
        assert_eq!(confirmed.state, CreationState::NetworkingPending);
        assert_eq!(confirmed.account["account_anchor"], anchor);
        assert!(bus.confirm(&words(&phrase, positions)?).await.is_err());
        let ordinary = LocalBusClient::connect(&socket).await?;
        // The compatibility ceremony stores public authority, without an ordinary data key.
        // Only account.create.confirm with a passphrase installs an unlocked data actor.
        let status = ordinary
            .request_frame_response(LocalBusFrame::request(
                "pending-status",
                Some("birth".into()),
                "account",
                "account.status",
                serde_json::json!({}),
            ))
            .await?;
        assert_eq!(status.error.as_ref().map(|error| error.code.as_str()), Some("AccountNotOpen"));
        // The generic client rejects creation before serializing secret-capable requests.
        assert!(matches!(
            ordinary
                .request_frame_response(LocalBusFrame::request(
                    "legacy-retry",
                    None,
                    "account",
                    "account.create",
                    serde_json::json!({"local_account_id":"birth"}),
                ))
                .await,
            Err(SdkError::CustodySetupInvalid)
        ));
        let response = ordinary
            .request_frame_response(LocalBusFrame::request(
                "session",
                Some("birth".into()),
                "account",
                "account.unlock",
                serde_json::json!({}),
            ))
            .await?;
        assert_eq!(response.error.as_ref().map(|e| e.code.as_str()), Some("CustodySetupInvalid"));
        drop(bus);
        drop(ordinary);
        stop.send(true)?;
        Ok::<_, Box<dyn std::error::Error>>(())
    };
    let (server, flow) = tokio::join!(crate::serve_local_bus_until(config, receiver), flow);
    server?;
    flow?;
    // Restart without the creation option: reads and the persisted mode guard still apply.
    let (stop, receiver) = watch::channel(false);
    let flow = async {
        let _shutdown = Shutdown(stop.clone());
        let mut bus = connect(&socket).await?;
        assert!(matches!(
            bus.begin(&input("disabled")).await,
            Err(SdkError::CustodyCreationDisabled)
        ));
        let mut ordinary = LocalBusClient::connect(&socket).await?;
        // The compatibility ceremony stores public authority, without an ordinary data key.
        // Only account.create.confirm with a passphrase installs an unlocked data actor.
        let status = ordinary
            .request_frame_response(LocalBusFrame::request(
                "pending-status",
                Some("birth".into()),
                "account",
                "account.status",
                serde_json::json!({}),
            ))
            .await?;
        assert_eq!(status.error.as_ref().map(|error| error.code.as_str()), Some("AccountNotOpen"));
        let daemon =
            ordinary.request(None, "daemon", "daemon.status", serde_json::json!({})).await?;
        assert_eq!(daemon["accounts"], 0);
        let listed =
            ordinary.request(None, "account", "account.list", serde_json::json!({})).await?;
        assert!(listed.to_string().contains("networking_pending"));
        stop.send(true)?;
        Ok::<_, Box<dyn std::error::Error>>(())
    };
    let (server, flow) = tokio::join!(
        crate::serve_local_bus_until(LocalBusConfig::new(&socket, &root.0), receiver),
        flow
    );
    server?;
    flow?;
    Ok(())
}
#[tokio::test]
async fn custody_bus_disconnect_wrong_words_and_show_replay_publish_nothing() -> Result {
    let root = Root::new()?;
    let socket = root.0.join("bus.sock");
    let mut config = LocalBusConfig::new(&socket, &root.0);
    config.enable_born_v3_creation = true;
    config.custody_vault = Some(Arc::new(TestVault::default()));
    let (stop, receiver) = watch::channel(false);
    let flow = async {
        let _shutdown = Shutdown(stop.clone());
        let mut bus = connect(&socket).await?;
        bus.begin(&input("disconnect")).await?;
        let phrase = bus.show_once().await?;
        drop(bus);
        let mut bus = connect(&socket).await?;
        assert!(bus.hidden_challenge().await.is_err());
        bus.begin(&input("repeat")).await?;
        drop(bus.show_once().await?);
        assert!(bus.show_once().await.is_err());
        assert!(bus.hidden_challenge().await.is_err());
        bus.begin(&input("wrong")).await?;
        drop(bus.show_once().await?);
        bus.hidden_challenge().await?;
        let words = [
            zeroize::Zeroizing::new("invalid".into()),
            zeroize::Zeroizing::new("invalid".into()),
            zeroize::Zeroizing::new("invalid".into()),
        ];
        assert!(matches!(bus.confirm(&words).await, Err(SdkError::CustodyConfirmationFailed)));
        assert!(bus.confirm(&words).await.is_err());
        assert!(!root.0.join("custody_accounts").exists());
        // AccountIndex has no committed setup or phrase-bearing retry/event records.
        let index = ramflux_storage::AccountIndex::open(&root.0)?;
        assert_eq!(index.known_account_ids()?, Vec::<String>::new());
        drop(index);
        let mut file_contents = Vec::new();
        for entry in std::fs::read_dir(&root.0)? {
            let path = entry?.path();
            if path.is_file() {
                file_contents.extend(std::fs::read(path)?);
            }
        }
        assert!(!file_contents.windows(phrase.len()).any(|bytes| bytes == phrase.as_bytes()));
        stop.send(true)?;
        Ok::<_, Box<dyn std::error::Error>>(())
    };
    let (server, flow) = tokio::join!(crate::serve_local_bus_until(config, receiver), flow);
    server?;
    flow?;
    Ok(())
}

#[tokio::test]
async fn custody_bus_unavailable_provider_refuses_before_phrase_display() -> Result {
    let root = Root::new()?;
    let socket = root.0.join("bus.sock");
    let vault = Arc::new(TestVault::default());
    vault.fail.store(true, std::sync::atomic::Ordering::SeqCst);
    let mut config = LocalBusConfig::new(&socket, &root.0);
    config.enable_born_v3_creation = true;
    config.custody_vault = Some(vault);
    let (stop, receiver) = watch::channel(false);
    let flow = async {
        let _shutdown = Shutdown(stop.clone());
        let mut bus = connect(&socket).await?;
        assert!(matches!(
            bus.begin(&input("unavailable")).await,
            Err(SdkError::CustodyVaultUnavailable)
        ));
        assert!(bus.show_once().await.is_err());
        assert!(!root.0.join("custody_accounts").exists());
        assert_eq!(
            ramflux_storage::AccountIndex::open(&root.0)?.known_account_ids()?,
            Vec::<String>::new()
        );
        stop.send(true)?;
        Ok::<_, Box<dyn std::error::Error>>(())
    };
    let (server, flow) = tokio::join!(crate::serve_local_bus_until(config, receiver), flow);
    server?;
    flow?;
    Ok(())
}

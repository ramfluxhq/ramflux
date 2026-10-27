// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Real same-user Unix-socket ceremony with an in-memory test vault; no remote services.
use crate::custody::tests::{Root, TestVault, input, words};
use crate::{
    custody::{CreationState, CustodyBusClient, PrimaryVault},
    *,
};
use ramflux_crypto::custody::SelfSigningKey;
use std::sync::{Arc, Condvar, Mutex};
use tokio::sync::watch;
use zeroize::Zeroizing;
pub(super) struct Shutdown(pub(super) watch::Sender<bool>);
impl Drop for Shutdown {
    fn drop(&mut self) {
        let _ = self.0.send(true);
    }
}
type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;
pub(super) async fn connect(path: &std::path::Path) -> Result<CustodyBusClient> {
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
        let mut ordinary = LocalBusClient::connect(&socket).await?;
        let status = ordinary
            .request(Some("birth".into()), "account", "account.status", serde_json::json!({}))
            .await?;
        assert_eq!(status["state"], "networking_pending");
        let response = ordinary
            .request_frame_response(LocalBusFrame::request(
                "legacy-retry",
                None,
                "account",
                "account.create",
                serde_json::json!({"local_account_id":"birth"}),
            ))
            .await?;
        assert_eq!(response.error.as_ref().map(|e| e.code.as_str()), Some("NetworkingPending"));
        let response = ordinary
            .request_frame_response(LocalBusFrame::request(
                "session",
                Some("birth".into()),
                "account",
                "account.unlock",
                serde_json::json!({}),
            ))
            .await?;
        assert_eq!(response.error.as_ref().map(|e| e.code.as_str()), Some("NetworkingPending"));
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
        let status = ordinary
            .request(Some("birth".into()), "account", "account.status", serde_json::json!({}))
            .await?;
        assert_eq!(status["state"], "networking_pending");
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

#[tokio::test]
async fn custody_disabled_and_oversized_request_ids_have_no_side_effects() -> Result {
    let root = Root::new()?;
    let vault = Arc::new(TestVault::default());
    let mut config = LocalBusConfig::new(root.0.join("bus.sock"), &root.0);
    config.custody_vault = Some(vault.clone());
    let mut ceremony = None;
    let mut disabled = LocalBusFrame::request(
        "disabled",
        None,
        "account",
        "account.custody.begin",
        serde_json::to_value(input("disabled"))?,
    );
    let reply =
        crate::bus::custody_setup::respond(&mut disabled, &config, &mut ceremony, None).await?;
    assert!(std::str::from_utf8(&reply)?.contains("CustodyCreationDisabled"));
    assert!(!root.0.join("custody_accounts/disabled").exists());
    assert_eq!(
        ramflux_storage::AccountIndex::open(&root.0)?.known_account_ids()?,
        Vec::<String>::new()
    );
    assert_eq!(vault.len(), 0);

    let mut oversized = LocalBusFrame::request(
        "x".repeat(crate::custody::SETUP_REQUEST_ID_BYTES + 1),
        None,
        "account",
        "account.custody.begin",
        serde_json::to_value(input("oversized"))?,
    );
    assert!(matches!(
        crate::bus::custody_setup::respond(&mut oversized, &config, &mut ceremony, None).await,
        Err(SdkError::CustodySetupInvalid)
    ));
    assert!(!root.0.join("custody_accounts/oversized").exists());
    assert_eq!(vault.len(), 0);
    Ok(())
}

#[tokio::test]
async fn startup_removes_an_orphan_marker_and_releases_its_id() -> Result {
    let root = Root::new()?;
    let marker = root.0.join("custody_accounts/reusable");
    std::fs::create_dir_all(&marker)?;
    let socket = root.0.join("bus.sock");
    let mut config = LocalBusConfig::new(&socket, &root.0);
    config.enable_born_v3_creation = true;
    config.custody_vault = Some(Arc::new(TestVault::default()));
    let (stop, receiver) = watch::channel(false);
    let flow = async {
        let _shutdown = Shutdown(stop.clone());
        let mut bus = connect(&socket).await?;
        assert!(!marker.exists());
        assert_ne!(bus.begin(&input("reusable")).await?, "");
        stop.send(true)?;
        Ok::<_, Box<dyn std::error::Error>>(())
    };
    let (server, flow) = tokio::join!(crate::serve_local_bus_until(config, receiver), flow);
    server?;
    flow?;
    Ok(())
}

#[tokio::test]
async fn legacy_create_between_begin_and_confirm_is_preserved_and_unlockable() -> Result {
    let root = Root::new()?;
    let socket = root.0.join("bus.sock");
    let mut config = LocalBusConfig::new(&socket, &root.0);
    config.enable_born_v3_creation = true;
    config.custody_vault = Some(Arc::new(TestVault::default()));
    let (stop, receiver) = watch::channel(false);
    let flow = async {
        let _shutdown = Shutdown(stop.clone());
        let mut custody = connect(&socket).await?;
        custody.begin(&input("legacy-wins")).await?;
        let phrase = custody.show_once().await?;
        let positions = custody.hidden_challenge().await?;
        let answers = words(&phrase, positions)?;

        let ordinary = LocalBusClient::connect(&socket).await?;
        let request = LocalBusAccountCreateRequest {
            label: None,
            kind: None,
            node_id: None,
            local_account_id: "legacy-wins".into(),
            principal_id: "legacy-principal".into(),
            principal_commitment: String::new(),
            device_id: "legacy-device".into(),
            target_delivery_id: "legacy-delivery".into(),
            account_secret: "legacy-secret".into(),
            root_seed: [0x81; 32],
            device_seed: [0x82; 32],
            client_mode: LocalBusClientMode::AttendedCli,
            gateway: crate::gateway::GatewayQuicEndpointConfig {
                bind_addr: "127.0.0.1:0".parse()?,
                gateway_addr: "127.0.0.1:1".parse()?,
                server_name: "missing-gateway".into(),
                ca_cert: root.0.join("missing-ca.pem"),
                principal_id: String::new(),
                device_id: String::new(),
                target_delivery_id: String::new(),
                prekey_http_url: None,
            },
        };
        let response = ordinary
            .request_frame_response(LocalBusFrame::request(
                "legacy-create",
                None,
                "account",
                "account.create",
                serde_json::to_value(request)?,
            ))
            .await?;
        assert!(response.error.is_some(), "activation must fail against the absent gateway");
        let manifest = super::daemon::local_bus_account_manifest_path(&root.0, "legacy-wins");
        assert!(manifest.exists());
        let index = ramflux_storage::AccountIndex::open(&root.0)?;
        let before = index.account("legacy-wins")?;
        let before_wrapped = index.load_wrapped_db_key("legacy-wins")?;
        assert!(before_wrapped.is_some());

        assert!(matches!(custody.confirm(&answers).await, Err(SdkError::CustodyAccountConflict)));
        assert!(!root.0.join("custody_accounts/legacy-wins").exists());
        let after = index.account("legacy-wins")?;
        assert_eq!(after, before);
        assert_eq!(index.load_wrapped_db_key("legacy-wins")?, before_wrapped);
        drop(index);
        drop(custody);
        drop(ordinary);
        stop.send(true)?;
        Ok::<_, Box<dyn std::error::Error>>(())
    };
    let (server, flow) = tokio::join!(crate::serve_local_bus_until(config, receiver), flow);
    server?;
    flow?;

    let mut client = RamfluxClient::new();
    client.open_account_index(&root.0)?;
    client.unlock_account("legacy-wins", b"legacy-secret")?;
    Ok(())
}

struct BlockingVault {
    inner: TestVault,
    entered: tokio::sync::Notify,
    release: (Mutex<bool>, Condvar),
}
impl BlockingVault {
    fn new() -> Self {
        Self {
            inner: TestVault::default(),
            entered: tokio::sync::Notify::new(),
            release: (Mutex::new(false), Condvar::new()),
        }
    }
    fn release(&self) {
        if let Ok(mut released) = self.release.0.lock() {
            *released = true;
            self.release.1.notify_all();
        }
    }
}
impl PrimaryVault for BlockingVault {
    fn preflight(&self) -> std::result::Result<(), SdkError> {
        self.inner.preflight()
    }
    fn store_new(
        &self,
        reference: &str,
        key: &SelfSigningKey,
    ) -> std::result::Result<(), SdkError> {
        self.entered.notify_one();
        let mut released = self.release.0.lock().map_err(|_| SdkError::CustodyVaultUnavailable)?;
        while !*released {
            released =
                self.release.1.wait(released).map_err(|_| SdkError::CustodyVaultUnavailable)?;
        }
        self.inner.store_new(reference, key)
    }
    fn load_primary(&self, reference: &str) -> std::result::Result<SelfSigningKey, SdkError> {
        self.inner.load_primary(reference)
    }
    fn store_branch(
        &self,
        reference: &str,
        seeds: &Zeroizing<[u8; 64]>,
    ) -> std::result::Result<(), SdkError> {
        self.inner.store_branch(reference, seeds)
    }
}

#[tokio::test]
async fn custody_confirm_vault_and_fsync_work_does_not_stall_the_daemon_thread() -> Result {
    let root = Root::new()?;
    let socket = root.0.join("bus.sock");
    let vault = Arc::new(BlockingVault::new());
    let mut config = LocalBusConfig::new(&socket, &root.0);
    config.enable_born_v3_creation = true;
    config.custody_vault = Some(vault.clone());
    let (stop, receiver) = watch::channel(false);
    let flow = async {
        let _shutdown = Shutdown(stop.clone());
        let mut bus = connect(&socket).await?;
        bus.begin(&input("blocking")).await?;
        let phrase = bus.show_once().await?;
        let positions = bus.hidden_challenge().await?;
        let answers = words(&phrase, positions)?;
        let confirm = tokio::spawn(async move { bus.confirm(&answers).await });
        tokio::time::timeout(std::time::Duration::from_secs(2), vault.entered.notified()).await?;
        let mut ordinary = LocalBusClient::connect(&socket).await?;
        let status = tokio::time::timeout(
            std::time::Duration::from_millis(500),
            ordinary.request(None, "daemon", "daemon.status", serde_json::json!({})),
        )
        .await??;
        assert_eq!(status["accounts"], 0);
        vault.release();
        assert_eq!(confirm.await??.state, CreationState::NetworkingPending);
        stop.send(true)?;
        Ok::<_, Box<dyn std::error::Error>>(())
    };
    let (server, flow) = tokio::join!(crate::serve_local_bus_until(config, receiver), flow);
    vault.release();
    server?;
    flow?;
    Ok(())
}

#[tokio::test]
async fn disconnect_during_confirm_finishes_a_complete_pending_account() -> Result {
    let root = Root::new()?;
    let socket = root.0.join("bus.sock");
    let vault = Arc::new(BlockingVault::new());
    let mut config = LocalBusConfig::new(&socket, &root.0);
    config.enable_born_v3_creation = true;
    config.custody_vault = Some(vault.clone());
    let (stop, receiver) = watch::channel(false);
    let flow = async {
        let _shutdown = Shutdown(stop.clone());
        let mut bus = connect(&socket).await?;
        bus.begin(&input("disconnect-confirm")).await?;
        let phrase = bus.show_once().await?;
        let positions = bus.hidden_challenge().await?;
        let answers = words(&phrase, positions)?;
        let confirm = tokio::spawn(async move { bus.confirm(&answers).await });
        tokio::time::timeout(std::time::Duration::from_secs(10), vault.entered.notified()).await?;
        confirm.abort();
        let _ = confirm.await;
        vault.release();
        tokio::time::timeout(std::time::Duration::from_secs(10), async {
            while !root.0.join("custody_accounts/disconnect-confirm/authority.json").exists() {
                tokio::task::yield_now().await;
            }
        })
        .await?;
        assert_eq!(
            crate::custody::load_account(
                &root.0,
                "disconnect-confirm",
                super::custody_setup::now()?
            )?
            .state(),
            CreationState::NetworkingPending
        );
        stop.send(true)?;
        Ok::<_, Box<dyn std::error::Error>>(())
    };
    let (server, flow) = tokio::join!(crate::serve_local_bus_until(config, receiver), flow);
    vault.release();
    server?;
    flow?;
    Ok(())
}

#[tokio::test]
async fn custody_shutdown_cannot_release_the_data_root_while_confirmation_is_blocked() -> Result {
    struct Release(Arc<BlockingVault>);
    impl Drop for Release {
        fn drop(&mut self) {
            self.0.release();
        }
    }
    let root = Root::new()?;
    let socket = root.0.join("bus.sock");
    let vault = Arc::new(BlockingVault::new());
    let mut config = LocalBusConfig::new(&socket, &root.0);
    config.enable_born_v3_creation = true;
    config.custody_vault = Some(vault.clone());
    let second = LocalBusConfig::new(root.0.join("second.sock"), &root.0);
    let (stop, receiver) = watch::channel(false);
    let flow = async {
        let _shutdown = Shutdown(stop.clone());
        let _release = Release(vault.clone());
        let mut bus = connect(&socket).await?;
        bus.begin(&input("late-confirm")).await?;
        let phrase = bus.show_once().await?;
        let answers = words(&phrase, bus.hidden_challenge().await?)?;
        let confirm = tokio::spawn(async move { bus.confirm(&answers).await });
        tokio::time::timeout(std::time::Duration::from_secs(10), vault.entered.notified()).await?;
        stop.send(true)?;
        tokio::time::timeout(std::time::Duration::from_secs(10), async {
            while socket.exists() {
                tokio::task::yield_now().await;
            }
        })
        .await?;
        let attempt = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            crate::serve_local_bus_until(second, stop.subscribe()),
        )
        .await?;
        assert!(
            matches!(attempt, Err(SdkError::Io(e)) if e.kind()==std::io::ErrorKind::WouldBlock)
        );
        assert!(root.0.join("custody_accounts/late-confirm").exists());
        assert!(!root.0.join("second.sock").exists());
        vault.release();
        let _ = confirm.await;
        Ok::<_, Box<dyn std::error::Error>>(())
    };
    let (server, flow) = tokio::join!(crate::serve_local_bus_until(config, receiver), flow);
    vault.release();
    server?;
    flow?;
    assert!(root.0.join("custody_accounts/late-confirm/authority.json").exists());
    Ok(())
}

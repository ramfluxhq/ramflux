// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Startup isolation for active and inconsistent custody accounts.
use super::custody_setup_tests::{Shutdown, connect};
use crate::{
    custody::tests::{Root, TestVault, input},
    *,
};
use std::{
    os::unix::{ffi::OsStringExt, fs::MetadataExt},
    sync::Arc,
};
use tokio::sync::watch;
type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;

#[tokio::test]
async fn custody_second_daemon_cannot_unlink_the_live_socket_or_reconcile_its_root() -> Result {
    let root = Root::new()?;
    let socket = root.0.join("bus.sock");
    let config = LocalBusConfig::new(&socket, &root.0);
    let (stop, receiver) = watch::channel(false);
    let flow = async {
        let _stop = Shutdown(stop.clone());
        let _bus = connect(&socket).await?;
        let inode = std::fs::metadata(&socket)?.ino();
        let marker = root.0.join("custody_accounts/active-marker");
        std::fs::create_dir_all(&marker)?;
        let attempt = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            crate::serve_local_bus_until(LocalBusConfig::new(&socket, &root.0), stop.subscribe()),
        )
        .await?;
        assert!(matches!(attempt,Err(SdkError::Io(e)) if e.kind()==std::io::ErrorKind::WouldBlock));
        assert!(marker.exists());
        assert_eq!(std::fs::metadata(&socket)?.ino(), inode);
        let mut ordinary = LocalBusClient::connect(&socket).await?;
        let status =
            ordinary.request(None, "daemon", "daemon.status", serde_json::json!({})).await?;
        assert_eq!(status["accounts"], 0);
        Ok::<_, Box<dyn std::error::Error>>(())
    };
    let (server, flow) = tokio::join!(crate::serve_local_bus_until(config, receiver), flow);
    server?;
    flow?;
    Ok(())
}
#[tokio::test]
async fn custody_inconsistent_and_invalidly_named_markers_leave_other_accounts_available() -> Result
{
    let root = Root::new()?;
    let socket = root.0.join("bus.sock");
    let bad = root.0.join("custody_accounts/broken");
    std::fs::create_dir_all(&bad)?;
    std::fs::write(bad.join("authority.json"), b"invalid-public-authority")?;
    let non_utf8 = root.0.join("custody_accounts").join(if cfg!(target_os = "macos") {
        // APFS rejects invalid UTF-8 before it can appear in a directory listing.
        std::ffi::OsString::from("invalid account name")
    } else {
        std::ffi::OsString::from_vec(vec![0xff])
    });
    std::fs::create_dir(&non_utf8)?;
    let mut config = LocalBusConfig::new(&socket, &root.0);
    config.enable_born_v3_creation = true;
    config.custody_vault = Some(Arc::new(TestVault::default()));
    let (stop, receiver) = watch::channel(false);
    let flow = async {
        let _stop = Shutdown(stop.clone());
        let mut ceremony = connect(&socket).await?;
        let mut bus = LocalBusClient::connect(&socket).await?;
        assert_eq!(
            bus.request(None, "daemon", "daemon.status", serde_json::json!({})).await?["accounts"],
            0
        );
        let list = bus.request(None, "account", "account.list", serde_json::json!({})).await?;
        let row = list["account_details"]
            .as_array()
            .ok_or("accounts")?
            .iter()
            .find(|r| r["local_account_id"] == "broken")
            .ok_or("broken account missing")?;
        assert_eq!(row["setup_error"], "CustodySetupInvalid");
        let response = bus
            .request_frame_response(LocalBusFrame::request(
                "bad",
                Some("broken".into()),
                "account",
                "account.status",
                serde_json::json!({}),
            ))
            .await?;
        assert_eq!(response.error.as_ref().map(|e| e.code.as_str()), Some("CustodySetupInvalid"));
        assert_ne!(ceremony.begin(&input("healthy")).await?, "");
        assert!(bad.exists());
        assert!(non_utf8.exists());
        Ok::<_, Box<dyn std::error::Error>>(())
    };
    let (server, flow) = tokio::join!(crate::serve_local_bus_until(config, receiver), flow);
    server?;
    flow?;
    Ok(())
}

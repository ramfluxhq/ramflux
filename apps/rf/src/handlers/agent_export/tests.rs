// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use super::*;
use ramflux_sdk::{LocalBusFrame, LocalBusFrameKind};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

fn listed(active: &str) -> Value {
    json!({"active_account_id":active,"accounts":["agent","owner","other"],"account_details":[
        {"id":"agent","kind":"headless_ai","custodian_account_id":"owner"},
        {"id":"owner","kind":"human"},{"id":"other","kind":"human"}
    ]})
}

#[tokio::test]
async fn agent_export_resolves_recorded_custodian_when_agent_or_unrelated_account_is_active()
-> Result {
    for (active, selected) in [("agent", None), ("other", None), ("agent", Some("owner"))] {
        let root = ramflux_test_support::TestPath::new()
            .expect("test: allocate fixture directory")
            .child(format!(
                "rf-agent-export-{}-{}",
                std::process::id(),
                std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_nanos()
            ));
        std::fs::create_dir(&root)?;
        let socket = root.join("bus.sock");
        let destination = root.join("agent.bundle");
        let expected = destination.clone();
        let listener = tokio::net::UnixListener::bind(&socket)?;
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await?;
            for (method, account, body) in [
                ("account.list", None, listed(active)),
                ("subscription.open", Some("owner"), json!({})),
                ("account.export_agent_credentials", Some("owner"), json!({"exported":true})),
            ] {
                let len = stream.read_u32().await?;
                let mut bytes = vec![0; usize::try_from(len)?];
                stream.read_exact(&mut bytes).await?;
                let mut request: LocalBusFrame = serde_json::from_slice(&bytes)?;
                assert_eq!(request.method, method);
                assert_eq!(request.account_id.as_deref(), account);
                if method == "subscription.open" {
                    assert_eq!(request.body["attended_frontend"], true);
                }
                if method == "account.export_agent_credentials" {
                    assert_eq!(request.body["account"], "agent");
                    assert_eq!(request.body["path"], serde_json::to_value(&expected)?);
                }
                request.kind = LocalBusFrameKind::Response;
                request.ok = Some(true);
                request.body = body;
                let bytes = serde_json::to_vec(&request)?;
                stream.write_u32(u32::try_from(bytes.len())?).await?;
                stream.write_all(&bytes).await?;
            }
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
        });
        let mut bus = LocalBusClient::connect(&socket).await?;
        export(
            &mut bus,
            AccountExportAgentCredentials {
                account: "agent".into(),
                custodian: selected.map(str::to_owned),
                out: destination,
            },
        )
        .await?;
        server.await??;
        drop(bus);
        std::fs::remove_dir_all(root)?;
    }
    Ok(())
}

#[tokio::test]
async fn agent_export_refuses_wrong_custodian_with_named_reason() -> Result {
    let root = ramflux_test_support::TestPath::new()
        .expect("test: allocate fixture directory")
        .child(format!(
            "rf-agent-refusal-{}-{}",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_nanos()
        ));
    std::fs::create_dir(&root)?;
    let socket = root.join("bus.sock");
    let listener = tokio::net::UnixListener::bind(&socket)?;
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await?;
        let len = stream.read_u32().await?;
        let mut bytes = vec![0; usize::try_from(len)?];
        stream.read_exact(&mut bytes).await?;
        let mut request: LocalBusFrame = serde_json::from_slice(&bytes)?;
        assert_eq!(request.method, "account.list");
        request.kind = LocalBusFrameKind::Response;
        request.ok = Some(true);
        request.body = listed("agent");
        let bytes = serde_json::to_vec(&request)?;
        stream.write_u32(u32::try_from(bytes.len())?).await?;
        stream.write_all(&bytes).await?;
        let next = stream.read_u32().await;
        assert!(
            matches!(next, Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof),
            "wrong custodian must be refused before subscription/export"
        );
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
    });
    let mut bus = LocalBusClient::connect(&socket).await?;
    let destination = root.join("must-not-exist.bundle");
    let error = export(
        &mut bus,
        AccountExportAgentCredentials {
            account: "agent".into(),
            custodian: Some("other".into()),
            out: destination.clone(),
        },
    )
    .await
    .err()
    .ok_or("wrong custodian was accepted")?
    .to_string();
    assert_eq!(error, "custodian `other` is not agent `agent`'s recorded custodian `owner`");
    assert!(!destination.exists());
    drop(bus);
    server.await??;
    Ok(())
}

#[test]
fn agent_export_names_missing_custodian_record_and_accepts_explicit_override() -> Result {
    let value = json!({"active_account_id":"agent","account_details":[{"id":"agent"}]});
    let error =
        custodian(&value, "agent", None).err().ok_or("missing record was accepted")?.to_string();
    assert_eq!(error, "agent `agent` has no custodian record; pass `--custodian <owner id>`");
    assert_eq!(custodian(&value, "agent", Some("owner"))?, "owner");
    Ok(())
}

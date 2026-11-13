// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Durable forwarding resume checkpoints across failed and successful reconnects.
use super::*;

type ServerResult = Result<(), Box<dyn std::error::Error + Send + Sync>>;
type HeldServer = (tokio::task::JoinHandle<ServerResult>, tokio::sync::oneshot::Sender<()>);
async fn reconnect_gateway(
    account: &mut LocalBusAccountState,
    root: &std::path::Path,
) -> Result<HeldServer, Box<dyn std::error::Error>> {
    let certificate = rcgen::generate_simple_self_signed(vec!["localhost".into()])?;
    let ca = root.join("ca.pem");
    let cert = root.join("server.pem");
    let key = root.join("server.key");
    std::fs::write(&ca, certificate.cert.pem())?;
    std::fs::write(&cert, certificate.cert.pem())?;
    std::fs::write(&key, certificate.signing_key.serialize_pem())?;
    let acceptor = tokio_rustls::TlsAcceptor::from(std::sync::Arc::new(
        ramflux_transport::tcp_gateway_server_config(&ramflux_transport::MeshTlsConfig {
            ca_cert: ca.clone(),
            service_cert: cert,
            service_key: key,
        })?,
    ));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    account.gateway_config.transport_kind = crate::GatewaySessionTransportKind::TcpTls;
    account.gateway_config.tcp_gateway_addr = Some(address);
    account.gateway_config.server_name = "localhost".into();
    account.gateway_config.ca_cert = ca;
    let (release, held) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await?;
        let mut stream = tokio_rustls::TlsStream::Server(acceptor.accept(tcp).await?);
        let open: GatewayClientFrame =
            ramflux_transport::read_gateway_session_json(&mut stream).await?;
        let GatewayClientFrame::Open { open } = open else {
            return Err("missing open".into());
        };
        assert_eq!(open.previous_session_id.as_deref(), Some("forwarded-session"));
        assert_eq!(open.last_seen_inbox_seq, Some(41));
        assert!(open.resume_token_hash.is_some());
        let auth: GatewayClientFrame =
            ramflux_transport::read_gateway_session_json(&mut stream).await?;
        assert!(matches!(auth, GatewayClientFrame::Auth { .. }));
        ramflux_transport::write_gateway_session_json(
            &mut stream,
            &GatewayServerFrame::SessionEstablished {
                session: crate::GatewaySessionEstablishedFrame {
                    call_session_generation: None,
                    session_id: "resumed-session".into(),
                    gateway_id: "test-gateway".into(),
                    accepted_cursor: None,
                    resume_token: "next-token".into(),
                    resume_window_seconds: 60,
                },
            },
        )
        .await?;
        let _ = held.await;
        Ok::<(), Box<dyn std::error::Error + Send + Sync>>(())
    });
    Ok((server, release))
}

#[tokio::test]
async fn forwarded_session_resume_checkpoint_clears_only_after_success()
-> Result<(), Box<dyn std::error::Error>> {
    let root = super::super::runtime_tests::root("forward-resume-clear");
    let mut account = super::super::runtime_tests::account(
        &root,
        "sender",
        None,
        std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
    )?;
    let mut engine = account.session_client().await?;
    engine.test_update_resume("forwarded-session", "forwarded-resume").await?;
    account
        .connection
        .as_ref()
        .ok_or("connection")?
        .call(
            |engine| {
                Box::pin(async move {
                    engine.config.last_seen_inbox_seq = 41;
                    Ok(())
                })
            },
            tokio::time::Instant::now() + std::time::Duration::from_secs(5),
        )
        .await?;
    account.retire_session(&engine)?;
    let checkpoint = LocalBusAccountState::GATEWAY_RESUME_CHECKPOINT;
    let mut config = account.gateway_config.clone();
    config.last_seen_inbox_seq = 50;
    let restored = account.restore_gateway_resume_checkpoint(&mut config)?;
    assert!(restored);
    assert_eq!(config.previous_session_id.as_deref(), Some("forwarded-session"));
    assert_eq!(config.resume_token.as_deref(), Some("forwarded-resume"));
    assert_eq!(config.last_seen_inbox_seq, 50);
    account.finish_restored_resume_checkpoint(false)?;
    assert!(
        account.client.projection_checkpoint(checkpoint)?.is_some_and(|value| !value.is_empty())
    );
    account.gateway_config.transport_kind = crate::GatewaySessionTransportKind::TcpTls;
    account.gateway_config.tcp_gateway_addr = Some(account.gateway_config.gateway_addr);
    // D1: join the retired host before forcing the next admission attempt.
    if let Some(handle) = account.connection.take() {
        handle.stop().await;
    }
    account.test_connector = None;
    // A failed real connection retains the journal for another attempt.
    assert!(account.ensure_gateway_live().await.is_err());
    assert!(
        account.client.projection_checkpoint(checkpoint)?.is_some_and(|value| !value.is_empty())
    );
    if let Some(handle) = account.connection.take() {
        handle.stop().await;
    }
    let (server, release) = reconnect_gateway(&mut account, &root).await?;
    tokio::time::timeout(std::time::Duration::from_secs(5), account.ensure_gateway_live())
        .await??;
    let _ = release.send(());
    server.await?.map_err(|error| error.to_string())?;
    assert_eq!(account.client.projection_checkpoint(checkpoint)?.as_deref(), Some(""));
    assert!(!account.restore_gateway_resume_checkpoint(&mut config)?);
    drop(account);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[tokio::test]
async fn priority_timeout_retires_with_resume_without_restoring_rotated_authority()
-> Result<(), Box<dyn std::error::Error>> {
    for borrowed in [false, true] {
        for rotate in [false, true] {
            let root = super::super::runtime_tests::root("retire-fence");
            let mut account = super::super::runtime_tests::account(
                &root,
                "sender",
                None,
                std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
            )?;
            let client = account.session_client().await?;
            let client = if borrowed { client } else { account.session_client().await? };
            if rotate {
                account.gateway_config.device_epoch += 1;
                account.gateway_config.target_delivery_id = "rotated-target".into();
                account.gateway_config.gateway_addr = "127.0.0.1:1234".parse()?;
                account.gateway_config.previous_session_id = Some("current-session".into());
                account.gateway_config.resume_token = Some("current-token".into());
            }
            let expected = account.gateway_config.clone();
            account.retire_session(&client)?;
            account.apply_session_metadata(client);
            assert_eq!(account.gateway_config.device_epoch, expected.device_epoch);
            assert_eq!(account.gateway_config.target_delivery_id, expected.target_delivery_id);
            assert_eq!(account.gateway_config.gateway_addr, expected.gateway_addr);
            let mut restored = expected.clone();
            assert!(account.restore_gateway_resume_checkpoint(&mut restored)?);
            assert_eq!(restored.previous_session_id, expected.previous_session_id);
            assert_eq!(restored.resume_token, expected.resume_token);
            assert!(account.connection.as_ref().is_some_and(
                super::super::connection_manager::ConnectionHandle::retirement_requested
            ));
            drop(account);
            std::fs::remove_dir_all(root)?;
        }
    }
    Ok(())
}

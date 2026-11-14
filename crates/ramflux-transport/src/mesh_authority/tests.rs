// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use super::MeshAuthorityClient;
use crate::{MeshQuicServer, MeshTlsConfig};
use std::{
    path::Path,
    sync::Arc,
    time::{Duration, Instant},
};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

fn certificates(root: &Path) -> TestResult<(MeshTlsConfig, MeshTlsConfig)> {
    crate::tls_config::ensure_ring_crypto_provider_installed();
    let mut params = rcgen::CertificateParams::new(Vec::<String>::new())?;
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    params.key_usages = vec![rcgen::KeyUsagePurpose::KeyCertSign];
    let ca = rcgen::CertifiedIssuer::self_signed(params, rcgen::KeyPair::generate()?)?;
    std::fs::write(root.join("ca.pem"), ca.pem())?;
    let peer = |name: &str, identity: &str| -> TestResult<MeshTlsConfig> {
        let key = rcgen::KeyPair::generate()?;
        let mut params = rcgen::CertificateParams::new(vec!["localhost".into()])?;
        params.subject_alt_names.push(rcgen::SanType::URI(identity.try_into()?));
        params.extended_key_usages = vec![
            rcgen::ExtendedKeyUsagePurpose::ServerAuth,
            rcgen::ExtendedKeyUsagePurpose::ClientAuth,
        ];
        let cert = params.signed_by(&key, &ca)?;
        let service_cert = root.join(format!("{name}.pem"));
        let service_key = root.join(format!("{name}.key"));
        std::fs::write(&service_cert, cert.pem())?;
        std::fs::write(&service_key, key.serialize_pem())?;
        Ok(MeshTlsConfig { ca_cert: root.join("ca.pem"), service_cert, service_key })
    };
    Ok((
        peer("server", "spiffe://test/ramflux-gateway/gw-a")?,
        peer("client", "spiffe://test/ramflux-notify")?,
    ))
}

async fn exchange(
    path: &'static str,
    expected: &'static str,
    response_size: usize,
    budget: Duration,
) -> TestResult<(bool, bool)> {
    const MAX_RESPONSE: usize = 66_000;
    if response_size > MAX_RESPONSE {
        return Err("test: response fixture exceeds its bound".into());
    }
    let temp = tempfile::TempDir::new()?;
    let (server_tls, client_tls) = certificates(temp.path())?;
    let roots = std::fs::read_to_string(&server_tls.ca_cert)?;
    let server = MeshQuicServer::bind_with_pem_roots_provider(
        "127.0.0.1:0",
        &server_tls,
        Arc::new(move || Ok(vec![roots.clone()])),
    )?;
    let client = MeshAuthorityClient::new(
        server.local_addr()?.to_string(),
        expected.into(),
        "localhost".into(),
        client_tls,
        Arc::new(tokio::sync::Semaphore::new(64)),
    );
    let mut task = tokio::spawn(async move {
        let connection = server.accept_connection().await?;
        assert_eq!(
            connection.peer_spiffe_uri(),
            Some("spiffe://test/ramflux-notify"),
            "real mTLS connection did not authenticate the notify caller"
        );
        let request = tokio::time::timeout(
            Duration::from_secs(2),
            MeshQuicServer::accept_control_request_on_connection(&connection),
        )
        .await;
        let Ok(Ok(request)) = request else { return Ok::<_, crate::TransportError>(false) };
        assert_eq!(
            request.raw_body.as_deref(),
            Some(b"{\"request\":1}".as_slice()),
            "control body changed in transport"
        );
        if response_size == 0 {
            std::future::pending::<()>().await;
        }
        let response = serde_json::json!({"padding":"x".repeat(response_size)});
        let _ = request.write_json_response(200, &response).await;
        Ok(true)
    });
    let result = tokio::time::timeout(
        Duration::from_secs(4),
        tokio::task::spawn_blocking(move || {
            client.post(path, &serde_json::json!({"request":1}), Instant::now() + budget)
        }),
    )
    .await??;
    if response_size == 1024
        && expected.ends_with("/gw-a")
        && let Err(error) = &result
    {
        task.abort();
        let _ = task.await;
        return Err(std::io::Error::other(format!(
            "test: exact-instance positive RPC failed: {error}"
        ))
        .into());
    }
    if response_size == 0 {
        task.abort();
        let _ = task.await;
        return Ok((result.is_ok(), true));
    }
    let received = match tokio::time::timeout(Duration::from_secs(3), &mut task).await {
        Ok(result) => result??,
        Err(error) => {
            task.abort();
            let _ = task.await;
            return Err(std::io::Error::other(format!("test: server completion {path}, expected={expected}, response_size={response_size}, client={result:?}: {error}")).into());
        }
    };
    Ok((result.is_ok(), received))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn real_mtls_authority_pins_instance_and_enforces_control_and_read_caps() -> TestResult {
    let run = async {
        let control = "/internal/notify/fence-check/v1";
        let read = "/internal/gateway/notify-call/v1";
        let identity = "spiffe://test/ramflux-gateway/gw-a";
        assert_eq!(
            exchange(control, identity, 1024, Duration::from_secs(3)).await?,
            (true, true),
            "exact-instance mTLS positive control failed"
        );
        assert_eq!(
            exchange(control, "spiffe://test/ramflux-gateway/gw-b", 1024, Duration::from_secs(3))
                .await?,
            (false, false),
            "wrong instance received a control body"
        );
        assert!(
            !exchange(control, identity, 9000, Duration::from_secs(3)).await?.0,
            "control response exceeded its original-byte 8 KiB cap"
        );
        assert!(
            exchange(read, identity, 9000, Duration::from_secs(3)).await?.0,
            "read response incorrectly used the smaller control cap"
        );
        assert!(
            !exchange(read, identity, 66_000, Duration::from_secs(3)).await?.0,
            "read response exceeded its original-byte 64 KiB cap"
        );
        assert!(
            !exchange(read, identity, 0, Duration::from_millis(150)).await?.0,
            "stalled authority read escaped the caller's absolute deadline"
        );
        Ok(())
    };
    tokio::time::timeout(Duration::from_secs(20), run).await?
}

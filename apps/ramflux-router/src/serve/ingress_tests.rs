// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain
//! The router's real async QUIC ingress keeps `/source` bodies byte-exact (P25 N5b).
use super::{RouterAsyncMeshPeerAuth, router_async_mesh_quic_connection_loop};
use ramflux_transport::{MeshQuicServer, MeshTlsConfig, mesh_quic_exchange_raw_frame};
use std::{
    collections::BTreeSet,
    path::{Path, PathBuf},
    process::Command,
    sync::Arc,
    time::{Duration, Instant},
};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
const SOURCE_PATH: &str = "/s9/attachments/renew/source";
const CAP: usize = 16 * 1024;

fn openssl(args: &[&str]) -> TestResult {
    if Command::new("openssl").args(args).status()?.success() {
        Ok(())
    } else {
        Err(format!("openssl {args:?}").into())
    }
}
fn s(path: &Path) -> TestResult<&str> {
    path.to_str().ok_or_else(|| "utf8 path".into())
}
fn service(root: &Path, ca_key: &Path, ca: &Path, id: &str) -> TestResult<MeshTlsConfig> {
    let dir = root.join(id);
    std::fs::create_dir_all(&dir)?;
    let (key, csr, cert, ext) =
        (dir.join("key.pem"), dir.join("req.csr"), dir.join("cert.pem"), dir.join("ext.cnf"));
    openssl(&["genpkey", "-algorithm", "ED25519", "-out", s(&key)?])?;
    openssl(&["req", "-new", "-key", s(&key)?, "-out", s(&csr)?, "-subj", &format!("/CN={id}")])?;
    std::fs::write(
        &ext,
        format!(
            "subjectAltName = DNS:{id}, DNS:localhost, URI:spiffe://node-a/{id}\nextendedKeyUsage = serverAuth, clientAuth\nkeyUsage = digitalSignature\n"
        ),
    )?;
    openssl(&[
        "x509",
        "-req",
        "-in",
        s(&csr)?,
        "-CA",
        s(ca)?,
        "-CAkey",
        s(ca_key)?,
        "-CAcreateserial",
        "-out",
        s(&cert)?,
        "-days",
        "30",
        "-extfile",
        s(&ext)?,
    ])?;
    Ok(MeshTlsConfig { ca_cert: ca.to_path_buf(), service_cert: cert, service_key: key })
}

/// The frame payload as a client writes it (the helper adds the length prefix), with the
/// body text under our control.
fn frame(body: &str) -> Vec<u8> {
    format!(r#"{{"method":"POST","path":"{SOURCE_PATH}","body":{body}}}"#).into_bytes()
}
fn string_body(n: usize) -> String {
    format!("\"{}\"", "a".repeat(n - 2))
}
/// A valid JSON object whose text is exactly `n` bytes, mostly whitespace. Decoding and
/// re-serializing it would shrink it to `{"a":1}`.
fn padded_body(n: usize) -> String {
    format!("{{\"a\":1{}}}", " ".repeat(n - 7))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn source_route_cap_is_exact_on_raw_received_bytes_through_real_quic() -> TestResult {
    let root: PathBuf = std::env::temp_dir().join(format!(
        "rf-router-ingress-{}-{}",
        std::process::id(),
        Instant::now().elapsed().as_nanos()
    ));
    std::fs::create_dir_all(&root)?;
    let (ca_key, ca) = (root.join("ca-key.pem"), root.join("ca.pem"));
    openssl(&["genpkey", "-algorithm", "ED25519", "-out", s(&ca_key)?])?;
    openssl(&[
        "req",
        "-x509",
        "-new",
        "-key",
        s(&ca_key)?,
        "-out",
        s(&ca)?,
        "-days",
        "30",
        "-subj",
        "/CN=Ingress Test CA",
    ])?;
    let ca_pem = std::fs::read_to_string(&ca)?;
    let router_tls = service(&root, &ca_key, &ca, "ramflux-router")?;
    let federation = service(&root, &ca_key, &ca, "ramflux-federation")?;
    let gateway = service(&root, &ca_key, &ca, "ramflux-gateway")?;

    let (state, store, db_path) = crate::router_runtime::tests::test_router("source-ingress")?;
    let router = Arc::new(crate::router_runtime::RouterHandle::tokio(state, store, None));
    let roots_pem = ca_pem.clone();
    let server = MeshQuicServer::bind_with_pem_roots_provider(
        "127.0.0.1:0",
        &router_tls,
        Arc::new(move || Ok(vec![roots_pem.clone()])),
    )?;
    let endpoint = server.local_addr()?.to_string();
    let auth = RouterAsyncMeshPeerAuth {
        local_service_id: "ramflux-router".into(),
        allowed_service_ids: BTreeSet::from([
            "ramflux-federation".into(),
            "ramflux-gateway".into(),
        ]),
    };
    let accept = tokio::spawn(async move {
        while let Ok(connection) = server.accept_connection().await {
            tokio::spawn(router_async_mesh_quic_connection_loop(
                connection,
                Arc::clone(&router),
                auth.clone(),
            ));
        }
    });
    let send = |tls: &MeshTlsConfig, body: String| {
        let (endpoint, roots) = (endpoint.clone(), vec![ca_pem.clone()]);
        let tls = tls.clone();
        async move {
            tokio::time::timeout(
                Duration::from_secs(15),
                mesh_quic_exchange_raw_frame(
                    &endpoint,
                    &tls,
                    "ramflux-router",
                    &roots,
                    &frame(&body),
                    Instant::now() + Duration::from_secs(10),
                ),
            )
            .await
        }
    };
    // Exactly at the cap the federation peer reaches the (unconfigured) route: 503, not 413.
    for body in [string_body(CAP), padded_body(CAP)] {
        let response = send(&federation, body).await??;
        assert_eq!(response.status, 503, "{response:?}");
    }
    // One byte over: refused as received, including a whitespace-padded valid object that
    // would have normalized under the cap.
    for body in [string_body(CAP + 1), padded_body(CAP + 1)] {
        let response = send(&federation, body).await??;
        assert_eq!(response.status, 413, "{response:?}");
    }
    // The peer gate still comes first for a service that may not use the route.
    let refused = send(&gateway, string_body(CAP)).await??;
    assert_eq!(refused.status, 403, "{refused:?}");
    accept.abort();
    let _ = std::fs::remove_dir_all(&root);
    let _ = std::fs::remove_file(&db_path);
    Ok(())
}

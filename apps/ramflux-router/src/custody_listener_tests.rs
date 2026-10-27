// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Public direct-listener handshake deadlines protect pre-authentication holders.
use super::*;
struct Cleanup(std::path::PathBuf);
impl Drop for Cleanup {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
#[tokio::test]
async fn direct_custody_slow_tls_peer_loses_its_holder_after_five_seconds() -> anyhow::Result<()> {
    let root = std::env::temp_dir().join(format!(
        "ramflux-custody-public-tls-{}",
        ramflux_protocol::encode_base64url(ramflux_crypto::random_32()?)
    ));
    std::fs::create_dir(&root)?;
    let _cleanup = Cleanup(root.clone());
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()])?;
    let tls = ramflux_transport::MeshTlsConfig {
        ca_cert: root.join("ca.pem"),
        service_cert: root.join("public.pem"),
        service_key: root.join("public.key"),
    };
    std::fs::write(&tls.ca_cert, cert.cert.pem())?;
    std::fs::write(&tls.service_cert, cert.cert.pem())?;
    std::fs::write(&tls.service_key, cert.signing_key.serialize_pem())?;
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(
        ramflux_transport::tcp_gateway_server_config(&tls)?,
    ));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let client = tokio::net::TcpStream::connect(listener.local_addr()?).await?;
    let (socket, _) = listener.accept().await?;
    let started = tokio::time::Instant::now();
    let result =
        tokio::time::timeout(Duration::from_secs(10), accept_tls(&acceptor, socket)).await?;
    assert!(result.is_err());
    assert!(started.elapsed() >= Duration::from_secs(5));
    drop(client);
    Ok(())
}

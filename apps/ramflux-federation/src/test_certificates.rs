// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

pub(crate) struct TestCa {
    cert: PathBuf,
    key: PathBuf,
}

pub(crate) struct TestPeerCerts {
    pub(crate) tls: ramflux_transport::MeshTlsConfig,
    pub(crate) ca_pem: String,
}

pub(crate) fn temp_cert_root(name: &str) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let elapsed = SystemTime::now().duration_since(UNIX_EPOCH)?;
    let root = std::env::temp_dir().join(format!(
        "ramflux-federation-certs-{name}-{}-{}",
        std::process::id(),
        elapsed.as_nanos()
    ));
    if root.exists() {
        std::fs::remove_dir_all(&root)?;
    }
    std::fs::create_dir_all(&root)?;
    Ok(root)
}

pub(crate) fn issue_test_ca(root: &Path) -> Result<TestCa, Box<dyn std::error::Error>> {
    let ca_key = root.join("ca-key.pem");
    let ca_cert = root.join("ca.pem");
    run_openssl(&["genpkey", "-algorithm", "ED25519", "-out", path_str(&ca_key)?])?;
    run_openssl(&[
        "req",
        "-x509",
        "-new",
        "-key",
        path_str(&ca_key)?,
        "-out",
        path_str(&ca_cert)?,
        "-days",
        "30",
        "-subj",
        "/CN=Ramflux Federation QUIC Test CA",
    ])?;
    Ok(TestCa { cert: ca_cert, key: ca_key })
}

pub(crate) fn issue_test_service_cert(
    ca: &TestCa,
    node_id: &str,
    service_id: &str,
) -> Result<TestPeerCerts, Box<dyn std::error::Error>> {
    let service_dir = ca
        .cert
        .parent()
        .ok_or_else(|| test_error("CA cert has no parent"))?
        .join(node_id)
        .join(service_id);
    std::fs::create_dir_all(&service_dir)?;
    let service_key = service_dir.join(format!("{service_id}-key.pem"));
    let service_csr = service_dir.join(format!("{service_id}.csr"));
    let service_cert = service_dir.join(format!("{service_id}.pem"));
    let ext = service_dir.join(format!("{service_id}.ext"));
    run_openssl(&["genpkey", "-algorithm", "ED25519", "-out", path_str(&service_key)?])?;
    run_openssl(&[
        "req",
        "-new",
        "-key",
        path_str(&service_key)?,
        "-out",
        path_str(&service_csr)?,
        "-subj",
        &format!("/CN={service_id}"),
    ])?;
    std::fs::write(
        &ext,
        format!(
            "subjectAltName = DNS:{service_id}, DNS:localhost, URI:spiffe://{node_id}/{service_id}\nextendedKeyUsage = serverAuth, clientAuth\nkeyUsage = digitalSignature\n"
        ),
    )?;
    run_openssl(&[
        "x509",
        "-req",
        "-in",
        path_str(&service_csr)?,
        "-CA",
        path_str(&ca.cert)?,
        "-CAkey",
        path_str(&ca.key)?,
        "-CAcreateserial",
        "-out",
        path_str(&service_cert)?,
        "-days",
        "30",
        "-extfile",
        path_str(&ext)?,
    ])?;
    Ok(TestPeerCerts {
        tls: ramflux_transport::MeshTlsConfig {
            ca_cert: ca.cert.clone(),
            service_cert,
            service_key,
        },
        ca_pem: std::fs::read_to_string(&ca.cert)?,
    })
}

fn run_openssl(args: &[&str]) -> Result<(), Box<dyn std::error::Error>> {
    let status = Command::new("openssl").args(args).status()?;
    if !status.success() {
        return Err(format!("openssl failed with status {status}: {}", args.join(" ")).into());
    }
    Ok(())
}

fn path_str(path: &Path) -> Result<&str, Box<dyn std::error::Error>> {
    path.to_str().ok_or_else(|| format!("non-UTF-8 path {}", path.display()).into())
}

fn test_error(message: impl Into<String>) -> Box<dyn std::error::Error> {
    message.into().into()
}

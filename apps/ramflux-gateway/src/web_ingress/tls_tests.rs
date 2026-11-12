// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use super::{ALPN_HTTP_1_1, build, ensure_distinct_keys};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn generated() -> Result<(CertificateDer<'static>, PrivateKeyDer<'static>), rcgen::Error> {
    let certified = rcgen::generate_simple_self_signed(vec!["gw.example.org".to_owned()])?;
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(certified.key_pair.serialize_der()));
    Ok((certified.cert.der().clone(), key))
}

#[test]
fn web_listener_refuses_to_start_when_certificate_key_equals_mesh_key() -> TestResult {
    let (_, web) = generated()?;
    let (_, mesh) = generated()?;
    assert!(ensure_distinct_keys(&web, &mesh).is_ok());
    assert!(ensure_distinct_keys(&web, &web.clone_key()).is_err());
    Ok(())
}

#[test]
fn web_listener_offers_http_1_1_only_and_tls_1_3_only() -> TestResult {
    let (certificate, key) = generated()?;
    let config = build(vec![certificate], key)?;
    assert_eq!(config.alpn_protocols, vec![ALPN_HTTP_1_1.to_vec()]);
    Ok(())
}

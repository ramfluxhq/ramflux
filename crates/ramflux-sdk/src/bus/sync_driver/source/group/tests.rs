// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Both directory preparation branches retain exact failed roots, including URLs.
use super::*;
use crate::client::native_test_support::{Fixture, TestResult};
use crate::client::routed::group_directory::{LegacyGroupRequest, Lookup};
use crate::client::shared_group::GroupDirectoryRequest;

fn assert_root<T>(result: Result<T, SdkError>, root: &str) {
    assert!(
        matches!(result, Err(SdkError::DirectoryAuthorityUnavailable { root: failed, .. }) if failed == root),
        "inbound group directory failure must retain its exact root"
    );
}
#[tokio::test]
async fn group_directory_outages_retain_exact_legacy_and_addition_roots() -> TestResult {
    let native = Fixture::new("inbound-group-roots").await?;
    let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
    let address = listener.local_addr()?;
    drop(listener);
    let cert = rcgen::generate_simple_self_signed(vec!["directory.test".into()])?;
    let mut config = native.config;
    config.transport_kind = crate::GatewaySessionTransportKind::TcpTls;
    config.gateway_addr = address;
    config.tcp_gateway_addr = Some(address);
    config.server_name = "directory.test".into();
    config.ca_cert = native.root.0.join("directory.pem");
    std::fs::write(&config.ca_cert, cert.cert.pem())?;
    let legacy = native.manifest.principal_commitment;
    let addition = crate::client::identity_authority::test_support::remote_manifest(
        "addition", "primary", [43; 32],
    )?
    .principal_commitment;
    for url in [None, Some(format!("http://{address}"))] {
        let request = LegacyGroupRequest::Control {
            lookup: Some(Lookup {
                root: legacy.clone(),
                device: "primary".into(),
                url: url.clone(),
            }),
        };
        assert_root(resolve_legacy(request, &config).await, &legacy);
        let request = GroupDirectoryRequest { root: addition.clone(), url };
        assert_root(resolve_addition(request, &config).await, &addition);
    }
    assert!(resolve_legacy(LegacyGroupRequest::Other, &config).await?.is_none());
    Ok(())
}

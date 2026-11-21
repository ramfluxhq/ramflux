// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Test-only helpers: an offline client (no request is ever sent through it) and a
//! capability set built from literal tokens.

use crate::capabilities::{BuildCommit, Capabilities};
use crate::client::PrxClient;
use crate::transport::ClientConfig;
use std::collections::BTreeSet;

/// A client aimed at a port nothing listens on. A call that reaches the network would fail
/// with `Unavailable`, so a test that expects a local refusal proves that nothing was sent.
pub(crate) fn offline_client() -> (tempfile::TempDir, PrxClient) {
    let dir = tempfile::TempDir::new().expect("test: temp dir");
    let token = dir.path().join("token");
    std::fs::write(&token, "offline-test-token").expect("test: write token");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&token, std::fs::Permissions::from_mode(0o600)).expect("test: chmod token");
    }
    let settings = ClientConfig::new("http://127.0.0.1:9", &token);
    let client = PrxClient::new(&settings).expect("test: offline client builds");
    (dir, client)
}

/// Capabilities with exactly these effective tokens.
pub(crate) fn caps_with(tokens: &[&str]) -> Capabilities {
    Capabilities {
        prx_version: "0.8.171".to_owned(),
        commit: BuildCommit::Unknown,
        api: 1,
        capabilities: tokens.iter().map(|t| (*t).to_owned()).collect::<BTreeSet<_>>(),
        available: BTreeSet::new(),
    }
}

// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use super::*;
type TestResult = std::result::Result<(), Box<dyn std::error::Error>>;
const NODE_ISSUES: usize = 60;
const NOW: u64 = 1_700_000_040;
fn peer(node: &str) -> std::result::Result<crate::MeshPeerIdentity, crate::NodeCoreError> {
    crate::parse_mesh_spiffe_uri(&format!("spiffe://{node}/ramflux-federation"))
}
#[test]
fn cr_cost_peer_budgets_bind_tls_identity_and_survive_reopen() -> TestResult {
    let dir = tempfile::TempDir::new()?;
    let path = dir.path().join("federation.redb");
    let store = FederationRedbStore::open(&path)?;
    let node = peer("source.example")?;
    let remote = "192.0.2.20".parse()?;
    for _ in 0..NODE_ISSUES {
        store.admit_contact_cost(&node, remote, NOW)?;
    }
    assert!(
        matches!(
            store.admit_contact_cost(&node, remote, NOW),
            Err(ReachError::Refused(Reason::ForeignRateLimited))
        ),
        "a request body cannot evade the actual TLS node's 60-per-minute issue cap"
    );
    drop(store);
    let store = FederationRedbStore::open(&path)?;
    assert!(
        matches!(
            store.admit_contact_cost(&node, remote, NOW - 60),
            Err(ReachError::Refused(Reason::ForeignRateLimited))
        ),
        "restart and wall-clock rollback cannot reset the authenticated peer budget"
    );
    let other = peer("other.example")?;
    for _ in 0..NODE_ISSUES {
        store.admit_contact_cost(&other, "192.0.2.99".parse()?, NOW)?;
    }
    assert!(
        matches!(
            store.admit_contact_cost(&peer("third.example")?, "192.0.2.100".parse()?, NOW),
            Err(ReachError::Refused(Reason::ForeignRateLimited))
        ),
        "different authenticated nodes still share the observed egress /24 cap"
    );
    store.admit_contact_cost(&node, remote, NOW + 60)?;
    let wrong = crate::parse_mesh_spiffe_uri("spiffe://source.example/ramflux-router")?;
    assert!(
        store.admit_contact_cost(&wrong, remote, NOW + 60).is_err(),
        "another authenticated service role cannot enter the public issuer path"
    );
    Ok(())
}

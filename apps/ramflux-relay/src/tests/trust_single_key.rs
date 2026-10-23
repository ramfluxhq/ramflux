// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use crate::config::now_unix_seconds;
#[cfg(feature = "itest-provider-single-key")]
use crate::trust_single_key::{load_trust_snapshot_cache, persist_trust_snapshot_cache};

use std::collections::BTreeSet;

#[cfg(feature = "itest-provider-single-key")]
#[test]
fn trust_snapshot_cache_persistence_round_trips_atomically() -> anyhow::Result<()> {
    let root = std::env::temp_dir().join(format!(
        "ramflux-relay-trust-cache-{}-{}",
        std::process::id(),
        now_unix_seconds()
    ));
    let path = root.join("trust-snapshot.json");
    let envelope = ramflux_node_core::SignedFederatedIssuerTrustSnapshot {
        schema: ramflux_node_core::FEDERATED_ISSUER_TRUST_SNAPSHOT_ENVELOPE_SCHEMA.to_owned(),
        version: ramflux_node_core::OBJECT_RELAY_V3_PROOF_VERSION,
        snapshot: ramflux_node_core::FederatedIssuerTrustSnapshot {
            schema: ramflux_node_core::FEDERATED_ISSUER_TRUST_SNAPSHOT_SCHEMA.to_owned(),
            version: ramflux_node_core::OBJECT_RELAY_V3_PROOF_VERSION,
            node_id: "node-b".to_owned(),
            generation: 7,
            pin_epoch: 2,
            trust_status: ramflux_node_core::FederatedIssuerTrustStatus::Active,
            roots: Vec::new(),
            revoked_cert_ids: BTreeSet::new(),
            hard_stale_at: 2_000_000,
        },
        provider_signing_key_id: "provider-1".to_owned(),
        provider_public_key: "provider-public-key".to_owned(),
        issued_at: 1_000_000,
        expires_at: 1_000_300,
        signature: "signature".to_owned(),
    };
    let path_string = path.to_string_lossy();
    persist_trust_snapshot_cache(&path_string, &envelope)?;
    let loaded = load_trust_snapshot_cache(&path_string)?;
    assert_eq!(loaded, envelope);
    assert!(!path.with_extension(format!("tmp.{}", std::process::id())).exists());
    std::fs::remove_dir_all(root)?;
    Ok(())
}

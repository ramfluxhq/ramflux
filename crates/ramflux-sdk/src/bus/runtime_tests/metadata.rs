// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Typed request metadata persists in local client projections.

use super::*;
use serde_json::json;

#[test]
fn typed_account_and_object_metadata_reach_client_records() -> Result<(), SdkError> {
    let root = root("typed-metadata");
    let account = account(&root, "alice", None, Arc::new(AtomicBool::new(false)))?;
    let create: LocalBusAccountCreateRequest = serde_json::from_value(json!({
        "label":"Alice profile", "kind":"bot", "local_account_id":"alice",
        "principal_id":"alice", "principal_commitment":"commitment-alice", "device_id":"device-alice",
        "target_delivery_id":"target", "account_secret":"actor-test-secret", "root_seed":vec![0x61_u8;32],
        "device_seed":vec![0x62_u8;32], "client_mode":"attended_cli"
    }))?;
    let create = request("create", "alice", "account.create", serde_json::to_value(create)?);
    super::super::read_model::capture(&account, &create, &json!({}))?;
    super::super::read_model::initialize(&account)?;
    let manifest =
        read_local_bus_account_manifest(&local_bus_account_manifest_path(&root, "alice"))?;
    assert_eq!(manifest.label.as_deref(), Some("Alice profile"));
    assert_eq!(manifest.kind.as_deref(), Some("bot"));
    let db = account.client.account_db()?;
    let identity =
        db.client_record("identity", "alice")?.ok_or_else(|| failure("missing identity"))?;
    assert_eq!(identity["display_name"], "Alice profile");
    assert_eq!(identity["kind"], "bot");
    // The retired message.submit attachment input is gone; object metadata now reaches the
    // client records through the live object.put route.
    let put = request(
        "put",
        "alice",
        "object.put",
        json!({
            "object_id":"object", "name":"sample.txt", "mime":"text/plain",
            "plaintext_base64":ramflux_protocol::encode_base64url(b"sample"), "chunk_size":4096,
            "relay_endpoint":"quic://relay.example:443"
        }),
    );
    super::super::read_model::capture(&account, &put, &json!({}))?;
    let object =
        db.client_record("object", "object")?.ok_or_else(|| failure("missing attachment"))?;
    assert_eq!(object["name"], "sample.txt");
    assert_eq!(object["mime"], "text/plain");
    assert_eq!(object["size"], 6);
    drop(account);
    Ok(())
}

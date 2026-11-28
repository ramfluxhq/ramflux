// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Typed object request metadata persists in local client projections.

use super::*;
use serde_json::json;

#[test]
fn typed_object_metadata_reaches_client_records() -> Result<(), SdkError> {
    let root = root("typed-metadata");
    let account = account(&root, "alice", None, Arc::new(AtomicBool::new(false)))?;
    let db = account.client.account_db()?;
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

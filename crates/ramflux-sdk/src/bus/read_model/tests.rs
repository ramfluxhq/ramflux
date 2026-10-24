// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use super::*;

struct Fixture {
    root: PathBuf,
    client: RamfluxClient,
}
impl Fixture {
    fn new() -> Result<Self, SdkError> {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |time| time.as_nanos());
        let root =
            PathBuf::from(format!("/tmp/ramflux-read-model-{}-{unique}", std::process::id()));
        let mut client = RamfluxClient::new();
        client.create_identity_root("alice", [0x31; 32]);
        client.create_device_branch("alice", "alice-phone", 1, [0x32; 32]);
        client.open_account_index(&root)?;
        client.create_account("local-alice", "commit-alice")?;
        client.unlock_account("local-alice", b"test-secret")?;
        client.account_db()?.persist_client_record(
            "self",
            "account",
            &json!({"principal_id":"alice","device_id":"alice-phone"}),
        )?;
        client.account_db()?.persist_client_record("identity","alice",&json!({"id":"alice","principal_id":"alice","contact_identity_commitment":"commit-alice","devices":[{"id":"alice-phone"}],"kind":"human","is_self":true}))?;
        Ok(Self { root, client })
    }
    fn read(&self, method: &str, body: Value) -> Result<Value, SdkError> {
        read(
            &self.client,
            &LocalBusFrame::request("read", Some("local-alice".to_owned()), "client", method, body),
        )
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

#[test]
fn empty_directories_and_self_identity_are_readable() -> Result<(), SdkError> {
    let f = Fixture::new()?;
    for (method, field) in [
        ("conversation.directory", "conversations"),
        ("object.directory", "objects"),
        ("group.list", "groups"),
        ("mcp.server.list", "servers"),
        ("mcp.approval.list", "approvals"),
    ] {
        let value = f.read(method, json!({}))?;
        assert_eq!(value[field], json!([]));
        assert!(value["next_cursor"].is_null());
    }
    let identities = f.read("identity.directory", json!({}))?;
    assert_eq!(identities["identities"][0]["principal_id"], "alice");
    Ok(())
}

#[test]
fn direct_and_distinct_group_conversation_ids_join_public_routes() -> Result<(), SdkError> {
    let f = Fixture::new()?;
    let db = f.client.account_db()?;
    db.send_direct_message("dm", "message", "alice-phone", b"secret-payload")?;
    db.persist_client_record("conversation","dm",&json!({"kind":"direct","title":"Bob","participants":["alice","bob"],"direct_route":{"recipient_principal_commitment":"commit-bob","recipient_device_ids":["bob-phone","bob-laptop"],"target_delivery_id":"deliver-bob"}}))?;
    f.client.create_group("group", "alice-phone")?;
    db.persist_client_record("group", "group", &json!({"conversation_id":"group-thread"}))?;
    db.persist_client_record(
        "conversation",
        "group-thread",
        &json!({"kind":"group","group_id":"group","participants":["alice","bob"]}),
    )?;
    let value = f.read("conversation.directory", json!({}))?;
    assert_eq!(value["conversations"][0]["direct_route"]["target_delivery_id"], "deliver-bob");
    assert_eq!(value["conversations"][0]["self_principal_id"], "alice");
    assert_eq!(value["conversations"][1]["id"], "group-thread");
    assert_eq!(value["conversations"][1]["group_id"], "group");
    assert_eq!(f.read("group.list", json!({}))?["groups"][0]["conversation_id"], "group-thread");
    assert!(!serde_json::to_string(&value)?.contains("secret-payload"));
    Ok(())
}

#[test]
fn object_pages_never_serialize_content_keys_or_ciphertext_and_are_scope_bound()
-> Result<(), SdkError> {
    let mut f = Fixture::new()?;
    for id in ["a", "b", "c"] {
        f.client.put_encrypted_object(id, b"private object bytes")?;
    }
    let db = f.client.account_db()?;
    db.persist_client_record("object","a",&json!({"name":"attachment.txt","size":20,"mime":"text/plain","direction":"outgoing","owner":"alice","conversation_id":"dm","message_id":"msg","ciphertext":"forbidden","object_content_key":"forbidden"}))?;
    let first = f.read("object.directory", json!({"limit":2}))?;
    let encoded = serde_json::to_string(&first)?;
    for forbidden in [
        "ciphertext",
        "object_content_key",
        "plaintext",
        "nonce",
        "forbidden",
        "private object bytes",
    ] {
        assert!(!encoded.contains(forbidden), "serialized {forbidden}");
    }
    assert_eq!(first["objects"][0]["name"], "attachment.txt");
    assert_eq!(first["objects"].as_array().map(Vec::len), Some(2));
    let cursor = first["next_cursor"].clone();
    let second = f.read("object.directory", json!({"limit":2,"cursor":cursor}))?;
    assert_eq!(second["objects"][0]["id"], "c");
    assert!(second["next_cursor"].is_null());
    assert!(f.read("identity.directory", json!({"cursor":first["next_cursor"]})).is_err());
    for limit in [0, 101] {
        assert!(f.read("object.directory", json!({"limit":limit})).is_err());
    }
    assert!(f.read("object.directory", json!({"cursor":"bad"})).is_err());
    Ok(())
}

#[test]
fn large_metadata_pages_stop_before_frame_cap_without_losing_rows() -> Result<(), SdkError> {
    let f = Fixture::new()?;
    for id in ["a", "b", "c"] {
        f.client.account_db()?.persist_client_record(
            "identity",
            id,
            &json!({"id":id,"display_name":"x".repeat(280_000)}),
        )?;
    }
    let first = f.read("identity.directory", json!({"limit":100}))?;
    let frame = LocalBusFrame::request(
        "size",
        Some("local-alice".to_owned()),
        "client",
        "identity.directory",
        json!({}),
    );
    assert!(
        super::super::io::encode_local_bus_frame(&local_bus_response(&frame, first.clone()))?.len()
            < super::super::io::MAX_LOCAL_BUS_FRAME_BYTES
    );
    assert!(first["next_cursor"].is_string());
    let next = f.read("identity.directory", json!({"limit":100,"cursor":first["next_cursor"]}))?;
    assert_ne!(first["identities"][0]["id"], next["identities"][0]["id"]);
    Ok(())
}

#[test]
fn multi_device_identity_safety_and_approval_context_are_explicit() -> Result<(), SdkError> {
    let f = Fixture::new()?;
    let db = f.client.account_db()?;
    db.persist_client_record("identity","bob",&json!({"id":"bob","principal_id":"bob","contact_identity_commitment":"commit-bob","devices":[{"id":"phone","signing_public_key":"pk","target_delivery_id":"target"},{"id":"laptop"}],"safety_number":"123456"}))?;
    db.persist_client_record("approval","approval",&json!({"id":"approval","approval_id":"approval","status":"pending","conversation_id":"dm","context_id":"task"}))?;
    let value = f.read("identity.directory", json!({}))?;
    assert_eq!(value["identities"][1]["devices"].as_array().map(Vec::len), Some(2));
    assert_eq!(value["identities"][1]["safety_number_available"], true);
    let approval = f.read("mcp.approval.list", json!({}))?;
    assert_eq!(approval["approvals"][0]["conversation_id"], "dm");
    db.persist_client_record("approval", "approval", &json!({"id":"approval","status":"denied"}))?;
    assert_eq!(f.read("mcp.approval.list", json!({}))?["approvals"], json!([]));
    Ok(())
}

#[test]
fn server_health_is_unknown_until_observed_and_not_inferred_from_tools() -> Result<(), SdkError> {
    let f = Fixture::new()?;
    let db = f.client.account_db()?;
    db.upsert_mcp_tool(&McpToolWrite {
        tool_manifest_hash: "hash",
        server_id: "server",
        tool_name: "tool",
        required_capability: "echo",
        risk_level: "low",
        manifest: &json!({}),
        updated_at: 1,
    })?;
    let value = f.read("mcp.server.list", json!({}))?;
    assert_eq!(value["servers"], json!(["server"]));
    assert!(value["server_details"][0]["reachable"].is_null());
    assert!(value["server_details"][0]["last_check"].is_null());
    assert_eq!(value["server_details"][0]["health_source"], "not_checked");
    Ok(())
}

#[test]
fn remote_attachments_are_listed_with_public_fetch_status_only() -> Result<(), SdkError> {
    let f = Fixture::new()?;
    let db = f.client.account_db()?;
    db.persist_actor_state(
        "attachment/reference/remote",
        &json!({"access_grant":"PRIVATE_GRANT","key_slot":"PRIVATE_SLOT"}),
    )?;
    db.persist_client_record("object", "remote", &json!({"owner":"peer","size":42,"conversation_id":"dm","message_id":"message","manifest_hash":"hash","plaintext_hash":"plain-hash","access_grant":"PRIVATE_GRANT","key_slot":"PRIVATE_SLOT"}))?;
    let listed = f.read("object.directory", json!({"limit":1}))?;
    assert_eq!(listed["objects"][0]["id"], "remote");
    assert_eq!(listed["objects"][0]["transfer_state"], "not_fetched");
    assert_eq!(listed["objects"][0]["size"], 42);
    for state in ["failed", "retrying", "available"] {
        db.persist_actor_state("attachment/fetch/remote", &json!({"object_id":"remote","operation_id":"fetch-op","transfer_state":state,"last_error":if state=="failed" {Some("attachment transport failed")} else {None},"attempts":2}))?;
        let listed = f.read("object.directory", json!({}))?;
        assert_eq!(listed["objects"][0]["transfer_state"], state);
        assert!(!listed.to_string().contains("PRIVATE_"));
        assert!(!listed.to_string().contains("key_slot"));
        assert!(!listed.to_string().contains("access_grant"));
        if state == "failed" {
            assert_eq!(listed["objects"][0]["last_error"], "attachment transport failed");
        }
    }
    Ok(())
}

#[test]
fn identity_directory_exposes_manual_pair_recovery_without_private_state() -> Result<(), SdkError> {
    let f = Fixture::new()?;
    let db = f.client.account_db()?;
    db.persist_client_record("device", "bob-phone", &json!({"principal_id":"bob"}))?;
    db.persist_client_record(
        "identity",
        "bob",
        &json!({"principal_id":"bob","devices":[{"id":"bob-phone"}]}),
    )?;
    db.persist_actor_state("dm-pair/test/manual",&json!({"local_device_id":"alice-phone","device_id":"bob-phone","state":"needs_manual_recovery","at":10}))?;
    let result = f.read("identity.directory", json!({}))?;
    let bob = result["identities"]
        .as_array()
        .ok_or_else(|| SdkError::LocalBus("identities".into()))?
        .iter()
        .find(|row| row["principal_id"] == "bob")
        .ok_or_else(|| SdkError::LocalBus("bob".into()))?;
    assert_eq!(bob["pair_recovery"][0]["state"], "needs_manual_recovery");
    assert_eq!(bob["pair_recovery"][0]["device_id"], "bob-phone");
    Ok(())
}

#[test]
fn pinned_member_safety_changes_are_visible_in_group_list() -> Result<(), SdkError> {
    let f = Fixture::new()?;
    f.client.create_group("group", "alice-phone")?;
    let change =
        json!({"state":"key_changed","device_id":"bob","reason":"pinned_group_member_key_changed"});
    f.client.account_db()?.persist_client_record(
        "group",
        "group",
        &json!({"safety_change":change}),
    )?;
    let row = f.read("group.list", json!({}))?;
    assert_eq!(row["groups"][0]["safety_change"], change);
    Ok(())
}

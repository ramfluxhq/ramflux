// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use super::*;
use std::collections::{BTreeMap, BTreeSet};

pub(super) const ACCOUNT: &str = "acct";
pub(super) const OPERATION: &str = "op-spool-1";
pub(super) const OBJECT_ID: &str = "object_spool_1";

pub(super) fn temp_data_root(test: &str) -> ramflux_test_support::TestPath {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    ramflux_test_support::TestPath::new()
        .expect("test: allocate fixture directory")
        .child(format!("ramflux-spool-{test}-{}-{nanos}", std::process::id()))
}

pub(super) fn make_state(data_root: &Path) -> LocalBusDaemonState {
    let data_root = data_root.to_path_buf();
    let mut client = RamfluxClient::new();
    client.create_identity_root("principal_spool_test", [0x51; 32]);
    client.create_device_branch("principal_spool_test", "device_spool_test", 1, [0x52; 32]);
    client.open_account_index(&data_root).expect("open account index");
    client.create_account(ACCOUNT, "principal_spool_test").expect("create account");
    client.set_active_account(ACCOUNT).expect("set active account");
    client.unlock_account(ACCOUNT, b"spool-test-secret").expect("unlock account");
    let gateway = GatewaySessionConfig::quic(GatewayQuicEndpointConfig {
        bind_addr: "127.0.0.1:0".parse().expect("bind addr"),
        gateway_addr: "127.0.0.1:1".parse().expect("gateway addr"),
        server_name: "ramflux-gateway".to_owned(),
        ca_cert: PathBuf::from("ca.pem"),
        principal_id: "principal_spool_test".to_owned(),
        device_id: "device_spool_test".to_owned(),
        target_delivery_id: "target_spool_test".to_owned(),
        prekey_http_url: None,
    });
    LocalBusDaemonState {
        account_index: None,
        nodes: crate::node::NodeStore::default(),
        config: LocalBusConfig::new(data_root.join("bus.sock"), data_root),
        accounts: BTreeMap::from([(
            ACCOUNT.to_owned(),
            LocalBusAccountState::disconnected(client, gateway, "principal_spool_test".to_owned()),
        )]),
        active_account_id: Some(ACCOUNT.to_owned()),
        attended_accounts: BTreeSet::new(),
        subscribers: BTreeMap::new(),
    }
}

async fn dispatch(
    state: &mut LocalBusDaemonState,
    method: &str,
    body: serde_json::Value,
) -> Result<serde_json::Value, SdkError> {
    let frame = LocalBusFrame::request("req", Some(ACCOUNT.to_owned()), "object", method, body);
    Ok(dispatch_object_bus_request(&frame, state).await?.response_body)
}

pub(super) fn begin_body(total_len: usize, plaintext_hash: &str) -> serde_json::Value {
    serde_json::to_value(LocalBusObjectPutBeginRequest {
        object_id: OBJECT_ID.to_owned(),
        operation_id: OPERATION.to_owned(),
        total_len,
        plaintext_hash: plaintext_hash.to_owned(),
        chunk_size: 65_536,
        protocol_version: OBJECT_PUT_PROTOCOL_VERSION,
        relay_endpoint: None,
        relay_service_key_base64: None,
        relay_interrupt_after_chunks: None,
    })
    .expect("begin body")
}

pub(super) fn chunk_body(offset: usize, data: &[u8]) -> serde_json::Value {
    serde_json::to_value(LocalBusObjectPutChunkRequest {
        operation_id: OPERATION.to_owned(),
        offset,
        data_base64: ramflux_protocol::encode_base64url(data),
    })
    .expect("chunk body")
}

pub(super) fn finish_body() -> serde_json::Value {
    serde_json::to_value(LocalBusObjectPutFinishRequest {
        object_id: OBJECT_ID.to_owned(),
        operation_id: OPERATION.to_owned(),
    })
    .expect("finish body")
}

pub(super) fn plaintext_hash(bytes: &[u8]) -> String {
    ramflux_crypto::blake3_256_base64url(ramflux_protocol::domain::OBJECT, bytes)
}

fn spool_path(state: &LocalBusDaemonState) -> PathBuf {
    object_put_spool_path(&state.config.data_root, ACCOUNT, OPERATION)
}

#[tokio::test]
async fn retired_relay_keys_refuse_local_bus_requests_with_and_without_profile()
-> Result<(), Box<dyn std::error::Error>> {
    tokio::time::timeout(std::time::Duration::from_secs(15), async {
        for profile in [false, true] {
            let directory = tempfile::TempDir::new()?;
            let mut state = make_state(directory.path());
            if profile {
                state.accounts.get_mut(ACCOUNT).ok_or("test: account")?.client.node_relay_options = Some(RelayTransferOptions {
                    relay_endpoint: "quic://127.0.0.1:18443".into(),
                    interrupt_after_chunks: None,
                    relay_quic_peer_addr: Some("127.0.0.1:18443".into()),
                    relay_quic_server_name: Some("relay".into()),
                    relay_quic_ca_cert: Some(directory.path().join("ca.pem")),
                    relay_owner_home_node_id: Some("node".into()),
                    relay_owner_principal_id: Some("principal_spool_test".into()),
                    relay_audience_node_id: Some("node".into()),
                });
            }
            for (method, mut body) in [
                ("object.put", serde_json::json!({"object_id":OBJECT_ID,"plaintext_base64":"eA","chunk_size":1024,"relay_endpoint":null,"operation_id":null})),
                ("object.put.begin", begin_body(1, &plaintext_hash(b"x"))),
            ] {
                body.as_object_mut().ok_or("test: request")?.insert("relay_service_key_base64".into(), serde_json::json!("retired-test-key"));
                let error = dispatch(&mut state, method, body).await.err().ok_or("test: obsolete key accepted")?;
                assert!(matches!(error, SdkError::CapabilityDenied(_)), "retired key must produce typed capability refusal with profile={profile}");
                assert!(!object_put_spool_dir(directory.path()).try_exists()?, "retired key refusal must precede spool/journal writes");
            }
            let client = &state.accounts.get(ACCOUNT).ok_or("test: account")?.client;
            assert!(matches!(client.relay_transfer_options(None, Some("retired-test-key"), None), Err(SdkError::CapabilityDenied(_))), "profile shortcut must not bypass SDK option refusal");
        }
        Ok::<(), Box<dyn std::error::Error>>(())
    }).await?
}

#[tokio::test]
async fn retired_key_spool_journals_are_discarded_on_real_restore()
-> Result<(), Box<dyn std::error::Error>> {
    tokio::time::timeout(std::time::Duration::from_secs(15), async {
        for retired in [serde_json::json!("retired-test-key"), serde_json::Value::Null] {
            let directory = tempfile::TempDir::new()?;
            let mut state = make_state(directory.path());
            dispatch(&mut state, "object.put.begin", begin_body(1, &plaintext_hash(b"x"))).await?;
            let spool = object_put_spool_path(directory.path(), ACCOUNT, OPERATION);
            let journal = object_put_journal_path(directory.path(), ACCOUNT, OPERATION);
            let mut row: serde_json::Value =
                serde_json::from_slice(&read_object_put_journal(&journal)?)?;
            assert!(
                row.get("relay_service_key_base64").is_none(),
                "new journals must never serialize the retired key field"
            );
            row.as_object_mut()
                .ok_or("test: journal object")?
                .insert("relay_service_key_base64".into(), retired);
            std::fs::write(&journal, serde_json::to_vec(&row)?)?;
            let account = state.accounts.get_mut(ACCOUNT).ok_or("test: account")?;
            account.object_put_spools.clear();
            rehydrate_object_put_spools(account, directory.path(), ACCOUNT)?;
            assert!(
                account.object_put_spools.is_empty(),
                "key-bearing journal must not restore an upload session"
            );
            assert!(
                !spool.try_exists()? && !journal.try_exists()?,
                "refused obsolete journal and its uncommitted spool must be discarded"
            );
        }
        Ok::<(), Box<dyn std::error::Error>>(())
    })
    .await?
}

#[tokio::test]
async fn begin_chunk_finish_commits_compact_terminal_and_cleans_up() {
    let root = temp_data_root("happy");
    let mut state = make_state(&root);
    let plaintext = vec![0xA5_u8; 3 * 1024]; // three 1 KiB chunks
    let hash = plaintext_hash(&plaintext);
    dispatch(&mut state, "object.put.begin", begin_body(plaintext.len(), &hash))
        .await
        .expect("begin");
    assert!(spool_path(&state).exists(), "begin must create the spool file");
    let mut offset = 0;
    for chunk in plaintext.chunks(1024) {
        let response = dispatch(&mut state, "object.put.chunk", chunk_body(offset, chunk))
            .await
            .expect("chunk");
        offset += chunk.len();
        assert_eq!(response["written"], offset);
    }
    let terminal = dispatch(&mut state, "object.put.finish", finish_body()).await.expect("finish");
    // Compact terminal — NO ciphertext echo.
    assert_eq!(terminal["object_id"], OBJECT_ID);
    assert_eq!(terminal["committed"], true);
    assert_eq!(terminal["plaintext_hash"], serde_json::Value::String(hash.clone()));
    assert!(terminal.get("object").is_none(), "no object echo");
    assert!(terminal.get("chunks").is_none(), "no chunks echo");
    assert!(terminal.get("ciphertext").is_none(), "no ciphertext echo");
    // Spool file removed on success.
    assert!(!spool_path(&state).exists(), "finish must remove the spool file");
    // A2 object.put.status must report committed on the spool path.
    let status = dispatch(
        &mut state,
        "object.put.status",
        serde_json::json!({ "object_id": OBJECT_ID, "operation_id": OPERATION }),
    )
    .await
    .expect("status");
    assert_eq!(status["state"], "committed");
    assert!(status["terminal"]["committed"].as_bool().unwrap_or(false));
    std::fs::remove_dir_all(&root).ok();
}

#[tokio::test]
async fn oversize_begin_is_rejected_before_creating_a_file() {
    let root = temp_data_root("oversize");
    let mut state = make_state(&root);
    let error = dispatch(
        &mut state,
        "object.put.begin",
        begin_body(MAX_LOCAL_BUS_OBJECT_BYTES + 1, "hash"),
    )
    .await
    .expect_err("oversize begin must fail closed");
    assert!(error.to_string().contains("too large"), "{error}");
    assert!(!spool_path(&state).exists(), "no spool file on an oversize reject");
    std::fs::remove_dir_all(&root).ok();
}

#[tokio::test]
async fn offset_gap_fails_closed_and_destroys_the_spool() {
    let root = temp_data_root("gap");
    let mut state = make_state(&root);
    let plaintext = vec![0x11_u8; 2048];
    dispatch(
        &mut state,
        "object.put.begin",
        begin_body(plaintext.len(), &plaintext_hash(&plaintext)),
    )
    .await
    .expect("begin");
    // A chunk at offset 1 (a gap — expected 0) must fail closed and delete the spool.
    let error = dispatch(&mut state, "object.put.chunk", chunk_body(1, &plaintext[..1024]))
        .await
        .expect_err("gap chunk must fail");
    assert!(error.to_string().contains("gap/overlap/duplicate"), "{error}");
    assert!(!spool_path(&state).exists(), "a gap must destroy the spool (fail closed)");
    std::fs::remove_dir_all(&root).ok();
}

#[tokio::test]
async fn duplicate_offset_fails_closed() {
    let root = temp_data_root("dup");
    let mut state = make_state(&root);
    let plaintext = vec![0x22_u8; 2048];
    dispatch(
        &mut state,
        "object.put.begin",
        begin_body(plaintext.len(), &plaintext_hash(&plaintext)),
    )
    .await
    .expect("begin");
    dispatch(&mut state, "object.put.chunk", chunk_body(0, &plaintext[..1024]))
        .await
        .expect("first chunk");
    // Re-sending offset 0 (duplicate) — expected is now 1024 — must fail closed.
    let error = dispatch(&mut state, "object.put.chunk", chunk_body(0, &plaintext[..1024]))
        .await
        .expect_err("duplicate chunk must fail");
    assert!(error.to_string().contains("gap/overlap/duplicate"), "{error}");
    assert!(!spool_path(&state).exists());
    std::fs::remove_dir_all(&root).ok();
}

#[tokio::test]
async fn chunk_beyond_total_len_fails_closed() {
    let root = temp_data_root("overrun");
    let mut state = make_state(&root);
    dispatch(&mut state, "object.put.begin", begin_body(1024, &plaintext_hash(&[0x33; 1024])))
        .await
        .expect("begin");
    // 2048 bytes at offset 0 exceeds the declared total_len of 1024.
    let error = dispatch(&mut state, "object.put.chunk", chunk_body(0, &[0x33_u8; 2048]))
        .await
        .expect_err("overrun chunk must fail");
    assert!(error.to_string().contains("exceeds declared total_len"), "{error}");
    assert!(!spool_path(&state).exists());
    std::fs::remove_dir_all(&root).ok();
}

#[tokio::test]
async fn hash_mismatch_at_finish_fails_closed_and_cleans_up() {
    let root = temp_data_root("hashmismatch");
    let mut state = make_state(&root);
    let plaintext = vec![0x44_u8; 1024];
    // Bind a hash that does NOT match the streamed bytes.
    let wrong_hash = plaintext_hash(&[0x99_u8; 1024]);
    dispatch(&mut state, "object.put.begin", begin_body(plaintext.len(), &wrong_hash))
        .await
        .expect("begin");
    dispatch(&mut state, "object.put.chunk", chunk_body(0, &plaintext)).await.expect("chunk");
    let error = dispatch(&mut state, "object.put.finish", finish_body())
        .await
        .expect_err("finish must fail");
    assert!(error.to_string().contains("hash mismatch"), "{error}");
    // Spool removed even on a failed finish.
    assert!(!spool_path(&state).exists(), "failed finish must still remove the spool file");
    // Nothing was committed — status is unknown (no durable object operation).
    let status = dispatch(
        &mut state,
        "object.put.status",
        serde_json::json!({ "object_id": OBJECT_ID, "operation_id": OPERATION }),
    )
    .await
    .expect("status");
    assert_eq!(status["state"], "unknown");
    std::fs::remove_dir_all(&root).ok();
}

#[tokio::test]
async fn oversize_chunk_payload_fails_closed() {
    let root = temp_data_root("bigchunk");
    let mut state = make_state(&root);
    let total = MAX_LOCAL_BUS_CHUNK_PAYLOAD_BYTES + 4096;
    dispatch(&mut state, "object.put.begin", begin_body(total, &plaintext_hash(&vec![0; total])))
        .await
        .expect("begin");
    // A single chunk larger than the payload bound must fail closed (rf clamps; daemon defends).
    let oversized = vec![0x55_u8; MAX_LOCAL_BUS_CHUNK_PAYLOAD_BYTES + 1];
    let error = dispatch(&mut state, "object.put.chunk", chunk_body(0, &oversized))
        .await
        .expect_err("oversize chunk must fail");
    assert!(error.to_string().contains("exceeds the"), "{error}");
    assert!(!spool_path(&state).exists());
    std::fs::remove_dir_all(&root).ok();
}

// ---- T25-A5 (OBJ-IPC-01): durable upload journal crash-resume rehydration ----

#[tokio::test]
async fn rehydrate_resumes_a_chunk_phase_spool_after_restart() {
    let root = temp_data_root("rehydrate_resume");
    let mut state = make_state(&root);
    let plaintext = vec![0xB3_u8; 4096];
    let hash = plaintext_hash(&plaintext);
    dispatch(&mut state, "object.put.begin", begin_body(plaintext.len(), &hash))
        .await
        .expect("begin");
    // Stream only the first half, then simulate an rfd crash mid-upload.
    dispatch(&mut state, "object.put.chunk", chunk_body(0, &plaintext[..2048]))
        .await
        .expect("chunk 0");
    // "Crash": drop the in-memory session but keep the durable spool + journal on disk.
    state.accounts.get_mut(ACCOUNT).expect("account").object_put_spools.clear();
    // Restart: rehydrate from the durable journal; the resume offset is journal.written.
    {
        let data_root = state.config.data_root.clone();
        let account = state.accounts.get_mut(ACCOUNT).expect("account");
        rehydrate_object_put_spools(account, &data_root, ACCOUNT).expect("rehydrate");
        let session = account.object_put_spools.get(OPERATION).expect("rehydrated session");
        assert_eq!(session.written, 2048, "resume offset = durable journal.written");
    }
    // Resume the remaining half from the durable offset, then finish -> commits byte-identical.
    dispatch(&mut state, "object.put.chunk", chunk_body(2048, &plaintext[2048..]))
        .await
        .expect("resume chunk");
    let terminal = dispatch(&mut state, "object.put.finish", finish_body()).await.expect("finish");
    assert_eq!(terminal["committed"], true, "resumed upload commits: {terminal}");
    assert_eq!(terminal["plaintext_hash"], serde_json::Value::String(hash));
    assert!(!spool_path(&state).exists(), "finish removes the spool");
    std::fs::remove_dir_all(&root).ok();
}

#[tokio::test]
async fn rehydrate_fails_closed_on_prefix_hash_mismatch() {
    use std::io::{Seek as _, SeekFrom, Write as _};
    let root = temp_data_root("rehydrate_mismatch");
    let mut state = make_state(&root);
    let plaintext = vec![0xC4_u8; 4096];
    let hash = plaintext_hash(&plaintext);
    dispatch(&mut state, "object.put.begin", begin_body(plaintext.len(), &hash))
        .await
        .expect("begin");
    dispatch(&mut state, "object.put.chunk", chunk_body(0, &plaintext[..2048]))
        .await
        .expect("chunk 0");
    let spool = spool_path(&state);
    let journal = object_put_journal_path(&state.config.data_root, ACCOUNT, OPERATION);
    state.accounts.get_mut(ACCOUNT).expect("account").object_put_spools.clear();
    // Tamper the durable spool prefix so BLAKE3(spool[0..written]) != journal.prefix_hash.
    {
        let mut file = std::fs::OpenOptions::new().write(true).open(&spool).expect("open spool");
        file.seek(SeekFrom::Start(0)).expect("seek");
        file.write_all(&[0x00_u8; 16]).expect("tamper");
        file.sync_all().expect("sync");
    }
    {
        let data_root = state.config.data_root.clone();
        let account = state.accounts.get_mut(ACCOUNT).expect("account");
        rehydrate_object_put_spools(account, &data_root, ACCOUNT).expect("rehydrate");
        assert!(account.object_put_spools.is_empty(), "a tampered prefix must not resume");
    }
    assert!(!spool.exists(), "fail-closed deletes the tampered spool");
    assert!(!journal.exists(), "fail-closed deletes the journal");
    std::fs::remove_dir_all(&root).ok();
}

// ---- T25-A4 (CTRL-104 / OBJ-IPC-01): bounded DOWNLOAD spool (begin/read/finish) ----

const GET_OPERATION: &str = "op-get-1";
const GET_OBJECT_ID: &str = "object_get_1";

fn get_spool_path(state: &LocalBusDaemonState) -> PathBuf {
    object_get_spool_path(&state.config.data_root, ACCOUNT, GET_OPERATION)
}

fn get_begin_body(object_id: &str) -> serde_json::Value {
    serde_json::to_value(LocalBusObjectGetBeginRequest {
        object_id: object_id.to_owned(),
        operation_id: GET_OPERATION.to_owned(),
        protocol_version: OBJECT_PUT_PROTOCOL_VERSION,
        relay_endpoint: None,
        relay_service_key_base64: None,
        relay_ack: false,
        relay_interrupt_after_chunks: None,
    })
    .expect("get begin body")
}

fn get_read_body(offset: usize, len: usize) -> serde_json::Value {
    serde_json::to_value(LocalBusObjectGetReadRequest {
        operation_id: GET_OPERATION.to_owned(),
        offset,
        len,
    })
    .expect("get read body")
}

/// Commits a local object (no relay) so a subsequent GET can decrypt it.
async fn put_local_object(state: &mut LocalBusDaemonState, object_id: &str, plaintext: &[u8]) {
    dispatch(
        state,
        "object.put",
        serde_json::json!({
            "object_id": object_id,
            "plaintext_base64": ramflux_protocol::encode_base64url(plaintext),
            "chunk_size": 65_536,
        }),
    )
    .await
    .expect("put local object");
}

// Mutation: omit the exact-payload resource registration from object_get_begin.
#[tokio::test]
async fn attachment_last_owner_deletion_closes_download_spool_and_refuses_later_reads()
-> Result<(), SdkError> {
    let root = temp_data_root("get_attachment_erasure");
    let mut state = make_state(&root);
    let mut donor = ramflux_sync::ObjectStore::new();
    let object = donor.put_encrypted_object(GET_OBJECT_ID, b"private attachment spool")?;
    let key = donor.object_key(GET_OBJECT_ID)?;
    let account = state
        .accounts
        .get(ACCOUNT)
        .ok_or_else(|| SdkError::LocalBus("fixture account or session missing".into()))?;
    let db = account.client.account_db()?;
    db.send_direct_message("thread", "message", "peer", b"body")?;
    db.register_object_reference(
        ramflux_storage::ObjectReferenceAdmission::FreshMessage,
        &ramflux_storage::ObjectReferenceOwner {
            reference_hash: "spool-reference",
            wire_id: GET_OBJECT_ID,
            manifest_hash: &object.manifest_hash,
            selector: GET_OBJECT_ID,
            message_id: "message",
            reference: &serde_json::json!({}),
            metadata: &serde_json::json!({}),
        },
    )?;
    db.upsert_object(&ramflux_storage::ObjectWrite {
        object_id: GET_OBJECT_ID,
        manifest_hash: &object.manifest_hash,
        nonce: &object.nonce,
        ciphertext: &object.ciphertext,
        plaintext_hash: &object.plaintext_hash,
        tombstoned: false,
        backup_excluded: false,
        content_key: Some(&key),
        object: &object,
        updated_at: 1,
    })?;
    dispatch(&mut state, "object.get.begin", get_begin_body(GET_OBJECT_ID)).await?;
    let path = get_spool_path(&state);
    assert!(path.is_file());
    let account = state
        .accounts
        .get(ACCOUNT)
        .ok_or_else(|| SdkError::LocalBus("fixture account or session missing".into()))?;
    let file = std::sync::Arc::clone(
        &account
            .object_get_spools
            .get(GET_OPERATION)
            .ok_or_else(|| SdkError::LocalBus("fixture account or session missing".into()))?
            .file,
    );
    account.client.delete_direct_message(
        "thread",
        "message",
        "local",
        &ramflux_protocol::encode_base64url([9; 32]),
    )?;
    assert!(!path.exists());
    assert!(file.lock().map_err(|_| SdkError::ObjectErased)?.is_none());
    assert!(matches!(
        dispatch(&mut state, "object.get.read", get_read_body(0, 1)).await,
        Err(SdkError::ObjectErased)
    ));
    drop(state);
    Ok(())
}

#[tokio::test]
async fn get_begin_read_finish_streams_bounded_and_cleans_up() {
    let root = temp_data_root("get_happy");
    let mut state = make_state(&root);
    // 3 * 512 KiB + a partial tail: forces multiple bounded reads and a final short read.
    let plaintext = vec![0xC7_u8; 3 * MAX_LOCAL_BUS_CHUNK_PAYLOAD_BYTES + 4096];
    let hash = plaintext_hash(&plaintext);
    put_local_object(&mut state, GET_OBJECT_ID, &plaintext).await;

    let begin = dispatch(&mut state, "object.get.begin", get_begin_body(GET_OBJECT_ID))
        .await
        .expect("get begin");
    // Compact begin response — NO plaintext echo.
    assert_eq!(begin["operation_id"], GET_OPERATION);
    assert_eq!(begin["object_id"], GET_OBJECT_ID);
    assert_eq!(begin["total_len"], plaintext.len());
    assert_eq!(begin["plaintext_hash"], serde_json::Value::String(hash.clone()));
    assert!(begin.get("plaintext_base64").is_none(), "begin must not echo plaintext");
    assert!(begin.get("data_base64").is_none(), "begin must not echo data");
    assert!(get_spool_path(&state).exists(), "begin must create the spool file");

    // Stream bounded reads until eof; reassemble and compare.
    let mut reassembled = Vec::new();
    let mut offset = 0;
    loop {
        let len = (plaintext.len() - offset).min(MAX_LOCAL_BUS_CHUNK_PAYLOAD_BYTES);
        let read = dispatch(&mut state, "object.get.read", get_read_body(offset, len))
            .await
            .expect("get read");
        assert_eq!(read["offset"], offset);
        assert_eq!(read["len"], len);
        let data =
            ramflux_protocol::decode_base64url(read["data_base64"].as_str().expect("data_base64"))
                .expect("decode");
        assert_eq!(data.len(), len);
        reassembled.extend_from_slice(&data);
        offset += len;
        if read["eof"].as_bool().unwrap_or(false) {
            assert_eq!(offset, plaintext.len(), "eof only at total_len");
            break;
        }
    }
    assert_eq!(reassembled, plaintext, "streamed plaintext must match byte-for-byte");
    assert_eq!(plaintext_hash(&reassembled), hash, "streamed hash must match begin");

    // Status reports complete before finish.
    let status = dispatch(
        &mut state,
        "object.get.status",
        serde_json::json!({ "operation_id": GET_OPERATION }),
    )
    .await
    .expect("status");
    assert_eq!(status["state"], "complete");
    assert_eq!(status["read_offset"], plaintext.len());

    // Finish removes the spool.
    let finish = dispatch(
        &mut state,
        "object.get.finish",
        serde_json::json!({ "operation_id": GET_OPERATION }),
    )
    .await
    .expect("finish");
    assert_eq!(finish["removed"], true);
    assert!(!get_spool_path(&state).exists(), "finish must remove the spool file");
    // Status after finish is unknown.
    let status = dispatch(
        &mut state,
        "object.get.status",
        serde_json::json!({ "operation_id": GET_OPERATION }),
    )
    .await
    .expect("status");
    assert_eq!(status["state"], "unknown");
    std::fs::remove_dir_all(&root).ok();
}

#[tokio::test]
async fn get_read_frame_stays_below_cap_for_a_maximal_read() {
    let root = temp_data_root("get_framecap");
    let mut state = make_state(&root);
    let plaintext = vec![0x5A_u8; MAX_LOCAL_BUS_CHUNK_PAYLOAD_BYTES];
    put_local_object(&mut state, GET_OBJECT_ID, &plaintext).await;
    dispatch(&mut state, "object.get.begin", get_begin_body(GET_OBJECT_ID)).await.expect("begin");
    // A maximal read (512 KiB raw). Serialize the full response frame and prove it is < 1 MiB.
    let read = dispatch(
        &mut state,
        "object.get.read",
        get_read_body(0, MAX_LOCAL_BUS_CHUNK_PAYLOAD_BYTES),
    )
    .await
    .expect("read");
    let frame = crate::bus::protocol::LocalBusFrame::request(
        "req",
        Some(ACCOUNT.to_owned()),
        "object",
        "object.get.read",
        read,
    );
    let bytes = ramflux_protocol::canonical_json_bytes(&frame).expect("frame bytes");
    assert!(
        bytes.len() < crate::bus::io::MAX_LOCAL_BUS_FRAME_BYTES,
        "a maximal object.get.read frame {} must stay below the 1 MiB cap",
        bytes.len()
    );
    std::fs::remove_dir_all(&root).ok();
}

#[tokio::test]
async fn get_read_gap_overlap_and_out_of_range_fail_closed() {
    let root = temp_data_root("get_faults");
    let mut state = make_state(&root);
    let plaintext = vec![0x33_u8; 4096];
    put_local_object(&mut state, GET_OBJECT_ID, &plaintext).await;
    dispatch(&mut state, "object.get.begin", get_begin_body(GET_OBJECT_ID)).await.expect("begin");
    // Forward gap: offset 1 with nothing served yet (expected 0).
    let gap = dispatch(&mut state, "object.get.read", get_read_body(1, 1024))
        .await
        .expect_err("gap must fail");
    assert!(gap.to_string().contains("gap/overlap/duplicate"), "{gap}");
    // Serve the first slice, then re-read offset 0 (overlap/duplicate) — expected is now 1024.
    dispatch(&mut state, "object.get.read", get_read_body(0, 1024)).await.expect("first read");
    let dup = dispatch(&mut state, "object.get.read", get_read_body(0, 1024))
        .await
        .expect_err("duplicate must fail");
    assert!(dup.to_string().contains("gap/overlap/duplicate"), "{dup}");
    // Out of range: from the current frontier (1024), a read that runs past total_len.
    let oor = dispatch(&mut state, "object.get.read", get_read_body(1024, 4096))
        .await
        .expect_err("out of range must fail");
    assert!(oor.to_string().contains("exceeds total_len"), "{oor}");
    // The session survives fail-closed reads (they do not corrupt the spool).
    assert!(get_spool_path(&state).exists());
    std::fs::remove_dir_all(&root).ok();
}

#[tokio::test]
async fn get_read_oversize_len_fails_closed() {
    let root = temp_data_root("get_biglen");
    let mut state = make_state(&root);
    let plaintext = vec![0x44_u8; MAX_LOCAL_BUS_CHUNK_PAYLOAD_BYTES + 8192];
    put_local_object(&mut state, GET_OBJECT_ID, &plaintext).await;
    dispatch(&mut state, "object.get.begin", get_begin_body(GET_OBJECT_ID)).await.expect("begin");
    let error = dispatch(
        &mut state,
        "object.get.read",
        get_read_body(0, MAX_LOCAL_BUS_CHUNK_PAYLOAD_BYTES + 1),
    )
    .await
    .expect_err("oversize len must fail");
    assert!(error.to_string().contains("exceeds the"), "{error}");
    std::fs::remove_dir_all(&root).ok();
}

#[tokio::test]
async fn get_begin_of_unknown_object_fails_and_leaves_no_spool() {
    let root = temp_data_root("get_missing");
    let mut state = make_state(&root);
    let error = dispatch(&mut state, "object.get.begin", get_begin_body("object_does_not_exist"))
        .await
        .expect_err("begin of a missing object must fail");
    assert!(!error.to_string().is_empty(), "{error}");
    assert!(!get_spool_path(&state).exists(), "a failed begin must leave no spool file");
    std::fs::remove_dir_all(&root).ok();
}

#[tokio::test]
async fn get_begin_reentry_restarts_from_a_clean_spool() {
    let root = temp_data_root("get_reentry");
    let mut state = make_state(&root);
    let plaintext = vec![0x77_u8; 2048];
    put_local_object(&mut state, GET_OBJECT_ID, &plaintext).await;
    dispatch(&mut state, "object.get.begin", get_begin_body(GET_OBJECT_ID)).await.expect("begin");
    // Advance the read frontier, then re-begin (a restart) — the session must reset to offset 0.
    dispatch(&mut state, "object.get.read", get_read_body(0, 1024)).await.expect("read");
    dispatch(&mut state, "object.get.begin", get_begin_body(GET_OBJECT_ID))
        .await
        .expect("re-begin");
    let status = dispatch(
        &mut state,
        "object.get.status",
        serde_json::json!({ "operation_id": GET_OPERATION }),
    )
    .await
    .expect("status");
    assert_eq!(status["read_offset"], 0, "re-begin resets the read frontier");
    assert_eq!(status["state"], "reading");
    std::fs::remove_dir_all(&root).ok();
}

#[tokio::test]
async fn small_one_shot_get_still_returns_plaintext() {
    let root = temp_data_root("get_oneshot");
    let mut state = make_state(&root);
    let plaintext = vec![0x9E_u8; 4096];
    put_local_object(&mut state, GET_OBJECT_ID, &plaintext).await;
    let response =
        dispatch(&mut state, "object.get", serde_json::json!({ "object_id": GET_OBJECT_ID }))
            .await
            .expect("one-shot get");
    let decoded = ramflux_protocol::decode_base64url(
        response["plaintext_base64"].as_str().expect("plaintext_base64"),
    )
    .expect("decode");
    assert_eq!(decoded, plaintext, "one-shot get must round-trip the small object");
    std::fs::remove_dir_all(&root).ok();
}

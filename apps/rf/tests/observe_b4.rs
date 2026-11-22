// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

#![cfg(unix)]

//! Thumbnail metadata and last-owner erasure through one real `rf` daemon.
//! The media fixture is the canonical r4 reference a real send stores; `message.read`
//! on that daemon is what `object thumbnail` parses.

use ramflux_protocol::message as g;
use ramflux_sdk::RamfluxClient;
use ramflux_storage::{
    AccountDb, AccountIndex, FileVaultSecretSource, VaultSecretSource, unwrap_with_vault_secret,
};
use ramflux_sync::{EncryptedObject, ObjectStore};
use std::fs::File;
use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

const CHILD_OUTPUT_CAP: usize = 65_536;
const DAEMON_LOG_CAP: usize = 65_536;
const ACCOUNT: &str = "acct";
const PRINCIPAL: &str = "principal_spool_test";
const DEVICE: &str = "device_spool_test";
const TARGET: &str = "target_spool_test";
const PASSPHRASE: &str = "spool-test-secret";
const CONVERSATION: &str = "thread";

type TestError = Box<dyn std::error::Error>;

fn pause() {
    std::thread::sleep(Duration::from_millis(10));
}

struct Process(Child);

impl Drop for Process {
    fn drop(&mut self) {
        if self.0.try_wait().ok().flatten().is_none() {
            let _ = self.0.kill();
        }
        let _ = self.0.wait();
    }
}

fn wait_exit(child: &mut Child, budget: Duration) -> std::io::Result<ExitStatus> {
    let deadline = Instant::now() + budget;
    loop {
        if let Some(status) = child.try_wait()? {
            return Ok(status);
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "rf child exceeded its kill deadline",
            ));
        }
        pause();
    }
}

struct Captured {
    status: ExitStatus,
    stdout: String,
    stderr: String,
}

fn run_rf(
    socket: &Path,
    args: &[&str],
    stdout: &Path,
    stderr: &Path,
) -> Result<Captured, TestError> {
    let mut child = Process(
        Command::new(env!("CARGO_BIN_EXE_rf"))
            .arg("--socket")
            .arg(socket)
            .args(args)
            .env("OBSERVE_B4_PASSPHRASE", PASSPHRASE)
            .stdout(File::create(stdout)?)
            .stderr(File::create(stderr)?)
            .spawn()?,
    );
    let status = wait_exit(&mut child.0, Duration::from_secs(30))?;
    Ok(Captured {
        status,
        stdout: read_bounded(stdout, CHILD_OUTPUT_CAP, "child stdout")?,
        stderr: read_bounded(stderr, CHILD_OUTPUT_CAP, "child stderr")?,
    })
}

fn read_bounded(path: &Path, cap: usize, label: &str) -> Result<String, TestError> {
    let mut file = File::open(path)?;
    let mut buf = vec![0_u8; cap.saturating_add(1)];
    let mut filled = 0_usize;
    while filled < buf.len() {
        match file.read(&mut buf[filled..])? {
            0 => break,
            read => filled = filled.saturating_add(read),
        }
    }
    if filled > cap {
        return Err(format!("{label} exceeded {cap} bytes").into());
    }
    String::from_utf8(buf[..filled].to_vec()).map_err(|_| format!("{label} is not utf-8").into())
}

fn require_success(captured: &Captured, label: &str) -> Result<(), TestError> {
    if captured.status.success() {
        Ok(())
    } else {
        Err(format!("{label} failed: stdout={} stderr={}", captured.stdout, captured.stderr).into())
    }
}

fn parse_json(captured: &Captured, label: &str) -> Result<serde_json::Value, TestError> {
    serde_json::from_str(&captured.stdout).map_err(|error| {
        format!("{label} json: {error}; stdout={} stderr={}", captured.stdout, captured.stderr)
            .into()
    })
}

fn load_media() -> Result<g::MediaRef, TestError> {
    let path =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/demo-b-b4-media.json");
    let bytes = std::fs::read(&path)?;
    Ok(ramflux_protocol::parse_i_json(&bytes)?)
}

fn store_object(
    db: &AccountDb,
    object_id: &str,
    plaintext: &[u8],
) -> Result<EncryptedObject, TestError> {
    let mut donor = ObjectStore::new();
    let object = donor.put_encrypted_object(object_id, plaintext)?;
    let key = donor.object_key(object_id)?;
    db.upsert_object(&ramflux_storage::ObjectWrite {
        object_id,
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
    Ok(object)
}

fn project_message(
    db: &AccountDb,
    author: &g::QualifiedDevice,
    sequence: u64,
    content: &g::Content,
) -> Result<String, TestError> {
    let id = g::identity::derive(author, CONVERSATION, sequence)?;
    let identity = g::EventIdentity {
        id: id.to_vec(),
        conversation_id: CONVERSATION.into(),
        author: Some(author.clone()),
        device_sequence: sequence,
        hlc: 1,
        group_id: None,
        group_epoch: None,
    };
    let message_id = ramflux_protocol::encode_base64url(id);
    let exact = RamfluxClient::encode_generated_inner(identity.clone(), content)?;
    db.send_direct_message(CONVERSATION, &message_id, &author.device_id, b"body")?;
    db.store_message_content(CONVERSATION, &message_id, &exact)?;
    db.persist_message_actor_state(
        &message_id,
        &format!("routed/generated-identity/{message_id}"),
        &identity,
    )?;
    Ok(message_id)
}

fn own(
    db: &AccountDb,
    object: &EncryptedObject,
    message_id: &str,
    reference_hash: &str,
) -> Result<(), TestError> {
    let reference = serde_json::json!({});
    let metadata = serde_json::json!({});
    db.register_object_reference(
        ramflux_storage::ObjectReferenceAdmission::FreshMessage,
        &ramflux_storage::ObjectReferenceOwner {
            reference_hash,
            wire_id: &object.object_id,
            manifest_hash: &object.manifest_hash,
            selector: &object.object_id,
            message_id,
            reference: &reference,
            metadata: &metadata,
        },
    )?;
    Ok(())
}

fn write_manifest(data: &Path, commitment: &str) -> Result<(), TestError> {
    let root_seed = vec![0x51_u8; 32];
    let device_seed = vec![0x52_u8; 32];
    let manifest = serde_json::json!({
        "schema": "ramflux.local_bus.account_manifest.v1",
        "local_account_id": ACCOUNT,
        "principal_id": PRINCIPAL,
        "principal_commitment": commitment,
        "device_id": DEVICE,
        "target_delivery_id": TARGET,
        "account_secret": PASSPHRASE,
        "root_seed": root_seed,
        "device_seed": device_seed,
        "client_mode": "attended_cli",
        "gateway": {
            "bind_addr": "127.0.0.1:0",
            "gateway_addr": "127.0.0.1:1",
            "server_name": "ramflux-gateway",
            "ca_cert": data.join("unused-ca.pem"),
            "principal_id": PRINCIPAL,
            "device_id": DEVICE,
            "target_delivery_id": TARGET,
            "prekey_http_url": null
        }
    });
    let dir = data.join("local_bus_accounts");
    std::fs::create_dir_all(&dir)?;
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))?;
    let path = dir.join(format!("{ACCOUNT}.json"));
    let mut file = File::create(&path)?;
    file.write_all(&serde_json::to_vec_pretty(&manifest)?)?;
    file.sync_all()?;
    drop(file);
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    Ok(())
}

fn seed(data: &Path) -> Result<(String, String, String), TestError> {
    let mut client = RamfluxClient::new();
    let root = client.create_identity_root(PRINCIPAL, [0x51; 32]);
    let commitment = ramflux_crypto::identity_root_commitment(&root.signing_key.verifying_key());
    let branch = client.create_device_branch(PRINCIPAL, DEVICE, 1, [0x52; 32]);
    let device_epoch = branch.device_epoch;
    client.open_account_index(data)?;
    client.create_account(ACCOUNT, &commitment)?;
    client.set_active_account(ACCOUNT)?;
    client.unlock_account(ACCOUNT, PASSPHRASE.as_bytes())?;
    drop(client);

    let index = AccountIndex::open(data)?;
    let wrapped = index.load_wrapped_db_key(ACCOUNT)?.ok_or("wrapped db key row missing")?;
    let vault = FileVaultSecretSource::new(data).vault_secret(ACCOUNT)?;
    let kek = ramflux_sdk::account_db_key_encryption_key(&vault, PASSPHRASE.as_bytes())?;
    let key = unwrap_with_vault_secret(&kek, &wrapped)?;
    let db = AccountDb::open(&index, ACCOUNT, &key)?;
    let author = g::QualifiedDevice {
        account_anchor: commitment.clone(),
        device_id: DEVICE.into(),
        device_epoch,
    };
    let media = load_media()?;
    let object_id = media.object_id.clone();
    if object_id.is_empty() {
        return Err("fixture object id is empty".into());
    }
    let stored = store_object(&db, &object_id, b"sole-bytes")?;
    let attachment = RamfluxClient::attachment_message_content("caption", &[media])?;
    let sole = project_message(&db, &author, 1, &attachment)?;
    own(&db, &stored, &sole, "sole-ref")?;

    let shared = store_object(&db, "obj-shared", b"shared-bytes")?;
    let plain = RamfluxClient::attachment_message_content("plain", &[])?;
    let shared_a = project_message(&db, &author, 2, &plain)?;
    let shared_b = project_message(&db, &author, 3, &plain)?;
    own(&db, &shared, &shared_a, "shared-a")?;
    own(&db, &shared, &shared_b, "shared-b")?;
    let text = project_message(&db, &author, 4, &plain)?;
    drop(db);
    drop(index);
    write_manifest(data, &commitment)?;
    Ok((sole, shared_a, text))
}

struct Live {
    root: tempfile::TempDir,
    socket: PathBuf,
    sole: String,
    shared: String,
    text: String,
    daemon: Process,
}

fn bring_up() -> Result<Live, TestError> {
    // A pathname socket must be shorter than SUN_LEN. The canonical user temp
    // directory plus this fixture name exceeds that on macOS.
    let root = tempfile::Builder::new().prefix("rf-ob4-").tempdir_in("/tmp")?;
    let data = root.path().join("data");
    std::fs::create_dir_all(&data)?;
    let (sole, shared, text) = seed(&data)?;
    let socket = root.path().join("rfd.sock");
    let log = root.path().join("daemon.err");
    let mut daemon = Process(
        Command::new(env!("CARGO_BIN_EXE_rf"))
            .arg("--socket")
            .arg(&socket)
            .args(["daemon", "start", "--data-root"])
            .arg(&data)
            .stdout(Stdio::null())
            .stderr(Stdio::from(File::create(&log)?))
            .spawn()?,
    );
    wait_socket(&mut daemon, &socket, &log)?;
    let unlocked = run_rf(
        &socket,
        &["account", "unlock", "--account", ACCOUNT, "--passphrase-env", "OBSERVE_B4_PASSPHRASE"],
        &root.path().join("unlock.out"),
        &root.path().join("unlock.err"),
    )?;
    require_success(&unlocked, "unlock")?;
    Ok(Live { root, socket, sole, shared, text, daemon })
}

fn wait_socket(daemon: &mut Process, socket: &Path, log: &Path) -> Result<(), TestError> {
    let ready = Instant::now() + Duration::from_secs(30);
    while !socket.exists() {
        if daemon.0.try_wait()?.is_some() {
            let detail = read_bounded(log, DAEMON_LOG_CAP, "daemon log")?;
            return Err(format!("daemon exited before bind: {detail}").into());
        }
        if Instant::now() >= ready {
            return Err("daemon did not bind its socket".into());
        }
        pause();
    }
    Ok(())
}

fn check_sole_thumbnail(live: &Live) -> Result<(), TestError> {
    let thumb = run_rf(
        &live.socket,
        &[
            "object",
            "thumbnail",
            "--account",
            ACCOUNT,
            "--conversation",
            CONVERSATION,
            "--message",
            &live.sole,
        ],
        &live.root.path().join("thumb.out"),
        &live.root.path().join("thumb.err"),
    )?;
    require_success(&thumb, "thumbnail")?;
    if thumb.stdout.contains("encodedImage") {
        return Err(format!("image bytes on stdout: {}", thumb.stdout).into());
    }
    if thumb.stdout.contains("thumb-bytes") {
        return Err(format!("raw thumbnail on stdout: {}", thumb.stdout).into());
    }
    let receipt = parse_json(&thumb, "thumbnail")?;
    let item = receipt
        .get("thumbnails")
        .and_then(|value| value.get(0))
        .ok_or_else(|| format!("thumbnail list missing: {receipt}"))?;
    if item.get("mime").and_then(serde_json::Value::as_str) != Some("image/jpeg") {
        return Err(format!("thumbnail mime: {receipt}").into());
    }
    let expected = u64::try_from(b"thumb-bytes".len()).unwrap_or(0);
    let size = item.get("size").ok_or_else(|| format!("thumbnail size missing: {receipt}"))?;
    if !size.is_number() || size.as_u64() != Some(expected) {
        return Err(format!("decoded thumbnail size: {receipt}").into());
    }
    Ok(())
}

fn check_text_thumbnail_count(live: &Live) -> Result<(), TestError> {
    let out = live.root.path().join("text-thumb.bin");
    let out_arg = out.to_str().ok_or("thumbnail --out path is not utf-8")?;
    let refused = run_rf(
        &live.socket,
        &[
            "object",
            "thumbnail",
            "--account",
            ACCOUNT,
            "--conversation",
            CONVERSATION,
            "--message",
            &live.text,
            "--out",
            out_arg,
        ],
        &live.root.path().join("count.out"),
        &live.root.path().join("count.err"),
    )?;
    if refused.status.code() != Some(1) {
        return Err(format!("text thumbnail exit: {}", refused.stderr).into());
    }
    if !refused.stderr.contains("ThumbnailCount") {
        return Err(format!("typed count refusal: {}", refused.stderr).into());
    }
    if out.exists() {
        return Err("thumbnail --out must not create a file for a text message".into());
    }
    Ok(())
}

fn delete_local(live: &Live, message: &str, label: &str) -> Result<serde_json::Value, TestError> {
    let captured = run_rf(
        &live.socket,
        &[
            "dm",
            "delete",
            "--account",
            ACCOUNT,
            "--conversation",
            CONVERSATION,
            "--message",
            message,
            "--scope",
            "local",
        ],
        &live.root.path().join(format!("{label}.out")),
        &live.root.path().join(format!("{label}.err")),
    )?;
    require_success(&captured, label)?;
    parse_json(&captured, label)
}

fn check_shared_owner_stays(live: &Live) -> Result<(), TestError> {
    let body = delete_local(live, &live.shared, "shared")?;
    if body.get("object_erased") != Some(&serde_json::Value::Bool(false)) {
        return Err(format!("shared owner stays: {body}").into());
    }
    if body.get("bytes_erased") != Some(&serde_json::json!(0)) {
        return Err(format!("shared bytes stay: {body}").into());
    }
    Ok(())
}

fn check_sole_owner_erased(live: &Live) -> Result<(), TestError> {
    let body = delete_local(live, &live.sole, "erase")?;
    if body.get("object_erased") != Some(&serde_json::Value::Bool(true)) {
        return Err(format!("sole owner erased: {body}").into());
    }
    let bytes = body.get("bytes_erased").and_then(serde_json::Value::as_u64).unwrap_or(0);
    if bytes == 0 {
        return Err(format!("sole owner bytes erased: {body}").into());
    }
    Ok(())
}

#[test]
fn daemon_thumbnail_and_last_owner_erasure_use_real_rf() -> Result<(), TestError> {
    let mut live = bring_up()?;
    check_sole_thumbnail(&live)?;
    check_text_thumbnail_count(&live)?;
    check_shared_owner_stays(&live)?;
    check_sole_owner_erased(&live)?;
    if live.daemon.0.try_wait()?.is_some() {
        return Err("daemon exited during the checks".into());
    }
    Ok(())
}

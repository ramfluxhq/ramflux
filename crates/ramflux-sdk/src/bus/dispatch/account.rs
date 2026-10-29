// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

#![allow(clippy::missing_errors_doc)]
#![allow(clippy::wildcard_imports)]
use crate::prelude::*;
use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use zeroize::{Zeroize, Zeroizing};

const ACCOUNT_BACKUP_SCHEMA: &str = "ramflux.local_bus.account_backup.v1";
const ACCOUNT_BACKUP_VERSION: u32 = 1;
const ACCOUNT_BACKUP_ARGON2_MEMORY_KIB: u32 = 256 * 1024;
const ACCOUNT_BACKUP_ARGON2_TIME_COST: u32 = 3;
const ACCOUNT_BACKUP_ARGON2_PARALLELISM: u32 = 1;

pub(crate) async fn dispatch_account_bus_request(
    request: &LocalBusFrame,
    state: &mut LocalBusDaemonState,
) -> Result<LocalBusDispatchResult, SdkError> {
    match request.method.as_str() {
        #[cfg(feature = "itest-legacy-accounts")]
        "account.itest_legacy.create" if state.config.itest_legacy_accounts => {
            let body = serde_json::from_value(request.body.clone())?;
            let response = super::itest_legacy::local_bus_account_create(state, body).await?;
            Ok(local_bus_ok(serde_json::to_value(response)?))
        }
        // Creation is owned by the exclusive secret ceremony on the connection.
        "account.create" => Err(SdkError::CustodySetupInvalid),
        "account.list" => Ok(local_bus_ok(serde_json::json!({
            "active_account_id": state.active_account_id,
            "accounts": state.accounts.keys().cloned().collect::<Vec<_>>(),
        }))),
        "account.switch" => {
            let account_id = request_account_id(request)?.to_owned();
            if !state.accounts.contains_key(&account_id) {
                return Err(SdkError::AccountNotOpen(account_id));
            }
            state.active_account_id = Some(account_id.clone());
            Ok(local_bus_ok(serde_json::json!({ "active_account_id": account_id })))
        }
        "account.status" => account_status(state, request),
        "account.lock" => {
            let account_id = request_account_id(request)?.to_owned();
            local_bus_account_lock(state, &account_id)?;
            Ok(local_bus_ok(serde_json::json!({
                "local_account_id": account_id,
                "locked": true,
            })))
        }
        "account.unlock" => {
            let account_id = request_account_id(request)?.to_owned();
            if crate::custody::account_exists(&state.config.data_root, &account_id)? {
                let result =
                    super::super::native_account::unlock_request(state, &account_id, request)
                        .await?;
                return Ok(local_bus_ok(serde_json::to_value(result)?));
            }

            let mut body: LocalBusAccountUnlockRequest =
                serde_json::from_value(request.body.clone())?;
            let response = local_bus_account_unlock(state, &account_id, &mut body).await?;
            Ok(local_bus_ok(serde_json::to_value(response)?))
        }
        "account.backup.export" => {
            let account_id = request_account_id(request)?.to_owned();
            let mut body: LocalBusAccountBackupExportRequest =
                serde_json::from_value(request.body.clone())?;
            local_bus_account_backup_export(state, &account_id, &mut body)?;
            Ok(local_bus_ok(serde_json::json!({
                "local_account_id": account_id,
                "output_path": body.output_path,
                "encrypted": true,
            })))
        }
        "account.backup.import" => {
            let mut body: LocalBusAccountBackupImportRequest =
                serde_json::from_value(request.body.clone())?;
            let response =
                local_bus_account_backup_import(state, &mut body, request.account_id.as_deref())
                    .await?;
            Ok(local_bus_ok(serde_json::to_value(response)?))
        }
        "account.passphrase.rotate" => {
            let account_id = request_account_id(request)?.to_owned();
            let mut body: LocalBusAccountPassphraseRotateRequest =
                serde_json::from_value(request.body.clone())?;
            local_bus_account_passphrase_rotate(state, &account_id, &mut body)?;
            Ok(local_bus_ok(serde_json::json!({
                "local_account_id": account_id,
                "rotated": true,
            })))
        }
        other => Err(SdkError::LocalBus(format!("unsupported local bus method: {other}"))),
    }
}

fn account_status(
    state: &LocalBusDaemonState,
    request: &LocalBusFrame,
) -> Result<LocalBusDispatchResult, SdkError> {
    let account_id = request_account_id(request)?;
    let account = local_bus_account(state, account_id)?;
    if account.client.born_v3_account.is_some() {
        return Ok(local_bus_ok(super::super::native_account::status(account, account_id)?));
    }
    let manifest = read_local_bus_account_manifest(&local_bus_account_manifest_path(
        &state.config.data_root,
        account_id,
    ))?;
    let reestablishing = account
        .client
        .account_db()
        .ok()
        .map(|db| db.load_actor_state::<bool>("backup/reestablishing"))
        .transpose()?
        .flatten()
        .unwrap_or(false);
    Ok(local_bus_ok(serde_json::json!({
        "local_account_id": account_id,
        "secure_sessions":if reestablishing{"reestablishing"}else{"ready"},
        "node_id": manifest.node_id,
        "client_mode":manifest.client_mode,
        "local_device_authorized":manifest.devices.iter().any(|device|device.device_id==account.gateway_config.device_id),
        "principal_id": account.gateway_config.principal_id,
        "principal_commitment":account.principal_commitment,
        "device_id": account.gateway_config.device_id,
        "target_delivery_id": account.target_delivery_id,
        "session_id": account.engine.as_ref().map(|engine| engine.session().session_id.clone()),
        "active_transport_kind": account.engine.as_ref().map(|engine| engine.active_transport_kind().wire_name()),
        "pending_deliveries": account.pending_deliveries.len(),
    })))
}

pub(crate) fn local_bus_account_response(
    manifest: &LocalBusPersistedAccount,
    account: &LocalBusAccountState,
) -> LocalBusAccountCreateResponse {
    LocalBusAccountCreateResponse {
        local_account_id: manifest.local_account_id.clone(),
        principal_id: manifest.principal_id.clone(),
        principal_commitment: manifest.principal_commitment.clone(),
        device_id: manifest.device_id.clone(),
        target_delivery_id: manifest.target_delivery_id.clone(),
        client_mode: manifest.client_mode.clone(),
        session_id: account.engine.as_ref().map_or_else(
            || "disconnected".to_owned(),
            |engine| engine.session().session_id.clone(),
        ),
        active_transport_kind: account.engine.as_ref().map_or_else(
            || "disconnected".to_owned(),
            |engine| engine.active_transport_kind().wire_name().to_owned(),
        ),
        contact_restore: None,
    }
}

fn local_bus_account_lock(
    state: &mut LocalBusDaemonState,
    account_id: &str,
) -> Result<(), SdkError> {
    if let Some(account) = state.accounts.get(account_id) {
        let db = account.client.account_db()?;
        let tick = db.journal_bounds()?.head_seq;
        db.append_journal(
            &format!("account:locked:{tick}"),
            "account.state",
            &serde_json::json!({"local_account_id":account_id,"state":"locked"}),
            now_unix_timestamp(),
            None,
        )?;
    }
    let removed = state.accounts.remove(account_id);
    if removed.is_none() {
        return Err(SdkError::AccountNotOpen(account_id.to_owned()));
    }
    if state.active_account_id.as_deref() == Some(account_id) {
        state.active_account_id = None;
    }
    state.attended_accounts.remove(account_id);
    state.subscribers.retain(|_, subscriber| subscriber.account_id != account_id);
    Ok(())
}

async fn local_bus_account_unlock(
    state: &mut LocalBusDaemonState,
    account_id: &str,
    body: &mut LocalBusAccountUnlockRequest,
) -> Result<LocalBusAccountCreateResponse, SdkError> {
    let passphrase = Zeroizing::new(std::mem::take(&mut body.passphrase));
    let manifest_path = local_bus_account_manifest_path(&state.config.data_root, account_id);
    let manifest = read_local_bus_account_manifest(&manifest_path)?;
    let response = if let Some(account) = state.accounts.get(account_id) {
        // The actor serializes startup restore and client unlock. Repeated unlocks must still
        // authenticate against the wrapped database key, never the cached manifest secret.
        account.client.verify_active_account_secret(account_id, passphrase.as_bytes())?;
        local_bus_account_response(&manifest, account)
    } else {
        restore_local_bus_account_with_passphrase(state, &manifest, &passphrase).await?
    };
    state.active_account_id = Some(response.local_account_id.clone());
    Ok(response)
}

fn local_bus_account_backup_export(
    state: &LocalBusDaemonState,
    account_id: &str,
    body: &mut LocalBusAccountBackupExportRequest,
) -> Result<(), SdkError> {
    let account = local_bus_account(state, account_id)?;
    let manifest_path = local_bus_account_manifest_path(&state.config.data_root, account_id);
    let manifest = read_local_bus_account_manifest(&manifest_path)?;
    let backup =
        encrypt_account_backup(&manifest, account.client.backup_contacts()?, &mut body.passphrase)?;
    let output_path = PathBuf::from(&body.output_path);
    if let Some(parent) = output_path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent)?;
        set_owner_only_dir_permissions(parent)?;
    }
    let tmp_path = output_path.with_extension("tmp");
    if tmp_path.exists() {
        std::fs::remove_file(&tmp_path)?;
    }
    let bytes = serde_json::to_vec_pretty(&backup)?;
    let mut tmp_file =
        std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(&tmp_path)?;
    tmp_file.write_all(&bytes)?;
    tmp_file.sync_all()?;
    drop(tmp_file);
    set_owner_only_file_permissions(&tmp_path)?;
    std::fs::rename(&tmp_path, &output_path)?;
    set_owner_only_file_permissions(&output_path)?;
    Ok(())
}

async fn local_bus_account_backup_import(
    state: &mut LocalBusDaemonState,
    body: &mut LocalBusAccountBackupImportRequest,
    expected_account: Option<&str>,
) -> Result<LocalBusAccountCreateResponse, SdkError> {
    let bytes = std::fs::read(&body.input_path)?;
    let backup: LocalBusAccountBackupFile = serde_json::from_slice(&bytes)?;
    let restored = decrypt_account_backup_state(&backup, &mut body.passphrase)?;
    if crate::custody::account_exists(&state.config.data_root, &restored.manifest.local_account_id)?
    {
        return Err(SdkError::CustodyModeDowngrade);
    }
    let manifest = restored.manifest;
    if expected_account.is_some_and(|id| id != manifest.local_account_id) {
        return Err(SdkError::LocalBus("backup account changed during import".to_owned()));
    }
    write_local_bus_account_manifest(&state.config.data_root, &manifest)?;
    ensure_local_bus_account_index_record(
        &state.config.data_root,
        &manifest,
        state.account_index.clone(),
    )?;
    state.accounts.remove(&manifest.local_account_id);
    // Backup import is an offline root/account restore. Rejoining gateway and publishing a fresh
    // device prekey is a separate device-activation flow, so do not touch the network here.
    let mut response = restore_local_bus_account_offline(state, &manifest).await?;
    let contact_restore = local_bus_account(state, &manifest.local_account_id)?
        .client
        .restore_backup_contacts(&restored.contacts)?;
    response.contact_restore = Some(contact_restore);
    state.active_account_id = Some(response.local_account_id.clone());
    Ok(response)
}

fn ensure_local_bus_account_index_record(
    data_root: &Path,
    manifest: &LocalBusPersistedAccount,
    shared_index: Option<AccountIndex>,
) -> Result<(), SdkError> {
    let index = match shared_index {
        Some(index) => index,
        None => AccountIndex::open(data_root)?,
    };
    match index.account(&manifest.local_account_id) {
        Ok(_record) => Ok(()),
        Err(StorageError::AccountNotFound(_)) => {
            index.create_account(&manifest.local_account_id, &manifest.principal_commitment)?;
            Ok(())
        }
        Err(error) => Err(error.into()),
    }
}

fn local_bus_account_passphrase_rotate(
    state: &mut LocalBusDaemonState,
    account_id: &str,
    body: &mut LocalBusAccountPassphraseRotateRequest,
) -> Result<(), SdkError> {
    if let Some(old_passphrase) = body.old_passphrase.as_mut() {
        local_bus_account(state, account_id)?
            .client
            .verify_active_account_secret(account_id, old_passphrase.as_bytes())?;
        old_passphrase.zeroize();
    }
    {
        let account = local_bus_account_mut(state, account_id)?;
        account.client.rekey_active_account(account_id, body.new_passphrase.as_bytes())?;
    }
    if local_bus_account(state, account_id)?.client.born_v3_account.is_some() {
        body.new_passphrase.zeroize();
        return Ok(());
    }
    let manifest_path = local_bus_account_manifest_path(&state.config.data_root, account_id);
    let mut manifest = read_local_bus_account_manifest(&manifest_path)?;
    manifest.account_secret.zeroize();
    manifest.account_secret.clone_from(&body.new_passphrase);
    write_local_bus_account_manifest(&state.config.data_root, &manifest)?;
    body.new_passphrase.zeroize();
    Ok(())
}

pub(crate) fn local_bus_backup_account_id(
    mut body: LocalBusAccountBackupImportRequest,
) -> Result<String, SdkError> {
    let bytes = std::fs::read(&body.input_path)?;
    let backup: LocalBusAccountBackupFile = serde_json::from_slice(&bytes)?;
    let manifest = decrypt_account_backup(&backup, &mut body.passphrase)?;
    Ok(manifest.local_account_id)
}

#[derive(serde::Deserialize, serde::Serialize)]
struct LocalBusAccountBackupFile {
    schema: String,
    version: u32,
    kdf: LocalBusAccountBackupKdf,
    aead: LocalBusAccountBackupAead,
    ciphertext_base64url: String,
}

#[derive(serde::Deserialize, serde::Serialize)]
struct LocalBusAccountBackupKdf {
    alg: String,
    memory_kib: u32,
    time_cost: u32,
    parallelism: u32,
    salt_base64url: String,
}

#[derive(serde::Deserialize, serde::Serialize)]
struct LocalBusAccountBackupAead {
    alg: String,
    nonce_base64url: String,
}

#[derive(serde::Deserialize, serde::Serialize)]
struct LocalBusAccountBackupPlaintext {
    manifest: LocalBusPersistedAccount,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    contacts: Vec<String>,
}

fn encrypt_account_backup(
    manifest: &LocalBusPersistedAccount,
    contacts: Vec<String>,
    passphrase: &mut String,
) -> Result<LocalBusAccountBackupFile, SdkError> {
    let salt = ramflux_crypto::random_32()?;
    let nonce_seed = ramflux_crypto::random_32()?;
    let nonce = &nonce_seed[..12];
    let key = ramflux_crypto::derive_recovery_secret(passphrase.as_bytes(), &salt)?;
    passphrase.zeroize();
    let cipher = Aes256Gcm::new_from_slice(key.expose())
        .map_err(|_error| SdkError::LocalBus("account backup AEAD key init failed".to_owned()))?;
    let plaintext = LocalBusAccountBackupPlaintext { manifest: manifest.clone(), contacts };
    let plaintext_bytes = serde_json::to_vec(&plaintext)?;
    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(nonce),
            Payload { msg: &plaintext_bytes, aad: ACCOUNT_BACKUP_SCHEMA.as_bytes() },
        )
        .map_err(|_error| SdkError::LocalBus("account backup encryption failed".to_owned()))?;
    Ok(LocalBusAccountBackupFile {
        schema: ACCOUNT_BACKUP_SCHEMA.to_owned(),
        version: ACCOUNT_BACKUP_VERSION,
        kdf: LocalBusAccountBackupKdf {
            alg: "argon2id".to_owned(),
            memory_kib: ACCOUNT_BACKUP_ARGON2_MEMORY_KIB,
            time_cost: ACCOUNT_BACKUP_ARGON2_TIME_COST,
            parallelism: ACCOUNT_BACKUP_ARGON2_PARALLELISM,
            salt_base64url: ramflux_protocol::encode_base64url(salt),
        },
        aead: LocalBusAccountBackupAead {
            alg: "aes-256-gcm".to_owned(),
            nonce_base64url: ramflux_protocol::encode_base64url(nonce),
        },
        ciphertext_base64url: ramflux_protocol::encode_base64url(ciphertext),
    })
}

fn decrypt_account_backup(
    backup: &LocalBusAccountBackupFile,
    passphrase: &mut String,
) -> Result<LocalBusPersistedAccount, SdkError> {
    Ok(decrypt_account_backup_state(backup, passphrase)?.manifest)
}

fn decrypt_account_backup_state(
    backup: &LocalBusAccountBackupFile,
    passphrase: &mut String,
) -> Result<LocalBusAccountBackupPlaintext, SdkError> {
    if backup.schema != ACCOUNT_BACKUP_SCHEMA || backup.version != ACCOUNT_BACKUP_VERSION {
        return Err(SdkError::LocalBus("unsupported account backup format".to_owned()));
    }
    if backup.kdf.alg != "argon2id" || backup.aead.alg != "aes-256-gcm" {
        return Err(SdkError::LocalBus("unsupported account backup crypto suite".to_owned()));
    }
    let salt = ramflux_protocol::decode_base64url(&backup.kdf.salt_base64url)
        .map_err(|error| SdkError::LocalBus(format!("invalid account backup salt: {error}")))?;
    let nonce = ramflux_protocol::decode_base64url(&backup.aead.nonce_base64url)
        .map_err(|error| SdkError::LocalBus(format!("invalid account backup nonce: {error}")))?;
    if nonce.len() != 12 {
        return Err(SdkError::LocalBus("invalid account backup nonce length".to_owned()));
    }
    let ciphertext =
        ramflux_protocol::decode_base64url(&backup.ciphertext_base64url).map_err(|error| {
            SdkError::LocalBus(format!("invalid account backup ciphertext: {error}"))
        })?;
    let key = ramflux_crypto::derive_recovery_secret(passphrase.as_bytes(), &salt)?;
    passphrase.zeroize();
    let cipher = Aes256Gcm::new_from_slice(key.expose())
        .map_err(|_error| SdkError::LocalBus("account backup AEAD key init failed".to_owned()))?;
    let plaintext = cipher
        .decrypt(
            Nonce::from_slice(&nonce),
            Payload { msg: &ciphertext, aad: ACCOUNT_BACKUP_SCHEMA.as_bytes() },
        )
        .map_err(|_error| {
            SdkError::LocalBus(
                "account backup decrypt failed; passphrase or file is invalid".to_owned(),
            )
        })?;
    let backup_plaintext: LocalBusAccountBackupPlaintext = serde_json::from_slice(&plaintext)?;
    Ok(backup_plaintext)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn backup_manifest() -> LocalBusPersistedAccount {
        LocalBusPersistedAccount {
            label: None,
            kind: None,
            activation_pending: false,
            node_id: None,
            node_tcp_addr: None,
            node_relay: None,
            schema: "ramflux.local_bus.account_manifest.v1".to_owned(),
            local_account_id: "alice".to_owned(),
            principal_id: "principal_alice".to_owned(),
            principal_commitment: "commitment_alice".to_owned(),
            device_id: "device_alice".to_owned(),
            target_delivery_id: "target_alice".to_owned(),
            account_secret: "correct-horse-battery-staple".to_owned(),
            root_seed: [0x11; 32],
            device_seed: [0x22; 32],
            client_mode: LocalBusClientMode::AttendedCli,
            gateway: GatewayQuicEndpointConfig {
                bind_addr: SocketAddr::from(([0, 0, 0, 0], 0)),
                gateway_addr: SocketAddr::from(([127, 0, 0, 1], 7443)),
                server_name: "localhost".to_owned(),
                ca_cert: PathBuf::from("ca.pem"),
                principal_id: "principal_alice".to_owned(),
                device_id: "device_alice".to_owned(),
                target_delivery_id: "target_alice".to_owned(),
                prekey_http_url: None,
            },
            devices: vec![LocalBusDeviceRecord {
                device_id: "device_alice".to_owned(),
                device_epoch: 1,
                target_delivery_id: "target_alice".to_owned(),
                capability_scope: default_device_capability_scope(),
                is_local: true,
            }],
        }
    }

    #[test]
    fn account_backup_encrypts_manifest_and_decrypts_with_passphrase() -> Result<(), SdkError> {
        let manifest = backup_manifest();
        let mut passphrase = "backup-passphrase-at-least-128-bit".to_owned();

        let backup = encrypt_account_backup(&manifest, Vec::new(), &mut passphrase)?;
        let encoded = serde_json::to_string(&backup)?;

        assert!(!encoded.contains("correct-horse-battery-staple"));
        assert!(!encoded.contains("principal_alice"));
        assert!(!encoded.contains("root_seed"));
        assert_eq!(passphrase, "");

        let mut decrypt_passphrase = "backup-passphrase-at-least-128-bit".to_owned();
        let restored = decrypt_account_backup(&backup, &mut decrypt_passphrase)?;

        assert_eq!(restored.local_account_id, manifest.local_account_id);
        assert_eq!(restored.root_seed, manifest.root_seed);
        assert_eq!(restored.device_seed, manifest.device_seed);
        assert_eq!(decrypt_passphrase, "");
        Ok(())
    }

    #[test]
    fn legacy_manifest_reads_do_not_open_an_unrelated_account_index() -> Result<(), SdkError> {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |t| t.as_nanos());
        let root = std::env::temp_dir()
            .join(format!("rf-legacy-manifest-index-{}-{unique}", std::process::id()));
        let manifest = backup_manifest();
        write_local_bus_account_manifest(&root, &manifest)?;
        std::fs::write(root.join(ramflux_storage::ACCOUNT_INDEX_FILE), b"not an index database")?;
        let path = local_bus_account_manifest_path(&root, &manifest.local_account_id);
        assert!(crate::bus::daemon::account_manifest_available(&path));
        assert_eq!(read_local_bus_account_manifest(&path)?.device_id, manifest.device_id);
        std::fs::remove_dir_all(root)?;
        Ok(())
    }
    #[tokio::test]
    async fn account_status_reports_the_local_sender_device() -> Result<(), SdkError> {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |time| time.as_nanos());
        let root =
            std::env::temp_dir().join(format!("rf-account-status-{}-{unique}", std::process::id()));
        let manifest = backup_manifest();
        write_local_bus_account_manifest(&root, &manifest)?;
        let gateway = GatewaySessionConfig::quic(manifest.gateway.clone());
        let mut state = LocalBusDaemonState {
            account_index: None,
            nodes: crate::node::NodeStore::default(),
            config: LocalBusConfig::new(root.join("bus.sock"), root.clone()),
            accounts: BTreeMap::from([(
                "alice".to_owned(),
                LocalBusAccountState::disconnected(
                    RamfluxClient::new(),
                    gateway,
                    manifest.principal_commitment.clone(),
                ),
            )]),
            active_account_id: Some("alice".to_owned()),
            attended_accounts: BTreeSet::new(),
            subscribers: BTreeMap::new(),
        };
        let request = LocalBusFrame {
            bus_protocol: "ramflux.local_bus.v1".into(),
            frame_id: "status".into(),
            kind: LocalBusFrameKind::Request,
            request_id: "status".into(),
            account_id: Some("alice".into()),
            sdk_api: "account".into(),
            method: "account.status".into(),
            body: serde_json::json!({}),
            trace_id: None,
            seq: None,
            at: None,
            deadline_ms: None,
            operation_id: None,
            ok: None,
            error: None,
        };
        let status = dispatch_account_bus_request(&request, &mut state).await?.response_body;
        // Clients build message.submit sender_id from this field.
        assert_eq!(status["device_id"], "device_alice");
        assert_eq!(status["principal_id"], "principal_alice");
        assert_eq!(status["target_delivery_id"], "target_alice");
        std::fs::remove_dir_all(root)?;
        Ok(())
    }

    #[tokio::test]
    async fn legacy_key_import_cannot_overwrite_a_native_account_without_request_scope()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = crate::custody::tests::Root::new()?;
        let vault = crate::custody::tests::TestVault::default();
        crate::custody::tests::create(&root.0, "alice", &vault, crate::custody::network_now()?)?;
        let authority_path = root.0.join("custody_accounts/alice/authority.json");
        let authority = std::fs::read(&authority_path)?;
        let backup = encrypt_account_backup(
            &backup_manifest(),
            Vec::new(),
            &mut "backup-passphrase-at-least-128-bit".to_owned(),
        )?;
        let input = root.0.join("legacy-backup.json");
        std::fs::write(&input, serde_json::to_vec(&backup)?)?;
        let mut state = LocalBusDaemonState {
            config: LocalBusConfig::new(root.0.join("bus.sock"), &root.0),
            account_index: Some(AccountIndex::open(&root.0)?),
            nodes: crate::node::NodeStore::default(),
            accounts: BTreeMap::new(),
            active_account_id: None,
            attended_accounts: BTreeSet::new(),
            subscribers: BTreeMap::new(),
        };
        let mut request = LocalBusAccountBackupImportRequest {
            input_path: input.to_string_lossy().into_owned(),
            passphrase: "backup-passphrase-at-least-128-bit".into(),
        };
        assert!(matches!(
            local_bus_account_backup_import(&mut state, &mut request, None).await,
            Err(SdkError::CustodyModeDowngrade)
        ));
        assert_eq!(std::fs::read(authority_path)?, authority);
        assert!(!local_bus_account_manifest_path(&root.0, "alice").exists());
        assert!(state.accounts.is_empty());
        Ok(())
    }

    #[test]
    fn account_backup_rejects_wrong_passphrase() -> Result<(), SdkError> {
        let manifest = backup_manifest();
        let mut passphrase = "backup-passphrase-at-least-128-bit".to_owned();
        let backup = encrypt_account_backup(&manifest, Vec::new(), &mut passphrase)?;
        let mut wrong = "wrong-passphrase-at-least-128bit".to_owned();

        let result = decrypt_account_backup(&backup, &mut wrong);

        assert!(result.is_err());
        assert_eq!(wrong, "");
        Ok(())
    }
}

#[cfg(test)]
#[path = "tests/key_backup_restore.rs"]
pub(crate) mod key_backup_restore;

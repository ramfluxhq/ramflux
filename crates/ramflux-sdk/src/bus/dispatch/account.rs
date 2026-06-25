#![allow(clippy::missing_errors_doc)]
#![allow(clippy::wildcard_imports)]
use crate::prelude::*;
use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use zeroize::Zeroize;

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
        "account.create" => {
            let body: LocalBusAccountCreateRequest = serde_json::from_value(request.body.clone())?;
            let response = local_bus_account_create(state, body).await?;
            Ok(local_bus_ok(serde_json::to_value(response)?))
        }
        "account.list" => Ok(local_bus_ok(serde_json::json!({
            "active_account_id": state.active_account_id,
            "accounts": state.accounts.keys().cloned().collect::<Vec<_>>(),
        }))),
        "account.switch" => {
            let account_id = request_account_id(request)?.to_owned();
            if !state.accounts.contains_key(&account_id) {
                return Err(SdkError::LocalBus(format!("account not open: {account_id}")));
            }
            state.active_account_id = Some(account_id.clone());
            Ok(local_bus_ok(serde_json::json!({ "active_account_id": account_id })))
        }
        "account.status" => {
            let account_id = request_account_id(request)?;
            let account = local_bus_account(state, account_id)?;
            Ok(local_bus_ok(serde_json::json!({
                "local_account_id": account_id,
                "principal_id": account.gateway_config.principal_id,
                "target_delivery_id": account.target_delivery_id,
                "session_id": account.engine.as_ref().map(|engine| engine.session().session_id.clone()),
                "active_transport_kind": account.engine.as_ref().map(|engine| engine.active_transport_kind().wire_name()),
                "pending_deliveries": account.pending_deliveries.len(),
            })))
        }
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
            let response = local_bus_account_backup_import(state, &mut body).await?;
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

pub(crate) async fn local_bus_account_create(
    state: &mut LocalBusDaemonState,
    mut body: LocalBusAccountCreateRequest,
) -> Result<LocalBusAccountCreateResponse, SdkError> {
    let data_root = state.config.data_root.clone();
    let manifest_path = local_bus_account_manifest_path(&data_root, &body.local_account_id);
    if manifest_path.exists() {
        let manifest = read_local_bus_account_manifest(&manifest_path)?;
        let response = restore_local_bus_account(state, &manifest).await?;
        state.active_account_id = Some(response.local_account_id.clone());
        return Ok(response);
    }
    let mut client = RamfluxClient::new();
    let root = client.create_identity_root(&body.principal_id, body.root_seed);
    let root_public_key =
        ramflux_protocol::encode_base64url(root.signing_key.verifying_key().to_bytes());
    let derived_commitment = identity_root_public_key_commitment(&root_public_key)?;
    if body.principal_commitment.is_empty() {
        body.principal_commitment.clone_from(&derived_commitment);
    } else if body.principal_commitment != derived_commitment {
        return Err(SdkError::LocalBus(format!(
            "principal_commitment mismatch: expected {derived_commitment}"
        )));
    }
    client.create_device_branch(&body.principal_id, &body.device_id, 1, body.device_seed);
    client.open_account_index(&data_root)?;
    client.create_account(&body.local_account_id, &body.principal_commitment)?;
    client.set_active_account(&body.local_account_id)?;
    client.unlock_account(&body.local_account_id, body.account_secret.as_bytes())?;
    let mode = body.client_mode.clone();
    let device_state = serde_json::json!({
        "device_kind": "cli",
        "client_mode": mode,
        "device_id": body.device_id,
        "target_delivery_id": body.target_delivery_id,
    });
    client.append_event(
        &format!("device.branch.created:{}", body.device_id),
        "device.branch.created",
        &serde_json::to_vec(&device_state)?,
    )?;
    let gateway = GatewaySessionConfig::auto(body.gateway.clone()).with_device_branch(
        client.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?.clone(),
    );
    client
        .initialize_and_publish_prekey_bundle_via_gateway_request(
            &gateway,
            &body.principal_commitment,
            &body.device_id,
            &body.target_delivery_id,
            body.device_seed,
        )
        .await?;
    let engine = client.connect_gateway_session(gateway).await?;
    let manifest = LocalBusPersistedAccount::from_create_request(&body);
    write_local_bus_account_manifest(&data_root, &manifest)?;
    let response = LocalBusAccountCreateResponse {
        local_account_id: body.local_account_id.clone(),
        principal_id: body.principal_id,
        principal_commitment: body.principal_commitment,
        device_id: body.device_id.clone(),
        target_delivery_id: body.target_delivery_id,
        client_mode: body.client_mode,
        session_id: engine.session().session_id.clone(),
        active_transport_kind: engine.active_transport_kind().wire_name().to_owned(),
    };
    let local_account_id = body.local_account_id;
    state.active_account_id = Some(local_account_id.clone());
    state.accounts.insert(local_account_id, LocalBusAccountState::new(client, engine));
    Ok(response)
}

fn local_bus_account_lock(
    state: &mut LocalBusDaemonState,
    account_id: &str,
) -> Result<(), SdkError> {
    let removed = state.accounts.remove(account_id);
    if removed.is_none() {
        return Err(SdkError::LocalBus(format!("account not open: {account_id}")));
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
    if state.accounts.contains_key(account_id) {
        return Err(SdkError::LocalBus(format!("account already open: {account_id}")));
    }
    let manifest_path = local_bus_account_manifest_path(&state.config.data_root, account_id);
    let manifest = read_local_bus_account_manifest(&manifest_path)?;
    let response =
        restore_local_bus_account_with_passphrase(state, &manifest, &body.passphrase).await?;
    body.passphrase.zeroize();
    state.active_account_id = Some(response.local_account_id.clone());
    Ok(response)
}

fn local_bus_account_backup_export(
    state: &LocalBusDaemonState,
    account_id: &str,
    body: &mut LocalBusAccountBackupExportRequest,
) -> Result<(), SdkError> {
    let _account = local_bus_account(state, account_id)?;
    let manifest_path = local_bus_account_manifest_path(&state.config.data_root, account_id);
    let manifest = read_local_bus_account_manifest(&manifest_path)?;
    let backup = encrypt_account_backup(&manifest, &mut body.passphrase)?;
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
) -> Result<LocalBusAccountCreateResponse, SdkError> {
    let bytes = std::fs::read(&body.input_path)?;
    let backup: LocalBusAccountBackupFile = serde_json::from_slice(&bytes)?;
    let manifest = decrypt_account_backup(&backup, &mut body.passphrase)?;
    write_local_bus_account_manifest(&state.config.data_root, &manifest)?;
    ensure_local_bus_account_index_record(&state.config.data_root, &manifest)?;
    state.accounts.remove(&manifest.local_account_id);
    // Backup import is an offline root/account restore. Rejoining gateway and publishing a fresh
    // device prekey is a separate device-activation flow, so do not touch the network here.
    let response = restore_local_bus_account_offline(state, &manifest).await?;
    state.active_account_id = Some(response.local_account_id.clone());
    Ok(response)
}

fn ensure_local_bus_account_index_record(
    data_root: &Path,
    manifest: &LocalBusPersistedAccount,
) -> Result<(), SdkError> {
    let index = AccountIndex::open(data_root)?;
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
        verify_existing_account_passphrase(&state.config.data_root, account_id, old_passphrase)?;
        old_passphrase.zeroize();
    }
    {
        let account = local_bus_account_mut(state, account_id)?;
        account.client.rekey_active_account(account_id, body.new_passphrase.as_bytes())?;
    }
    let manifest_path = local_bus_account_manifest_path(&state.config.data_root, account_id);
    let mut manifest = read_local_bus_account_manifest(&manifest_path)?;
    manifest.account_secret.zeroize();
    manifest.account_secret.clone_from(&body.new_passphrase);
    write_local_bus_account_manifest(&state.config.data_root, &manifest)?;
    body.new_passphrase.zeroize();
    Ok(())
}

fn verify_existing_account_passphrase(
    data_root: &Path,
    account_id: &str,
    old_passphrase: &str,
) -> Result<(), SdkError> {
    let mut verifier = RamfluxClient::new();
    verifier.open_account_index(data_root)?;
    verifier.unlock_account(account_id, old_passphrase.as_bytes())
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
}

fn encrypt_account_backup(
    manifest: &LocalBusPersistedAccount,
    passphrase: &mut String,
) -> Result<LocalBusAccountBackupFile, SdkError> {
    let salt = ramflux_crypto::random_32()?;
    let nonce_seed = ramflux_crypto::random_32()?;
    let nonce = &nonce_seed[..12];
    let key = ramflux_crypto::derive_recovery_secret(passphrase.as_bytes(), &salt)?;
    passphrase.zeroize();
    let cipher = Aes256Gcm::new_from_slice(key.expose())
        .map_err(|_error| SdkError::LocalBus("account backup AEAD key init failed".to_owned()))?;
    let plaintext = LocalBusAccountBackupPlaintext { manifest: manifest.clone() };
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
    Ok(backup_plaintext.manifest)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn backup_manifest() -> LocalBusPersistedAccount {
        LocalBusPersistedAccount {
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

        let backup = encrypt_account_backup(&manifest, &mut passphrase)?;
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
    fn account_backup_rejects_wrong_passphrase() -> Result<(), SdkError> {
        let manifest = backup_manifest();
        let mut passphrase = "backup-passphrase-at-least-128-bit".to_owned();
        let backup = encrypt_account_backup(&manifest, &mut passphrase)?;
        let mut wrong = "wrong-passphrase-at-least-128bit".to_owned();

        let result = decrypt_account_backup(&backup, &mut wrong);

        assert!(result.is_err());
        assert_eq!(wrong, "");
        Ok(())
    }
}

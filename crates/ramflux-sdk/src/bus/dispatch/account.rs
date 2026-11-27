// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

#![allow(clippy::missing_errors_doc)]
#![allow(clippy::wildcard_imports)]
use crate::prelude::*;
use zeroize::{Zeroize, Zeroizing};

fn account_request<T: serde::de::DeserializeOwned>(
    body: &serde_json::Value,
) -> Result<T, SdkError> {
    serde_json::from_value(body.clone())
        .map_err(|_| SdkError::LocalBus("invalid account request".to_owned()))
}

pub(crate) async fn dispatch_account_bus_request(
    request: &LocalBusFrame,
    state: &mut LocalBusDaemonState,
) -> Result<LocalBusDispatchResult, SdkError> {
    match request.method.as_str() {
        // Creation is owned by the exclusive secret ceremony on the connection.
        "account.create" => Err(SdkError::CustodySetupInvalid),
        "account.list" => Ok(local_bus_ok(account_list(state)?)),
        "account.switch" => {
            let account_id = request_account_id(request)?.to_owned();
            if !state.accounts.contains_key(&account_id) {
                return Err(SdkError::AccountNotOpen(account_id));
            }
            state.active_account_id = Some(account_id.clone());
            Ok(local_bus_ok(serde_json::json!({ "active_account_id": account_id })))
        }
        "account.status" => account_status(state, request),
        "account.config.get" | "account.config.set" => {
            let account_id = request_account_id(request)?;
            let account = local_bus_account_mut(state, account_id)?;
            if request.method == "account.config.set" {
                let config = crate::offline_retention::decode_config(request.body.clone())?;
                account.client.set_offline_retention_secs(config.offline_retention_secs)?;
            }
            Ok(local_bus_ok(serde_json::to_value(account.client.account_config()?)?))
        }
        "account.lock" | "account.sign_out" => {
            let account_id = request_account_id(request)?.to_owned();
            let reason = if request.method == "account.sign_out" { "sign_out" } else { "lock" };
            crate::client::surface::card_session::drop_account(&account_id, reason);
            local_bus_account_lock(state, &account_id).await?;
            let mut body = serde_json::json!({
                "local_account_id": account_id,
                "locked": true,
            });
            if request.method == "account.sign_out"
                && let Some(map) = body.as_object_mut()
            {
                map.insert("signed_out".to_owned(), serde_json::Value::Bool(true));
            }
            Ok(local_bus_ok(body))
        }
        "account.unlock" => {
            let account_id = request_account_id(request)?.to_owned();
            if crate::custody::account_exists(&state.config.data_root, &account_id)? {
                if let Some(reason) =
                    crate::custody::failed_setup(&state.config.data_root, &account_id)?
                {
                    return Err(crate::custody::failed_setup_error(&account_id, reason));
                }
                let result =
                    super::super::native_account::unlock_request(state, &account_id, request)?;
                return Ok(local_bus_ok(serde_json::to_value(result)?));
            }

            let mut body: LocalBusAccountUnlockRequest = account_request(&request.body)?;
            let response = local_bus_account_unlock(state, &account_id, &mut body).await?;
            Ok(local_bus_ok(serde_json::to_value(response)?))
        }
        "account.passphrase.rotate" => {
            let account_id = request_account_id(request)?.to_owned();
            let mut body: LocalBusAccountPassphraseRotateRequest = account_request(&request.body)?;
            local_bus_account_passphrase_rotate(state, &account_id, &mut body)?;
            Ok(local_bus_ok(serde_json::json!({
                "local_account_id": account_id,
                "rotated": true,
            })))
        }
        other => Err(SdkError::LocalBus(format!("unsupported local bus method: {other}"))),
    }
}

fn account_list(state: &LocalBusDaemonState) -> Result<serde_json::Value, SdkError> {
    // On-disk and locked rows stay. An open session still publishes its live name and kind.
    let mut body = super::super::account_local::daemon_list(state)?;
    if let Some(details) = body.get_mut("account_details").and_then(|value| value.as_array_mut()) {
        for detail in details {
            let Some(id) = detail.get("id").and_then(serde_json::Value::as_str) else {
                continue;
            };
            let id = id.to_owned();
            let Some(account) = state.accounts.get(&id) else {
                continue;
            };
            let open = open_account_detail(&id, account);
            let Some(map) = detail.as_object_mut() else {
                continue;
            };
            if let Some(name) = open.get("display_name").and_then(serde_json::Value::as_str)
                && !name.is_empty()
            {
                map.insert("display_name".to_owned(), serde_json::Value::String(name.to_owned()));
            }
            if let Some(kind) = open.get("kind") {
                map.insert("kind".to_owned(), kind.clone());
            }
        }
    }
    if let Some(details) = body.get("account_details").and_then(serde_json::Value::as_array) {
        let accounts = super::super::account_local::picker(details);
        if let Some(map) = body.as_object_mut() {
            map.insert("accounts".to_owned(), serde_json::Value::Array(accounts));
        }
    }
    Ok(body)
}

fn open_account_detail(id: &str, account: &LocalBusAccountState) -> serde_json::Value {
    if let Some(native) = account.client.born_v3_account.as_ref() {
        let body = &native.record().body;
        return serde_json::json!({
            "id": id,
            "display_name": body.profile.display_name,
            "kind": principal_kind_name(body.principal_kind),
        });
    }
    let principal = account
        .client
        .account_db()
        .ok()
        .and_then(|db| db.client_record("self", "account").ok().flatten())
        .and_then(|row| {
            row.get("principal_id").and_then(serde_json::Value::as_str).map(str::to_owned)
        });
    let display_name = principal.as_deref().and_then(|principal| {
        account
            .client
            .read_profile_facts(principal)
            .map(|facts| facts.profile.display_name.clone())
            .filter(|name| !name.is_empty())
    });
    serde_json::json!({
        "id": id,
        "display_name": display_name,
        "kind": serde_json::Value::Null,
    })
}

fn principal_kind_name(kind: ramflux_protocol::PrincipalKind) -> &'static str {
    match kind {
        ramflux_protocol::PrincipalKind::Human => "human",
        ramflux_protocol::PrincipalKind::HeadlessAi => "headless_ai",
        ramflux_protocol::PrincipalKind::Bot => "bot",
        ramflux_protocol::PrincipalKind::Workflow => "workflow",
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
        "session_delivery_mode":account.session_delivery_mode(),
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

async fn local_bus_account_lock(
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
    let pairing_pending =
        crate::custody::pairing::work_signal(&state.config.data_root, account_id).is_some();
    crate::custody::pairing::remove_actor_and_drain(&state.config.data_root, account_id).await?;
    let removed = state.accounts.remove(account_id);
    if removed.is_none() && !pairing_pending {
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
    fn legacy_manifest_reads_do_not_open_an_unrelated_account_index() -> Result<(), SdkError> {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |t| t.as_nanos());
        let root = ramflux_test_support::TestPath::new()
            .expect("test: allocate fixture directory")
            .child(format!("rf-legacy-manifest-index-{}-{unique}", std::process::id()));
        let manifest = backup_manifest();
        write_local_bus_account_manifest(&root, &manifest)?;
        std::fs::write(root.join(ramflux_storage::ACCOUNT_INDEX_FILE), b"not an index database")?;
        let path = local_bus_account_manifest_path(&root, &manifest.local_account_id);
        assert!(crate::bus::daemon::account_manifest_available(&path));
        assert_eq!(read_local_bus_account_manifest(&path)?.device_id, manifest.device_id);
        Ok(())
    }
    #[tokio::test]
    async fn account_status_reports_the_local_sender_device() -> Result<(), SdkError> {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |time| time.as_nanos());
        let root = ramflux_test_support::TestPath::new()
            .expect("test: allocate fixture directory")
            .child(format!("rf-account-status-{}-{unique}", std::process::id()));
        let manifest = backup_manifest();
        write_local_bus_account_manifest(&root, &manifest)?;
        let gateway = GatewaySessionConfig::quic(manifest.gateway.clone());
        let mut state = LocalBusDaemonState {
            account_index: None,
            nodes: crate::node::NodeStore::default(),
            config: LocalBusConfig::new(root.join("bus.sock"), root.to_path_buf()),
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
        Ok(())
    }
}

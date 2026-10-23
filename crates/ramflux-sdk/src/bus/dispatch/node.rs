// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use crate::node::{PendingNode, fetch_client_record, node_error};
use crate::prelude::*;
use ramflux_protocol::{DISCOVERY_MAX_CACHE_TTL_SECONDS, discovery_cache_ttl};
use serde::Deserialize;

#[derive(Deserialize)]
struct NodeAdd {
    url: String,
    #[serde(default)]
    refresh: bool,
}
#[derive(Deserialize)]
struct NodeConfirm {
    node_id: String,
    #[serde(default)]
    pin_source: Option<NodePinSource>,
    #[serde(default)]
    expected_public_key: Option<String>,
}
#[derive(Deserialize)]
struct NodeSelector {
    node_id: String,
    #[serde(default)]
    enabled: Option<bool>,
}

pub(crate) async fn dispatch_node_bus_request(
    request: &LocalBusFrame,
    state: &mut LocalBusDaemonState,
) -> Result<LocalBusDispatchResult, SdkError> {
    let now = now_unix_timestamp().unsigned_abs();
    match request.method.as_str() {
        "node.add" => add_node(request, state, now).await,
        "node.confirm" => {
            let body: NodeConfirm = serde_json::from_value(request.body.clone())?;
            let (url, pending) = state
                .nodes
                .pending
                .iter()
                .find(|(_, pending)| pending.record.node_id == body.node_id)
                .ok_or_else(|| node_error("no pending node; add it first"))?;
            let url = url.clone();
            let record = pending.record.clone();
            let mut nodes = state.nodes.clone();
            let mut profile = nodes.confirm(
                record,
                body.pin_source.unwrap_or(NodePinSource::Tofu),
                body.expected_public_key.as_deref(),
                now,
            )?;
            profile.discovery_url = url;
            nodes.profiles.insert(profile.node_id.clone(), profile.clone());
            nodes.save(&state.config.data_root)?;
            state.nodes = nodes;
            Ok(local_bus_ok(serde_json::to_value(profile)?))
        }
        "node.list" => Ok(local_bus_ok(
            serde_json::json!({ "default_node_id": state.nodes.default_node_id, "nodes": state.nodes.profiles.values().collect::<Vec<_>>() }),
        )),
        "node.probe" => crate::node::probe::dispatch_probe(request, state).await,
        "node.remove" | "node.set_default" | "node.set_enabled" => {
            let body: NodeSelector = serde_json::from_value(request.body.clone())?;
            let mut nodes = state.nodes.clone();
            if !nodes.profiles.contains_key(&body.node_id) {
                return Err(node_error("unknown node"));
            }
            match request.method.as_str() {
                "node.remove" => {
                    refuse_bound_node_removal(&state.config.data_root, &body.node_id)?;
                    nodes.profiles.remove(&body.node_id);
                    if nodes.default_node_id.as_deref() == Some(&body.node_id) {
                        nodes.default_node_id = None;
                    }
                }
                "node.set_default" => {
                    nodes.selected(Some(&body.node_id), false)?;
                    nodes.default_node_id = Some(body.node_id);
                }
                _ => {
                    let enabled = body.enabled.ok_or_else(|| node_error("enabled is required"))?;
                    if let Some(profile) = nodes.profiles.get_mut(&body.node_id) {
                        profile.enabled = enabled;
                    }
                    if !enabled && nodes.default_node_id.as_deref() == Some(&body.node_id) {
                        nodes.default_node_id = None;
                    }
                }
            }
            nodes.save(&state.config.data_root)?;
            state.nodes = nodes;
            Ok(local_bus_ok(serde_json::json!({"ok": true})))
        }
        _ => Err(node_error("unsupported node method")),
    }
}

pub(crate) fn refuse_bound_node_removal(root: &Path, id: &str) -> Result<(), SdkError> {
    let dir = crate::bus::daemon::local_bus_accounts_dir(root);
    if !dir.exists() {
        return Ok(());
    }
    for entry in std::fs::read_dir(dir)? {
        let path = entry?.path();
        if path.extension().and_then(std::ffi::OsStr::to_str) == Some("json") {
            let manifest = read_local_bus_account_manifest(&path)?;
            if manifest.node_id.as_deref() == Some(id) {
                return Err(node_error("cannot remove node while an account is bound"));
            }
        }
    }
    Ok(())
}

async fn add_node(
    request: &LocalBusFrame,
    state: &mut LocalBusDaemonState,
    now: u64,
) -> Result<LocalBusDispatchResult, SdkError> {
    let body: NodeAdd = serde_json::from_value(request.body.clone())?;
    let cached = state
        .nodes
        .pending
        .get(&body.url)
        .filter(|pending| !body.refresh && now < pending.cache_until);
    let record = if let Some(pending) = cached {
        pending.record.clone()
    } else {
        fetch_client_record(&body.url).await?
    };
    if state.nodes.observe(&record) {
        state.nodes.save(&state.config.data_root)?;
    }
    let cache_until = now.saturating_add(discovery_cache_ttl(
        record.expires_at,
        now,
        DISCOVERY_MAX_CACHE_TTL_SECONDS,
    ));
    state.nodes.pending.retain(|_, pending| pending.record.node_id != record.node_id);
    state
        .nodes
        .pending
        .insert(body.url.clone(), PendingNode { record: record.clone(), cache_until });
    let mut profile = NodeProfile::from_record(record, now);
    profile.discovery_url = body.url;
    if let Some(existing) = state.nodes.profiles.get(&profile.node_id) {
        profile.safety_warnings.extend(existing.safety_warnings.clone());
        if profile.node_public_key == existing.node_public_key {
            profile.pin_source = existing.pin_source;
        }
    }
    Ok(local_bus_ok(serde_json::json!({
        "node": profile,
        "key_fingerprint": ramflux_protocol::hash_hex(ramflux_protocol::CLIENT_DISCOVERY_DOMAIN, profile.node_public_key.as_bytes()),
        "ca_fingerprint": ramflux_protocol::hash_hex(ramflux_protocol::CLIENT_DISCOVERY_DOMAIN, profile.ca_cert_pem.as_bytes()),
        "persisted": false,
    })))
}

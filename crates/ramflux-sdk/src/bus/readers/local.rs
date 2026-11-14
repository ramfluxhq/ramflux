// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Local read projections and immutable actor-owned control views.

use crate::prelude::{
    LocalBusContactSafetyRequest, LocalBusConversationRequest, LocalBusDaemonState,
    LocalBusDeviceListResponse, LocalBusFrame, LocalBusGroupRequest,
    LocalBusMessageFrankingEvidenceRequest, LocalBusObjectGetStatusRequest,
    LocalBusObjectPutStatusRequest, LocalBusObjectTransferStatusRequest, LocalMcpAuditRecord,
    RamfluxClient, SdkError, local_bus_account, local_bus_account_manifest_path,
    read_local_bus_account_manifest,
};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
};

#[derive(Clone)]
struct DownloadView {
    status: Value,
    file: Arc<Mutex<Option<std::fs::File>>>,
}

#[derive(Clone, Default)]
pub(super) struct AccountView {
    pub native: Option<Box<crate::custody::BornAccount>>,
    pub account_root: Option<std::path::PathBuf>,
    pub connection: Option<super::super::connection_manager::ConnectionHandle>,
    pub account_has_relay: bool,
    pub upload_relays: BTreeMap<String, bool>,
    principal: String,
    anchor: String,
    status: Value,
    views: BTreeMap<&'static str, Value>,
    upload_offsets: BTreeMap<String, usize>,
    download_status: BTreeMap<String, DownloadView>,
}

impl AccountView {
    pub(super) fn install_reader_authority(&self, client: &mut RamfluxClient) {
        client.reader_principal_id = (!self.principal.is_empty()).then(|| self.principal.clone());
        client.born_v3_account.clone_from(&self.native);
        client.reader_account_root.clone_from(&self.account_root);
    }

    pub(super) fn capture(state: &LocalBusDaemonState, id: &str) -> Result<Self, SdkError> {
        let account = local_bus_account(state, id)?;
        let client = &account.client;
        let mut views = BTreeMap::new();
        views.insert("grant.list", json!({"grants":account.mcp_grants.values().collect::<Vec<_>>(),"approvals":super::super::dispatch::task_approval::list(account)?}));
        views.insert("grant.list_standing_approvals", json!({"standing_approvals":account.mcp_standing_approvals.values().collect::<Vec<_>>()}));
        views.insert("mcp.server.refresh", json!({"registry_hash":account.mcp_registry.registry_hash(),"tool_manifest_set_hash":account.mcp_registry.tool_manifest_set_hash()}));
        views.insert("mcp.tool.list", json!({"registry_hash":account.mcp_registry.registry_hash(),"tool_manifest_set_hash":account.mcp_registry.tool_manifest_set_hash(),"tools":account.mcp_registry.tools()}));
        views.insert("bot.list", json!({"bots":account.bots.values().collect::<Vec<_>>()}));
        let devices = super::super::dispatch::device::account_known_devices(state, id, account);
        if let Ok(devices) = devices {
            views.insert(
                "device.list",
                serde_json::to_value(LocalBusDeviceListResponse {
                    a2ui_renderer_capabilities: ramflux_protocol::renderer_capabilities(),
                    principal_id: account.gateway_config.principal_id.clone(),
                    local_device_id: account.gateway_config.device_id.clone(),
                    devices,
                })?,
            );
        }
        let native = client.born_v3_account.clone();
        let mut status = json!({
            "account_id":id,"local_account_id":id,"state":"unlocked",
            "principal_id":account.gateway_config.principal_id,
            "principal_commitment":account.principal_commitment,
            "device_id":account.gateway_config.device_id,
            "target_delivery_id":account.target_delivery_id,
            "node_id":client.account_db()?.load_actor_state::<String>("account/node-id")?,
            "session_delivery_mode":account.session_delivery_mode(),
            "session_id":account.engine.as_ref().map(|engine|engine.session().session_id.clone()),
            "active_transport_kind":account.engine.as_ref().map(|engine|engine.active_transport_kind().wire_name()),
            "pending_deliveries":account.pending_deliveries.len(),
        });
        if let Some(native) = native.as_ref() {
            status["display_name"] = json!(native.record().body.profile.display_name);
            status["principal_kind"] = json!(native.record().body.principal_kind);
            status["authority_blocked"] = json!(native.authority_blocked());
        } else if let Ok(manifest) = read_local_bus_account_manifest(
            &local_bus_account_manifest_path(&state.config.data_root, id),
        ) {
            status["node_id"] = json!(manifest.node_id);
            status["client_mode"] = json!(manifest.client_mode);
            status["local_device_authorized"] = json!(
                manifest
                    .devices
                    .iter()
                    .any(|device| device.device_id == account.gateway_config.device_id)
            );
            status["secure_sessions"] =
                json!(if client.account_db()?.load_actor_state::<bool>("backup/reestablishing")?
                    == Some(true)
                {
                    "reestablishing"
                } else {
                    "ready"
                });
        }
        Ok(Self {
            account_root: native.as_ref().map(|_| client.account_index().map(|index| index.root().to_path_buf())).transpose()?,
            native,
            connection: account.connection.clone(),
            account_has_relay:account.client.node_relay_options.is_some(),
            upload_relays:account.object_put_spools.iter().map(|(id,spool)|(id.clone(),spool.relay_endpoint.is_some())).collect(),
            principal: account.gateway_config.principal_id.clone(),
            anchor: account.principal_commitment.clone(),
            status,
            views,
            upload_offsets: account.object_put_spools.iter().map(|(id,spool)|(id.clone(),spool.written)).collect(),
            download_status: account.object_get_spools.iter().map(|(id, spool)| (id.clone(), DownloadView {
                status: json!({"operation_id":id,"object_id":spool.object_id,"state":if spool.read_offset==spool.total_len {"complete"} else {"reading"},"total_len":spool.total_len,"read_offset":spool.read_offset,"plaintext_hash":spool.plaintext_hash}),
                file: Arc::clone(&spool.file),
            })).collect(),
        })
    }
}

pub(super) fn read(
    client: &RamfluxClient,
    view: &AccountView,
    request: &LocalBusFrame,
) -> Result<Option<Value>, SdkError> {
    let value = match request.method.as_str() {
        "account.status" => status(client, view)?,
        "contact.list" => contacts(client, view)?,
        "contact.requests.list" => client.contact_requests_list()?,
        "contact.requests.policy.get" => {
            json!({"contact_requests":client.contact_request_policy()?,"authority_floors":client.contact_request_floor_status()?})
        }
        "contact.verification.status" => verification(client, view, request)?,
        "contact.rejected" => {
            let body: LocalBusConversationRequest = serde_json::from_value(request.body.clone())?;
            json!({"rejected":client.rejected_inbox(&body.conversation_id)?})
        }
        "group.history" => super::super::dispatch::group::history::read(client, request)?,
        "group.members" => {
            let body: LocalBusGroupRequest = serde_json::from_value(request.body.clone())?;
            match client.shared_group_metadata(&body.group_id)? {
                Some(metadata) => metadata,
                None => serde_json::to_value(client.group_state(&body.group_id)?)?,
            }
        }
        "group.requests.list" => client.group_change_statuses(request.body["group_id"].as_str())?,
        "group.invitations.list" => client.group_invitations()?,
        "object.list" => {
            super::super::dispatch::object::object_list_response(request, client)?.response_body
        }
        "object.transfer.status" => {
            let body: LocalBusObjectTransferStatusRequest =
                serde_json::from_value(request.body.clone())?;
            json!({"transfer":client.object_transfer_status(&body.object_id,body.direction.as_deref())?})
        }
        "object.put.status" => upload_status(client, view, request)?,
        "object.get.status" => {
            let body: LocalBusObjectGetStatusRequest =
                serde_json::from_value(request.body.clone())?;
            match view.download_status.get(&body.operation_id) {
                Some(DownloadView { status, file }) => {
                    let object = status["object_id"].as_str().ok_or(SdkError::ObjectErased)?;
                    client.account_db()?.check_object_access(object)?;
                    if file.lock().map_err(|_| SdkError::ObjectErased)?.is_none() {
                        return Err(SdkError::ObjectErased);
                    }
                    status.clone()
                }
                None => json!({"operation_id":body.operation_id,"state":"unknown"}),
            }
        }
        "mcp.audit.list" => {
            json!({"audit":client.account_db()?.load_mcp_audit::<LocalMcpAuditRecord>()?})
        }
        "message.franking_evidence" => {
            let body: LocalBusMessageFrankingEvidenceRequest =
                serde_json::from_value(request.body.clone())?;
            serde_json::to_value(client.selected_franking_evidence_for_direct_message(
                &body.conversation_id,
                &body.message_id,
            )?)?
        }
        "a2i.list" | "a2i.list_pending" => a2i(client, request.method == "a2i.list_pending")?,
        method => return Ok(view.views.get(method).cloned()),
    };
    Ok(Some(value))
}

fn status(client: &RamfluxClient, view: &AccountView) -> Result<Value, SdkError> {
    let mut status = view.status.clone();
    if view.native.is_some() {
        let now = crate::custody::network_now()?;
        let native = crate::custody::load_data_account(
            view.account_root.as_deref().ok_or(SdkError::AccountDbNotUnlocked)?,
            &client.account_db()?.local_account_id,
            now,
        )?;
        status["networking"] = serde_json::to_value(native.state())?;
        let reason = native.networking_view(now);
        status["networking_reason"] = serde_json::to_value(&reason)?;
        status.as_object_mut().ok_or(SdkError::CustodySetupInvalid)?.remove("networking_hint");
        if let Some(crate::AccountNetworkingReason::NodeBusy { capacity: Some(hint), .. }) =
            reason.as_ref().map(|view| &view.cause)
        {
            status["networking_hint"] = crate::custody::capacity_hint::message(hint).into();
        }
        let device = status["device_id"].as_str().ok_or(SdkError::CustodySetupInvalid)?;
        let authorized = !native.authority_blocked()
            && !native.branch_pending()
            && native
                .record()
                .body
                .devices
                .iter()
                .find(|entry| entry.device_id == device)
                .is_some_and(|entry| {
                    native
                        .verified()
                        .authorize(
                            &ramflux_protocol::custody::DeviceRef {
                                account_anchor: native.record().body.account_anchor.clone(),
                                device_id: entry.device_id.clone(),
                                device_epoch: entry.device_epoch,
                            },
                            "message",
                            now,
                        )
                        .is_ok()
                });
        status["local_device_authorized"] = json!(authorized);
        status["node_id"] =
            json!(client.account_db()?.load_actor_state::<String>("account/node-id")?);
    }
    if let Some(connection) = &view.connection {
        let mut snapshot = connection.snapshot();
        // The actor refreshes its cached receive status on networking observations.
        // W1 commits and ACK drains can advance the ledger between those observations,
        // so status reads need current DB watermarks even when the session stays Live.
        if let Some(receive) = &mut snapshot.receive
            && let Some(target) = status["target_delivery_id"].as_str()
        {
            let db = client.account_db()?;
            receive.committed_cursor =
                crate::bus::push_receiver::apply_w1::read_cursor(db, target)?;
            let counters = db.receive_status_counters(target)?;
            receive.ack_intents_pending = counters.ack_intents_pending;
            receive.held_entries = counters.held_entries;
        }
        if view.native.is_none() {
            status["networking"] = json!(snapshot.state);
        }
        status["session_delivery_mode"] =
            json!(if connection.session_mode().is_push() { "push" } else { "compat" });
        status["networking_snapshot"] = json!(snapshot);
        status["active_transport_kind"] = json!(snapshot.active_transport_kind);
        status["session_id"] = json!(snapshot.session_id);
    }
    Ok(status)
}

fn contacts(client: &RamfluxClient, view: &AccountView) -> Result<Value, SdkError> {
    client.with_profile_read_scope(|| {
        let mut contacts = Vec::new();
        for link in client.friend_links()? {
            let peer = if link.requester_id == view.principal || link.requester_id == view.anchor {
                &link.target_id
            } else {
                &link.requester_id
            };
            let principal = client
                .account_db()?
                .client_record("commitment", peer)?
                .and_then(|record| record["principal_id"].as_str().map(str::to_owned))
                .unwrap_or_else(|| peer.clone());
            let mut row = serde_json::to_value(link)?;
            if let Value::Object(fields) = client.contact_entry(&principal)? {
                row.as_object_mut().ok_or(crate::ContactReason::UnknownPrincipal)?.extend(fields);
            }
            contacts.push(row);
        }
        Ok(json!({"contacts":contacts}))
    })
}

fn verification(
    client: &RamfluxClient,
    view: &AccountView,
    request: &LocalBusFrame,
) -> Result<Value, SdkError> {
    let body: LocalBusContactSafetyRequest = serde_json::from_value(request.body.clone())?;
    if let Some(connection) = &view.connection {
        connection.refresh_contact_safety(&body.contact_identity_commitment);
    }
    let safety = client.contact_safety_number(&body.contact_identity_commitment)?;
    let stored = client.contact_verification_status(&body.contact_identity_commitment)?;
    Ok(
        json!({"contact_identity_commitment":body.contact_identity_commitment,"verification_state":safety.verification_state,"stored_verification_state":stored.as_ref().map_or("unverified",|record|record.verification_state.as_str()),"verified_at":stored.as_ref().map(|record|record.verified_at),"verified_by_device_id":stored.as_ref().map(|record|record.verified_by_device_id.clone()),"safety_number":safety.safety_number,"fingerprint_hex":safety.fingerprint_hex}),
    )
}

fn a2i(_client: &RamfluxClient, _pending: bool) -> Result<Value, SdkError> {
    RamfluxClient::refuse_a2i_binding_authority()
}

fn upload_status(
    client: &RamfluxClient,
    view: &AccountView,
    request: &LocalBusFrame,
) -> Result<Value, SdkError> {
    let body: LocalBusObjectPutStatusRequest = serde_json::from_value(request.body.clone())?;
    super::super::dispatch::object_status::upload_status(
        client,
        request,
        view.upload_offsets.get(&body.operation_id).copied(),
    )
}

#[cfg(test)]
mod a2i_authority_tests {
    use super::*;
    #[test]
    fn a2i_reader_refuses_before_reading_retained_rows() {
        for pending in [false, true] {
            assert!(matches!(
                a2i(&RamfluxClient::new(), pending),
                Err(SdkError::GeneratedRefused {
                    code: crate::error::GeneratedRefusalCode::Authority,
                    ..
                })
            ));
        }
    }
}

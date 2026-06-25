// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain
pub(crate) fn handle_mvp7_lifecycle_event(
    body: &[u8],
    state: &ramflux_node_core::RouterCore,
    store: &ramflux_node_core::RouterRedbStore,
) -> anyhow::Result<ramflux_node_core::ItestMvp7LifecycleResponse> {
    let request: ramflux_node_core::ItestMvp7LifecycleRequest = serde_json::from_slice(body)?;
    let response = state.mvp7_apply_lifecycle_event(&request)?;
    store.record_lifecycle_record(&response.record)?;
    if let Some(tombstone) = &response.tombstone {
        store.record_lifecycle_tombstone(tombstone)?;
    }
    Ok(response)
}

pub(crate) fn handle_mvp7_lifecycle_cancel(
    body: &[u8],
    state: &ramflux_node_core::RouterCore,
    store: &ramflux_node_core::RouterRedbStore,
) -> anyhow::Result<ramflux_node_core::ItestMvp7LifecycleResponse> {
    let request: ramflux_node_core::ItestMvp7LifecycleCancelRequest = serde_json::from_slice(body)?;
    let response = state.mvp7_cancel_delete(&request)?;
    store.record_lifecycle_record(&response.record)?;
    Ok(response)
}

pub(crate) fn handle_mvp7_lifecycle_finalize(
    body: &[u8],
    state: &ramflux_node_core::RouterCore,
    store: &ramflux_node_core::RouterRedbStore,
) -> anyhow::Result<ramflux_node_core::ItestMvp7LifecycleResponse> {
    let request: ramflux_node_core::ItestMvp7LifecycleFinalizeRequest =
        serde_json::from_slice(body)?;
    let target_delivery_id = state
        .mvp1_identities_snapshot()
        .target_delivery_id_for_principal(&request.principal_id)
        .map(str::to_owned);
    let response = state.mvp7_finalize_delete(&request)?;
    if let Some(target_delivery_id) = target_delivery_id {
        store.record_target_deleted_cleanup(
            &target_delivery_id,
            &state.mvp1_identities_snapshot(),
            &response.record,
        )?;
    } else {
        store.record_lifecycle_record(&response.record)?;
        store.record_identity_registry(&state.mvp1_identities_snapshot())?;
    }
    Ok(response)
}

pub(crate) fn handle_mvp7_lifecycle_get(
    path: &str,
    state: &ramflux_node_core::RouterCore,
) -> Option<ramflux_node_core::AccountLifecycleRecord> {
    let principal_id = path.trim_start_matches("/mvp7/lifecycle/");
    state.mvp7_lifecycle(principal_id)
}

pub(crate) fn handle_mvp7_metadata_get(
    path: &str,
    state: &ramflux_node_core::RouterCore,
) -> ramflux_node_core::ItestMvp7MetadataSummary {
    let principal_id = path.trim_start_matches("/mvp7/metadata/");
    state.mvp7_metadata_summary(principal_id)
}

pub(crate) fn handle_mvp7_federated_tombstone(
    body: &[u8],
    state: &ramflux_node_core::RouterCore,
    store: &ramflux_node_core::RouterRedbStore,
) -> anyhow::Result<ramflux_node_core::FederatedLifecycleTombstoneResponse> {
    let request: ramflux_node_core::FederatedLifecycleTombstoneRequest =
        serde_json::from_slice(body)?;
    let response = state.mvp7_apply_federated_tombstone(&request)?;
    store.record_federated_lifecycle_tombstone(
        request.tombstone.as_ref(),
        &response.target_delivery_id,
        &response.lifecycle_state,
    )?;
    Ok(response)
}

pub(crate) fn handle_mvp7_abuse_report(
    body: &[u8],
    state: &ramflux_node_core::RouterCore,
    store: &ramflux_node_core::RouterRedbStore,
) -> anyhow::Result<ramflux_node_core::AbuseReportResponse> {
    let request: ramflux_node_core::AbuseReportRequest = serde_json::from_slice(body)?;
    let response = state.mvp7_submit_abuse_report(&request)?;
    store.record_abuse_report(&response.report)?;
    Ok(response)
}

pub(crate) fn handle_mvp7_abuse_report_get(
    path: &str,
    state: &ramflux_node_core::RouterCore,
) -> Option<ramflux_node_core::AbuseReportRecord> {
    let report_id = path.trim_start_matches("/mvp7/abuse/report/");
    state.mvp7_abuse_report(report_id)
}

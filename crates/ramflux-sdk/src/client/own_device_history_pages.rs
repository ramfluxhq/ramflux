// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Authenticated continuation pages retain authority budgets without silently dropping a prefix.
use crate::{SdkError, own_device_sync::SdkOwnDeviceHistoryBundle};
use std::collections::BTreeSet;
const PAGE_BYTES: usize = 3 * 1024 * 1024;
fn empty(source: &SdkOwnDeviceHistoryBundle, n: usize) -> SdkOwnDeviceHistoryBundle {
    SdkOwnDeviceHistoryBundle {
        authority_only: true,
        next_page: None,
        schema: "ramflux.sdk.own_device_history_bundle.v2".into(),
        version: 2,
        principal_commitment: source.principal_commitment.clone(),
        source_device_id: source.source_device_id.clone(),
        target_device_id: source.target_device_id.clone(),
        snapshot_id: format!("{}:authority:{n}", source.snapshot_id),
        messages: Vec::new(),
        task_packets: Vec::new(),
        task_export_metadata: super::task::own_history::TaskExportMetadata::default(),
        surface_pages: Vec::new(),
        surface_controls: Vec::new(),
        surface_checkpoints: Vec::new(),
        surface_export_metadata: super::surface::SurfaceExportMetadata::default(),
        surface_message_epochs: std::collections::BTreeMap::default(),
        contents: std::collections::BTreeMap::default(),
        dm_sessions: Vec::new(),
        groups: Vec::new(),
        group_member_pins: Vec::new(),
        device_manifests: Vec::new(),
        accepted_contacts: Vec::new(),
        sender_key_distributions_base64: Vec::new(),
    }
}
pub(super) fn pages(
    mut bundle: SdkOwnDeviceHistoryBundle,
) -> Result<Vec<SdkOwnDeviceHistoryBundle>, SdkError> {
    if bundle.device_manifests.len() <= 512
        && bundle.accepted_contacts.len() <= 512
        && serde_json::to_vec(&(&bundle.device_manifests, &bundle.accepted_contacts))?.len()
            <= PAGE_BYTES
    {
        return Ok(vec![bundle]);
    }
    let manifests = std::mem::take(&mut bundle.device_manifests);
    let contacts = std::mem::take(&mut bundle.accepted_contacts);
    let mut output = Vec::new();
    let mut page = empty(&bundle, 0);
    let mut bytes = 0;
    for manifest in manifests {
        let size = serde_json::to_vec(&manifest)?.len();
        if size > PAGE_BYTES {
            return Err(SdkError::InboundRejected(
                "own history single authority exceeds page budget".into(),
            ));
        }
        if page.device_manifests.len() == 512 || bytes + size > PAGE_BYTES {
            output.push(page);
            page = empty(&bundle, output.len());
            bytes = 0;
        }
        bytes += size;
        page.device_manifests.push(manifest);
    }
    for contact in contacts {
        if contact.len() > PAGE_BYTES {
            return Err(SdkError::InboundRejected(
                "own history single contact exceeds page budget".into(),
            ));
        }
        if page.accepted_contacts.len() == 512 || bytes + contact.len() > PAGE_BYTES {
            output.push(page);
            page = empty(&bundle, output.len());
            bytes = 0;
        }
        bytes += contact.len();
        page.accepted_contacts.push(contact);
    }
    output.push(page);
    for page in &mut output {
        let roots = page
            .device_manifests
            .iter()
            .map(|m| m.principal_commitment.as_str())
            .collect::<BTreeSet<_>>();
        page.group_member_pins = bundle
            .group_member_pins
            .iter()
            .filter(|p| p.principal_commitment.as_deref().is_some_and(|r| roots.contains(r)))
            .cloned()
            .collect();
    }
    // All member authority is persisted before the ordinary history page is admitted.
    bundle.schema = "ramflux.sdk.own_device_history_bundle.v2".into();
    bundle.version = 2;
    output.push(bundle);
    Ok(output)
}

pub(super) struct UploadOptions<'a> {
    pub endpoint: &'a str,
    pub service_key: Option<String>,
    pub chunk_size: usize,
}

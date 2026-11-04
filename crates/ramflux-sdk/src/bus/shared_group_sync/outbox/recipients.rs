// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Local recipient selection and removal-boundary policy for group delivery.

use super::{
    Intent, RamfluxClient, RecipientCursor, SdkError, VerifiedGroupState, now_unix_timestamp,
    persist_intent,
};
pub(super) fn complete_root(
    client: &RamfluxClient,
    intent: &mut Intent,
    root: &str,
) -> Result<(), SdkError> {
    intent.cursor = Some(RecipientCursor { root: root.into(), after_device: None, complete: true });
    persist_intent(client, intent)
}
fn selected_boundary(intent: &Intent, root: &str, device: &str) -> bool {
    intent
        .terminal
        .iter()
        .any(|boundary| boundary.root == root && boundary.devices.contains(device))
}

pub(super) fn journal_failure(
    client: &RamfluxClient,
    state: &VerifiedGroupState,
    root: &str,
    name: &str,
) -> Result<(), SdkError> {
    let subject = ramflux_protocol::hash_base64url(
        "ramflux.group.delivery.subject.v1",
        &ramflux_protocol::canonical_json_bytes(&(&state.view().group_id, &root, &name))?,
    );
    let now = now_unix_timestamp();
    client.account_db()?.append_group_journal(&format!("group-device/{subject}/{}",now/300),"group.state.delivery_failed",&serde_json::json!({"group_id":state.view().group_id,"root_commitment":root,"device_id":name,"epoch":state.view().epoch,"reason":"submit_failed"}),now,&subject)?;
    Ok(())
}

pub(super) fn selected_devices(
    client: &RamfluxClient,
    intent: &Intent,
    state: &VerifiedGroupState,
    root: &str,
    manifest: crate::prekey::SdkDeviceManifestResponse,
) -> Result<Vec<crate::prekey::SdkDeviceManifestEntry>, SdkError> {
    let allowed = client.shared_group_selected_devices(state)?.remove(root).unwrap_or_default();
    let mut devices = manifest
        .devices
        .into_iter()
        .filter(|device| {
            allowed.contains(&device.device_id)
                || selected_boundary(intent, root, &device.device_id)
        })
        .collect::<Vec<_>>();
    devices.sort_by(|a, b| a.device_id.cmp(&b.device_id));
    Ok(devices)
}

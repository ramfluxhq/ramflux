// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Pinned current-member routing and sender-key distribution before each group task publication.
use super::task_transport::{Target, seal};
use crate::bus::task_delivery::Delivery;
use crate::client::task::{carrier::Carrier, invalid};
use crate::prelude::*;
use serde_json::json;
pub(super) struct Plan {
    group: String,
    pub targets: Vec<Target>,
}
pub(super) async fn plan(
    account: &LocalBusAccountState,
    conversation: &str,
    message: &str,
    group: &str,
    gateway: &GatewaySessionConfig,
) -> Result<Plan, SdkError> {
    let local = account.client.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?;
    account.client.pin_local_group_member(group)?;
    let body: LocalBusGroupSendRequest = serde_json::from_value(
        json!({"group_id":group,"conversation_id":conversation,"message_id":message,"sender_id":local.device_id,"encrypted_body_base64":""}),
    )?;
    let routes = if account.task_prepared_manifests.is_empty() {
        super::super::group_delivery::resolve_current(account, &body).await?
    } else {
        super::super::group_delivery::resolve(account, &body)?
    };
    let mut targets = Vec::new();
    for route in routes {
        let commitment = route
            .member_principal_commitment
            .as_deref()
            .ok_or_else(|| invalid("task group member root missing"))?;
        if commitment == account.principal_commitment {
            let own = account.client.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?;
            account.client.require_group_sender_pin(
                group,
                &own.principal_id,
                &account.client.device_identity_for_root(commitment, &route.member_id)?,
            )?;
            continue;
        }
        let verified = if let Some(prepared) = account.task_prepared_manifests.get(commitment) {
            prepared
                .devices
                .iter()
                .find(|device| device.device_id == route.member_id)
                .cloned()
                .ok_or_else(|| {
                    invalid("task group member is not active in the verified manifest")
                })?
        } else if let Some(federation) = &route.federation {
            let manifest = super::task_transport::fetch_federated_manifest(
                federation
                    .recipient_prekey_url
                    .as_deref()
                    .ok_or_else(|| invalid("task group federated prekey URL missing"))?,
                commitment,
            )
            .await?;
            account.client.persist_identity_directory(&manifest)?;
            for device in &manifest.devices {
                account.client.account_db()?.upsert_device_directory_entry(
                    &device.device_id,
                    &manifest.principal_commitment,
                    "task_group",
                    now_unix_timestamp(),
                )?;
            }
            manifest
                .devices
                .into_iter()
                .find(|device| device.device_id == route.member_id)
                .ok_or_else(|| {
                    invalid("task group member is not active in the verified manifest")
                })?
        } else {
            account
                .client
                .assert_manifest_active_device_cached(
                    gateway,
                    commitment,
                    &route.member_id,
                    "task_group",
                )
                .await?
        };
        account.client.require_group_sender_pin(
            group,
            &verified.principal_id,
            &account.client.device_identity_for_root(commitment, &verified.device_id)?,
        )?;
        targets.push(Target {
            identity: account.client.device_identity_for_root(commitment, &verified.device_id)?,
            device: verified.device_id,
            delivery: verified.target_delivery_id,
            federation: route.federation,
            own: false,
        });
    }
    Ok(Plan { group: group.into(), targets })
}
pub(super) async fn prepare(
    account: &LocalBusAccountState,
    engine: &mut GatewaySessionEngine,
    c: &Carrier,
    plan: Plan,
) -> Result<Vec<Delivery>, SdkError> {
    let encrypted = account.client.encrypt_group_message(&plan.group, &c.device_id, &c.bytes()?)?;
    let distribution =
        account.client.export_group_sender_key_distribution(&plan.group, &c.device_id)?;
    let wrapper = serde_json::to_vec(
        &json!({"schema":"ramflux.sdk.group_sender_key.distribution_envelope.v1","version":1,"membership_event_base64":null,"actor_manifest_url":null,"distribution_base64":ramflux_protocol::encode_base64url(distribution)}),
    )?;
    let mut deliveries = Vec::new();
    for target in plan.targets {
        let conversation = group_sender_key_distribution_conversation_id(
            &plan.group,
            &c.device_id,
            &target.device,
        );
        deliveries.push(
            seal(
                account,
                engine,
                &target,
                &conversation,
                &wrapper,
                crate::client::routed::Route::group_control(&plan.group),
            )
            .await?,
        );
        deliveries.push(
            seal(
                account,
                engine,
                &target,
                &c.conversation_id,
                &encrypted,
                crate::client::routed::Route::group_message(&plan.group),
            )
            .await?,
        );
    }
    Ok(deliveries)
}

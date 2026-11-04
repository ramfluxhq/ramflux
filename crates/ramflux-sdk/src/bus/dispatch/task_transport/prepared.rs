// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Local-only fanout drafts after the independent task manifest preparation stage.

use super::{Mode, Target, check_preparation_budget, delivery_route, invalid, own_payloads};
use crate::client::routed::{SendMaterial, SendMaterialRequest};
use crate::client::task::carrier::Carrier;
use crate::prelude::*;
use serde_json::Value;

pub(in crate::bus) struct Draft {
    pub target: Target,
    pub request: SendMaterialRequest,
    config: GatewaySessionConfig,
    message: GatewayDirectMessage,
    route: crate::client::routed::Route,
    body: zeroize::Zeroizing<Vec<u8>>,
}
impl Draft {
    pub(in crate::bus) fn new(
        account: &LocalBusAccountState,
        target: Target,
        conversation: &str,
        body: &[u8],
        route: crate::client::routed::Route,
    ) -> Result<Self, SdkError> {
        let local = account.client.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?;
        let id = crate::new_surface_message_id()?;
        let message = GatewayDirectMessage {
            conversation_id: conversation.into(),
            message_id: id.clone(),
            envelope_id: id,
            source_principal_id: local.principal_id.clone(),
            sender_id: local.device_id.clone(),
            recipient_device_id: Some(target.device.clone()),
            recipient_principal_commitment: Some(target.identity.root_commitment().into()),
            target_delivery_id: target.delivery.clone(),
            encrypted_body: Vec::new(),
            created_at: now_unix_timestamp(),
            ttl: 3600,
        };
        let config = account.gateway_config.clone();
        let request = account.client.routed_send_material_request(&config, &message)?;
        Ok(Self {
            target,
            request,
            config,
            message,
            route,
            body: zeroize::Zeroizing::new(body.to_vec()),
        })
    }
    pub(in crate::bus) fn seal(
        mut self,
        account: &LocalBusAccountState,
        material: SendMaterial,
    ) -> Result<ramflux_protocol::Envelope, SdkError> {
        let sealed = account.client.seal_routed_prepared(
            &self.config,
            &self.message,
            &self.body,
            self.route,
            material,
        )?;
        self.message.encrypted_body = serde_json::to_vec(&sealed)?;
        crate::dm::gateway_direct_message_envelope(&self.config, &self.message, None)
    }
}
pub(in crate::bus) fn own_targets(account: &LocalBusAccountState) -> Result<Vec<Target>, SdkError> {
    let manifest = account
        .task_prepared_manifests
        .get(&account.principal_commitment)
        .ok_or(SdkError::TaskManifestWorkerCapacity)?
        .clone();
    super::own_targets_from_manifest(account, manifest)
}
pub(in crate::bus) fn peers(
    account: &LocalBusAccountState,
    conversation: &str,
    message: &str,
    thread: &Value,
) -> Result<Vec<Target>, SdkError> {
    if let Some(group) = thread["group_id"].as_str() {
        Ok(super::super::task_group::prepared_plan(account, conversation, message, group)?.targets)
    } else {
        let input = super::direct_target_input(account, thread)?;
        let manifest = account
            .task_prepared_manifests
            .get(&input.root)
            .ok_or(SdkError::TaskManifestWorkerCapacity)?
            .clone();
        super::direct_targets_from_manifest(account, thread, manifest)
    }
}
pub(in crate::bus) fn controls(
    account: &LocalBusAccountState,
    carrier: &Carrier,
    thread: &Value,
    mode: Mode<'_>,
) -> Result<Vec<Draft>, SdkError> {
    if !account.task_prepared_only {
        return Err(invalid("prepared task transport requires manifest snapshot"));
    }
    let mut targets = own_targets(account)?;
    let peers = if matches!(mode, Mode::Own) {
        Vec::new()
    } else {
        peers(account, &carrier.conversation_id, &carrier.message_id, thread)?
    };
    let body = match &mode {
        Mode::Ack(ack) => {
            crate::client::task::control::Control::Ack(Box::new((*ack).clone())).bytes()?
        }
        Mode::Own => carrier.bytes()?,
        Mode::Event => return Err(invalid("background task transport requires a control")),
    };
    let (pages, original) = if targets.is_empty() {
        (Vec::new(), false)
    } else {
        own_payloads(&account.client, carrier, &body, &mode)?
    };
    crate::client::task::check_delivery_size(body.len())?;
    check_preparation_budget(Some(&pages), targets.len(), 0, peers.len(), body.len())?;
    targets.extend(peers);
    let mut drafts = Vec::new();
    for target in targets {
        let route = delivery_route(
            &target,
            matches!(mode, Mode::Ack(_)),
            original,
            thread["group_id"].as_str(),
        );
        if target.own {
            for page in &pages {
                drafts.push(Draft::new(
                    account,
                    target.clone(),
                    &carrier.conversation_id,
                    page,
                    route.clone(),
                )?);
            }
        } else {
            drafts.push(Draft::new(account, target, &carrier.conversation_id, &body, route)?);
        }
    }
    Ok(drafts)
}

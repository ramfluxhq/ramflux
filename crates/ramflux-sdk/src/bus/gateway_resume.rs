// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Cancelled gateway operations preserve resume metadata without restoring old authority.

use crate::prelude::*;

pub(super) struct Snapshot {
    identity: Option<ramflux_crypto::RootQualifiedDeviceRef>,
    config: GatewaySessionConfig,
}

impl Snapshot {
    pub(super) fn capture(account: &LocalBusAccountState) -> Self {
        Self {
            identity: account.client.owned_device_identity().ok(),
            config: account
                .engine
                .as_ref()
                .map_or_else(|| account.gateway_config.clone(), |engine| engine.config.clone()),
        }
    }

    pub(super) fn retire(self, account: &mut LocalBusAccountState) -> Result<(), SdkError> {
        account.persist_push_route_seq();
        // Remove before fallible persistence, and drop on every exit, including storage failure.
        let engine = account.engine.take();
        let candidate = engine.as_ref().map_or(&self.config, |engine| &engine.config);
        let unchanged = self.identity.is_some()
            && self.identity == account.client.owned_device_identity().ok()
            && same_route(&self.config, &account.gateway_config)
            && same_route(candidate, &account.gateway_config);
        let result = account.checkpoint_gateway_resume_from(if unchanged {
            candidate
        } else {
            &account.gateway_config
        });
        // Only the checkpoint's session/token/cursor are written. The current identity,
        // custody, signing and route configuration are never replaced by the snapshot.
        drop(engine);
        result
    }
}

fn same_route(left: &GatewaySessionConfig, right: &GatewaySessionConfig) -> bool {
    left.device_epoch == right.device_epoch
        && left.target_delivery_id == right.target_delivery_id
        && left.gateway_addr == right.gateway_addr
}

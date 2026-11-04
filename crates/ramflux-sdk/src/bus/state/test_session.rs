// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Fixture-only injection of a transport seed or an existing managed capability.

use super::LocalBusAccountState;
use crate::GatewaySessionEngine;
use crate::bus::connection_manager::{DisconnectReason, SessionClient};

pub(crate) enum TestSession {
    Seed(Box<GatewaySessionEngine>),
    Managed(Box<SessionClient>),
}
impl From<GatewaySessionEngine> for TestSession {
    fn from(engine: GatewaySessionEngine) -> Self {
        Self::Seed(Box::new(engine))
    }
}
impl From<SessionClient> for TestSession {
    fn from(client: SessionClient) -> Self {
        Self::Managed(Box::new(client))
    }
}

impl LocalBusAccountState {
    pub(crate) fn install_test_session(&mut self, session: impl Into<TestSession>) {
        match session.into() {
            TestSession::Seed(engine) => {
                if let Some(previous) = self.connection.take() {
                    previous.request_stop(DisconnectReason::Restart);
                }
                self.gateway_config = engine.config.clone();
                self.target_delivery_id = engine.target_delivery_id().into();
                self.engine = Some(*engine);
                self.persist_push_route_seq();
                self.forget_confirmed_push_clear();
            }
            TestSession::Managed(client) => self.apply_session_metadata(*client),
        }
    }
}

// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Transport selection remains outside the resident connection manager.

use super::engine::{GatewaySessionClientTransport, open_gateway_session_transport};
use super::{GatewaySessionConfig, GatewaySessionTransportKind};
use crate::SdkError;
use ramflux_transport::GatewaySessionTransport;
use std::{future::Future, pin::Pin, time::Duration};

pub(crate) type OpenedTransport = (
    GatewaySessionClientTransport,
    Box<dyn GatewaySessionTransport + Send>,
    GatewaySessionTransportKind,
);
pub(crate) type OpenFuture<'a> =
    Pin<Box<dyn Future<Output = Result<OpenedTransport, SdkError>> + Send + 'a>>;

pub(crate) trait TransportOpener: Send + Sync {
    fn open(&self, config: GatewaySessionConfig, timeout: Duration) -> OpenFuture<'_>;
}
pub(crate) struct ConfiguredTransport;
impl TransportOpener for ConfiguredTransport {
    fn open(&self, config: GatewaySessionConfig, timeout: Duration) -> OpenFuture<'_> {
        Box::pin(async move {
            tokio::time::timeout(timeout, open_gateway_session_transport(&config)).await.map_err(
                |_| SdkError::NodeTimeout { retry_after_ms: crate::node::NODE_RETRY_AFTER_MS },
            )?
        })
    }
}

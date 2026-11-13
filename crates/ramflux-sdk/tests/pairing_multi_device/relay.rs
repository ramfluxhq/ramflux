// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Real node-owned relay store with closed wire round trips and an explicit clock.
use super::node::Node;
use ramflux_protocol::custody::pairing::{PairingWire, relay::*};
use ramflux_sdk::{SdkError, custody::pairing::PairingTransport};
use std::{future::Future, pin::Pin, sync::Arc};
type Reply<T> = Pin<Box<dyn Future<Output = Result<T, SdkError>> + std::marker::Send>>;
pub struct Relay(pub Arc<Node>);
fn error(value: ramflux_node_core::pairing_relay::PairingRelayError) -> SdkError {
    SdkError::PairingCode(value.code())
}
fn wire<T: PairingWire>(value: &T) -> Result<T, SdkError> {
    let bytes = value.to_wire_bytes().map_err(|_| SdkError::PairingCode("InvalidInput"))?;
    T::from_wire_bytes(&bytes).map_err(|_| SdkError::PairingCode("InvalidInput"))
}
impl PairingTransport for Relay {
    fn claim(&self, _origin: String, value: Claim) -> Reply<Claimed> {
        let node = self.0.clone();
        Box::pin(async move {
            let value = wire(&value)?;
            wire(
                &node
                    .relay
                    .lock()
                    .map_err(|_| SdkError::PairingCode("Busy"))?
                    .claim(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), &value)
                    .map_err(error)?,
            )
        })
    }
    fn send(&self, _origin: String, value: Send) -> Reply<Sent> {
        let node = self.0.clone();
        Box::pin(async move {
            let value = wire(&value)?;
            wire(
                &node
                    .relay
                    .lock()
                    .map_err(|_| SdkError::PairingCode("Busy"))?
                    .send(&value)
                    .map_err(error)?,
            )
        })
    }
    fn poll(&self, _origin: String, value: Poll) -> Reply<Polled> {
        let node = self.0.clone();
        Box::pin(async move {
            let value = wire(&value)?;
            wire(
                &node
                    .relay
                    .lock()
                    .map_err(|_| SdkError::PairingCode("Busy"))?
                    .poll(&value)
                    .map_err(error)?,
            )
        })
    }
    fn close(&self, _origin: String, value: Close) -> Reply<Closed> {
        let node = self.0.clone();
        Box::pin(async move {
            let value = wire(&value)?;
            wire(
                &node
                    .relay
                    .lock()
                    .map_err(|_| SdkError::PairingCode("Busy"))?
                    .close(&value)
                    .map_err(error)?,
            )
        })
    }
}

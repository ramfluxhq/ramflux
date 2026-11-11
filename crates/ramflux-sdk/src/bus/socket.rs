// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Remove only the socket inode owned by this listener.

use crate::platform::listener::{BusListener, EndpointId};
use crate::prelude::*;

pub(super) struct SocketFile {
    endpoint: EndpointId,
}
impl SocketFile {
    pub(super) fn new<L: BusListener>(listener: &L) -> Result<Option<Self>, SdkError> {
        Ok(listener.endpoint()?.map(|endpoint| Self { endpoint }))
    }
    pub(super) fn remove(&self) -> Result<(), SdkError> {
        self.endpoint.remove_if_unchanged()
    }
}
impl Drop for SocketFile {
    fn drop(&mut self) {
        if let Err(error) = self.remove() {
            tracing::warn!(%error,"daemon socket cleanup failed");
        }
    }
}

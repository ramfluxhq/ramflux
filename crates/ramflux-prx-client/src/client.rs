// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! The client handle. Each route group adds its methods in its own module.

use crate::error::PrxError;
use crate::transport::{ClientConfig, Transport};

/// A typed client for one PRX daemon.
pub struct PrxClient {
    pub(crate) transport: Transport,
}

impl PrxClient {
    /// Builds a client. Refuses a non-loopback base URL, a token file whose mode is not
    /// 0600 (Unix) and an unreadable or empty token. No request is sent.
    ///
    /// # Errors
    /// Returns `PrxError::Config` for any refused setting.
    pub fn new(config: &ClientConfig) -> Result<Self, PrxError> {
        Ok(Self { transport: Transport::new(config)? })
    }
}

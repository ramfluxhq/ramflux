// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Owned, authenticated consent-history request; it never carries an account database.

use crate::{GatewaySessionConfig, SdkError};
use ramflux_protocol::custody::Publication;

pub(crate) enum NativeContactHistory {
    Ready(Box<Publication>),
    Fetch(String),
}
impl NativeContactHistory {
    pub(crate) async fn resolve(
        self,
        gateway: &GatewaySessionConfig,
    ) -> Result<Publication, SdkError> {
        match self {
            Self::Ready(publication) => Ok(*publication),
            Self::Fetch(path) => {
                crate::prekey::sdk_gateway_get_json::<Option<Publication>>(gateway, &path)
                    .await?
                    .ok_or_else(|| {
                        SdkError::ContactUnavailable(Box::new(SdkError::InboundPending(
                            "signed consent authority is unavailable".into(),
                        )))
                    })
            }
        }
    }
}

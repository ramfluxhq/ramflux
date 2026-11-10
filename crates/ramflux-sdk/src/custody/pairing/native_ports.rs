// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Existing authenticated native publication and public native directory query adapters.

use super::{NodeHeadPersist, PairingAuthorityQuery, PairingNative};
use crate::{GatewaySessionConfig, SdkError};
use ramflux_protocol::custody::{CustodyAuthority, Publication};
use std::sync::Arc;

/// Publication is called on the blocking local prepare/apply worker, after all file locks end.
pub struct NativePairingPublication {
    pub native: Arc<dyn PairingNative>,
    pub runtime: tokio::runtime::Handle,
}

impl NodeHeadPersist for NativePairingPublication {
    fn persist_head(&self, publication: &Publication, _now: u64) -> Result<String, SdkError> {
        self.runtime.block_on(self.native.publish(publication.clone()))
    }
}

/// The existing root-free native manifest read; never registers or opens an ordinary session.
pub struct NativePairingQuery {
    pub config: GatewaySessionConfig,
    pub runtime: tokio::runtime::Handle,
}

impl PairingAuthorityQuery for NativePairingQuery {
    fn current_authority(&self, anchor: &str) -> Result<CustodyAuthority, SdkError> {
        if self.config.custody.is_none() || anchor.len() != 43 {
            return Err(SdkError::PairingCode("WrongContext"));
        }
        let path = format!("/mvp1/device-manifest/{anchor}");
        let response: crate::prekey::SdkDeviceManifestResponse =
            self.runtime.block_on(crate::prekey::sdk_gateway_get_json(&self.config, &path))?;
        let native = response.custody.ok_or(SdkError::PairingCode("UpdateRequired"))?;
        let authority = CustodyAuthority {
            publication: native.publication,
            custodian_publication: native.custodian_publication,
        };
        let verified = ramflux_crypto::custody::verify_publication(
            &authority,
            crate::custody::network_now()?,
        )?;
        if verified.envelope().body.account_anchor != anchor {
            return Err(SdkError::PairingCode("WrongContext"));
        }
        Ok(authority)
    }
}

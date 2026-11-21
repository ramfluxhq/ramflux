// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! `GET /api/owner` (`owner_id_stable_v1`): the install owner id every paired bearer acts for.

use crate::capabilities::{Capabilities, OWNER_ID_STABLE_V1, require};
use crate::client::PrxClient;
use crate::error::{PrxError, config, decode_ok, protocol};
use reqwest::Method;
use serde::Deserialize;

const OWNER_PREFIX: &str = "api:install:";

/// The install owner id: `api:install:<32 lowercase hex>`. Not a secret.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnerId(String);

impl OwnerId {
    /// Parses the owner id text. Anything but the documented form is refused.
    ///
    /// # Errors
    /// Returns `PrxError::Config` when the text is not `api:install:` followed by 32 lowercase hex.
    pub fn parse(raw: &str) -> Result<Self, PrxError> {
        let hex = raw.strip_prefix(OWNER_PREFIX).unwrap_or("");
        let valid = hex.len() == 32 && hex.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'));
        if valid {
            Ok(Self(raw.to_owned()))
        } else {
            Err(config("owner id is not api:install:<32 lowercase hex>"))
        }
    }

    /// The owner id text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireOwner {
    owner_id: String,
}

impl PrxClient {
    /// Reads the install owner id for this paired bearer. Needs `owner_id_stable_v1`.
    ///
    /// # Errors
    /// Returns `Unsupported`, the API error (`auth_failed` without a paired bearer), or a
    /// transport or contract error. An owner id that is not the documented form is a contract
    /// violation.
    pub async fn owner_id(&self, caps: &Capabilities) -> Result<OwnerId, PrxError> {
        require(caps, OWNER_ID_STABLE_V1)?;
        let raw = self.transport.call(Method::GET, "/api/owner", None, None).await?;
        let wire: WireOwner = decode_ok(&raw.body)?;
        OwnerId::parse(&wire.owner_id).map_err(|_| protocol("owner_id has the wrong form"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const HEX: &str = "0123456789abcdef0123456789abcdef";

    #[test]
    fn accepts_the_documented_form_only() {
        let good = format!("{OWNER_PREFIX}{HEX}");
        assert_eq!(OwnerId::parse(&good).map(|o| o.as_str().to_owned()), Ok(good.clone()));
        for bad in [
            "api:local".to_owned(),
            format!("api:install:{}", HEX.to_uppercase()),
            format!("api:install:{}", &HEX[..31]),
            format!("api:install:{HEX}0"),
            format!("api:{HEX}"),
            format!("api:install:{HEX}\n"),
            String::new(),
        ] {
            assert!(OwnerId::parse(&bad).is_err(), "refused: {bad:?}");
        }
    }
}

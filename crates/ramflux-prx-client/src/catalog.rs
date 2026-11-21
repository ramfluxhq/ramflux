// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! `GET /api/agents/catalog`: models with credential readiness, tools, reserved names.

use crate::autonomy::Autonomy;
use crate::client::PrxClient;
use crate::error::{decode_ok, PrxError};
use crate::revision::CatalogRevision;
use reqwest::Method;
use serde::Deserialize;
use std::collections::BTreeSet;

/// The catalog body, with exactly the top-level fields of the token document.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Catalog {
    pub prx_version: String,
    /// Catalog revision. It is never a config revision and never matches an agent route.
    pub revision: CatalogRevision,
    pub capabilities: BTreeSet<String>,
    pub models: Vec<CatalogModel>,
    pub tools: Vec<CatalogTool>,
    pub reserved_names: Vec<String>,
    /// Main's effective autonomy level.
    pub defaults_autonomy: Autonomy,
    pub caller_reserved_session_key_prefixes: Vec<String>,
    pub reserved_session_key_prefixes: Vec<String>,
}

/// One chat-capable model row. `credentials_ready: None` means unknown, which is treated as not ready.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CatalogModel {
    pub provider: String,
    pub model: String,
    #[serde(default)]
    pub credentials_ready: Option<bool>,
}

/// One tool on Main's published surface.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CatalogTool {
    pub name: String,
    pub read_only: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireDefaults {
    autonomy: Autonomy,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireCatalog {
    prx_version: String,
    revision: CatalogRevision,
    capabilities: BTreeSet<String>,
    models: Vec<CatalogModel>,
    tools: Vec<CatalogTool>,
    reserved_names: Vec<String>,
    defaults: WireDefaults,
    reserved_session_key_prefixes: Vec<String>,
    caller_reserved_session_key_prefixes: Vec<String>,
}

impl Catalog {
    pub(crate) fn from_body(body: &[u8]) -> Result<Self, PrxError> {
        let wire: WireCatalog = decode_ok(body)?;
        Ok(Self {
            prx_version: wire.prx_version,
            revision: wire.revision,
            capabilities: wire.capabilities,
            models: wire.models,
            tools: wire.tools,
            reserved_names: wire.reserved_names,
            defaults_autonomy: wire.defaults.autonomy,
            caller_reserved_session_key_prefixes: wire.caller_reserved_session_key_prefixes,
            reserved_session_key_prefixes: wire.reserved_session_key_prefixes,
        })
    }
}

impl PrxClient {
    /// Reads the model and tool catalog. Needs no capability (it is the discovery route).
    ///
    /// # Errors
    /// Returns the transport, API or contract error of the call.
    pub async fn catalog(&self) -> Result<Catalog, PrxError> {
        let raw = self
            .transport
            .call(Method::GET, "/api/agents/catalog", None, None)
            .await?;
        Catalog::from_body(&raw.body)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const HEX: &str = "c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3";

    fn body(extra_top: &str, autonomy: &str, revision: &str) -> String {
        format!(
            r#"{{"prx_version":"0.8.171","revision":"{revision}","capabilities":["agent_catalog_v1","agent_crud_v1"],"models":[{{"provider":"ollama","model":"codellama","credentials_ready":true}},{{"provider":"openai","model":"gpt-x"}}],"tools":[{{"name":"read_file","read_only":true}}],"reserved_names":["catalog","main"],"defaults":{{"autonomy":"{autonomy}"}},"reserved_session_key_prefixes":["console-"],"caller_reserved_session_key_prefixes":["rf-"]{extra_top}}}"#
        )
    }

    #[test]
    fn decodes_documented_shape() {
        let catalog = Catalog::from_body(body("", "full", HEX).as_bytes()).expect("test: documented shape decodes");
        assert_eq!(catalog.defaults_autonomy, Autonomy::Full);
        assert_eq!(catalog.revision.as_str(), HEX);
        assert_eq!(catalog.models.first().and_then(|m| m.credentials_ready), Some(true));
        assert_eq!(catalog.models.get(1).map(|m| m.credentials_ready), Some(None), "missing key is unknown");
        assert_eq!(catalog.reserved_names, ["catalog", "main"]);
        assert_eq!(catalog.caller_reserved_session_key_prefixes, ["rf-"]);
    }

    #[test]
    fn unknown_top_level_field_fails_closed() {
        let bad = body(r#","limits":{}"#, "full", HEX);
        assert!(matches!(Catalog::from_body(bad.as_bytes()), Err(PrxError::Protocol { .. })));
    }

    #[test]
    fn unknown_autonomy_fails_closed() {
        let bad = body("", "read_only", HEX);
        assert!(matches!(Catalog::from_body(bad.as_bytes()), Err(PrxError::Protocol { .. })));
    }

    #[test]
    fn non_hex_catalog_revision_fails_closed() {
        let bad = body("", "full", "C3C3");
        assert!(matches!(Catalog::from_body(bad.as_bytes()), Err(PrxError::Protocol { .. })));
    }
}

// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::wildcard_imports)]
use crate::prelude::*;

impl RamfluxClient {
    pub fn install_mcp_tool(&mut self, manifest: McpToolManifest) {
        self.mcp_registry.install_tool(manifest);
    }

    #[must_use]
    pub fn mcp_registry_hash(&self) -> &str {
        self.mcp_registry.registry_hash()
    }

    #[must_use]
    pub fn mcp_tool_manifest_set_hash(&self) -> &str {
        self.mcp_registry.tool_manifest_set_hash()
    }

    /// # Errors
    /// Returns an error when validation, serialization, storage, or state checks fail.
    pub fn invoke_mcp_tool(
        &self,
        server_id: &str,
        tool_name: &str,
        grant: &McpGrantState,
    ) -> Result<String, SdkError> {
        Ok(self.mcp_registry.invoke_tool(server_id, tool_name, grant)?)
    }

    /// # Errors
    /// Returns an error when validation, serialization, storage, or state checks fail.
    pub fn render_a2ui_surface(
        &self,
        surface: &A2uiSurface,
        supported_catalogs: &BTreeSet<String>,
        granted_permissions: &BTreeSet<String>,
    ) -> Result<RenderedSurface, SdkError> {
        Ok(ramflux_sync::render_a2ui_surface(surface, supported_catalogs, granted_permissions)?)
    }
}

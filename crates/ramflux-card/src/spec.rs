// SPDX-License-Identifier: BSD-3-Clause
//! Authorized snapshot envelope. Authentication remains the caller SDK's responsibility.
use crate::{CardError, Tree};
use ramflux_protocol::a2ui::{
    DisplayLocale, ResolvedSurface, SurfaceDrafts, SurfaceSnapshot, SurfaceState,
};
use serde::{Deserialize, Serialize};
pub(crate) const MAX_INPUT: usize = 32 * 1024;
pub(crate) const MAX_JSON_DEPTH: usize = 32;
pub(crate) const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;
/// Only an independently authorized SDK read may populate this envelope.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CardSpec {
    pub conversation_id: String,
    pub author_principal_id: String,
    pub surface_ref: String,
    pub signed_version: u64,
    pub signed_hash: String,
    pub render_allowed: bool,
    pub snapshot: SurfaceSnapshot,
    #[serde(skip)]
    pub(crate) host: Option<crate::Presentation>,
    #[serde(skip)]
    pub(crate) drafts: SurfaceDrafts,
    #[serde(skip)]
    pub(crate) render_tree: Option<Tree>,
}
/// Check raw byte/depth limits before deserialization allocates any values.
pub(crate) fn preflight(bytes: &[u8], max: usize) -> Result<(), CardError> {
    if bytes.len() > max {
        return Err(CardError::Limit("JSON bytes"));
    }
    let (mut depth, mut quoted, mut escaped) = (0_usize, false, false);
    for b in bytes {
        if quoted {
            if escaped {
                escaped = false;
            } else if *b == b'\\' {
                escaped = true;
            } else if *b == b'"' {
                quoted = false;
            }
        } else {
            match b {
                b'"' => quoted = true,
                b'{' | b'[' => {
                    depth += 1;
                    if depth > MAX_JSON_DEPTH {
                        return Err(CardError::Limit("JSON depth"));
                    }
                }
                b'}' | b']' => {
                    depth = depth.checked_sub(1).ok_or(CardError::Invalid("JSON depth"))?;
                }
                _ => {}
            }
        }
    }
    Ok(())
}

impl CardSpec {
    /// Parse a bounded I-JSON session envelope, never a raw peer snapshot.
    /// # Errors
    /// Refuses noncanonical numbers, duplicate keys, unauthorized or invalid state.
    pub fn parse(bytes: &[u8]) -> Result<Self, CardError> {
        preflight(bytes, MAX_INPUT)?;
        let spec: Self = ramflux_protocol::parse_i_json(bytes)
            .map_err(|_| CardError::Invalid("I-JSON envelope"))?;
        spec.state()?;
        if spec.render_allowed && !spec.snapshot.closed {
            spec.validate()?;
        }
        Ok(spec)
    }
    pub(crate) fn presentation(&self) -> Result<crate::Presentation, CardError> {
        self.host.clone().map_or_else(|| crate::Presentation::bundled("en", false), Ok)
    }
    /// Supply host-owned presentation separately from signed/peer state.
    /// # Errors
    /// Refuses unsupported locales, incomplete or excessive theme catalogs.
    pub fn with_presentation(
        mut self,
        presentation: crate::Presentation,
    ) -> Result<Self, CardError> {
        presentation.validate()?;
        self.host = Some(presentation);
        Ok(self)
    }
    /// Reconstruct admitted signed state and verify its exact commitment.
    /// # Errors
    /// Refuses mismatched or invalid signed snapshots; session admission checks authority.
    pub fn state(&self) -> Result<SurfaceState, CardError> {
        if self.surface_ref != self.snapshot.surface_id
            || self.author_principal_id.is_empty()
            || self.author_principal_id.len() > 256
            || self.signed_version == 0
            || self.signed_version > MAX_SAFE_INTEGER
        {
            return Err(CardError::Invalid("session envelope"));
        }
        let state = SurfaceState::from_authorized_snapshot(
            &self.conversation_id,
            self.signed_version,
            self.snapshot.clone(),
        )?;
        if state.hash() != Some(self.signed_hash.as_str()) {
            return Err(CardError::Invalid("signed hash"));
        }
        Ok(state)
    }
    pub(crate) fn validate(&self) -> Result<(), CardError> {
        if !self.render_allowed || self.snapshot.closed {
            return Err(CardError::Inactive);
        }
        self.state()?;
        self.presentation()?.validate()?;
        if serde_json::to_vec(self)?.len() > MAX_INPUT {
            return Err(CardError::Limit("session envelope"));
        }
        if self.drafts.len() > 32 || serde_json::to_vec(&self.drafts)?.len() > 4096 {
            return Err(CardError::Limit("draft overlay"));
        }
        self.resolved()?;
        Ok(())
    }
    pub(crate) fn resolved(&self) -> Result<ResolvedSurface, CardError> {
        let locale = DisplayLocale::parse(&self.presentation()?.locale)?;
        Ok(self.snapshot.resolve_for_locale(&self.drafts, locale)?)
    }
    pub(crate) fn render_input(&self) -> Result<String, CardError> {
        let tree =
            self.render_tree.clone().map_or_else(|| crate::projection::expected(self), Ok)?;
        Ok(serde_json::to_string(&tree)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_closed_props_and_limits() {
        let input = include_str!("../fixtures/form.json");
        for candidate in [
            input.replace(
                "\"render_allowed\":true",
                "\"render_allowed\":true,\"render_allowed\":false",
            ),
            input.replacen('{', "{\"script\":0,", 1),
            input.replace("/name", "https://example.invalid/name"),
        ] {
            assert!(
                CardSpec::parse(candidate.as_bytes()).is_err(),
                "duplicate keys, unknown fields and nonlocal input bindings must reject"
            );
        }
        let mut spec = crate::runtime::tests::fixture();
        spec.snapshot.components = vec![spec.snapshot.components[0].clone(); 33];
        assert!(spec.validate().is_err(), "component limits must reject before allocating a VM");
        assert!(
            preflight(&[b'['; MAX_JSON_DEPTH + 1], MAX_INPUT).is_err(),
            "bound JSON recursion before parsing"
        );
    }
}

use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

use crate::SyncError;

pub const A2UI_ACTION_SIGNING_BODY_SCHEMA: &str = "ramflux.a2ui.action_signing_body.v1";

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct A2uiComponent {
    pub id: String,
    pub component_type: String,
    #[serde(default)]
    pub action_permission: Option<String>,
    #[serde(default)]
    pub children: Vec<A2uiComponent>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct A2uiSurface {
    pub surface_id: String,
    pub catalog: String,
    pub catalog_version: String,
    pub components: Vec<A2uiComponent>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RenderedSurface {
    pub semantic_snapshot: String,
    pub fallback_used: bool,
    pub surface_hash: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct A2uiAction {
    pub surface_id: String,
    pub surface_hash: String,
    pub component_id: String,
    pub permission: String,
    pub source_device_id: String,
    pub target_device_id: String,
    pub created_at: i64,
    pub nonce: String,
    #[serde(default)]
    pub signature: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct A2uiActionSigningBody {
    pub schema: String,
    pub surface_id: String,
    pub surface_hash: String,
    pub component_id: String,
    pub permission: String,
    pub source_device_id: String,
    pub target_device_id: String,
    pub created_at: i64,
    pub nonce: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct A2iControlEvent {
    pub event_id: String,
    pub event_type: String,
    pub source_device_id: String,
    pub target_device_id: String,
    pub control_domain: String,
    pub action: String,
    pub subject_base64: String,
    pub created_at: i64,
    pub acknowledged: bool,
}

/// # Errors
/// Returns an error when validation, serialization, storage, or state checks fail.
pub fn render_a2ui_surface(
    surface: &A2uiSurface,
    supported_catalogs: &BTreeSet<String>,
    granted_permissions: &BTreeSet<String>,
) -> Result<RenderedSurface, SyncError> {
    let fallback_used = !supported_catalogs.contains(&surface.catalog)
        || contains_unknown_component(&surface.components);
    if component_depth(&surface.components) > 8 || component_count(&surface.components) > 64 {
        return Err(SyncError::A2uiRejected);
    }
    for component in &surface.components {
        verify_component_permission(component, granted_permissions)?;
    }
    let semantic_snapshot = serde_json::to_string(surface)?;
    let surface_hash = a2ui_surface_hash(surface)?;
    Ok(RenderedSurface { semantic_snapshot, fallback_used, surface_hash })
}

/// # Errors
/// Returns an error when canonical surface encoding fails.
pub fn a2ui_surface_hash(surface: &A2uiSurface) -> Result<String, SyncError> {
    Ok(ramflux_crypto::blake3_256_base64url(
        ramflux_protocol::domain::A2I_CONTROL,
        &ramflux_protocol::canonical_json_bytes(surface)?,
    ))
}

/// # Errors
/// Returns an error when the action does not match the surface hash, component, or permission.
pub fn verify_a2ui_action(surface: &A2uiSurface, action: &A2uiAction) -> Result<(), SyncError> {
    if action.surface_id != surface.surface_id || action.surface_hash != a2ui_surface_hash(surface)?
    {
        return Err(SyncError::A2uiRejected);
    }
    if component_has_action_permission(
        &surface.components,
        &action.component_id,
        &action.permission,
    ) {
        Ok(())
    } else {
        Err(SyncError::A2uiRejected)
    }
}

#[must_use]
pub fn a2ui_action_signing_body(action: &A2uiAction) -> A2uiActionSigningBody {
    A2uiActionSigningBody {
        schema: A2UI_ACTION_SIGNING_BODY_SCHEMA.to_owned(),
        surface_id: action.surface_id.clone(),
        surface_hash: action.surface_hash.clone(),
        component_id: action.component_id.clone(),
        permission: action.permission.clone(),
        source_device_id: action.source_device_id.clone(),
        target_device_id: action.target_device_id.clone(),
        created_at: action.created_at,
        nonce: action.nonce.clone(),
    }
}

/// # Errors
/// Returns an error when the action binding or device-branch signature is invalid.
pub fn verify_a2ui_action_signature(
    surface: &A2uiSurface,
    action: &A2uiAction,
    device_public_key_base64url: &str,
) -> Result<(), SyncError> {
    verify_a2ui_action(surface, action)?;
    if action.signature.is_empty() {
        return Err(SyncError::A2uiRejected);
    }
    let body = a2ui_action_signing_body(action);
    ramflux_crypto::verify_device_branch_signature(
        device_public_key_base64url,
        &body,
        &action.signature,
    )
    .map_err(|_error| SyncError::A2uiRejected)
}

fn contains_unknown_component(components: &[A2uiComponent]) -> bool {
    components.iter().any(|component| {
        !matches!(
            component.component_type.as_str(),
            "text"
                | "button"
                | "list"
                | "message_card"
                | "approval_card"
                | "form_card"
                | "status_panel"
                | "task_card"
                | "agent_result"
        ) || contains_unknown_component(&component.children)
    })
}

fn component_depth(components: &[A2uiComponent]) -> usize {
    components
        .iter()
        .map(|component| 1 + component_depth(&component.children))
        .max()
        .unwrap_or_default()
}

fn component_count(components: &[A2uiComponent]) -> usize {
    components.iter().map(|component| 1 + component_count(&component.children)).sum()
}

fn verify_component_permission(
    component: &A2uiComponent,
    granted_permissions: &BTreeSet<String>,
) -> Result<(), SyncError> {
    if let Some(permission) = &component.action_permission
        && !granted_permissions.contains(permission)
    {
        return Err(SyncError::CapabilityDenied);
    }
    for child in &component.children {
        verify_component_permission(child, granted_permissions)?;
    }
    Ok(())
}

fn component_has_action_permission(
    components: &[A2uiComponent],
    component_id: &str,
    permission: &str,
) -> bool {
    components.iter().any(|component| {
        (component.id == component_id && component.action_permission.as_deref() == Some(permission))
            || component_has_action_permission(&component.children, component_id, permission)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn surface() -> A2uiSurface {
        A2uiSurface {
            surface_id: "surface_test".to_owned(),
            catalog: "ramflux.basic.v1".to_owned(),
            catalog_version: "1".to_owned(),
            components: vec![A2uiComponent {
                id: "approve".to_owned(),
                component_type: "approval_card".to_owned(),
                action_permission: Some("mcp.approve".to_owned()),
                children: Vec::new(),
            }],
        }
    }

    fn signed_action(
        surface: &A2uiSurface,
        device: &ramflux_crypto::DeviceBranch,
    ) -> Result<A2uiAction, SyncError> {
        let mut action = A2uiAction {
            surface_id: surface.surface_id.clone(),
            surface_hash: a2ui_surface_hash(surface)?,
            component_id: "approve".to_owned(),
            permission: "mcp.approve".to_owned(),
            source_device_id: device.device_id.clone(),
            target_device_id: "cli_ai_device".to_owned(),
            created_at: 1_760_000_700,
            nonce: "nonce_a2ui_test".to_owned(),
            signature: String::new(),
        };
        action.signature =
            ramflux_crypto::sign_with_device_branch(device, &a2ui_action_signing_body(&action))?;
        Ok(action)
    }

    fn public_key(device: &ramflux_crypto::DeviceBranch) -> String {
        ramflux_protocol::encode_base64url(device.signing_key.verifying_key().to_bytes())
    }

    #[test]
    fn a2ui_action_device_branch_signature_roundtrip() -> Result<(), SyncError> {
        let surface = surface();
        let device = ramflux_crypto::create_device_branch("principal", "app_device", 1, [0xA2; 32]);
        let action = signed_action(&surface, &device)?;
        assert!(verify_a2ui_action_signature(&surface, &action, &public_key(&device)).is_ok());
        Ok(())
    }

    #[test]
    fn a2ui_action_signature_rejects_tampered_surface_or_component() -> Result<(), SyncError> {
        let surface = surface();
        let device = ramflux_crypto::create_device_branch("principal", "app_device", 1, [0xA3; 32]);
        let mut action = signed_action(&surface, &device)?;
        action.component_id = "other".to_owned();
        assert!(verify_a2ui_action_signature(&surface, &action, &public_key(&device)).is_err());

        let mut other_surface = surface.clone();
        other_surface.surface_id = "other_surface".to_owned();
        let action = signed_action(&surface, &device)?;
        assert!(
            verify_a2ui_action_signature(&other_surface, &action, &public_key(&device)).is_err()
        );
        Ok(())
    }

    #[test]
    fn a2ui_action_signature_rejects_unregistered_or_pseudo_key() -> Result<(), SyncError> {
        let surface = surface();
        let device = ramflux_crypto::create_device_branch("principal", "app_device", 1, [0xA4; 32]);
        let other =
            ramflux_crypto::create_device_branch("principal", "other_device", 1, [0xA5; 32]);
        let action = signed_action(&surface, &device)?;
        assert!(verify_a2ui_action_signature(&surface, &action, &public_key(&other)).is_err());

        let mut pseudo = action;
        pseudo.signature = "attended-local:approve".to_owned();
        assert!(verify_a2ui_action_signature(&surface, &pseudo, &public_key(&device)).is_err());
        Ok(())
    }
}

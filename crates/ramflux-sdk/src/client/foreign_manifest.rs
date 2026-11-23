// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Receive-side directory origin for a sender root.
//! A card pin or the verified source home is required before any remote fetch.
//! The home is not written onto the contact record.

use crate::prelude::*;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum SenderManifestOrigin {
    Local,
    Remote { home: String, fingerprint: String },
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct HomePin {
    home: String,
    fingerprint: String,
}

impl RamfluxClient {
    /// Directory origin for `root` on this envelope.
    ///
    /// A card pin wins when it agrees with the verified source. The two must
    /// not name different homes or fingerprints. Neither one is stored.
    ///
    /// # Errors
    /// Returns an error when the account record cannot be read, the card pin
    /// is incomplete, the verified source is present but malformed, or the card
    /// and the verified source disagree.
    pub(crate) fn sender_manifest_origin(
        &self,
        envelope: &ramflux_protocol::Envelope,
        root: &str,
    ) -> Result<SenderManifestOrigin, SdkError> {
        let card = card_pin(self, root)?;
        let stamp = verified_stamp(envelope)?;
        if let (Some(card), Some(stamp)) = (&card, &stamp)
            && (card.home != stamp.home || card.fingerprint != stamp.fingerprint)
        {
            return Err(SdkError::LocalBus(
                "pinned home disagrees with the verified source".into(),
            ));
        }
        let Some(selected) = card.or(stamp) else {
            return Ok(SenderManifestOrigin::Local);
        };
        let own = self.account_db()?.load_actor_state::<String>("account/node-id")?;
        if own.as_deref() == Some(selected.home.as_str()) {
            Ok(SenderManifestOrigin::Local)
        } else {
            Ok(SenderManifestOrigin::Remote {
                home: selected.home,
                fingerprint: selected.fingerprint,
            })
        }
    }
}

/// Fetch and verify `root` from the selected origin.
///
/// A remote origin never falls back to the local gateway.
///
/// # Errors
/// Returns an error when the signed record, the manifest body, or verification fails.
pub(crate) async fn fetch_sender_manifest(
    gateway: &GatewaySessionConfig,
    origin: SenderManifestOrigin,
    root: &str,
) -> Result<SdkDeviceManifestResponse, SdkError> {
    match origin {
        SenderManifestOrigin::Local => {
            crate::client::contact::fetch_verified_device_manifest(gateway, root).await
        }
        SenderManifestOrigin::Remote { home, fingerprint } => {
            remote_manifest(&home, &fingerprint, root).await
        }
    }
}

async fn remote_manifest(
    home: &str,
    fingerprint: &str,
    root: &str,
) -> Result<SdkDeviceManifestResponse, SdkError> {
    let manifest =
        crate::client::recipient_home::public_device_manifest(home, fingerprint, root).await?;
    crate::client::contact::verify_device_manifest(&manifest, root)?;
    Ok(crate::client::identity_authority::ready_manifest(manifest, now_unix_timestamp()))
}

fn card_pin(client: &RamfluxClient, root: &str) -> Result<Option<HomePin>, SdkError> {
    let Some(principal) = crate::client::recipient_home::principal_for_commitment(client, root)?
    else {
        return Ok(None);
    };
    let Some(home) = crate::client::recipient_home::pinned_home(client, &principal)? else {
        return Ok(None);
    };
    let fingerprint = crate::client::recipient_home::pinned_node_fingerprint(client, root)?;
    Ok(Some(HomePin { home, fingerprint }))
}

fn verified_stamp(envelope: &ramflux_protocol::Envelope) -> Result<Option<HomePin>, SdkError> {
    let Some(value) = envelope.ext.ext.get(ramflux_protocol::VERIFIED_SOURCE_HOME) else {
        return Ok(None);
    };
    let object = value.as_object().ok_or_else(malformed_source)?;
    let home = crate::client::recipient_home::node_id(
        object.get("node_id").and_then(serde_json::Value::as_str),
    )
    .ok_or_else(malformed_source)?;
    let fingerprint = object
        .get("key_fingerprint")
        .and_then(serde_json::Value::as_str)
        .filter(|value| {
            value.len() == 64
                && value.bytes().all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        })
        .ok_or_else(malformed_source)?;
    Ok(Some(HomePin { home, fingerprint: fingerprint.to_owned() }))
}

fn malformed_source() -> SdkError {
    SdkError::LocalBus("verified source home is malformed".into())
}

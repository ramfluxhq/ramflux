// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Receive-side directory origin for a sender root.
//! A card pin or the verified source home is required before any remote fetch.
//! The home is not written onto the contact record. A verified remote source is
//! remembered by root so a later accept or send uses the same pin.

use crate::prelude::*;
use serde::{Deserialize, Serialize};

const SOURCE_HOME_PREFIX: &str = "source-home/";
const SOURCE_HOME_CAP: usize = 1024;

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

#[derive(Clone, Debug, Deserialize, Serialize)]
struct StoredSourceHome {
    home: String,
    key_fingerprint: String,
}

impl RamfluxClient {
    /// Directory origin for `root` on this envelope.
    ///
    /// A card pin wins when it agrees with the verified source and with any
    /// remembered pin. The three must not name different homes or fingerprints.
    /// A remote choice is remembered by root. It is not written on the contact.
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
        let stored = load_stored(self, root)?;
        agree(card.as_ref(), stamp.as_ref())?;
        agree(card.as_ref(), stored.as_ref())?;
        agree(stamp.as_ref(), stored.as_ref())?;
        let Some(selected) = card.or(stamp).or(stored) else {
            return Ok(SenderManifestOrigin::Local);
        };
        let origin = origin_for(self, selected)?;
        if let SenderManifestOrigin::Remote { home, fingerprint } = &origin {
            self.remember_source_home(root, home, fingerprint)?;
        }
        Ok(origin)
    }

    /// Origin for a peer root that has no envelope in hand.
    ///
    /// A card pin and a remembered verified source must agree. Neither one
    /// means this session's directory.
    ///
    /// # Errors
    /// Returns an error when a stored pin is malformed or disagrees with the card.
    pub(crate) fn pinned_manifest_origin(
        &self,
        root: &str,
    ) -> Result<SenderManifestOrigin, SdkError> {
        let card = card_pin(self, root)?;
        let stored = load_stored(self, root)?;
        agree(card.as_ref(), stored.as_ref())?;
        match card.or(stored) {
            Some(selected) => origin_for(self, selected),
            None => Ok(SenderManifestOrigin::Local),
        }
    }

    /// Fetch `root` from its card pin or remembered verified source.
    ///
    /// A remote origin never falls back to the local gateway.
    ///
    /// # Errors
    /// Returns an error when the pin, the signed record, or verification fails.
    pub(crate) async fn peer_device_manifest(
        &self,
        gateway: &GatewaySessionConfig,
        root: &str,
    ) -> Result<SdkDeviceManifestResponse, SdkError> {
        let origin = self.pinned_manifest_origin(root)?;
        fetch_sender_manifest(gateway, origin, root).await
    }

    fn remember_source_home(
        &self,
        root: &str,
        home: &str,
        fingerprint: &str,
    ) -> Result<(), SdkError> {
        if !root_key_ok(root) {
            return Err(SdkError::LocalBus("source home root is malformed".into()));
        }
        let home = crate::client::recipient_home::node_id(Some(home))
            .ok_or_else(|| SdkError::LocalBus("pinned home is not a node id".into()))?;
        if !fingerprint_ok(fingerprint) {
            return Err(malformed_source());
        }
        let db = self.account_db()?;
        let key = source_key(root);
        if let Some(stored) = db.load_actor_state::<StoredSourceHome>(&key)? {
            if stored.home == home && stored.key_fingerprint == fingerprint {
                return Ok(());
            }
            return Err(SdkError::LocalBus(
                "pinned home disagrees with the verified source".into(),
            ));
        }
        if db.actor_state_keys(SOURCE_HOME_PREFIX)?.len() >= SOURCE_HOME_CAP {
            return Err(SdkError::LocalBus("pinned source home capacity exhausted".into()));
        }
        db.persist_actor_state(
            &key,
            &StoredSourceHome { home, key_fingerprint: fingerprint.to_owned() },
        )?;
        Ok(())
    }
}

/// Remembered verified source for `root`, if one was stored.
///
/// # Errors
/// Returns an error when the stored pin is malformed.
pub(crate) fn stored_source(
    client: &RamfluxClient,
    root: &str,
) -> Result<Option<(String, String)>, SdkError> {
    Ok(load_stored(client, root)?.map(|pin| (pin.home, pin.fingerprint)))
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

fn origin_for(client: &RamfluxClient, selected: HomePin) -> Result<SenderManifestOrigin, SdkError> {
    let own = client.account_db()?.load_actor_state::<String>("account/node-id")?;
    if own.as_deref() == Some(selected.home.as_str()) {
        Ok(SenderManifestOrigin::Local)
    } else {
        Ok(SenderManifestOrigin::Remote { home: selected.home, fingerprint: selected.fingerprint })
    }
}

fn agree(left: Option<&HomePin>, right: Option<&HomePin>) -> Result<(), SdkError> {
    if let (Some(left), Some(right)) = (left, right)
        && (left.home != right.home || left.fingerprint != right.fingerprint)
    {
        return Err(SdkError::LocalBus("pinned home disagrees with the verified source".into()));
    }
    Ok(())
}

fn load_stored(client: &RamfluxClient, root: &str) -> Result<Option<HomePin>, SdkError> {
    if !root_key_ok(root) {
        return Ok(None);
    }
    let Some(stored) =
        client.account_db()?.load_actor_state::<StoredSourceHome>(&source_key(root))?
    else {
        return Ok(None);
    };
    if crate::client::recipient_home::node_id(Some(&stored.home)).is_none()
        || !fingerprint_ok(&stored.key_fingerprint)
    {
        return Err(malformed_source());
    }
    Ok(Some(HomePin { home: stored.home, fingerprint: stored.key_fingerprint }))
}

fn source_key(root: &str) -> String {
    format!("{SOURCE_HOME_PREFIX}{root}")
}

fn root_key_ok(root: &str) -> bool {
    !root.is_empty()
        && root.len() <= 128
        && !root.contains('/')
        && root.bytes().all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

fn fingerprint_ok(value: &str) -> bool {
    value.len() == 64
        && value.bytes().all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

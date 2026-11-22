// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Foreign envelope source admission. Custody senders are checked against the
//! publication carried on the envelope. Signed device sets stay a separate
//! account mode and are not a second admission path for custody evidence.
use super::RouterCore;
use crate::{DeviceAuthKeyResponse, NodeCoreError, RouterEnvelopeOrigin};

impl RouterCore {
    /// Authenticate the root-selected branch before using any claimed sender in a key.
    /// # Errors
    /// Rejects missing root claims, absent/revoked signed-set entries and forged signatures.
    pub fn authenticated_envelope_source(
        &self,
        envelope: &ramflux_protocol::Envelope,
    ) -> Result<ramflux_crypto::RootQualifiedDeviceRef, NodeCoreError> {
        ramflux_protocol::ephemeral::require_durable(envelope)?;
        self.authenticated_envelope_source_from(envelope, None, RouterEnvelopeOrigin::Gateway)
    }

    /// Authenticate a source and persist its highest foreign authority before accepting delivery.
    /// # Errors
    /// Rejects stale or forged authority and durable storage failures.
    pub fn authenticated_envelope_source_durable(
        &self,
        envelope: &ramflux_protocol::Envelope,
        store: &crate::RouterRedbStore,
    ) -> Result<ramflux_crypto::RootQualifiedDeviceRef, NodeCoreError> {
        ramflux_protocol::ephemeral::require_durable(envelope)?;
        self.authenticated_envelope_source_from(
            envelope,
            Some(store),
            RouterEnvelopeOrigin::Gateway,
        )
    }

    /// Authenticate an envelope using provenance from an already authenticated mesh peer.
    /// # Errors
    /// Rejects forged, stale, over-capacity or gateway-supplied foreign authority.
    pub fn authenticated_envelope_source_from(
        &self,
        envelope: &ramflux_protocol::Envelope,
        store: Option<&crate::RouterRedbStore>,
        origin: RouterEnvelopeOrigin,
    ) -> Result<ramflux_crypto::RootQualifiedDeviceRef, NodeCoreError> {
        ramflux_protocol::ephemeral::require_durable(envelope)?;
        let reject = || NodeCoreError::ItestHttp("envelope root authority mismatch".into());
        let root = envelope
            .ext
            .ext
            .get("source_root_commitment")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(reject)?;
        let lookup = ramflux_protocol::qualified_device_id(root, &envelope.source_device_id)
            .map_err(|_| reject())?;
        let registered = {
            let mut control = super::lock_unpoisoned(&self.control);
            let registry = &mut control.mvp1_identities;
            registry
                .resolve_device_selector(&lookup)
                .and_then(|identity| registry.device_auth_key(&identity))
        };
        if let Some(authority) = registered {
            return self.admit_registered_source(envelope, root, &authority);
        }
        if origin != RouterEnvelopeOrigin::Federation {
            return Err(NodeCoreError::Unauthorized(
                "foreign authority requires an authenticated federation peer".into(),
            ));
        }
        let (authority, _) = DeviceAuthKeyResponse::forwarded_envelope_source(envelope)?;
        if authority.custody_authority.is_some() {
            return self.admit_foreign_custody(envelope, store, root);
        }
        self.admit_foreign_signed_set(envelope, store, root, &authority)
    }

    fn admit_registered_source(
        &self,
        envelope: &ramflux_protocol::Envelope,
        root: &str,
        authority: &DeviceAuthKeyResponse,
    ) -> Result<ramflux_crypto::RootQualifiedDeviceRef, NodeCoreError> {
        let reject = || NodeCoreError::ItestHttp("envelope root authority mismatch".into());
        let source = authority.verify_envelope_source(envelope)?;
        // Native registration already supplies the current certificate chain.
        // A signed device set is absent on a custody account by design.
        if authority.custody_authority.is_some() {
            return Ok(source);
        }
        let record = authority.signed_device_set.as_ref().ok_or_else(reject)?;
        let control = super::lock_unpoisoned(&self.control);
        if let Some(fence) = control.foreign_device_heads.fences.get(root) {
            fence.check(crate::foreign_device_heads::EpochFence::of(record)?)?;
        }
        Ok(source)
    }

    fn admit_foreign_custody(
        &self,
        envelope: &ramflux_protocol::Envelope,
        store: Option<&crate::RouterRedbStore>,
        root: &str,
    ) -> Result<ramflux_crypto::RootQualifiedDeviceRef, NodeCoreError> {
        let reject = || NodeCoreError::ItestHttp("envelope root authority mismatch".into());
        {
            let control = super::lock_unpoisoned(&self.control);
            if control.mvp1_identities.signed_device_set(root).is_some() {
                return Err(reject());
            }
        }
        // The envelope does not carry the peer node id. Message limits use that id
        // in federation. Pin quota here shares the existing unspecified bucket.
        let Some(store) = store else {
            return Err(NodeCoreError::Unauthorized(
                "foreign custody admission requires durable pins".into(),
            ));
        };
        let _pin_admission = crate::forwarded_delivery::FOREIGN_PIN_ADMISSION
            .lock()
            .map_err(|error| NodeCoreError::Redb(error.to_string()))?;
        self.authenticated_native_forwarded_source_from_peer(
            "unspecified",
            envelope,
            &[],
            store,
            RouterEnvelopeOrigin::Federation,
        )
    }

    fn admit_foreign_signed_set(
        &self,
        envelope: &ramflux_protocol::Envelope,
        store: Option<&crate::RouterRedbStore>,
        root: &str,
        authority: &DeviceAuthKeyResponse,
    ) -> Result<ramflux_crypto::RootQualifiedDeviceRef, NodeCoreError> {
        let reject = || NodeCoreError::ItestHttp("envelope root authority mismatch".into());
        let source = authority.verify_envelope_source(envelope)?;
        let mut control = super::lock_unpoisoned(&self.control);
        if control
            .mvp1_identities
            .signed_device_set(root)
            .is_some_and(|current| authority.signed_device_set.as_ref() != Some(current))
        {
            return Err(reject());
        }
        let record = authority.signed_device_set.as_ref().ok_or_else(reject)?;
        let observation = if let Some(store) = store {
            store.observe_foreign_device_set(record)?
        } else {
            control.foreign_device_heads.prepare(record)?
        };
        control.foreign_device_heads.apply(record, observation);
        observation.admitted()?;
        Ok(source)
    }
}

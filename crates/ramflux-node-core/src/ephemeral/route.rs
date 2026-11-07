// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Read-only ephemeral route authority (C1). No store write, no foreign-head apply.

#[cfg(any(test, feature = "test-support"))]
use crate::HomeNodeMigrationRecord;
use crate::{EnvelopeAuthorityReason, NodeCoreError, RouterCore, lock_unpoisoned};
use ramflux_protocol::ephemeral::{EphemeralModeError, deadline};
use serde::{Deserialize, Serialize};

/// Gateway POST `/mvp0/envelope-ephemeral` body.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EphemeralRouteRequest {
    pub envelope: ramflux_protocol::Envelope,
    pub expires_at_ms: u64,
}

/// Wire reply for `/mvp0/envelope-ephemeral`.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum EphemeralRouteResponse {
    Online { gateway_id: String, session_id: String },
    Dropped { reason: EphemeralDropReason },
}

/// Dropped reasons produced by this part. Later parts add queue/rate/replay variants.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EphemeralDropReason {
    Offline,
    NotLocal,
    RecipientUnsupported,
    Invalid,
    Expired,
}

/// Exact route decision, including pre-C1 refusals the HTTP layer maps to `dropped`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EphemeralRouteResult {
    Online { gateway_id: String, session_id: String },
    Dropped(EphemeralDropReason),
    DeadlineMismatch,
    RevokedSource,
    RootMismatch,
}

impl EphemeralRouteResult {
    /// Map the exact decision onto the mesh reply shape.
    #[must_use]
    pub fn into_response(self) -> EphemeralRouteResponse {
        match self {
            Self::Online { gateway_id, session_id } => {
                EphemeralRouteResponse::Online { gateway_id, session_id }
            }
            Self::Dropped(reason) => EphemeralRouteResponse::Dropped { reason },
            Self::DeadlineMismatch | Self::RevokedSource | Self::RootMismatch => {
                EphemeralRouteResponse::Dropped { reason: EphemeralDropReason::Invalid }
            }
        }
    }
}

/// Byte-identical durable observation for the read-only proof.
#[cfg(any(test, feature = "test-support"))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EphemeralDurableSnapshot {
    pub identities: Vec<u8>,
    pub replay: Vec<u8>,
    pub foreign_device_heads: Vec<u8>,
}

impl RouterCore {
    /// Read-only ephemeral route: recompute D, verify source without E1, then C1.
    #[must_use]
    pub fn route_ephemeral(
        &self,
        envelope: &ramflux_protocol::Envelope,
        supplied_expires_at_ms: u64,
        now_ms: u64,
    ) -> EphemeralRouteResult {
        match deadline(envelope, now_ms) {
            Ok(computed) if computed == supplied_expires_at_ms => {}
            Ok(_) => return EphemeralRouteResult::DeadlineMismatch,
            Err(EphemeralModeError::Expired) => {
                return EphemeralRouteResult::Dropped(EphemeralDropReason::Expired);
            }
            Err(_) => {
                return EphemeralRouteResult::Dropped(EphemeralDropReason::Invalid);
            }
        }
        if let Err(result) = self.authenticate_ephemeral_source(envelope) {
            return result;
        }
        let now_secs = i64::try_from(now_ms / 1_000).unwrap_or(i64::MAX);
        if self.ephemeral_target_not_local(&envelope.target_delivery_id, now_secs) {
            return EphemeralRouteResult::Dropped(EphemeralDropReason::NotLocal);
        }
        match self.route_gate(&envelope.target_delivery_id) {
            crate::EphemeralRouteGate::Online { gateway_id, session_id } => {
                EphemeralRouteResult::Online { gateway_id, session_id }
            }
            crate::EphemeralRouteGate::Offline => {
                EphemeralRouteResult::Dropped(EphemeralDropReason::Offline)
            }
            crate::EphemeralRouteGate::RecipientUnsupported => {
                EphemeralRouteResult::Dropped(EphemeralDropReason::RecipientUnsupported)
            }
        }
    }

    fn authenticate_ephemeral_source(
        &self,
        envelope: &ramflux_protocol::Envelope,
    ) -> Result<(), EphemeralRouteResult> {
        let root = envelope
            .ext
            .ext
            .get("source_root_commitment")
            .and_then(serde_json::Value::as_str)
            .ok_or(EphemeralRouteResult::RootMismatch)?;
        let lookup = ramflux_protocol::qualified_device_id(root, &envelope.source_device_id)
            .map_err(|_| EphemeralRouteResult::RootMismatch)?;
        let control = lock_unpoisoned(&self.control);
        let Some(authority) = control
            .mvp1_identities
            .resolve_device_selector(&lookup)
            .and_then(|identity| control.mvp1_identities.device_auth_key(&identity))
        else {
            return Err(EphemeralRouteResult::RootMismatch);
        };
        match authority.verify_envelope_source(envelope) {
            Ok(_) => Ok(()),
            Err(NodeCoreError::SourceAuthorityRefused {
                reason_code: EnvelopeAuthorityReason::Revoked,
            }) => Err(EphemeralRouteResult::RevokedSource),
            Err(_) => Err(EphemeralRouteResult::RootMismatch),
        }
    }

    fn ephemeral_target_not_local(&self, target: &str, now_unix_seconds: i64) -> bool {
        self.effective_home_node_migration_for_target(target, now_unix_seconds).is_some()
    }

    /// Durable identities, replay guard and foreign-device heads as observed bytes.
    ///
    /// # Errors
    /// Returns an error when a snapshot field cannot be encoded.
    #[cfg(any(test, feature = "test-support"))]
    pub fn ephemeral_durable_snapshot(&self) -> Result<EphemeralDurableSnapshot, NodeCoreError> {
        let snap = self.snapshot();
        Ok(EphemeralDurableSnapshot {
            identities: serde_json::to_vec(&snap.mvp1_identities)
                .map_err(|error| NodeCoreError::SnapshotSerialization(error.to_string()))?,
            replay: serde_json::to_vec(&snap.replay_guard_state)
                .map_err(|error| NodeCoreError::SnapshotSerialization(error.to_string()))?,
            foreign_device_heads: serde_json::to_vec(&snap.foreign_device_heads)
                .map_err(|error| NodeCoreError::SnapshotSerialization(error.to_string()))?,
        })
    }

    /// Test-only: record an effective home-node migration for `identity_commitment`.
    #[cfg(any(test, feature = "test-support"))]
    pub fn test_put_home_node_migration(
        &self,
        identity_commitment: String,
        record: HomeNodeMigrationRecord,
    ) {
        let mut control = lock_unpoisoned(&self.control);
        control.home_node_migrations.insert(identity_commitment, record);
        self.refresh_migration_read_snapshot_from_control(&control);
    }

    /// Test-only: mark the envelope's registered source device revoked.
    #[cfg(any(test, feature = "test-support"))]
    pub fn test_revoke_envelope_source(&self, envelope: &ramflux_protocol::Envelope) {
        let Some(root) =
            envelope.ext.ext.get("source_root_commitment").and_then(serde_json::Value::as_str)
        else {
            return;
        };
        let Ok(lookup) = ramflux_protocol::qualified_device_id(root, &envelope.source_device_id)
        else {
            return;
        };
        let mut control = lock_unpoisoned(&self.control);
        if let Some(identity) = control.mvp1_identities.resolve_device_selector(&lookup) {
            control.mvp1_identities.revoked_devices.insert(identity.storage_key().to_owned());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        EphemeralDropReason, EphemeralDurableSnapshot, EphemeralRouteResult,
        HomeNodeMigrationRecord, RouterCore, deadline,
    };
    use crate::{
        IDENTITY_BIND_AUDIENCE, IDENTITY_BIND_CAPABILITY, IdentityRegisterRequest, RouterRedbStore,
        SessionDescriptor, SessionLifecycle, source_ip_hash,
    };
    use ramflux_protocol::{
        DeliveryClass, Envelope, Ext, Priority, SignatureAlg, SignedFields, ephemeral as proto,
    };
    use serde_json::json;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    type TestResult = Result<(), Box<dyn std::error::Error>>;
    type Fallible<T> = Result<T, Box<dyn std::error::Error>>;

    const NOW_MS: u64 = 1_760_000_000_000;
    const GATEWAY: &str = "gateway";
    const SESSION: &str = "session";
    const TARGET: &str = "target_alice";
    const DEVICE: &str = "alice_phone";

    fn temp_path(name: &str) -> PathBuf {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        std::env::temp_dir().join(format!(
            "ramflux-s6c-p06-{name}-{}-{}.redb",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ))
    }

    fn descriptor(target: &str, gateway: &str, session: &str) -> SessionDescriptor {
        SessionDescriptor {
            target_delivery_id: target.to_owned(),
            device_id: DEVICE.to_owned(),
            gateway_id: gateway.to_owned(),
            session_id: session.to_owned(),
            device_epoch: 1,
            session_seq: 1,
            last_cursor: None,
            push_alias_hash: None,
            lifecycle: SessionLifecycle::Live,
        }
    }

    fn register_alice(router: &RouterCore) -> TestResult {
        let root_seed = ramflux_crypto::blake3_256("ramflux.test.registration_root.v1", b"alice");
        let device_seed =
            ramflux_crypto::blake3_256("ramflux.test.runtime.device.v1", b"alice/alice_phone");
        let root = ramflux_crypto::create_identity_root("alice", root_seed);
        let device = ramflux_crypto::create_device_branch("alice", DEVICE, 1, device_seed);
        let agreement = ramflux_crypto::X25519KeyPair::from_seed(ramflux_crypto::blake3_256(
            "ramflux.test.runtime.agreement.v1",
            b"alice/alice_phone",
        ));
        let now: i64 = 1_760_000_010;
        let proof = ramflux_crypto::authorize_device_branch_v2(
            &root,
            &device,
            ramflux_crypto::BranchAuthorization {
                audience: IDENTITY_BIND_AUDIENCE,
                capability_scope: vec![IDENTITY_BIND_CAPABILITY.into()],
                issued_at: now.saturating_sub(10),
                expires_at: now.saturating_add(3_600),
                principal_kind: ramflux_protocol::PrincipalKind::Human,
                agreement_identity_public_key: agreement.public,
            },
        )?;
        let keys = ramflux_crypto::device_key_commitments(
            &ramflux_protocol::encode_base64url(device.signing_key.verifying_key().to_bytes()),
            &ramflux_protocol::encode_base64url(agreement.public),
        )?;
        let device_set = ramflux_crypto::sign_device_set(
            &root,
            ramflux_crypto::DeviceSetSigningInput {
                principal_kind: ramflux_protocol::PrincipalKind::Human,
                device_set_epoch: 1,
                devices: vec![ramflux_protocol::SignedDeviceSetEntry {
                    device_id: DEVICE.into(),
                    device_epoch: 1,
                    signing_key_commitment: keys.0,
                    agreement_key_commitment: keys.1,
                    status: ramflux_protocol::DeviceSetStatus::Active,
                    revoked_at: None,
                }],
            },
        )?;
        let root_public_key =
            ramflux_protocol::encode_base64url(root.signing_key.verifying_key().to_bytes());
        let root_public_key_bytes = ramflux_protocol::decode_base64url(&root_public_key)?;
        router.mvp1_register_identity(&IdentityRegisterRequest {
            device_set: Some(device_set),
            principal_commitment: ramflux_crypto::blake3_256_base64url(
                "ramflux.identity.root_public_key.commitment.v1",
                &root_public_key_bytes,
            ),
            root_public_key,
            branch_public_key: ramflux_protocol::encode_base64url(
                device.signing_key.verifying_key().to_bytes(),
            ),
            proof,
            target_delivery_id: TARGET.into(),
            gateway_id: GATEWAY.into(),
            session_id: SESSION.into(),
            push_alias_hash: None,
            now,
            registration_pow: None,
            source_ip_hash: Some(source_ip_hash("192.0.2.1")),
        })?;
        Ok(())
    }

    fn sign_seed() -> [u8; 32] {
        ramflux_crypto::blake3_256("ramflux.test.runtime.device.v1", b"alice/alice_phone")
    }

    fn signed_ephemeral(id: &str, target: &str) -> Fallible<Envelope> {
        let created_at = i64::try_from(NOW_MS / 1_000)?;
        let mut envelope = Envelope {
            schema: "ramflux.envelope.v1".into(),
            version: 1,
            domain: "ramflux.envelope.v1".into(),
            ext: Ext::default(),
            signed: SignedFields {
                signing_key_id: "test_key".into(),
                signature_alg: SignatureAlg::Ed25519,
                signature: String::new(),
            },
            envelope_id: id.into(),
            source_principal_id: "alice".into(),
            source_device_id: DEVICE.into(),
            target_delivery_id: target.into(),
            routing_set_id: None,
            delivery_class: DeliveryClass::OpaqueEvent,
            priority: Priority::Low,
            ttl: 5,
            created_at,
            encrypted_payload: "ciphertext".into(),
            payload_hash: "payload_hash".into(),
        };
        envelope.ext.ext.insert(proto::DELIVERY_MODE_EXTENSION.into(), json!("ephemeral"));
        let root = ramflux_crypto::create_identity_root(
            "alice",
            ramflux_crypto::blake3_256("ramflux.test.registration_root.v1", b"alice"),
        );
        envelope.ext.ext.insert(
            "source_root_commitment".into(),
            json!(ramflux_crypto::identity_root_commitment(&root.signing_key.verifying_key())),
        );
        envelope.signed.signature =
            ramflux_crypto::sign_protocol_object_with_seed(&envelope, sign_seed())?;
        Ok(envelope)
    }

    fn bind_capable(router: &RouterCore, target: &str) -> TestResult {
        router.clear_ephemeral_capability(target);
        router.upsert_session(descriptor(target, GATEWAY, SESSION))?;
        router.mark_live(target)?;
        router.bind_ephemeral_capability(target, GATEWAY, SESSION);
        Ok(())
    }

    fn computed_d(envelope: &Envelope) -> Fallible<u64> {
        Ok(deadline(envelope, NOW_MS)?)
    }

    fn route(router: &RouterCore, envelope: &Envelope, expires_at_ms: u64) -> EphemeralRouteResult {
        router.route_ephemeral(envelope, expires_at_ms, NOW_MS)
    }

    fn assert_no_dispatch(result: &EphemeralRouteResult) {
        assert!(
            !matches!(result, EphemeralRouteResult::Online { .. }),
            "zero forwards and enqueues, got {result:?}"
        );
    }

    fn assert_read_only(
        router: &RouterCore,
        before: &EphemeralDurableSnapshot,
        store_bytes: &[u8],
        path: &std::path::Path,
    ) -> TestResult {
        assert_eq!(&router.ephemeral_durable_snapshot()?, before);
        assert_eq!(std::fs::read(path).unwrap_or_default(), store_bytes);
        Ok(())
    }

    fn observe_route(
        router: &RouterCore,
        envelope: &Envelope,
        expires_at_ms: u64,
        path: &std::path::Path,
        store_bytes: &[u8],
    ) -> Fallible<EphemeralRouteResult> {
        let before = router.ephemeral_durable_snapshot()?;
        let result = route(router, envelope, expires_at_ms);
        assert_read_only(router, &before, store_bytes, path)?;
        Ok(result)
    }

    #[test]
    fn ephemeral_route_read_only() -> TestResult {
        let path = temp_path("read-only");
        let store = RouterRedbStore::open(&path)?;
        let router = RouterCore::new();
        register_alice(&router)?;
        store.record_identity_registry(&router.mvp1_identities_snapshot())?;
        bind_capable(&router, TARGET)?;
        let store_bytes = std::fs::read(&path).unwrap_or_default();

        let envelope = signed_ephemeral("ok", TARGET)?;
        let expires = computed_d(&envelope)?;
        let accepted = observe_route(&router, &envelope, expires, &path, &store_bytes)?;
        assert_eq!(
            accepted,
            EphemeralRouteResult::Online { gateway_id: GATEWAY.into(), session_id: SESSION.into() }
        );

        let mismatch = signed_ephemeral("mismatch", TARGET)?;
        let computed = computed_d(&mismatch)?;
        let d_mismatch =
            observe_route(&router, &mismatch, computed.saturating_add(1), &path, &store_bytes)?;
        assert_eq!(d_mismatch, EphemeralRouteResult::DeadlineMismatch);
        assert_no_dispatch(&d_mismatch);

        let mut root_mismatch = signed_ephemeral("root", TARGET)?;
        root_mismatch.ext.ext.insert("source_root_commitment".into(), json!("other-root"));
        let root_expires = deadline(&root_mismatch, NOW_MS).unwrap_or(expires);
        let root_result =
            observe_route(&router, &root_mismatch, root_expires, &path, &store_bytes)?;
        assert_eq!(root_result, EphemeralRouteResult::RootMismatch);
        assert_no_dispatch(&root_result);

        let offline = signed_ephemeral("offline", "target_offline")?;
        let offline_result =
            observe_route(&router, &offline, computed_d(&offline)?, &path, &store_bytes)?;
        assert_eq!(offline_result, EphemeralRouteResult::Dropped(EphemeralDropReason::Offline));
        assert_no_dispatch(&offline_result);

        let no_map = "target_no_map";
        router.upsert_session(descriptor(no_map, GATEWAY, SESSION))?;
        router.mark_live(no_map)?;
        let no_map_env = signed_ephemeral("nomap", no_map)?;
        let no_map_result =
            observe_route(&router, &no_map_env, computed_d(&no_map_env)?, &path, &store_bytes)?;
        assert_eq!(
            no_map_result,
            EphemeralRouteResult::Dropped(EphemeralDropReason::RecipientUnsupported)
        );
        assert_no_dispatch(&no_map_result);

        let mismatch_map = "target_map_ne";
        bind_capable(&router, mismatch_map)?;
        router.clear_ephemeral_capability(mismatch_map);
        router.bind_ephemeral_capability(mismatch_map, "other-gateway", SESSION);
        let map_ne = signed_ephemeral("mapne", mismatch_map)?;
        let map_ne_result =
            observe_route(&router, &map_ne, computed_d(&map_ne)?, &path, &store_bytes)?;
        assert_eq!(
            map_ne_result,
            EphemeralRouteResult::Dropped(EphemeralDropReason::RecipientUnsupported)
        );
        assert_no_dispatch(&map_ne_result);

        let keys = router.mvp1_identities_snapshot().identity_keys_for_target_delivery_id(TARGET);
        let identity = keys.first().ok_or("identity key")?.clone();
        router.set_local_home_node_id(Some("node-a".into()));
        router.test_put_home_node_migration(
            identity.clone(),
            HomeNodeMigrationRecord {
                format_version: 1,
                identity_commitment: identity,
                old_home_node: "node-a".into(),
                new_home_node: "node-b".into(),
                new_home_node_key_hash: "key".into(),
                route_record_hash: "route".into(),
                effective_at: 0,
                issued_at: 0,
                migration_proof_hash: "proof".into(),
                migrated_at: 0,
            },
        );
        let migrated = signed_ephemeral("migrated", TARGET)?;
        let not_local =
            observe_route(&router, &migrated, computed_d(&migrated)?, &path, &store_bytes)?;
        assert_eq!(not_local, EphemeralRouteResult::Dropped(EphemeralDropReason::NotLocal));
        assert_no_dispatch(&not_local);

        let revoked = signed_ephemeral("revoked", TARGET)?;
        router.test_revoke_envelope_source(&revoked);
        let revoked_result =
            observe_route(&router, &revoked, computed_d(&revoked)?, &path, &store_bytes)?;
        assert_eq!(revoked_result, EphemeralRouteResult::RevokedSource);
        assert_no_dispatch(&revoked_result);

        drop(store);
        Ok(())
    }

    #[test]
    fn ephemeral_deadline() -> TestResult {
        let router = RouterCore::new();
        register_alice(&router)?;
        bind_capable(&router, TARGET)?;
        let envelope = signed_ephemeral("deadline", TARGET)?;
        let expires = computed_d(&envelope)?;
        assert_eq!(
            router.route_ephemeral(&envelope, expires, expires.saturating_sub(1)),
            EphemeralRouteResult::Online { gateway_id: GATEWAY.into(), session_id: SESSION.into() }
        );
        assert_eq!(
            router.route_ephemeral(&envelope, expires, expires),
            EphemeralRouteResult::Dropped(EphemeralDropReason::Expired)
        );
        assert_eq!(
            router.route_ephemeral(&envelope, expires.saturating_add(1), NOW_MS),
            EphemeralRouteResult::DeadlineMismatch
        );
        Ok(())
    }
}

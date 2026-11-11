// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Read-only ephemeral route authority (C1). No store write, no foreign-head apply.
//! Volatile replay set (D3) lives on `RouterCore` outside snapshot/save.

use crate::lock_unpoisoned;
use ramflux_protocol::ephemeral::{EphemeralModeError, deadline};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeSet, HashMap};
use std::sync::atomic::{AtomicU64, Ordering};

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
    Replayed,
    RateLimited,
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

/// Inclusive bound: 65,536 live authenticated digests.
pub const EPHEMERAL_REPLAY_BOUND: usize = 65_536;

/// Bytes of one stored `(digest, D)` tuple payload (32 B digest + 8 B D).
pub const EPHEMERAL_REPLAY_ENTRY_BYTES: usize = 32 + 8;

/// Inclusive heap budget for the replay set (map + deadline index) at the entry cap.
/// Hash-table spare buckets, control bytes and the expiry index count against this
/// figure. It is measured by a counting allocator, not `len() × ENTRY_BYTES`.
pub const EPHEMERAL_REPLAY_BUDGET_BYTES: usize = 8_388_608;

static SATURATION_TOTAL: AtomicU64 = AtomicU64::new(0);

/// Outcome of inserting one authenticated ephemeral digest until exclusive deadline `D`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[must_use]
pub enum EphemeralReplayAdmit {
    /// Digest was not live; it is now recorded until `D`.
    Fresh,
    /// The same digest is already live (duplicate before `D`).
    Replayed,
    /// The set holds 65,536 live markers; this new digest is refused and no live marker is evicted.
    RateLimited,
    /// Incoming `D` is not live (`now_ms >= D * 1000`); the digest is not recorded.
    /// A stored live marker for the same digest is left in place.
    Expired,
}

/// Domain-separated marker of authenticated source root/device, envelope id and payload hash.
#[must_use]
pub fn ephemeral_replay_digest(
    source_root: &str,
    source_device: &str,
    envelope_id: &str,
    payload_hash: &str,
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key("ramflux.ephemeral.replay.v1");
    for part in [source_root, source_device, envelope_id, payload_hash] {
        let len = u64::try_from(part.len()).unwrap_or(u64::MAX);
        hasher.update(&len.to_be_bytes());
        hasher.update(part.as_bytes());
    }
    *hasher.finalize().as_bytes()
}

/// Unix-seconds exclusive deadline `D`. Stored D3 values are seconds, never milliseconds.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) struct DeadlineSecs(u64);

impl DeadlineSecs {
    /// Exact `expires_at_ms == secs * 1000`. Non-multiples of 1000 ms are refused.
    fn from_expires_at_ms(expires_at_ms: u64) -> Option<Self> {
        let secs = expires_at_ms / 1_000;
        match secs.checked_mul(1_000) {
            Some(restored_ms) if restored_ms == expires_at_ms => Some(Self(secs)),
            _ => None,
        }
    }

    fn from_unix(secs: u64) -> Self {
        Self(secs)
    }

    fn unix(self) -> u64 {
        self.0
    }
}

/// Exclusive live check: a marker survives only while `now_ms < D * 1000`.
fn marker_is_live(now_ms: u64, deadline: DeadlineSecs) -> bool {
    deadline.unix().checked_mul(1_000).is_some_and(|deadline_ms| now_ms < deadline_ms)
}

#[derive(Clone, Debug, Default)]
pub(crate) struct EphemeralReplaySet {
    /// Sole `(digest, D)` store. Layout overhead counts toward [`EPHEMERAL_REPLAY_BUDGET_BYTES`].
    by_digest: HashMap<[u8; 32], DeadlineSecs>,
    /// Compact expiry index keyed by stored `D` (no second digest copy).
    by_deadline: BTreeSet<DeadlineSecs>,
}

impl EphemeralReplaySet {
    fn expire_due(&mut self, now_ms: u64) {
        let mut dropped_any = false;
        while let Some(&deadline) = self.by_deadline.first() {
            if marker_is_live(now_ms, deadline) {
                break;
            }
            self.by_deadline.pop_first();
            dropped_any = true;
        }
        if dropped_any {
            self.by_digest.retain(|_, stored| marker_is_live(now_ms, *stored));
        }
    }

    fn admit(
        &mut self,
        digest: [u8; 32],
        deadline: DeadlineSecs,
        now_ms: u64,
    ) -> EphemeralReplayAdmit {
        self.expire_due(now_ms);
        if !marker_is_live(now_ms, deadline) {
            return EphemeralReplayAdmit::Expired;
        }
        if self.by_digest.contains_key(&digest) {
            return EphemeralReplayAdmit::Replayed;
        }
        if self.by_digest.len() >= EPHEMERAL_REPLAY_BOUND {
            SATURATION_TOTAL.fetch_add(1, Ordering::Relaxed);
            tracing::debug!("ephemeral replay set full; live marker not evicted");
            return EphemeralReplayAdmit::RateLimited;
        }
        self.by_digest.insert(digest, deadline);
        self.by_deadline.insert(deadline);
        EphemeralReplayAdmit::Fresh
    }

    #[cfg(test)]
    fn contains_live(&self, digest: &[u8; 32], now_ms: u64) -> bool {
        self.by_digest.get(digest).is_some_and(|deadline| marker_is_live(now_ms, *deadline))
    }
}

/// Byte-identical durable observation for the read-only proof.
#[cfg(any(test, feature = "test-support"))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EphemeralDurableSnapshot {
    pub identities: Vec<u8>,
    pub replay: Vec<u8>,
    pub foreign_device_heads: Vec<u8>,
    pub sessions: Vec<u8>,
    pub home_node_migrations: Vec<u8>,
    pub local_home_node_id: Vec<u8>,
}

impl crate::EphemeralRouterView<'_> {
    /// Read-only ephemeral route: recompute D, verify source without E1, then C1.
    #[must_use]
    pub fn route_ephemeral(
        &self,
        envelope: &ramflux_protocol::Envelope,
        supplied_expires_at_ms: u64,
        now_ms: u64,
    ) -> EphemeralRouteResult {
        self.record_route_call();
        if ramflux_protocol::message::outer::refuse_named_fields_while_gate_off(envelope).is_err() {
            return EphemeralRouteResult::Dropped(EphemeralDropReason::Invalid);
        }
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
        if self.target_not_local(&envelope.target_delivery_id, now_secs) {
            return EphemeralRouteResult::Dropped(EphemeralDropReason::NotLocal);
        }
        match self.route_gate(&envelope.target_delivery_id) {
            crate::EphemeralRouteGate::Online { gateway_id, session_id } => self
                .admit_routed_replay(
                    envelope,
                    supplied_expires_at_ms,
                    now_ms,
                    gateway_id,
                    session_id,
                ),
            crate::EphemeralRouteGate::Offline => {
                EphemeralRouteResult::Dropped(EphemeralDropReason::Offline)
            }
            crate::EphemeralRouteGate::RecipientUnsupported => {
                EphemeralRouteResult::Dropped(EphemeralDropReason::RecipientUnsupported)
            }
        }
    }

    fn admit_routed_replay(
        &self,
        envelope: &ramflux_protocol::Envelope,
        supplied_expires_at_ms: u64,
        now_ms: u64,
        gateway_id: String,
        session_id: String,
    ) -> EphemeralRouteResult {
        let Some(root) =
            envelope.ext.ext.get("source_root_commitment").and_then(serde_json::Value::as_str)
        else {
            return EphemeralRouteResult::RootMismatch;
        };
        let Some(deadline) = DeadlineSecs::from_expires_at_ms(supplied_expires_at_ms) else {
            return EphemeralRouteResult::DeadlineMismatch;
        };
        let digest = ephemeral_replay_digest(
            root,
            &envelope.source_device_id,
            &envelope.envelope_id,
            &envelope.payload_hash,
        );
        match self.admit_ephemeral_replay(digest, deadline.unix(), now_ms) {
            EphemeralReplayAdmit::Fresh => EphemeralRouteResult::Online { gateway_id, session_id },
            EphemeralReplayAdmit::Replayed => {
                EphemeralRouteResult::Dropped(EphemeralDropReason::Replayed)
            }
            EphemeralReplayAdmit::RateLimited => {
                EphemeralRouteResult::Dropped(EphemeralDropReason::RateLimited)
            }
            EphemeralReplayAdmit::Expired => {
                EphemeralRouteResult::Dropped(EphemeralDropReason::Expired)
            }
        }
    }

    /// Record or refuse an authenticated ephemeral digest until exclusive deadline `D`.
    pub fn admit_ephemeral_replay(
        &self,
        digest: [u8; 32],
        deadline_unix: u64,
        now_ms: u64,
    ) -> EphemeralReplayAdmit {
        lock_unpoisoned(self.replay_state()).admit(
            digest,
            DeadlineSecs::from_unix(deadline_unix),
            now_ms,
        )
    }

    #[cfg(test)]
    pub(crate) fn ephemeral_replay_len(&self) -> usize {
        lock_unpoisoned(self.replay_state()).by_digest.len()
    }

    #[cfg(test)]
    pub(crate) fn ephemeral_replay_contains_live(&self, digest: &[u8; 32], now_ms: u64) -> bool {
        lock_unpoisoned(self.replay_state()).contains_live(digest, now_ms)
    }
}

#[cfg(test)]
pub(crate) fn saturation_total() -> u64 {
    SATURATION_TOTAL.load(Ordering::Relaxed)
}

#[cfg(test)]
mod tests {
    use super::{
        DeadlineSecs, EPHEMERAL_REPLAY_BOUND, EphemeralReplayAdmit, EphemeralRouteRequest,
        EphemeralRouteResponse, ephemeral_replay_digest,
    };
    use super::{EphemeralDropReason, EphemeralDurableSnapshot, EphemeralRouteResult, deadline};
    use crate::{HomeNodeMigrationRecord, RouterCore};
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
            delivery_mode: None,
            collapse_tag: None,
            report_commitment: None,
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

    fn routed_digest(envelope: &Envelope) -> Fallible<[u8; 32]> {
        let root = envelope
            .ext
            .ext
            .get("source_root_commitment")
            .and_then(serde_json::Value::as_str)
            .ok_or("source_root_commitment")?;
        Ok(ephemeral_replay_digest(
            root,
            &envelope.source_device_id,
            &envelope.envelope_id,
            &envelope.payload_hash,
        ))
    }

    fn route(router: &RouterCore, envelope: &Envelope, expires_at_ms: u64) -> EphemeralRouteResult {
        router.route_ephemeral(envelope, expires_at_ms, NOW_MS)
    }

    fn assert_no_dispatch(router: &RouterCore, target: &str, result: &EphemeralRouteResult) {
        assert!(
            !matches!(result, EphemeralRouteResult::Online { .. }),
            "zero forwards and enqueues, got {result:?}"
        );
        assert_eq!(
            router.ephemeral_dispatch_observation(target),
            crate::EphemeralDispatchObservation {
                pending_inbox: 0,
                forwarding_reservations: 0,
                durable_enqueues: 0,
                forward_dispatches: 0
            },
            "inbox and home-node forwards stay empty"
        );
    }

    fn assert_read_only(
        router: &RouterCore,
        before: &EphemeralDurableSnapshot,
        store_bytes: &[u8],
        path: &std::path::Path,
    ) -> TestResult {
        assert_eq!(&router.ephemeral_durable_snapshot()?, before);
        assert_eq!(std::fs::read(path)?, store_bytes);
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
        let before_dispatch = router.ephemeral_dispatch_observation(&envelope.target_delivery_id);
        let result = route(router, envelope, expires_at_ms);
        assert_read_only(router, &before, store_bytes, path)?;
        assert_eq!(
            router.ephemeral_dispatch_observation(&envelope.target_delivery_id),
            before_dispatch
        );
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
        let store_bytes = std::fs::read(&path)?;

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
        assert_no_dispatch(&router, TARGET, &d_mismatch);

        let mut root_mismatch = signed_ephemeral("root", TARGET)?;
        root_mismatch.ext.ext.insert("source_root_commitment".into(), json!("other-root"));
        let root_expires = deadline(&root_mismatch, NOW_MS).unwrap_or(expires);
        let root_result =
            observe_route(&router, &root_mismatch, root_expires, &path, &store_bytes)?;
        assert_eq!(root_result, EphemeralRouteResult::RootMismatch);
        assert_no_dispatch(&router, TARGET, &root_result);

        let offline = signed_ephemeral("offline", "target_offline")?;
        let offline_result =
            observe_route(&router, &offline, computed_d(&offline)?, &path, &store_bytes)?;
        assert_eq!(offline_result, EphemeralRouteResult::Dropped(EphemeralDropReason::Offline));
        assert_no_dispatch(&router, "target_offline", &offline_result);

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
        assert_no_dispatch(&router, no_map, &no_map_result);

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
        assert_no_dispatch(&router, mismatch_map, &map_ne_result);

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
        assert_no_dispatch(&router, TARGET, &not_local);

        let revoked = signed_ephemeral("revoked", TARGET)?;
        router.test_revoke_envelope_source(&revoked);
        let revoked_result =
            observe_route(&router, &revoked, computed_d(&revoked)?, &path, &store_bytes)?;
        assert_eq!(revoked_result, EphemeralRouteResult::RevokedSource);
        assert_no_dispatch(&router, TARGET, &revoked_result);

        drop(store);
        Ok(())
    }

    #[test]
    fn ephemeral_route_missing_store_fails_oracle() -> TestResult {
        let router = RouterCore::new();
        register_alice(&router)?;
        bind_capable(&router, TARGET)?;
        let before = router.ephemeral_durable_snapshot()?;
        let missing = temp_path("missing-oracle");
        let Err(err) = assert_read_only(&router, &before, b"", &missing) else {
            return Err("missing store artifact must fail the oracle".into());
        };
        let io =
            err.downcast_ref::<std::io::Error>().ok_or("missing artifact must be io::Error")?;
        assert_eq!(io.kind(), std::io::ErrorKind::NotFound);
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

    #[test]
    fn ephemeral_route_replay_deadline() -> TestResult {
        let router = RouterCore::new();
        register_alice(&router)?;
        bind_capable(&router, TARGET)?;
        let envelope = signed_ephemeral("marker-d", TARGET)?;
        let expires = computed_d(&envelope)?;
        let digest = routed_digest(&envelope)?;
        let deadline_unix = DeadlineSecs::from_expires_at_ms(expires).ok_or("exact secs")?.unix();

        assert_eq!(
            router.route_ephemeral(&envelope, expires, expires.saturating_sub(1)),
            EphemeralRouteResult::Online { gateway_id: GATEWAY.into(), session_id: SESSION.into() }
        );
        assert!(router.ephemeral_replay_contains_live(&digest, expires.saturating_sub(1)));
        assert!(
            !router.ephemeral_replay_contains_live(&digest, expires),
            "marker must be gone at exclusive D"
        );
        assert_eq!(
            router.route_ephemeral(&envelope, expires, expires),
            EphemeralRouteResult::Dropped(EphemeralDropReason::Expired)
        );
        assert_eq!(
            router.admit_ephemeral_replay(digest, deadline_unix, expires),
            EphemeralReplayAdmit::Expired
        );
        assert_eq!(
            router.admit_ephemeral_replay(digest, deadline_unix.saturating_add(1), expires),
            EphemeralReplayAdmit::Fresh
        );

        assert_eq!(
            DeadlineSecs::from_expires_at_ms(1_005_000),
            Some(DeadlineSecs::from_unix(1_005))
        );
        assert_eq!(DeadlineSecs::from_expires_at_ms(1_005_001), None);
        assert_eq!(
            router.route_ephemeral(&envelope, expires.saturating_add(1), NOW_MS),
            EphemeralRouteResult::DeadlineMismatch
        );
        Ok(())
    }

    fn independently_signed(
        id: &str,
        target: &str,
        seed: [u8; 32],
        mutate: impl FnOnce(&mut Envelope),
    ) -> Fallible<Envelope> {
        let mut envelope = signed_ephemeral(id, target)?;
        envelope.signed.signature.clear();
        mutate(&mut envelope);
        envelope.signed.signature =
            ramflux_crypto::sign_protocol_object_with_seed(&envelope, seed)?;
        Ok(envelope)
    }

    fn round_trip_json<T: serde::Serialize + serde::de::DeserializeOwned + PartialEq>(
        value: &T,
    ) -> Fallible<T> {
        let bytes = serde_json::to_vec(value)?;
        let decoded: T = serde_json::from_slice(&bytes)?;
        assert_eq!(serde_json::to_vec(&decoded)?, bytes);
        Ok(decoded)
    }

    fn digest(n: u32) -> [u8; 32] {
        let mut out = [0_u8; 32];
        out[28..].copy_from_slice(&n.to_be_bytes());
        out
    }

    #[test]
    fn ephemeral_route_authority() -> TestResult {
        let path = temp_path("authority");
        let store = RouterRedbStore::open(&path)?;
        let router = RouterCore::new();
        register_alice(&router)?;
        store.record_identity_registry(&router.mvp1_identities_snapshot())?;
        bind_capable(&router, TARGET)?;
        let store_bytes = std::fs::read(&path)?;

        let bad_sig = independently_signed("sig", TARGET, [7_u8; 32], |_| {})?;
        let sig_result =
            observe_route(&router, &bad_sig, computed_d(&bad_sig)?, &path, &store_bytes)?;
        assert_eq!(sig_result, EphemeralRouteResult::RootMismatch);
        assert_no_dispatch(&router, TARGET, &sig_result);

        let principal = independently_signed("principal", TARGET, sign_seed(), |envelope| {
            envelope.source_principal_id = "bob".into();
        })?;
        let principal_result =
            observe_route(&router, &principal, computed_d(&principal)?, &path, &store_bytes)?;
        assert_eq!(principal_result, EphemeralRouteResult::RootMismatch);
        assert_no_dispatch(&router, TARGET, &principal_result);

        let device = independently_signed("device", TARGET, sign_seed(), |envelope| {
            envelope.source_device_id = "alice_laptop".into();
        })?;
        let device_result =
            observe_route(&router, &device, computed_d(&device)?, &path, &store_bytes)?;
        assert_eq!(device_result, EphemeralRouteResult::RootMismatch);
        assert_no_dispatch(&router, TARGET, &device_result);

        let root = independently_signed("root-signed", TARGET, sign_seed(), |envelope| {
            envelope.ext.ext.insert("source_root_commitment".into(), json!("other-root"));
        })?;
        let root_result = observe_route(&router, &root, computed_d(&root)?, &path, &store_bytes)?;
        assert_eq!(root_result, EphemeralRouteResult::RootMismatch);
        assert_no_dispatch(&router, TARGET, &root_result);
        drop(store);
        Ok(())
    }

    #[test]
    fn ephemeral_route_byte_identity() -> TestResult {
        let path = temp_path("bytes");
        let store = RouterRedbStore::open(&path)?;
        let router = RouterCore::new();
        register_alice(&router)?;
        store.record_identity_registry(&router.mvp1_identities_snapshot())?;
        bind_capable(&router, TARGET)?;
        let store_bytes = std::fs::read(&path)?;
        let envelope = signed_ephemeral("bytes", TARGET)?;
        let decoded = round_trip_json(&envelope)?;
        let expires = computed_d(&decoded)?;
        let request = round_trip_json(&EphemeralRouteRequest {
            envelope: decoded.clone(),
            expires_at_ms: expires,
        })?;
        let accepted =
            observe_route(&router, &request.envelope, request.expires_at_ms, &path, &store_bytes)?;
        assert_eq!(
            accepted,
            EphemeralRouteResult::Online { gateway_id: GATEWAY.into(), session_id: SESSION.into() }
        );
        let online = round_trip_json(&accepted.clone().into_response())?;
        assert_eq!(
            online,
            EphemeralRouteResponse::Online {
                gateway_id: GATEWAY.into(),
                session_id: SESSION.into()
            }
        );
        let mismatch = signed_ephemeral("bytes-mm", TARGET)?;
        let computed = computed_d(&mismatch)?;
        let refused =
            observe_route(&router, &mismatch, computed.saturating_add(1), &path, &store_bytes)?;
        let dropped = round_trip_json(&refused.into_response())?;
        assert_eq!(
            dropped,
            EphemeralRouteResponse::Dropped { reason: EphemeralDropReason::Invalid }
        );
        drop(store);
        Ok(())
    }

    #[test]
    fn ephemeral_route_replay_outcomes() -> TestResult {
        let path = temp_path("replay-path");
        let store = RouterRedbStore::open(&path)?;
        let router = RouterCore::new();
        register_alice(&router)?;
        store.record_identity_registry(&router.mvp1_identities_snapshot())?;
        bind_capable(&router, TARGET)?;
        let store_bytes = std::fs::read(&path)?;
        let envelope = signed_ephemeral("dup", TARGET)?;
        let expires = computed_d(&envelope)?;
        let first = observe_route(&router, &envelope, expires, &path, &store_bytes)?;
        assert_eq!(
            first,
            EphemeralRouteResult::Online { gateway_id: GATEWAY.into(), session_id: SESSION.into() }
        );
        let second = observe_route(&router, &envelope, expires, &path, &store_bytes)?;
        assert_eq!(second, EphemeralRouteResult::Dropped(EphemeralDropReason::Replayed));
        assert_no_dispatch(&router, TARGET, &second);
        assert_eq!(router.ephemeral_replay_len(), 1);

        let saturated = RouterCore::new();
        register_alice(&saturated)?;
        bind_capable(&saturated, TARGET)?;
        let live_d = NOW_MS / 1_000 + 5;
        for n in 0..EPHEMERAL_REPLAY_BOUND {
            let n = u32::try_from(n)?;
            assert_eq!(
                saturated.admit_ephemeral_replay(digest(n), live_d, NOW_MS),
                EphemeralReplayAdmit::Fresh
            );
        }
        let overflow = signed_ephemeral("sat", TARGET)?;
        assert_eq!(
            route(&saturated, &overflow, computed_d(&overflow)?),
            EphemeralRouteResult::Dropped(EphemeralDropReason::RateLimited)
        );
        assert_eq!(saturated.ephemeral_replay_len(), EPHEMERAL_REPLAY_BOUND);
        drop(store);
        Ok(())
    }
}

#[cfg(test)]
mod replay_tests {
    use super::{
        EPHEMERAL_REPLAY_BOUND, EphemeralReplayAdmit, ephemeral_replay_digest, saturation_total,
    };
    use crate::{RouterCore, RouterRedbStore};
    use redb::{ReadableDatabase, ReadableTable, TableHandle};
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    const DEADLINE_UNIX: u64 = 2_000;
    const NOW_LIVE_MS: u64 = 1_000_000;
    const NOW_AT_D_MS: u64 = 2_000_000;
    const NOW_BEFORE_D_MS: u64 = 1_999_999;

    fn temp_path(name: &str) -> PathBuf {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        std::env::temp_dir().join(format!(
            "ramflux-s6c-p07-replay-{name}-{}-{}.redb",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ))
    }

    fn digest(n: u32) -> [u8; 32] {
        let mut out = [0_u8; 32];
        out[28..].copy_from_slice(&n.to_be_bytes());
        out
    }

    fn restarted(router: &RouterCore) -> RouterCore {
        RouterCore::from_snapshot(router.snapshot())
    }

    fn row_digest_is_domain_separated() {
        let a = ephemeral_replay_digest("root", "dev", "env", "hash");
        let b = ephemeral_replay_digest("root", "dev", "env", "hash");
        let c = ephemeral_replay_digest("root", "dev", "env2", "hash");
        let d = ephemeral_replay_digest("rootX", "dev", "env", "hash");
        assert_eq!(a, b);
        assert_ne!(a, c);
        assert_ne!(a, d);
        assert_ne!(a, [0_u8; 32]);
    }

    fn fill(router: &RouterCore, count: usize, now_ms: u64) -> TestResult {
        for n in 0..count {
            let n = u32::try_from(n)?;
            assert_eq!(
                router.admit_ephemeral_replay(digest(n), DEADLINE_UNIX, now_ms),
                EphemeralReplayAdmit::Fresh,
                "digest {n} should be fresh"
            );
        }
        Ok(())
    }

    fn row_bound_accepted() -> TestResult {
        let router = RouterCore::new();
        fill(&router, EPHEMERAL_REPLAY_BOUND, NOW_LIVE_MS)?;
        assert_eq!(router.ephemeral_replay_len(), EPHEMERAL_REPLAY_BOUND);
        assert!(router.ephemeral_replay_contains_live(&digest(0), NOW_LIVE_MS));
        assert!(router.ephemeral_replay_contains_live(
            &digest(u32::try_from(EPHEMERAL_REPLAY_BOUND - 1)?),
            NOW_LIVE_MS
        ));
        Ok(())
    }

    fn row_next_refused_without_eviction() -> TestResult {
        let router = RouterCore::new();
        fill(&router, EPHEMERAL_REPLAY_BOUND, NOW_LIVE_MS)?;
        let before = saturation_total();
        let overflow = u32::try_from(EPHEMERAL_REPLAY_BOUND)?;
        assert_eq!(
            router.admit_ephemeral_replay(digest(overflow), DEADLINE_UNIX, NOW_LIVE_MS),
            EphemeralReplayAdmit::RateLimited
        );
        assert_eq!(router.ephemeral_replay_len(), EPHEMERAL_REPLAY_BOUND);
        assert!(!router.ephemeral_replay_contains_live(&digest(overflow), NOW_LIVE_MS));
        assert!(router.ephemeral_replay_contains_live(&digest(0), NOW_LIVE_MS));
        assert_eq!(
            router.admit_ephemeral_replay(digest(0), DEADLINE_UNIX, NOW_LIVE_MS),
            EphemeralReplayAdmit::Replayed
        );
        assert_eq!(router.ephemeral_replay_len(), EPHEMERAL_REPLAY_BOUND);
        assert!(saturation_total() > before);
        Ok(())
    }

    fn row_duplicate_replayed_from_valid() {
        let router = RouterCore::new();
        assert_eq!(
            router.admit_ephemeral_replay(digest(1), DEADLINE_UNIX, NOW_LIVE_MS),
            EphemeralReplayAdmit::Fresh
        );
        assert_eq!(
            router.admit_ephemeral_replay(digest(1), DEADLINE_UNIX, NOW_LIVE_MS),
            EphemeralReplayAdmit::Replayed
        );
        assert_eq!(router.ephemeral_replay_len(), 1);
    }

    fn row_live_at_exclusive_lower_ms() {
        let router = RouterCore::new();
        assert_eq!(
            router.admit_ephemeral_replay(digest(2), DEADLINE_UNIX, NOW_BEFORE_D_MS),
            EphemeralReplayAdmit::Fresh
        );
        assert!(router.ephemeral_replay_contains_live(&digest(2), NOW_BEFORE_D_MS));
        assert_eq!(
            router.admit_ephemeral_replay(digest(2), DEADLINE_UNIX, NOW_BEFORE_D_MS),
            EphemeralReplayAdmit::Replayed
        );
    }

    fn row_expired_incoming_preserves_live_marker() {
        let router = RouterCore::new();
        let x = digest(11);
        assert_eq!(
            router.admit_ephemeral_replay(x, 1005, NOW_LIVE_MS),
            EphemeralReplayAdmit::Fresh
        );
        assert_eq!(router.ephemeral_replay_len(), 1);
        assert_eq!(
            router.admit_ephemeral_replay(x, 1000, NOW_LIVE_MS),
            EphemeralReplayAdmit::Expired
        );
        assert_eq!(router.ephemeral_replay_len(), 1);
        assert!(router.ephemeral_replay_contains_live(&x, NOW_LIVE_MS));
        assert_eq!(
            router.admit_ephemeral_replay(x, 1005, NOW_LIVE_MS),
            EphemeralReplayAdmit::Replayed
        );
        assert_eq!(router.ephemeral_replay_len(), 1);
    }

    fn row_stored_expired_cleanup_still_works() {
        let router = RouterCore::new();
        let x = digest(12);
        assert_eq!(router.admit_ephemeral_replay(x, 1000, 999_000), EphemeralReplayAdmit::Fresh);
        assert_eq!(router.ephemeral_replay_len(), 1);
        assert_eq!(
            router.admit_ephemeral_replay(x, 1000, 1_000_000),
            EphemeralReplayAdmit::Expired
        );
        assert!(!router.ephemeral_replay_contains_live(&x, 1_000_000));
        assert_eq!(router.ephemeral_replay_len(), 0);
    }

    fn row_expired_at_d_drops_marker() {
        let router = RouterCore::new();
        assert_eq!(
            router.admit_ephemeral_replay(digest(3), DEADLINE_UNIX, NOW_BEFORE_D_MS),
            EphemeralReplayAdmit::Fresh
        );
        assert!(router.ephemeral_replay_contains_live(&digest(3), NOW_BEFORE_D_MS));
        assert_eq!(
            router.admit_ephemeral_replay(digest(3), DEADLINE_UNIX, NOW_AT_D_MS),
            EphemeralReplayAdmit::Expired
        );
        assert!(!router.ephemeral_replay_contains_live(&digest(3), NOW_AT_D_MS));
        assert_eq!(router.ephemeral_replay_len(), 0);
    }

    fn row_deadline_mul_overflow_expired() {
        let router = RouterCore::new();
        let overflowing = (u64::MAX / 1_000) + 1;
        assert_eq!(
            router.admit_ephemeral_replay(digest(4), overflowing, NOW_LIVE_MS),
            EphemeralReplayAdmit::Expired
        );
        assert_eq!(router.ephemeral_replay_len(), 0);
    }

    fn row_expiry_frees_slot() -> TestResult {
        let router = RouterCore::new();
        fill(&router, EPHEMERAL_REPLAY_BOUND, NOW_LIVE_MS)?;
        let overflow = u32::try_from(EPHEMERAL_REPLAY_BOUND)?;
        assert_eq!(
            router.admit_ephemeral_replay(digest(overflow), DEADLINE_UNIX, NOW_AT_D_MS),
            EphemeralReplayAdmit::Expired
        );
        assert_eq!(router.ephemeral_replay_len(), 0);
        assert_eq!(
            router.admit_ephemeral_replay(digest(overflow), DEADLINE_UNIX, NOW_LIVE_MS),
            EphemeralReplayAdmit::Fresh
        );
        assert_eq!(router.ephemeral_replay_len(), 1);
        Ok(())
    }

    fn scan_tables_for_replay_set(path: &Path) -> TestResult {
        let db = redb::Database::open(path)?;
        let tx = db.begin_read()?;
        for table in tx.list_tables()? {
            let name = table.name().to_owned();
            assert!(
                !name.contains("ephemeral_replay") && !name.contains("ephemeral/route"),
                "replay table {name}"
            );
            let definition = redb::TableDefinition::<&str, &[u8]>::new(name.as_str());
            let Ok(opened) = tx.open_table(definition) else {
                continue;
            };
            for entry in opened.iter()? {
                let (key, value) = entry?;
                let key = key.value();
                let value = String::from_utf8_lossy(value.value());
                assert!(!key.contains("ephemeral_replay"), "key {key}");
                assert!(!value.contains("ephemeral_replay"), "value in {name}");
            }
        }
        Ok(())
    }

    fn row_restart_empties_then_duplicate_before_d() {
        let router = RouterCore::new();
        assert_eq!(
            router.admit_ephemeral_replay(digest(7), DEADLINE_UNIX, NOW_LIVE_MS),
            EphemeralReplayAdmit::Fresh
        );
        let restored = restarted(&router);
        assert_eq!(restored.ephemeral_replay_len(), 0);
        assert!(!restored.ephemeral_replay_contains_live(&digest(7), NOW_LIVE_MS));
        assert_eq!(
            restored.admit_ephemeral_replay(digest(7), DEADLINE_UNIX, NOW_LIVE_MS),
            EphemeralReplayAdmit::Fresh
        );
        assert_eq!(restored.ephemeral_replay_len(), 1);
    }

    fn row_repeated_restarts_duplicate_only_before_d() {
        let mut router = RouterCore::new();
        for _ in 0..3 {
            assert_eq!(
                router.admit_ephemeral_replay(digest(8), DEADLINE_UNIX, NOW_LIVE_MS),
                EphemeralReplayAdmit::Fresh
            );
            router = restarted(&router);
            assert_eq!(router.ephemeral_replay_len(), 0);
        }
        assert_eq!(
            router.admit_ephemeral_replay(digest(8), DEADLINE_UNIX, NOW_BEFORE_D_MS),
            EphemeralReplayAdmit::Fresh
        );
        router = restarted(&router);
        assert_eq!(
            router.admit_ephemeral_replay(digest(8), DEADLINE_UNIX, NOW_AT_D_MS),
            EphemeralReplayAdmit::Expired
        );
        assert_eq!(router.ephemeral_replay_len(), 0);
        assert!(!router.ephemeral_replay_contains_live(&digest(8), NOW_AT_D_MS));
    }

    fn row_clone_keeps_in_process_markers() {
        let router = RouterCore::new();
        assert_eq!(
            router.admit_ephemeral_replay(digest(9), DEADLINE_UNIX, NOW_LIVE_MS),
            EphemeralReplayAdmit::Fresh
        );
        let cloned = router.clone();
        assert_eq!(cloned.ephemeral_replay_len(), 1);
        assert_eq!(
            cloned.admit_ephemeral_replay(digest(9), DEADLINE_UNIX, NOW_LIVE_MS),
            EphemeralReplayAdmit::Replayed
        );
    }

    fn row_save_reopen_has_empty_set() -> TestResult {
        let path = temp_path("reopen");
        let store = RouterRedbStore::open(&path)?;
        let router = RouterCore::new();
        assert_eq!(
            router.admit_ephemeral_replay(digest(10), DEADLINE_UNIX, NOW_LIVE_MS),
            EphemeralReplayAdmit::Fresh
        );
        store.save_router(&router)?;
        drop(router);
        drop(store);
        scan_tables_for_replay_set(&path)?;
        let store = RouterRedbStore::open(&path)?;
        let restored = store.load_router()?;
        match restored {
            None => {}
            Some(restored) => {
                assert_eq!(restored.ephemeral_replay_len(), 0);
                assert!(!restored.ephemeral_replay_contains_live(&digest(10), NOW_LIVE_MS));
            }
        }
        drop(store);
        let _ = std::fs::remove_file(&path);
        Ok(())
    }

    #[test]
    fn ephemeral_replay_saturation() -> TestResult {
        row_digest_is_domain_separated();
        row_bound_accepted()?;
        row_next_refused_without_eviction()?;
        row_duplicate_replayed_from_valid();
        row_expiry_frees_slot()?;
        Ok(())
    }

    #[test]
    fn ephemeral_restart_window() -> TestResult {
        row_live_at_exclusive_lower_ms();
        row_expired_at_d_drops_marker();
        row_expired_incoming_preserves_live_marker();
        row_stored_expired_cleanup_still_works();
        row_deadline_mul_overflow_expired();
        row_restart_empties_then_duplicate_before_d();
        row_repeated_restarts_duplicate_only_before_d();
        row_clone_keeps_in_process_markers();
        row_save_reopen_has_empty_set()?;
        Ok(())
    }
}

// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use super::*;
use std::path::{Path, PathBuf};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Class {
    Ingress,
    Sink,
    NonIngress(&'static str),
}

const DURABLE_INGRESS: &[(&str, Class)] = &[
    (
        "custody_authority.rs:publish_custody_record",
        Class::NonIngress("custody publication API; no envelope delivery effect"),
    ),
    (
        "custody_authority.rs:publish_custody_record_from",
        Class::NonIngress("custody publication API; no envelope delivery effect"),
    ),
    (
        "custody_authority/forwarded.rs:authenticated_native_forwarded_source_with_floors",
        Class::Sink,
    ),
    ("custody_authority/forwarded.rs:authenticated_native_forwarded_source_from_peer", Class::Sink),
    ("custody_delivery.rs:submit", Class::Ingress),
    (
        "device_source.rs:verify_envelope_source",
        Class::NonIngress("pure source-signature verification"),
    ),
    (
        "device_source.rs:forwarded_envelope_source",
        Class::NonIngress("pure forwarded-source verification"),
    ),
    ("entry_bound.rs:single_entry_frame_size", Class::NonIngress("pure size calculation")),
    ("entry_bound.rs:check_entry_bound", Class::NonIngress("pure admission validation")),
    (
        "federation_crypto.rs:sign_federated_envelope_forward",
        Class::NonIngress("pure signing helper"),
    ),
    (
        "federation_crypto.rs:verify_federated_envelope_forward",
        Class::NonIngress("pure signature verification"),
    ),
    (
        "federation_crypto.rs:verify_federated_envelope_forward_with_timings",
        Class::NonIngress("pure signature verification"),
    ),
    (
        "federation_delivery.rs:ensure_cross_node_friend_request_allowed",
        Class::NonIngress("friend-request policy; no envelope persistence"),
    ),
    (
        "federation_delivery.rs:ensure_federated_envelope_allowed",
        Class::NonIngress("pure federation policy check"),
    ),
    ("federation_store.rs:spool_outbound_forward", Class::Ingress),
    ("federation_store.rs:accept_inbound_forward_once", Class::Ingress),
    ("federation_store.rs:deliver_inbound_forward_once", Class::Ingress),
    ("federation_store.rs:deliver_inbound_forward_once_with_lease", Class::Ingress),
    (
        "federation_store.rs:federated_forward_replay_key",
        Class::NonIngress("pure replay-key construction"),
    ),
    (
        "federation_store/dead_letters.rs:dead_letter_outbound",
        Class::NonIngress("stored-durable-row consumer, protected upstream by E4"),
    ),
    ("forwarded_delivery.rs:submit_forwarded_envelope", Class::Ingress),
    ("forwarded_delivery.rs:prepare_forwarded_envelope", Class::Ingress),
    ("forwarded_delivery.rs:prepare_forwarded_envelope_with_metadata", Class::Ingress),
    (
        "home_migration_store/refusals.rs:migration_submission_refusal",
        Class::NonIngress("typed refusal construction; no envelope persistence"),
    ),
    (
        "home_migration_store/refusals.rs:migration_source_submission_refusal",
        Class::NonIngress("typed refusal construction; no envelope persistence"),
    ),
    (
        "home_node_migration.rs:federated_forward_request",
        Class::NonIngress("pure request construction from an admitted plan"),
    ),
    ("relay/cache.rs:get_object_chunk", Class::NonIngress("relay object read")),
    (
        "relay/legacy.rs:validate_object_permission",
        Class::NonIngress("pure relay permission validation"),
    ),
    (
        "relay/legacy.rs:object_permission_canonical_bytes",
        Class::NonIngress("pure canonical encoding"),
    ),
    ("relay/legacy.rs:permission_owner_matches_token", Class::NonIngress("pure relay owner check")),
    (
        "relay/trust.rs:federated_trust_snapshot_envelope_signing_bytes",
        Class::NonIngress("pure canonical encoding"),
    ),
    (
        "relay/trust.rs:verify_federated_trust_snapshot_envelope",
        Class::NonIngress("pure signature verification"),
    ),
    (
        "replay_guard.rs:check_envelope",
        Class::NonIngress("in-memory replay-guard primitive; guarded by E6 caller"),
    ),
    (
        "replay_guard.rs:accept_envelope_once",
        Class::NonIngress("in-memory replay-guard primitive; guarded by E6 caller"),
    ),
    ("replay_guard.rs:holds_envelope", Class::NonIngress("in-memory replay-guard read")),
    (
        "replay_guard.rs:envelope_replay_tuple_key",
        Class::NonIngress("pure replay-key construction"),
    ),
    ("router.rs:mvp10_own_device_fanout", Class::Ingress),
    ("router.rs:mvp10_own_device_fanout_at", Class::Ingress),
    ("router.rs:accept_envelope_replay", Class::Ingress),
    ("router.rs:submit_replay_accepted_envelope", Class::Ingress),
    ("router.rs:accept_own_device_fanout_replay", Class::Ingress),
    ("router.rs:accept_leased_fanout", Class::Ingress),
    ("router.rs:submit_envelope", Class::Ingress),
    ("router.rs:submit_envelope_at", Class::Ingress),
    ("router.rs:submit_envelope_with_home_node_forward_at", Class::Ingress),
    ("router.rs:prepare_envelope_with_home_node_forward_at", Class::Ingress),
    (
        "router.rs:complete_home_node_forward",
        Class::NonIngress("completes an already admitted forward reservation"),
    ),
    ("router.rs:authenticated_envelope_source", Class::Sink),
    ("router.rs:authenticated_envelope_source_durable", Class::Sink),
    ("router.rs:authenticated_envelope_source_from", Class::Sink),
    (
        "router.rs:refresh_registered_envelope_authority",
        Class::NonIngress("registered-source refresh; not an inbound delivery"),
    ),
    ("router/committed_forward.rs:prepare_committed_home_forward", Class::Ingress),
    ("router/sender_fanout.rs:prepare_sender_fanout", Class::Ingress),
    ("router_store/custody.rs:custody_node_history", Class::NonIngress("custody history read")),
    ("router_store/sender_retry.rs:content_digest", Class::NonIngress("pure content digest")),
    ("router_store/sender_retry.rs:sender_assignment", Class::NonIngress("retry assignment read")),
    ("router_store/sender_retry/registry.rs:admit_sender_retry", Class::Sink),
    (
        "service_signing.rs:home_migration_node",
        Class::NonIngress("pure node identifier constructor"),
    ),
    (
        "session.rs:route_envelope",
        Class::NonIngress("session routing lookup; no persistent envelope effect"),
    ),
];

#[test]
fn durable_ingress_registry_refuses_marked_envelopes() -> Result<(), Box<dyn std::error::Error>> {
    let listed = DURABLE_INGRESS.iter().map(|(name, _)| (*name).to_owned()).collect::<Vec<_>>();
    let source_root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");
    let sources = public_envelope_sources(&source_root)?;
    assert_registry_scan_matches(&sources, &listed).map_err(std::io::Error::other)?;

    let ingress_count =
        DURABLE_INGRESS.iter().filter(|(_, class)| *class == Class::Ingress).count();
    let sink_count = DURABLE_INGRESS.iter().filter(|(_, class)| *class == Class::Sink).count();
    let non_ingress_count =
        DURABLE_INGRESS.iter().filter(|(_, class)| matches!(class, Class::NonIngress(_))).count();
    assert_eq!((ingress_count, sink_count, non_ingress_count), (20, 6, 33));
    for (entry, class) in DURABLE_INGRESS {
        if let Class::NonIngress(reason) = class {
            assert!(!reason.is_empty(), "{entry} needs a NonIngress reason");
        }
        if matches!(class, Class::Ingress | Class::Sink) {
            assert!(
                first_statement_has_mode_guard(
                    &PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src"),
                    entry,
                )?,
                "{entry} must refuse marked delivery modes before its first effect"
            );
        }
    }
    for with_wal in [true, false] {
        let router_path = temp_store_path(if with_wal { "registry_wal" } else { "registry_redb" })?;
        let router_store = if with_wal {
            RouterRedbStore::open_with_wal(&router_path, router_path.with_extension("wal"))?
        } else {
            RouterRedbStore::open_without_wal(&router_path)?
        };
        let federation_store = FederationRedbStore::open(temp_store_path("registry_federation")?)?;
        let router = RouterCore::new();
        let mut ordinal = 0_u64;
        for (entry, class) in DURABLE_INGRESS {
            if *class != Class::Ingress {
                continue;
            }
            for mode in [
                serde_json::Value::String("ephemeral".into()),
                serde_json::Value::String("unknown-mode".into()),
                serde_json::Value::Null,
            ] {
                let mut marked = envelope(
                    &format!("registry_{with_wal}_{ordinal}"),
                    "registry_target",
                    DeliveryClass::OpaqueEvent,
                );
                marked.source_device_id = format!("foreign_registry_{ordinal}");
                marked.priority = Priority::Low;
                marked.ttl = 50;
                marked.ext.ext.insert("delivery_mode".into(), mode.clone());
                let marked = forwarded_source_envelope(marked)?;
                let control = without_delivery_mode(&marked)?;
                let authority: DeviceAuthKeyResponse =
                    serde_json::from_value(marked.ext.ext["source_device_authority"].clone())?;
                let source = authority.authenticated_device_identity()?;
                let fixture = IngressFixture {
                    router: &router,
                    router_store: &router_store,
                    federation_store: &federation_store,
                    source: &source,
                    envelope: &marked,
                    control: &control,
                    ordinal,
                };
                exercise_ingress_control(entry, fixture)?;
                let before = (
                    router.durable_ingress_ephemeral_snapshot(),
                    router_store.durable_ingress_snapshot()?,
                    federation_store.durable_ingress_snapshot()?,
                );
                exercise_ingress(entry, fixture)?;
                let after = (
                    router.durable_ingress_ephemeral_snapshot(),
                    router_store.durable_ingress_snapshot()?,
                    federation_store.durable_ingress_snapshot()?,
                );
                assert_eq!(after, before, "WAL={with_wal}, ingress={entry}, mode={mode}");
                ordinal += 1;
            }
        }
    }
    Ok(())
}

#[derive(Clone, Copy)]
struct IngressFixture<'a> {
    router: &'a RouterCore,
    router_store: &'a RouterRedbStore,
    federation_store: &'a FederationRedbStore,
    source: &'a ramflux_crypto::RootQualifiedDeviceRef,
    envelope: &'a Envelope,
    control: &'a Envelope,
    ordinal: u64,
}

fn exercise_ingress_control(
    entry: &str,
    fixture: IngressFixture<'_>,
) -> Result<(), Box<dyn std::error::Error>> {
    let IngressFixture { router, router_store, federation_store, source, control, .. } = fixture;
    match entry {
        "custody_delivery.rs:submit" => {}
        "federation_store.rs:spool_outbound_forward"
        | "federation_store.rs:accept_inbound_forward_once"
        | "federation_store.rs:deliver_inbound_forward_once"
        | "federation_store.rs:deliver_inbound_forward_once_with_lease" => {
            exercise_federation_control(entry, federation_store, source, control)?;
        }
        "forwarded_delivery.rs:submit_forwarded_envelope"
        | "forwarded_delivery.rs:prepare_forwarded_envelope"
        | "forwarded_delivery.rs:prepare_forwarded_envelope_with_metadata" => {
            exercise_forwarded_control(entry, router, router_store, control)?;
        }
        _ => exercise_router_control(entry, router, router_store, source, control)?,
    }
    Ok(())
}

fn without_delivery_mode(envelope: &Envelope) -> Result<Envelope, Box<dyn std::error::Error>> {
    let mut control = envelope.clone();
    control.ext.ext.remove("delivery_mode");
    control.signed.signature = ramflux_crypto::sign_protocol_object(&control)?;
    Ok(control)
}

fn exercise_ingress(
    entry: &str,
    fixture: IngressFixture<'_>,
) -> Result<(), Box<dyn std::error::Error>> {
    let IngressFixture {
        router, router_store, federation_store, source, envelope, ordinal, ..
    } = fixture;
    match entry {
        "custody_delivery.rs:submit" => {
            exercise_custody_ingress(router, router_store, envelope, ordinal)
        }
        "federation_store.rs:spool_outbound_forward"
        | "federation_store.rs:accept_inbound_forward_once"
        | "federation_store.rs:deliver_inbound_forward_once"
        | "federation_store.rs:deliver_inbound_forward_once_with_lease" => {
            exercise_federation_ingress(entry, federation_store, source, envelope)
        }
        "forwarded_delivery.rs:submit_forwarded_envelope"
        | "forwarded_delivery.rs:prepare_forwarded_envelope"
        | "forwarded_delivery.rs:prepare_forwarded_envelope_with_metadata" => {
            exercise_forwarded_ingress(entry, router, router_store, envelope)
        }
        _ => exercise_router_ingress(entry, router, router_store, source, envelope),
    }
}

fn exercise_custody_ingress(
    router: &RouterCore,
    store: &RouterRedbStore,
    envelope: &Envelope,
    ordinal: u64,
) -> Result<(), Box<dyn std::error::Error>> {
    let seed = u8::try_from(ordinal % 200)?;
    let driver = super::custody_sessions::Driver::new("durable_ingress_registry", seed)?;
    let authority = ramflux_crypto::custody::verify_record(
        &driver.publication.record,
        1_760_000_000,
        None,
        None,
    )?;
    let branch = ramflux_crypto::create_device_branch(
        "durable_ingress_registry",
        "primary",
        1,
        [seed + 2; 32],
    );
    let source =
        ramflux_crypto::RootQualifiedDeviceRef::from_custody_record(&authority, "primary")?;
    let mut valid = super::envelope(
        &format!("custody_registry_{ordinal}"),
        "registry_target",
        DeliveryClass::OpaqueEvent,
    );
    valid.source_principal_id = "durable_ingress_registry".into();
    valid.source_device_id = "primary".into();
    valid
        .ext
        .ext
        .insert("source_root_commitment".into(), serde_json::json!(source.root_commitment()));
    valid.signed.signature =
        ramflux_crypto::sign_protocol_object_with_device_branch(&branch, &valid)?;
    valid.ext.ext.insert(
        "delivery_mode".into(),
        envelope.ext.ext.get("delivery_mode").cloned().ok_or("marked mode absent")?,
    );
    let mut control = valid.clone();
    control.ext.ext.remove("delivery_mode");
    let session = ramflux_protocol::custody::CustodySession {
        session_id: format!("session_{ordinal}"),
        device_ref: driver.reference.clone(),
        target_delivery_id: valid.target_delivery_id.clone(),
        record_hash: "record_hash".into(),
        proof_hash: "proof_hash".into(),
        binding_mode: ramflux_protocol::custody::BindingMode::HomeRelayReceipt,
        expires_at: 1_760_000_100,
    };
    let control_result = crate::custody_delivery::submit(
        router,
        store,
        crate::custody_delivery::DeliveryAuthority {
            authority: &authority,
            session: &session,
            source: &source,
        },
        control,
        1_760_000_000,
    );
    assert_eq!(
        control_result,
        Err(ramflux_protocol::custody::CustodyRefusal::AuthorityUnavailable)
    );
    assert_eq!(
        ramflux_protocol::ephemeral::require_durable(&valid)
            .map_err(NodeCoreError::from)
            .err()
            .map(|error| error.to_string())
            .as_deref(),
        Some("delivery_mode_refused")
    );
    let result = crate::custody_delivery::submit(
        router,
        store,
        crate::custody_delivery::DeliveryAuthority {
            authority: &authority,
            session: &session,
            source: &source,
        },
        valid,
        1_760_000_000,
    );
    assert_eq!(result, Err(ramflux_protocol::custody::CustodyRefusal::InvalidInput));
    Ok(())
}

fn exercise_federation_ingress(
    entry: &str,
    store: &FederationRedbStore,
    source: &ramflux_crypto::RootQualifiedDeviceRef,
    envelope: &Envelope,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut forward = super::federation::federation_forward_request(
        &envelope.envelope_id,
        &envelope.target_delivery_id,
    );
    forward.envelope.clone_from(envelope);
    let now = 1_760_000_010;
    match entry {
        "federation_store.rs:spool_outbound_forward" => {
            assert_delivery_mode_refused(
                store.spool_outbound_forward("peer", &forward, now, 5),
                entry,
            );
        }
        "federation_store.rs:accept_inbound_forward_once" => {
            assert_delivery_mode_refused(
                store.accept_inbound_forward_once(source, &forward, now),
                entry,
            );
        }
        "federation_store.rs:deliver_inbound_forward_once" => {
            assert_delivery_mode_refused(
                store.deliver_inbound_forward_once(source, &forward, now, || {
                    Err(NodeCoreError::Unauthorized("unexpected delivery".into()))
                }),
                entry,
            );
        }
        "federation_store.rs:deliver_inbound_forward_once_with_lease" => {
            assert_delivery_mode_refused(
                store.deliver_inbound_forward_once_with_lease(source, &forward, now, 10, || {
                    Err(NodeCoreError::Unauthorized("unexpected delivery".into()))
                }),
                entry,
            );
        }
        _ => return Err(format!("unknown federation ingress {entry}").into()),
    }
    Ok(())
}

fn exercise_federation_control(
    entry: &str,
    store: &FederationRedbStore,
    source: &ramflux_crypto::RootQualifiedDeviceRef,
    envelope: &Envelope,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut forward = super::federation::federation_forward_request(
        &envelope.envelope_id,
        &envelope.target_delivery_id,
    );
    forward.envelope.clone_from(envelope);
    match entry {
        "federation_store.rs:spool_outbound_forward" => assert_not_mode_refused(
            store.spool_outbound_forward("peer", &forward, 1_760_000_010, 5),
            entry,
        ),
        "federation_store.rs:accept_inbound_forward_once" => assert_not_mode_refused(
            store.accept_inbound_forward_once(source, &forward, 1_760_000_010),
            entry,
        ),
        "federation_store.rs:deliver_inbound_forward_once" => assert_not_mode_refused(
            store.deliver_inbound_forward_once(source, &forward, 1_760_000_010, || {
                Err(NodeCoreError::Unauthorized("next-stage control".into()))
            }),
            entry,
        ),
        "federation_store.rs:deliver_inbound_forward_once_with_lease" => assert_not_mode_refused(
            store.deliver_inbound_forward_once_with_lease(
                source,
                &forward,
                1_760_000_010,
                10,
                || Err(NodeCoreError::Unauthorized("next-stage control".into())),
            ),
            entry,
        ),
        _ => return Err(format!("unknown federation ingress {entry}").into()),
    }
    Ok(())
}

fn exercise_forwarded_ingress(
    entry: &str,
    router: &RouterCore,
    store: &RouterRedbStore,
    envelope: &Envelope,
) -> Result<(), Box<dyn std::error::Error>> {
    let request = || crate::ForwardedEnvelopeRequest {
        peer_node_id: "peer".into(),
        envelope: envelope.clone(),
        migration_evidence: None,
    };
    match entry {
        "forwarded_delivery.rs:submit_forwarded_envelope" => {
            assert_delivery_mode_refused(
                router.submit_forwarded_envelope(store, None, request(), 1_760_000_010),
                entry,
            );
        }
        "forwarded_delivery.rs:prepare_forwarded_envelope" => {
            assert_delivery_mode_refused(
                router.prepare_forwarded_envelope(store, None, request(), 1_760_000_010),
                entry,
            );
        }
        "forwarded_delivery.rs:prepare_forwarded_envelope_with_metadata" => {
            assert_delivery_mode_refused(
                router.prepare_forwarded_envelope_with_metadata(
                    store,
                    None,
                    request(),
                    1_760_000_010,
                ),
                entry,
            );
        }
        _ => return Err(format!("unknown forwarded ingress {entry}").into()),
    }
    Ok(())
}

fn exercise_forwarded_control(
    entry: &str,
    router: &RouterCore,
    store: &RouterRedbStore,
    envelope: &Envelope,
) -> Result<(), Box<dyn std::error::Error>> {
    let request = || crate::ForwardedEnvelopeRequest {
        peer_node_id: "peer".into(),
        envelope: envelope.clone(),
        migration_evidence: None,
    };
    match entry {
        "forwarded_delivery.rs:submit_forwarded_envelope" => assert_not_mode_refused(
            router.submit_forwarded_envelope(store, None, request(), 1_760_000_010),
            entry,
        ),
        "forwarded_delivery.rs:prepare_forwarded_envelope" => assert_not_mode_refused(
            router.prepare_forwarded_envelope(store, None, request(), 1_760_000_010),
            entry,
        ),
        "forwarded_delivery.rs:prepare_forwarded_envelope_with_metadata" => {
            assert_not_mode_refused(
                router.prepare_forwarded_envelope_with_metadata(
                    store,
                    None,
                    request(),
                    1_760_000_010,
                ),
                entry,
            );
        }
        _ => return Err(format!("unknown forwarded ingress {entry}").into()),
    }
    Ok(())
}

fn exercise_router_ingress(
    entry: &str,
    router: &RouterCore,
    store: &RouterRedbStore,
    source: &ramflux_crypto::RootQualifiedDeviceRef,
    envelope: &Envelope,
) -> Result<(), Box<dyn std::error::Error>> {
    let request = || ItestMvp10OwnDeviceFanoutRequest {
        principal_id: envelope.source_principal_id.clone(),
        source_device_id: envelope.source_device_id.clone(),
        envelope: envelope.clone(),
    };
    let rejected = |outcome: RouterSubmitOutcome| matches!(outcome, RouterSubmitOutcome::RejectedSecurity { reason, .. } if reason == "delivery_mode_refused");
    match entry {
        "router.rs:mvp10_own_device_fanout" => {
            assert_delivery_mode_refused(router.mvp10_own_device_fanout(request()), entry);
        }
        "router.rs:mvp10_own_device_fanout_at" => assert_delivery_mode_refused(
            router.mvp10_own_device_fanout_at(request(), 1_760_000_010),
            entry,
        ),
        "router.rs:accept_envelope_replay" => assert_delivery_mode_refused(
            router.accept_envelope_replay(source, envelope.clone(), 1_760_000_010),
            entry,
        ),
        "router.rs:submit_replay_accepted_envelope" => {
            assert!(rejected(router.submit_replay_accepted_envelope(
                ReplayAcceptedEnvelope { envelope: envelope.clone() },
                1_760_000_010
            )));
        }
        "router.rs:accept_own_device_fanout_replay" => assert_delivery_mode_refused(
            router.accept_own_device_fanout_replay(request(), 1_760_000_010),
            entry,
        ),
        "router.rs:accept_leased_fanout" => assert_delivery_mode_refused(
            router.accept_leased_fanout(request(), store, 1_760_000_010),
            entry,
        ),
        "router.rs:submit_envelope" => {
            assert!(rejected(router.submit_envelope(source, envelope.clone())));
        }
        "router.rs:submit_envelope_at" => {
            assert!(rejected(router.submit_envelope_at(source, envelope.clone(), 1_760_000_010)));
        }
        "router.rs:submit_envelope_with_home_node_forward_at" => {
            let outcome = router.submit_envelope_with_home_node_forward_at(
                source,
                envelope.clone(),
                1_760_000_010,
                RouterEnvelopeOrigin::Federation,
                |_| Err(NodeCoreError::Unauthorized("unexpected forward".into())),
            );
            assert!(rejected(outcome));
        }
        "router.rs:prepare_envelope_with_home_node_forward_at" => match router
            .prepare_envelope_with_home_node_forward_at(
                source,
                envelope.clone(),
                1_760_000_010,
                RouterEnvelopeOrigin::Federation,
                10,
            ) {
            RouterForwardPreparation::Complete(outcome) => assert!(rejected(*outcome)),
            RouterForwardPreparation::Forward(_) => {
                return Err("marked envelope reserved a forward".into());
            }
        },
        "router/committed_forward.rs:prepare_committed_home_forward" => {
            assert_delivery_mode_refused(
                router.prepare_committed_home_forward(
                    store,
                    source,
                    envelope.clone(),
                    1_760_000_010,
                    10,
                ),
                entry,
            );
        }
        "router/sender_fanout.rs:prepare_sender_fanout" => assert_delivery_mode_refused(
            router.prepare_sender_fanout(store, &request(), 1_760_000_010),
            entry,
        ),
        _ => return Err(format!("unknown router ingress {entry}").into()),
    }
    Ok(())
}

fn exercise_router_control(
    entry: &str,
    router: &RouterCore,
    store: &RouterRedbStore,
    source: &ramflux_crypto::RootQualifiedDeviceRef,
    envelope: &Envelope,
) -> Result<(), Box<dyn std::error::Error>> {
    let request = || ItestMvp10OwnDeviceFanoutRequest {
        principal_id: envelope.source_principal_id.clone(),
        source_device_id: envelope.source_device_id.clone(),
        envelope: envelope.clone(),
    };
    match entry {
        "router.rs:mvp10_own_device_fanout" => {
            assert_not_mode_refused(router.mvp10_own_device_fanout(request()), entry);
        }
        "router.rs:mvp10_own_device_fanout_at" => assert_not_mode_refused(
            router.mvp10_own_device_fanout_at(request(), 1_760_000_010),
            entry,
        ),
        "router.rs:accept_envelope_replay" => assert_not_mode_refused(
            router.accept_envelope_replay(source, envelope.clone(), 1_760_000_010),
            entry,
        ),
        "router.rs:submit_replay_accepted_envelope" => {
            assert_submit_control(
                router.submit_replay_accepted_envelope(
                    ReplayAcceptedEnvelope { envelope: envelope.clone() },
                    1_760_000_010,
                ),
                entry,
            );
        }
        "router.rs:accept_own_device_fanout_replay" => assert_not_mode_refused(
            router.accept_own_device_fanout_replay(request(), 1_760_000_010),
            entry,
        ),
        "router.rs:accept_leased_fanout" => assert_not_mode_refused(
            router.accept_leased_fanout(request(), store, 1_760_000_010),
            entry,
        ),
        "router.rs:submit_envelope" => {
            assert_submit_control(router.submit_envelope(source, envelope.clone()), entry);
        }
        "router.rs:submit_envelope_at" => assert_submit_control(
            router.submit_envelope_at(source, envelope.clone(), 1_760_000_010),
            entry,
        ),
        "router.rs:submit_envelope_with_home_node_forward_at" => assert_submit_control(
            router.submit_envelope_with_home_node_forward_at(
                source,
                envelope.clone(),
                1_760_000_010,
                RouterEnvelopeOrigin::Federation,
                |_| Err(NodeCoreError::Unauthorized("next-stage control".into())),
            ),
            entry,
        ),
        "router.rs:prepare_envelope_with_home_node_forward_at" => match router
            .prepare_envelope_with_home_node_forward_at(
                source,
                envelope.clone(),
                1_760_000_010,
                RouterEnvelopeOrigin::Federation,
                10,
            ) {
            RouterForwardPreparation::Complete(outcome) => assert_submit_control(*outcome, entry),
            RouterForwardPreparation::Forward(_) => {}
        },
        "router/committed_forward.rs:prepare_committed_home_forward" => assert_not_mode_refused(
            router.prepare_committed_home_forward(
                store,
                source,
                envelope.clone(),
                1_760_000_010,
                10,
            ),
            entry,
        ),
        "router/sender_fanout.rs:prepare_sender_fanout" => assert_not_mode_refused(
            router.prepare_sender_fanout(store, &request(), 1_760_000_010),
            entry,
        ),
        _ => return Err(format!("unknown router ingress {entry}").into()),
    }
    Ok(())
}

fn assert_not_mode_refused<T>(result: Result<T, NodeCoreError>, entry: &str) {
    let mode_refused =
        result.err().is_some_and(|error| error.to_string() == "delivery_mode_refused");
    assert!(!mode_refused, "control rejected at mode check: {entry}");
}

fn assert_delivery_mode_refused<T>(result: Result<T, NodeCoreError>, entry: &str) {
    assert_eq!(
        result.err().map(|error| error.to_string()).as_deref(),
        Some("delivery_mode_refused"),
        "{entry}"
    );
}

fn assert_submit_control(outcome: RouterSubmitOutcome, entry: &str) {
    assert!(
        !matches!(outcome, RouterSubmitOutcome::RejectedSecurity { reason, .. } if reason == "delivery_mode_refused"),
        "control rejected at mode check: {entry}"
    );
}

fn first_statement_has_mode_guard(
    src: &Path,
    entry: &str,
) -> Result<bool, Box<dyn std::error::Error>> {
    let (relative, function) = entry.split_once(':').ok_or("invalid registry key")?;
    let source = std::fs::read_to_string(src.join(relative))?;
    let lines = source.lines().collect::<Vec<_>>();
    let Some(start) = lines.iter().position(|line| line.contains("fn ") && line.contains(function))
    else {
        return Ok(false);
    };
    let mut body = start;
    while body < lines.len() && !lines[body].contains('{') {
        body += 1;
    }
    if body == lines.len() {
        return Ok(false);
    }
    let after_brace = lines[body].split_once('{').map_or("", |(_, rest)| rest).trim();
    if !after_brace.is_empty() {
        return Ok(after_brace.contains("require_durable"));
    }
    Ok(lines
        .iter()
        .skip(body + 1)
        .map(|line| line.trim())
        .find(|line| !line.is_empty() && !line.starts_with("//"))
        .is_some_and(|line| line.contains("require_durable")))
}

fn public_envelope_sources(
    src: &Path,
) -> Result<Vec<(String, String)>, Box<dyn std::error::Error>> {
    let mut files = Vec::new();
    collect_rust_files(src, &mut files)?;
    files
        .into_iter()
        .map(|file| {
            let relative = file.strip_prefix(src)?.to_string_lossy().replace('\\', "/");
            Ok((relative, std::fs::read_to_string(file)?))
        })
        .collect()
}

fn scan_public_envelope_functions(
    sources: &[(String, String)],
) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let mut matches = Vec::new();
    for (relative, source) in sources {
        if relative.split('/').any(|part| part.contains("test") || part.contains("fixture")) {
            continue;
        }
        let lines = source.lines().collect::<Vec<_>>();
        let mut index = 0;
        while index < lines.len() {
            let line = lines[index].trim_start();
            if line == "#[cfg(test)]"
                && lines.get(index + 1).is_some_and(|next| is_mod_declaration(next.trim_start()))
            {
                break;
            }
            if is_public_function(line) {
                let mut signature = String::from(line);
                let mut complete = line.trim_end().ends_with('{') || line.trim_end().ends_with(';');
                while !complete && index + 1 < lines.len() {
                    index += 1;
                    let next = lines[index];
                    signature.push(' ');
                    signature.push_str(next.trim());
                    complete = next.trim_end().ends_with('{') || next.trim_end().ends_with(';');
                }
                if ["Envelope", "ForwardRequest", "FanoutRequest", "CustodySessionAction"]
                    .iter()
                    .any(|needle| signature.contains(needle))
                {
                    let function = signature
                        .split("fn ")
                        .nth(1)
                        .and_then(|rest| {
                            rest.split(|ch: char| !(ch.is_ascii_alphanumeric() || ch == '_')).next()
                        })
                        .ok_or("public function signature did not contain a function name")?;
                    matches.push(format!("{relative}:{function}"));
                }
            }
            index += 1;
        }
    }
    matches.sort();
    Ok(matches)
}

fn assert_registry_scan_matches(
    sources: &[(String, String)],
    listed: &[String],
) -> Result<(), String> {
    let mut sorted_listed = listed.to_vec();
    sorted_listed.sort();
    if listed.len() != sorted_listed.len() {
        return Err("duplicate durable ingress registry entries".into());
    }
    let scanned = scan_public_envelope_functions(sources).map_err(|error| error.to_string())?;
    if scanned != sorted_listed {
        return Err(format!("scanner matches differ: {scanned:?} != {sorted_listed:?}"));
    }
    Ok(())
}

#[test]
fn durable_ingress_registry_scanner_rejects_drift_fixtures() {
    let unlisted =
        vec![("registry.rs".to_owned(), "pub fn newly_exposed(envelope: Envelope) {}".to_owned())];
    assert!(assert_registry_scan_matches(&unlisted, &[]).is_err());

    let no_longer_matching =
        vec![("registry.rs".to_owned(), "pub fn previously_listed() {}".to_owned())];
    assert!(
        assert_registry_scan_matches(
            &no_longer_matching,
            &["registry.rs:previously_listed".to_owned()]
        )
        .is_err()
    );
}

fn collect_rust_files(directory: &Path, files: &mut Vec<PathBuf>) -> std::io::Result<()> {
    for entry in std::fs::read_dir(directory)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            collect_rust_files(&path, files)?;
        } else if path.extension().is_some_and(|extension| extension == "rs") {
            files.push(path);
        }
    }
    Ok(())
}

fn is_mod_declaration(line: &str) -> bool {
    line.starts_with("mod ")
        || line.starts_with("pub mod ")
        || line.starts_with("pub(crate) mod ")
        || line.starts_with("pub(super) mod ")
}

fn is_public_function(line: &str) -> bool {
    [
        "pub fn ",
        "pub(crate) fn ",
        "pub(super) fn ",
        "pub async fn ",
        "pub(crate) async fn ",
        "pub(super) async fn ",
    ]
    .iter()
    .any(|prefix| line.starts_with(prefix))
}

#[test]
fn e1_public_wrappers_refuse_marked_fresh_foreign_authority()
-> Result<(), Box<dyn std::error::Error>> {
    let modes = [
        serde_json::Value::String("ephemeral".into()),
        serde_json::Value::String("unknown-mode".into()),
        serde_json::Value::Null,
    ];
    for with_wal in [true, false] {
        for (index, mode) in modes.iter().enumerate() {
            for wrapper in
                ["authenticated_envelope_source", "authenticated_envelope_source_durable"]
            {
                let path = temp_store_path(&format!("e1_{wrapper}_{with_wal}_{index}"))?;
                let store = if with_wal {
                    RouterRedbStore::open_with_wal(&path, path.with_extension("wal"))?
                } else {
                    RouterRedbStore::open_without_wal(&path)?
                };
                let router = RouterCore::new();
                let mut marked = envelope(
                    &format!("e1_{wrapper}_{with_wal}_{index}"),
                    "foreign_target",
                    DeliveryClass::OpaqueEvent,
                );
                marked.source_device_id = format!("foreign_device_{with_wal}_{index}");
                marked.priority = Priority::Low;
                marked.ttl = 50;
                marked.ext.ext.insert("delivery_mode".into(), mode.clone());
                let marked = forwarded_source_envelope(marked)?;
                let control = without_delivery_mode(&marked)?;
                let control_result = if wrapper == "authenticated_envelope_source" {
                    router.authenticated_envelope_source(&control)
                } else {
                    router.authenticated_envelope_source_durable(&control, &store)
                };
                assert!(
                    matches!(control_result, Err(NodeCoreError::Unauthorized(_))),
                    "unmarked {wrapper} control did not reach its gateway-origin check: {control_result:?}"
                );
                let before = store.foreign_authority_row_counts()?;
                let result = if wrapper == "authenticated_envelope_source" {
                    router.authenticated_envelope_source(&marked)
                } else {
                    router.authenticated_envelope_source_durable(&marked, &store)
                };
                assert_eq!(
                    result.err().map(|error| error.to_string()).as_deref(),
                    Some("delivery_mode_refused")
                );
                assert_eq!(store.foreign_authority_row_counts()?, before);
            }
        }
    }
    Ok(())
}

#[test]
fn ephemeral_mode_errors_map_to_durable_delivery_refusal() {
    use ramflux_protocol::ephemeral::EphemeralModeError as ModeError;

    let errors = [
        ModeError::EphemeralAtDurableSink,
        ModeError::InvalidDeliveryMode,
        ModeError::NotEphemeral,
        ModeError::InvalidPriority,
        ModeError::InvalidTtl,
        ModeError::CreatedAtTtlOverflow,
        ModeError::NegativeDeadline,
        ModeError::DeadlineMillisecondsOverflow,
        ModeError::ClockToleranceOverflow,
        ModeError::CreatedAtTooFarInFuture,
        ModeError::Expired,
    ];
    for error in errors {
        assert_eq!(NodeCoreError::from(error).to_string(), "delivery_mode_refused");
    }
}

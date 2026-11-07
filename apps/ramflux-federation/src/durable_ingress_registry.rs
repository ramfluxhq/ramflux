// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Scanner-backed durable ingress registry for the federation crate.

use std::path::{Path, PathBuf};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Class {
    Ingress,
    NonIngress(&'static str),
}

const DURABLE_INGRESS: &[(&str, Class)] = &[
    (
        "durable_mode.rs:refused_forward",
        Class::NonIngress("typed refusal construction; no envelope persist"),
    ),
    (
        "durable_mode.rs:rejected_security",
        Class::NonIngress("typed refusal construction; no envelope persist"),
    ),
    ("flow.rs:handle_s8_forward_envelope", Class::Ingress),
    (
        "flow.rs:attach_forward_source_authority",
        Class::NonIngress("authority refresh helper; no inbound delivery persist"),
    ),
    ("flow.rs:handle_s8_receive_envelope", Class::Ingress),
    ("flow.rs:post_inbound_to_router", Class::Ingress),
    ("flow.rs:post_forwarded_to_router", Class::Ingress),
    (
        "flow.rs:ensure_receive_target_node",
        Class::NonIngress("target-node equality check; no envelope persist"),
    ),
    (
        "state.rs:record_receive_signature_segments",
        Class::NonIngress("observability timing recorder"),
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
    let non_ingress_count =
        DURABLE_INGRESS.iter().filter(|(_, class)| matches!(class, Class::NonIngress(_))).count();
    assert_eq!((ingress_count, non_ingress_count), (4, 5));
    for (entry, class) in DURABLE_INGRESS {
        if let Class::NonIngress(reason) = class {
            assert!(!reason.is_empty(), "{entry} needs a NonIngress reason");
        }
        if *class == Class::Ingress {
            assert!(
                first_statement_has_mode_guard(&source_root, entry)?,
                "{entry} must refuse marked delivery modes before its first effect"
            );
        }
    }

    for with_wal in [true, false] {
        let path = temp_store_path(if with_wal { "fed_wal" } else { "fed_redb" })?;
        let store = ramflux_node_core::FederationRedbStore::open(&path)?;
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
                let request = marked_forward(ordinal, mode.clone())?;
                let control = unmarked_forward(&request)?;
                exercise_federation_control(entry, &store, &control)?;
                let before = store_snapshot(&path)?;
                exercise_federation_ingress(entry, &store, &request)?;
                let after = store_snapshot(&path)?;
                assert_eq!(after, before, "WAL={with_wal}, ingress={entry}, mode={mode}");
                ordinal += 1;
            }
        }
        drop(store);
        let _ = std::fs::remove_file(&path);
    }
    Ok(())
}

#[test]
fn durable_ingress_registry_scanner_rejects_drift_fixtures() {
    let unlisted =
        vec![("registry.rs".to_owned(), "pub fn newly_exposed(envelope: Envelope) {}".to_owned())];
    assert_eq!(
        assert_registry_scan_matches(&unlisted, &[]),
        Err("scanner matches differ: [\"registry.rs:newly_exposed\"] != []".to_owned())
    );
    let no_longer_matching =
        vec![("registry.rs".to_owned(), "pub fn previously_listed() {}".to_owned())];
    assert_eq!(
        assert_registry_scan_matches(
            &no_longer_matching,
            &["registry.rs:previously_listed".to_owned()]
        ),
        Err("scanner matches differ: [] != [\"registry.rs:previously_listed\"]".to_owned())
    );
}

fn exercise_federation_control(
    entry: &str,
    store: &ramflux_node_core::FederationRedbStore,
    request: &ramflux_node_core::FederatedEnvelopeForwardRequest,
) -> Result<(), Box<dyn std::error::Error>> {
    match entry {
        "flow.rs:post_inbound_to_router" => {
            let response = crate::flow::post_inbound_to_router(request, false, |_, _| {
                Ok(serde_json::json!({
                    "outcome": "offline_queued",
                    "target_delivery_id": request.envelope.target_delivery_id,
                    "inbox_seq": 1,
                    "cursor": null
                }))
            })?;
            assert_eq!(response.outcome, "offline_queued", "{entry}");
        }
        "flow.rs:post_forwarded_to_router" => {
            let response = crate::flow::post_forwarded_to_router(request, |_, _| {
                serde_json::from_value(serde_json::json!({
                    "accepted": true,
                    "retryable": false,
                    "delivery": {
                        "outcome": "offline_queued",
                        "target_delivery_id": request.envelope.target_delivery_id,
                        "inbox_seq": 1,
                        "cursor": null
                    }
                }))
                .map_err(|error| ramflux_node_core::NodeCoreError::ItestJson(error.to_string()))
            })?;
            assert_eq!(response.outcome, "offline_queued", "{entry}");
        }
        "flow.rs:handle_s8_forward_envelope" => {
            let response = crate::flow::handle_s8_forward_envelope(
                request,
                &crate::SharedFederationTrustState::new(
                    ramflux_node_core::FederationTrustState::new(),
                ),
                store,
                &dummy_router(),
                &dummy_discovery(),
            );
            assert_control_forward(entry, response);
        }
        "flow.rs:handle_s8_receive_envelope" => {
            let response = crate::flow::handle_s8_receive_envelope(
                request,
                &crate::SharedFederationTrustState::new(
                    ramflux_node_core::FederationTrustState::new(),
                ),
                store,
                &dummy_router(),
                &dummy_discovery(),
                None,
            );
            assert_control_forward(entry, response);
        }
        other => return Err(format!("unknown federation ingress {other}").into()),
    }
    Ok(())
}

fn exercise_federation_ingress(
    entry: &str,
    store: &ramflux_node_core::FederationRedbStore,
    request: &ramflux_node_core::FederatedEnvelopeForwardRequest,
) -> Result<(), Box<dyn std::error::Error>> {
    match entry {
        "flow.rs:handle_s8_forward_envelope" => {
            let response = crate::flow::handle_s8_forward_envelope(
                request,
                &crate::SharedFederationTrustState::new(
                    ramflux_node_core::FederationTrustState::new(),
                ),
                store,
                &dummy_router(),
                &dummy_discovery(),
            )?;
            assert_refused_forward(&response, entry);
        }
        "flow.rs:handle_s8_receive_envelope" => {
            let response = crate::flow::handle_s8_receive_envelope(
                request,
                &crate::SharedFederationTrustState::new(
                    ramflux_node_core::FederationTrustState::new(),
                ),
                store,
                &dummy_router(),
                &dummy_discovery(),
                None,
            )?;
            assert_refused_forward(&response, entry);
        }
        "flow.rs:post_inbound_to_router" => {
            let response = crate::flow::post_inbound_to_router(request, true, |_, _| {
                Err(ramflux_node_core::NodeCoreError::ItestJson(
                    "marked envelope posted to router".into(),
                ))
            })?;
            assert_eq!(response.outcome, "rejected_security:delivery_mode_refused", "{entry}");
        }
        "flow.rs:post_forwarded_to_router" => {
            let response = crate::flow::post_forwarded_to_router(request, |_, _| {
                Err(ramflux_node_core::NodeCoreError::ItestJson(
                    "marked envelope posted to router".into(),
                ))
            })?;
            assert_eq!(response.outcome, "rejected_security:delivery_mode_refused", "{entry}");
        }
        other => return Err(format!("unknown federation ingress {other}").into()),
    }
    Ok(())
}

fn assert_refused_forward(
    response: &ramflux_node_core::FederatedEnvelopeForwardResponse,
    entry: &str,
) {
    assert!(!response.accepted, "{entry}");
    assert_eq!(response.delivery.outcome, "rejected_security:delivery_mode_refused", "{entry}");
}

const CONTROL_FORWARD: &str =
    "itest HTTP operation failed: federation delivery paused for node-b.example";
const CONTROL_RECEIVE: &str = "itest HTTP operation failed: federation inbound target node-b.example is not local node node-a.example";

fn assert_control_forward(
    entry: &str,
    response: Result<
        ramflux_node_core::FederatedEnvelopeForwardResponse,
        ramflux_node_core::NodeCoreError,
    >,
) {
    let expected = match entry {
        "flow.rs:handle_s8_forward_envelope" => CONTROL_FORWARD,
        "flow.rs:handle_s8_receive_envelope" => CONTROL_RECEIVE,
        _ => "",
    };
    match response {
        Ok(reply) => {
            assert_eq!(
                "admitted", expected,
                "control {entry} admitted: {}",
                reply.delivery.outcome
            );
        }
        Err(error) => assert_eq!(error.to_string(), expected, "{entry}"),
    }
}

fn marked_forward(
    ordinal: u64,
    mode: serde_json::Value,
) -> Result<ramflux_node_core::FederatedEnvelopeForwardRequest, Box<dyn std::error::Error>> {
    let discovery = dummy_discovery();
    let now = i64::try_from(ramflux_node_core::now_unix_seconds())?;
    let root = ramflux_crypto::create_identity_root("alice", [0x91; 32]);
    let branch = ramflux_crypto::create_device_branch(
        "alice",
        "alice_phone",
        1,
        ramflux_crypto::FIXTURE_SIGNING_KEY_BYTES,
    );
    let agreement = ramflux_crypto::X25519KeyPair::from_seed([0x92; 32]);
    let keys = ramflux_crypto::device_key_commitments(
        &ramflux_protocol::encode_base64url(branch.signing_key.verifying_key().to_bytes()),
        &ramflux_protocol::encode_base64url(agreement.public),
    )?;
    let set = ramflux_crypto::sign_device_set(
        &root,
        ramflux_crypto::DeviceSetSigningInput {
            principal_kind: ramflux_protocol::PrincipalKind::Human,
            device_set_epoch: 1,
            devices: vec![ramflux_protocol::SignedDeviceSetEntry {
                device_id: "alice_phone".into(),
                device_epoch: 1,
                signing_key_commitment: keys.0,
                agreement_key_commitment: keys.1,
                status: ramflux_protocol::DeviceSetStatus::Active,
                revoked_at: None,
            }],
        },
    )?;
    let authority = ramflux_node_core::DeviceAuthKeyResponse {
        custody_authority: None,
        root_public_key: Some(ramflux_protocol::encode_base64url(
            root.signing_key.verifying_key().to_bytes(),
        )),
        signed_device_set: Some(set),
        principal_id: "alice".into(),
        device_id: "alice_phone".into(),
        device_epoch: 1,
        branch_public_key: ramflux_protocol::encode_base64url(
            branch.signing_key.verifying_key().to_bytes(),
        ),
        target_delivery_id: "peer".into(),
        revoked: false,
    };
    let mut request: ramflux_node_core::FederatedEnvelopeForwardRequest = serde_json::from_value(
        serde_json::json!({
            "admin_token":"", "source_node_id": discovery.node_id, "target_node_id":"node-b.example",
            "delivery_class":"opaque_event", "required_capability":"opaque_delivery",
            "signing_key_id": discovery.node_id,"signature_alg":"ed25519","signature":"",
            "envelope": {
                "schema":"ramflux.envelope.v1","version":1,"domain":"ramflux.envelope.v1",
                "ext":{
                    "source_root_commitment": ramflux_crypto::identity_root_commitment(
                        &root.signing_key.verifying_key()
                    )
                },
                "signing_key_id":"device","signature_alg":"ed25519","signature":"sig",
                "envelope_id": format!("fed_{ordinal}"),
                "source_principal_id":"alice","source_device_id":"alice_phone",
                "target_delivery_id":"peer","routing_set_id":null,"delivery_class":"opaque_event",
                "priority":"low","ttl":5,"created_at": now,
                "encrypted_payload":"opaque","payload_hash":"hash"
            }
        }),
    )?;
    request.envelope.ext.ext.insert("delivery_mode".into(), mode);
    request.envelope.signed.signature =
        ramflux_crypto::sign_protocol_object_with_device_branch(&branch, &request.envelope)?;
    request
        .envelope
        .ext
        .ext
        .insert("source_device_authority".into(), serde_json::to_value(authority)?);
    ramflux_node_core::sign_federated_envelope_forward(&mut request, discovery.node_signing_seed)?;
    Ok(request)
}

fn unmarked_forward(
    request: &ramflux_node_core::FederatedEnvelopeForwardRequest,
) -> Result<ramflux_node_core::FederatedEnvelopeForwardRequest, Box<dyn std::error::Error>> {
    let mut control = request.clone();
    control.envelope.ext.ext.remove("delivery_mode");
    let branch = ramflux_crypto::create_device_branch(
        "alice",
        "alice_phone",
        1,
        ramflux_crypto::FIXTURE_SIGNING_KEY_BYTES,
    );
    control.envelope.signed.signature =
        ramflux_crypto::sign_protocol_object_with_device_branch(&branch, &control.envelope)?;
    ramflux_node_core::sign_federated_envelope_forward(
        &mut control,
        dummy_discovery().node_signing_seed,
    )?;
    Ok(control)
}

fn dummy_router() -> crate::RouterMeshClient {
    crate::RouterMeshClient {
        endpoint: "127.0.0.1:1".into(),
        server_name: "ramflux-router".into(),
        tls: ramflux_transport::MeshTlsConfig {
            ca_cert: PathBuf::from("ca.pem"),
            service_cert: PathBuf::from("federation.pem"),
            service_key: PathBuf::from("federation-key.pem"),
        },
        client: ramflux_transport::MeshHttpClient::new(),
        async_mesh: None,
    }
}

fn dummy_discovery() -> crate::FederationDiscoverySurface {
    crate::FederationDiscoverySurface {
        node_id: "node-a.example".into(),
        public_endpoint: "ramflux-federation:7443".into(),
        node_public_key: "node-public-key".into(),
        node_ca_cert_pem: "node-ca".into(),
        node_signing_seed: [7; 32],
        protocol_versions: vec!["s8".into()],
        transport_backends: vec!["quic".into()],
        node_capabilities: vec!["mesh".into()],
        attachment_authority: None,
    }
}

fn store_snapshot(path: &Path) -> Result<(u64, Vec<u8>), Box<dyn std::error::Error>> {
    let meta = std::fs::metadata(path)?;
    let bytes = std::fs::read(path).unwrap_or_default();
    Ok((meta.len(), ramflux_crypto::blake3_256("ramflux.test.durable_ingress.v1", &bytes).into()))
}

fn temp_store_path(name: &str) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let path = std::env::temp_dir().join(format!(
        "ramflux-s6c-p03-fed-{name}-{}-{}.redb",
        std::process::id(),
        ramflux_protocol::encode_base64url(&ramflux_crypto::random_32()?[..8])
    ));
    Ok(path)
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
    Ok(lines
        .iter()
        .skip(body)
        .map(|line| line.trim())
        .filter(|line| !line.is_empty() && !line.starts_with("//") && *line != "{")
        .take(40)
        .any(|line| line.contains("require_durable")))
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
    let mut deduped = sorted_listed.clone();
    deduped.dedup();
    if deduped.len() != sorted_listed.len() {
        return Err("duplicate durable ingress registry entries".into());
    }
    let scanned = scan_public_envelope_functions(sources).map_err(|error| error.to_string())?;
    if scanned != sorted_listed {
        return Err(format!("scanner matches differ: {scanned:?} != {sorted_listed:?}"));
    }
    Ok(())
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

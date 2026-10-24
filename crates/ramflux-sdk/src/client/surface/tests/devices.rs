// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use super::*;
use crate::client::surface::{ControlKind, control::SurfaceControl};
pub(super) struct Terminals {
    root: PathBuf,
    pub(super) clients: Vec<RamfluxClient>,
}
impl Terminals {
    pub(super) fn new() -> Result<Self, SdkError> {
        let root = std::env::temp_dir().join(crate::new_surface_message_id()?);
        let mut clients = Vec::new();
        for (principal, device, root_seed, device_seed) in [
            ("author", "author-device", 31, 32),
            ("author", "author-two", 31, 33),
            ("human", "human-device", 35, 36),
            ("human", "human-two", 35, 37),
        ] {
            let mut c = RamfluxClient::new();
            c.create_identity_root(principal, [root_seed; 32]);
            c.create_device_branch(principal, device, 1, [device_seed; 32]);
            c.open_account_index(root.join(device))?;
            c.create_account(principal, &c.surface_local_root_commitment()?)?;
            c.unlock_account(principal, b"surface-test-secret")?;
            clients.push(c);
        }
        let mut manifests =
            std::collections::BTreeMap::<String, crate::prekey::SdkDeviceManifestResponse>::new();
        for remote in &clients {
            let next = crate::client::identity_authority::test_support::public_manifest(remote)?;
            manifests
                .entry(next.principal_id.clone())
                .and_modify(|current| current.devices.extend(next.devices.clone()))
                .or_insert(next);
        }
        for (principal, manifest) in &mut manifests {
            let owner = clients
                .iter()
                .find(|client| {
                    client
                        .identity_root
                        .as_ref()
                        .is_some_and(|root| root.principal_id == *principal)
                })
                .ok_or(SdkError::IdentityRootMissing)?;
            crate::client::identity_authority::test_support::sign_manifest(
                owner.identity_root.as_ref().ok_or(SdkError::IdentityRootMissing)?,
                manifest,
                2,
            )?;
        }
        for local in &clients {
            for manifest in manifests.values() {
                local.persist_root_verified_directory(manifest)?;
            }
            local.account_db()?.persist_client_record(
                "conversation",
                "thread",
                &json!({"kind":"direct","participants":["author","human"]}),
            )?;
        }
        Ok(Self { root, clients })
    }
}
impl Drop for Terminals {
    fn drop(&mut self) {
        self.clients.clear();
        let _ = std::fs::remove_dir_all(&self.root);
    }
}
pub(super) fn entry(
    source: &RamfluxClient,
    id: &str,
) -> Result<crate::GatewayInboxEntry, SdkError> {
    let d = source.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?;
    let endpoint = crate::GatewayQuicEndpointConfig {
        bind_addr: "127.0.0.1:0".parse().map_err(|_| SdkError::LocalBus("test address".into()))?,
        gateway_addr: "127.0.0.1:1"
            .parse()
            .map_err(|_| SdkError::LocalBus("test address".into()))?,
        server_name: "test".into(),
        ca_cert: PathBuf::new(),
        principal_id: d.principal_id.clone(),
        device_id: d.device_id.clone(),
        target_delivery_id: "test-target".into(),
        prekey_http_url: None,
    };
    let config = crate::GatewaySessionConfig::quic(endpoint).with_account_identity(source)?;
    let message = crate::GatewayDirectMessage {
        conversation_id: "thread".into(),
        message_id: id.into(),
        envelope_id: id.into(),
        source_principal_id: d.principal_id.clone(),
        sender_id: d.device_id.clone(),
        recipient_device_id: None,
        recipient_principal_commitment: None,
        target_delivery_id: "test-target".into(),
        encrypted_body: b"surface control".to_vec(),
        created_at: crate::prelude::now_unix_timestamp(),
        ttl: 600,
    };
    Ok(crate::GatewayInboxEntry {
        inbox_seq: 1,
        target_delivery_id: "test-target".into(),
        envelope: crate::dm::gateway_direct_message_envelope(&config, &message, None)?,
    })
}

fn own_forward(
    source: &RamfluxClient,
    target: &RamfluxClient,
    signed: &Carrier,
) -> Result<(), SdkError> {
    // Device records stand in for already verified directory responses; no directory I/O is needed.
    let mut control = source.surface_control_packet(signed, ControlKind::Own, None)?;
    control.manifests.clear();
    target.receive_surface_control(
        &entry(source, &signed.message_id)?,
        "thread",
        None,
        &control.bytes()?,
    )?;
    Ok(())
}
#[test]
fn two_terminals_per_identity_share_one_action_executor_and_decision() -> TestResult {
    let t = Terminals::new()?;
    let [b1, b2, a1, a2] = t.clients.as_slice() else { return Err("terminals".into()) };
    let mut create =
        carrier(b1, PayloadKind::Event, "create", &event(1, C::CreateSurface(snapshot()))?)?;
    b1.attach_surface_snapshot(&mut create)?;
    create = b1.sign_surface_carrier(create)?;
    project(b1, &create, "b1-create")?;
    project(a1, &create, "a1-create")?;
    own_forward(b1, b2, &create)?;
    // The peer's second terminal receives the same original bytes from the directory fanout.
    project(a2, &create, "a2-create")?;
    for terminal in [b1, b2, a1, a2] {
        let view = terminal.surface_get("s", 0, None)?;
        assert_eq!(view["version"], 1);
        assert_eq!(view["executor_device_id"], "author-device");
    }
    let hash = b1.surface_get("s", 0, None)?["surface_hash"].as_str().ok_or("hash")?.to_owned();
    let first = action(a1, "decision-one", 1, &hash)?;
    assert!(project(b2, &first, "b2-first")?.queued);
    assert_eq!(b2.surface_get("s", 0, None)?["actions"], json!([]));
    assert!(project(b1, &first, "b1-first")?.accepted);
    let reference = first.surface_reference()?;
    let prefix = super::super::key("actions", &reference) + "/";
    let rows = b1.account_db()?.surface_history_page::<Value>(&prefix, &prefix, 100)?;
    let ack: Carrier =
        serde_json::from_value(rows.first().ok_or("action")?["attestation"].clone())?;
    assert_eq!(ack.payload_kind, PayloadKind::ActionReceipt);
    // The receiver already has the human's verified directory record. The signed own context
    // below exercises receiver authentication without a network directory request.
    let control = SurfaceControl {
        kind: ControlKind::Own,
        carrier_base64: ramflux_protocol::encode_base64url(ack.bytes()?),
        group_epoch: None,
        context: Some(super::super::control::OwnContext {
            conversation_id: "thread".into(),
            participants: vec!["author".into(), "human".into()],
            group: None,
            friend: None,
        }),
        manifests: Vec::new(),
    };
    b2.receive_surface_control(&entry(b1, "receipt")?, "thread", None, &control.bytes()?)?;
    assert!(project(b2, &first, "b2-replay")?.accepted);
    let retry = action(a2, "another-terminal", 1, &hash)?;
    assert_eq!(
        project(b1, &retry, "b1-retry")?.renderer_error.ok_or("error")?["code"],
        "action_already_used"
    );
    assert_eq!(
        project(b2, &retry, "b2-retry")?.renderer_error.ok_or("error")?["code"],
        "action_already_used"
    );
    let executable =
        [b1, b2].into_iter().map(|b| b.surface_get("s", 0, None)).collect::<Result<Vec<_>, _>>()?;
    assert_eq!(
        executable
            .iter()
            .flat_map(|v| v["actions"].as_array().into_iter().flatten())
            .filter(|a| a["actionable"] == true)
            .count(),
        1
    );
    assert_eq!(executable[1]["actions"][0]["actionable"], false);
    Ok(())
}
#[test]
fn own_forwarding_requires_the_same_root_even_if_principal_label_matches() -> TestResult {
    let t = Terminals::new()?;
    let b1 = &t.clients[0];
    let b2 = &t.clients[1];
    let mut c =
        carrier(b1, PayloadKind::Event, "create", &event(1, C::CreateSurface(snapshot()))?)?;
    b1.attach_surface_snapshot(&mut c)?;
    c = b1.sign_surface_carrier(c)?;
    let db = b2.account_db()?;
    let mut record = db.client_record("device", "author-device")?.ok_or("device")?;
    record["principal_commitment"] = json!("another-root");
    db.persist_client_record("device", "author-device", &record)?;
    assert!(own_forward(b1, b2, &c).is_err());
    assert!(b2.surface_get("s", 0, None)?.is_null());
    Ok(())
}

#[test]
fn own_history_retains_closed_surfaces_with_full_finality_and_quoted_fallback() -> TestResult {
    let t = Terminals::new()?;
    let source = &t.clients[0];
    let target = &t.clients[1];
    let mut first =
        carrier(source, PayloadKind::Event, "create", &event(1, C::CreateSurface(snapshot()))?)?;
    source.attach_surface_snapshot(&mut first)?;
    first = source.sign_surface_carrier(first)?;
    project(source, &first, "create")?;
    let mut close = carrier(
        source,
        PayloadKind::Event,
        "close",
        &event(2, C::DeleteSurface(DeleteSurfaceCommand { surface_id: "s".into(), reason: None }))?,
    )?;
    source.attach_surface_snapshot(&mut close)?;
    close = source.sign_surface_carrier(close)?;
    project(source, &close, "close")?;
    let exported = source.own_surface_history_export(None)?;
    assert!(exported.controls.is_empty());
    assert_eq!(exported.checkpoints.len(), 1);
    // The enclosing root-authenticated own-device bundle carries the validated checkpoint.
    target.import_owned_surface_checkpoints(&exported.checkpoints)?;
    let view = target.surface_get("s", 0, None)?;
    assert_eq!(view["version"], 2);
    assert_eq!(view["closed"], true);
    assert_eq!(view["fallback_text"], super::super::fallback::render("author", "Working"));
    assert_eq!(view["is_action_executor"], false);
    assert!(!project(target, &first, "covered-create")?.retryable);
    Ok(())
}

#[test]
fn own_surface_history_omits_group_state_below_the_current_membership_floor() -> TestResult {
    let t = Terminals::new()?;
    let source = &t.clients[0];
    source.create_group("g", "author-device")?;
    let db = source.account_db()?;
    db.persist_client_record("conversation", "thread", &json!({"kind":"group","group_id":"g"}))?;
    let mut first =
        carrier(source, PayloadKind::Event, "create", &event(1, C::CreateSurface(snapshot()))?)?;
    source.attach_surface_snapshot(&mut first)?;
    first = source.sign_surface_carrier(first)?;
    source.project_surface_message(
        "thread",
        "group-create",
        super::super::SurfaceSender {
            principal: "author",
            device: "author-device",
            envelope_id: "group-create",
            expires_at: None,
            group_epoch: Some(1),
        },
        &first.bytes()?,
        false,
    )?;
    assert_eq!(source.own_surface_history_export(None)?.checkpoints.len(), 1);
    db.upsert_group_local_membership_snapshot("g", 5, 128, "none", "author-device", "owner", 5)?;
    assert_eq!(source.own_surface_history_controls()?.len(), 0);
    Ok(())
}

#[test]
fn live_deltas_omit_repeated_context_while_explicit_history_keeps_it() -> TestResult {
    let t = Terminals::new()?;
    let author = &t.clients[0];
    let create =
        carrier(author, PayloadKind::Event, "create", &event(1, C::CreateSurface(snapshot()))?)?;
    assert!(project(author, &create, "create")?.accepted);
    assert!(author.live_surface_control_packet(&create, None)?.context.is_some());
    author.mark_own_surface_context_announced("thread", None)?;
    let delta = carrier(
        author,
        PayloadKind::Event,
        "append",
        &event(
            2,
            C::StreamAppend(StreamAppendCommand {
                surface_id: "s".into(),
                component_id: "stream".into(),
                text_delta: "x".into(),
                final_: false,
            }),
        )?,
    )?;
    let live = author.live_surface_control_packet(&delta, None)?;
    assert!(live.context.is_none());
    assert_eq!(live.manifests.len(), 0);
    assert!(author.surface_control_packet(&delta, ControlKind::Own, None)?.context.is_some());
    assert!(!author.own_surface_context_announced("thread", Some(2))?);
    Ok(())
}

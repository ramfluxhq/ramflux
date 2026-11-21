// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use super::*;
use crate::client::surface::{ControlKind, control::SurfaceControl, invalid};
use std::path::PathBuf;
pub(super) struct Terminals {
    pub(super) clients: Vec<RamfluxClient>,
    _root: ramflux_test_support::TestPath,
}
impl Terminals {
    pub(super) async fn new() -> TestResult<Self> {
        let root = ramflux_test_support::TestPath::new()?;
        let clients = super::super::test_support::owned_terminals(&root).await?;
        Ok(Self { clients, _root: root })
    }
}
impl Drop for Terminals {
    fn drop(&mut self) {
        self.clients.clear();
    }
}
pub(super) fn entry(
    source: &RamfluxClient,
    target: &RamfluxClient,
    id: &str,
) -> Result<crate::GatewayInboxEntry, SdkError> {
    use crate::client::routed::{Route, SendMaterial};
    use ramflux_protocol::message as g;
    let local = source.owned_device_identity()?;
    let remote = target.owned_device_identity()?;
    let mut config = crate::GatewaySessionConfig::quic(crate::GatewayQuicEndpointConfig {
        bind_addr: "127.0.0.1:0".parse().map_err(|_| invalid("test bind"))?,
        gateway_addr: "127.0.0.1:1".parse().map_err(|_| invalid("test gateway"))?,
        server_name: "test".into(),
        ca_cert: PathBuf::new(),
        principal_id: source
            .device_branch
            .as_ref()
            .ok_or(SdkError::IdentityRootMissing)?
            .principal_id
            .clone(),
        device_id: local.device_id().into(),
        target_delivery_id: local.storage_key().into(),
        prekey_http_url: None,
    });
    // This component fixture installs its genuinely certified local proof directly;
    // it creates no session handshake and claims no custodian login acceptance.
    config.device_branch = Some(std::sync::Arc::new(
        source.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?.clone(),
    ));
    config.source_identity = Some(local.clone());
    let identity = source.allocate_generated_identity(
        "thread",
        crate::client::generated_identity::now_ms(),
        false,
    )?;
    let mut message = crate::GatewayDirectMessage {
        conversation_id: "thread".into(),
        message_id: ramflux_protocol::encode_base64url(&identity.id),
        envelope_id: id.into(),
        source_principal_id: config.principal_id.clone(),
        sender_id: local.device_id().into(),
        recipient_device_id: Some(remote.device_id().into()),
        recipient_principal_commitment: Some(remote.root_commitment().into()),
        target_delivery_id: remote.storage_key().into(),
        encrypted_body: Vec::new(),
        created_at: crate::time::now_unix_timestamp(),
        ttl: 600,
    };
    let exact = RamfluxClient::encode_generated_inner(
        identity,
        &g::Content {
            value: Some(g::content::Value::Message(g::Message {
                text: "surface transport fixture".into(),
                ..Default::default()
            })),
        },
    )?;
    let bundle = target.load_x3dh_private_state(&remote)?.bundle;
    let envelope = source.account_db()?.write_transaction(|| {
        let sealed = source.seal_generated_routed_prepared(
            &config,
            &message,
            &exact,
            Route::direct(),
            SendMaterial { manifest: None, bundle: Some(bundle) },
        )?;
        crate::dm::gateway_generated_envelope_from_sealed(&config, &mut message, sealed)
    })?;
    Ok(crate::GatewayInboxEntry {
        forwarded: false,
        inbox_seq: 1,
        target_delivery_id: remote.storage_key().into(),
        envelope,
    })
}

fn own_forward(
    source: &RamfluxClient,
    target: &RamfluxClient,
    signed: &Carrier,
) -> Result<(), SdkError> {
    // Every terminal already cached the genuine enrolled-device publications.
    let mut control = source.surface_control_packet(signed, ControlKind::Own, None)?;
    control.manifests.clear();
    target.receive_surface_control(
        &entry(source, target, &signed.message_id)?,
        "thread",
        None,
        &control.bytes()?,
    )?;
    Ok(())
}
#[tokio::test(flavor = "current_thread")]
async fn two_terminals_per_identity_share_one_action_executor_and_decision() -> TestResult {
    crate::client::native_test_support::watchdog::within(
        two_terminals_per_identity_share_one_action_executor_and_decision_body(),
    )
    .await?
}
async fn two_terminals_per_identity_share_one_action_executor_and_decision_body() -> TestResult {
    let t = Box::pin(Terminals::new()).await?;
    let [b1, b2, a1, a2] = t.clients.as_slice() else { return Err("terminals".into()) };
    let mut create =
        carrier(b1, PayloadKind::Event, "create", &event(1, C::CreateSurface(snapshot()))?)?;

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
    let waiting = project(b2, &first, "b2-first")?;
    assert!(
        waiting.queued,
        "the secondary must await its executor: accepted={}, retryable={}, error={:?}",
        waiting.accepted, waiting.retryable, waiting.renderer_error
    );
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
    b2.receive_surface_control(&entry(b1, b2, "receipt")?, "thread", None, &control.bytes()?)?;
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
#[tokio::test(flavor = "current_thread")]
async fn own_forwarding_requires_the_same_root_even_if_principal_label_matches() -> TestResult {
    crate::client::native_test_support::watchdog::within(
        own_forwarding_requires_the_same_root_even_if_principal_label_matches_body(),
    )
    .await?
}
async fn own_forwarding_requires_the_same_root_even_if_principal_label_matches_body() -> TestResult
{
    let t = Box::pin(Terminals::new()).await?;
    let b1 = &t.clients[0];
    let b2 = &t.clients[1];
    let mut c =
        carrier(b1, PayloadKind::Event, "create", &event(1, C::CreateSurface(snapshot()))?)?;

    c = b1.sign_surface_carrier(c)?;
    let db = b2.account_db()?;
    let mut record = db.client_record("device", "author-device")?.ok_or("device")?;
    db.remove_actor_state(&format!(
        "directory/device/{}",
        b1.owned_device_identity()?.storage_key()
    ))?;
    record["principal_commitment"] = json!("another-root");
    db.persist_client_record("device", "author-device", &record)?;
    assert!(own_forward(b1, b2, &c).is_err());
    assert!(b2.surface_get("s", 0, None)?.is_null());
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn own_history_retains_closed_surfaces_with_full_finality_and_quoted_fallback() -> TestResult
{
    crate::client::native_test_support::watchdog::within(
        own_history_retains_closed_surfaces_with_full_finality_and_quoted_fallback_body(),
    )
    .await?
}
async fn own_history_retains_closed_surfaces_with_full_finality_and_quoted_fallback_body()
-> TestResult {
    let t = Box::pin(Terminals::new()).await?;
    let source = &t.clients[0];
    let target = &t.clients[1];
    let mut first =
        carrier(source, PayloadKind::Event, "create", &event(1, C::CreateSurface(snapshot()))?)?;

    first = source.sign_surface_carrier(first)?;
    project(source, &first, "create")?;
    let mut close = carrier(
        source,
        PayloadKind::Event,
        "close",
        &event(2, C::DeleteSurface(DeleteSurface { surface_id: "s".into() }))?,
    )?;

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

#[tokio::test(flavor = "current_thread")]
async fn own_surface_history_omits_group_state_below_the_current_membership_floor() -> TestResult {
    crate::client::native_test_support::watchdog::within(
        own_surface_history_omits_group_state_below_the_current_membership_floor_body(),
    )
    .await?
}
async fn own_surface_history_omits_group_state_below_the_current_membership_floor_body()
-> TestResult {
    let t = Box::pin(Terminals::new()).await?;
    let source = &t.clients[0];
    source.create_group("g", "author-device")?;
    let db = source.account_db()?;
    db.persist_client_record("conversation", "thread", &json!({"kind":"group","group_id":"g"}))?;
    let mut first =
        carrier(source, PayloadKind::Event, "create", &event(1, C::CreateSurface(snapshot()))?)?;

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

#[tokio::test(flavor = "current_thread")]
async fn live_deltas_omit_repeated_context_while_explicit_history_keeps_it() -> TestResult {
    crate::client::native_test_support::watchdog::within(
        live_deltas_omit_repeated_context_while_explicit_history_keeps_it_body(),
    )
    .await?
}
async fn live_deltas_omit_repeated_context_while_explicit_history_keeps_it_body() -> TestResult {
    let t = Box::pin(Terminals::new()).await?;
    let author = &t.clients[0];
    let create =
        carrier(author, PayloadKind::Event, "create", &event(1, C::CreateSurface(snapshot()))?)?;
    assert!(project(author, &create, "create")?.accepted);
    assert!(author.live_surface_control_packet(&create, None)?.context.is_some());
    let targets = vec!["sibling".to_owned()];
    let (_, delivery) = author.prepare_own_surface_context(
        &author.live_surface_control_packet(&create, None)?.bytes()?,
        &targets,
    )?;
    author.finish_own_surface_context(&delivery.ok_or("context delivery")?, true)?;
    let delta = carrier(
        author,
        PayloadKind::Event,
        "append",
        &event(
            2,
            C::AppendText(AppendText {
                surface_id: "s".into(),
                path: "/stream".into(),
                delta: "x".into(),
                final_: false,
            }),
        )?,
    )?;
    let staged = author.live_surface_control_packet(&delta, None)?;
    assert!(staged.context.is_some(), "staging retains context until current targets are known");
    let (bytes, _) = author.prepare_own_surface_context(&staged.bytes()?, &targets)?;
    let live: super::super::SurfaceControl =
        super::super::SurfaceControl::decode(&bytes)?.ok_or("typed Surface missing")?;
    assert!(live.context.is_none());
    assert_eq!(live.manifests.len(), 0);
    assert!(author.surface_control_packet(&delta, ControlKind::Own, None)?.context.is_some());
    let (bytes, _) = author.prepare_own_surface_context(
        &author.live_surface_control_packet(&delta, Some(2))?.bytes()?,
        &targets,
    )?;
    let changed: super::super::SurfaceControl =
        super::super::SurfaceControl::decode(&bytes)?.ok_or("typed Surface missing")?;
    assert!(changed.context.is_some());
    Ok(())
}

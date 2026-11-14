// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use super::{Carrier, Outcome, PayloadKind, key};
use crate::{RamfluxClient, SdkError};
use ramflux_protocol::{
    ACTION_SCHEMA, Action, ActionFrame, ActionMessage, AppendText, CATALOG_ID, DeleteSurface,
    EVENT_SCHEMA, EventFrame, Mutation, MutationMessage, Resync, SurfaceSnapshot, SurfaceState,
};
use std::cell::RefCell;
use std::collections::BTreeMap;
#[derive(Clone)]
enum C {
    CreateSurface(SurfaceSnapshot),
    AppendText(AppendText),
    DeleteSurface(DeleteSurface),
    Resync(SurfaceSnapshot),
}
thread_local! { static AUTHOR_STATES: RefCell<BTreeMap<(String,u64),SurfaceState>> = const { RefCell::new(BTreeMap::new()) }; }

use serde_json::{Value, json};
use std::sync::atomic::{AtomicU64, Ordering};
type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
struct Fixture {
    author: RamfluxClient,
    human: RamfluxClient,
    root: ramflux_test_support::TestPath,
    vault: std::sync::Arc<crate::custody::tests::TestVault>,
}
fn client(root: &std::path::Path, id: &str, seed: u8) -> Result<RamfluxClient, SdkError> {
    let mut client = RamfluxClient::new();
    client.create_identity_root(id, [seed; 32]);
    client.create_device_branch(id, &format!("{id}-device"), 1, [seed + 1; 32]);
    client.open_account_index(root)?;
    client.create_account(id, "surface-test-commitment")?;
    client.unlock_account(id, b"surface-test-secret")?;
    Ok(client)
}
impl Fixture {
    async fn new() -> TestResult<Self> {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        AUTHOR_STATES.with(|states| states.borrow_mut().clear());
        let root = ramflux_test_support::TestPath::new()
            .expect("test: allocate fixture directory")
            .child(format!(
                "rf-surface-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
        let (human, author, vault) =
            super::test_support::owned_pair_with_vault(&root, "human", "author").await?;
        for (local, remote) in [(&author, &human), (&human, &author)] {
            let _ = remote;
            local.account_db()?.persist_client_record(
                "conversation",
                "thread",
                &json!({"kind":"direct","participants":["author","human"]}),
            )?;
        }
        Ok(Self { author, human, root, vault })
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        self.author = RamfluxClient::new();
        self.human = RamfluxClient::new();
    }
}
fn snapshot() -> SurfaceSnapshot {
    let mut components = vec![
        json!({"id":"root","component":"Column","children":["stream","result","approve"]}),
        json!({"id":"stream","component":"Text","text":{"@path":"/stream"}}),
        json!({"id":"result","component":"Text","text":{"@path":"/result"}}),
        json!({"id":"approve","component":"Button","child":"approve_label","action":{"event":{"name":"approve","context":{"approved":true}}}}),
        json!({"id":"approve_label","component":"Text","text":"Approve"}),
    ];
    components.sort_by(|a, b| {
        a.get("id").and_then(Value::as_str).cmp(&b.get("id").and_then(Value::as_str))
    });
    SurfaceSnapshot {
        surface_id: "s".into(),
        catalog_id: CATALOG_ID.into(),
        fallback_text: "Working".into(),
        metadata: None,
        components,
        data_model: json!({"stream":"","result":""}),
        final_: Vec::new(),
        closed: false,
    }
}
fn event(version: u64, intent: C) -> Result<Vec<u8>, SdkError> {
    AUTHOR_STATES.with(|states| {
        let mut states = states.borrow_mut();
        let surface = match &intent {
            C::CreateSurface(s) | C::Resync(s) => &s.surface_id,
            C::AppendText(a) => &a.surface_id,
            C::DeleteSurface(c) => &c.surface_id,
        }
        .clone();
        let previous = if matches!(intent, C::CreateSurface(_)) {
            SurfaceState::default()
        } else {
            states
                .get(&(surface.clone(), version.saturating_sub(1)))
                .cloned()
                .or_else(|| {
                    states
                        .iter()
                        .rev()
                        .find(|((id, _), _)| *id == surface)
                        .map(|(_, state)| state.clone())
                })
                .map_or_else(
                    || {
                        let mut content = snapshot();
                        content.surface_id = surface.clone();
                        let frame = super::test_support::create_frame("thread", &content)?;
                        Ok::<_, SdkError>(SurfaceState::validate_proof(
                            &ramflux_protocol::SurfaceEvent::from_wire_bytes(&frame.wire_bytes()?)?,
                        )?)
                    },
                    Ok,
                )?
        };
        let expected = previous.version() + 1;
        let mut frame = EventFrame {
            schema: EVENT_SCHEMA.into(),
            conversation_id: "thread".into(),
            surface_version: expected,
            base_surface_hash: previous.hash().map(str::to_owned),
            new_surface_hash: "invalid".into(),
            fallback_text: None,
            close_reason: None,
            a2ui: None,
            append_text: None,
            resync: None,
            final_: None,
            closed: None,
            metadata: None,
        };
        match intent {
            C::CreateSurface(s) => {
                frame.fallback_text = Some(s.fallback_text.clone());
                frame.new_surface_hash = s.hash()?;
                frame.a2ui = Some(MutationMessage::new(Mutation::CreateSurface(s.create())));
            }
            C::AppendText(a) => frame.append_text = Some(a),
            C::DeleteSurface(c) => {
                frame.a2ui = Some(MutationMessage::new(Mutation::DeleteSurface(c)));
            }
            C::Resync(s) => {
                frame.base_surface_hash = None;
                frame.fallback_text = Some(s.fallback_text.clone());
                frame.new_surface_hash = s.hash()?;
                frame.resync = Some(Resync {
                    a2ui: MutationMessage::new(Mutation::CreateSurface(s.create())),
                });
                frame.final_ = Some(s.final_.clone());
                frame.closed = Some(s.closed);
                frame.metadata = s.metadata;
            }
        }
        if frame.resync.is_none()
            && let Ok(prepared) = previous.prepare_event(frame.clone())
        {
            frame = prepared;
        }
        frame.surface_version = version;
        let wire = frame.wire_bytes()?;
        if let Ok(next) = previous.apply(&ramflux_protocol::SurfaceEvent::from_wire_bytes(&wire)?) {
            states.insert((surface, version), next);
        }
        while states.len() > 256 {
            states.pop_first();
        }
        Ok(wire)
    })
}
fn carrier(
    sender: &RamfluxClient,
    kind: PayloadKind,
    message: &str,
    wire: &[u8],
) -> Result<Carrier, SdkError> {
    let device = sender.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?;
    let signed = Carrier {
        schema: ramflux_protocol::domain::SURFACE_CARRIER.into(),
        content_type: "surface".into(),
        posted_at: None,
        updated_at: None,
        payload_kind: kind,
        conversation_id: "thread".into(),
        surface_id: "s".into(),
        message_id: message.into(),
        sender_principal_id: device.principal_id.clone(),
        sender_device_id: device.device_id.clone(),
        author_principal_id: "author".into(),
        wire_base64: ramflux_protocol::encode_base64url(wire),
        signature: String::new(),
        snapshot: None,
    };
    sender.sign_surface_carrier(signed)
}
fn project(
    client: &RamfluxClient,
    carrier: &Carrier,
    projection: &str,
) -> Result<Outcome, SdkError> {
    client
        .project_surface_message(
            "thread",
            projection,
            crate::client::surface::SurfaceSender {
                principal: &carrier.sender_principal_id,
                device: &carrier.sender_device_id,
                envelope_id: projection,
                expires_at: None,
                group_epoch: None,
            },
            &carrier.bytes()?,
            false,
        )?
        .ok_or_else(|| super::invalid("not a surface"))
}
fn create(f: &Fixture) -> Result<(), SdkError> {
    create_for(&f.author, &f.human)
}
fn create_for(author: &RamfluxClient, human: &RamfluxClient) -> Result<(), SdkError> {
    let wire = event(1, C::CreateSurface(snapshot()))?;
    let signed = carrier(author, PayloadKind::Event, "create", &wire)?;
    project(author, &signed, "create-author")?;
    project(human, &signed, "create-human")?;
    Ok(())
}
fn action(
    client: &RamfluxClient,
    message: &str,
    version: u64,
    hash: &str,
) -> Result<Carrier, SdkError> {
    let mut frame = ActionFrame {
        schema: ACTION_SCHEMA.into(),
        conversation_id: "thread".into(),
        surface_version: version,
        surface_hash: hash.into(),
        source_instance: Vec::new(),
        args_hash: String::new(),
        task_binding: None,
        a2ui: ActionMessage {
            version: "1.0".into(),
            action: Action {
                name: "approve".into(),
                surface_id: "s".into(),
                source_component_id: "approve".into(),
                timestamp: "2026-11-14T00:00:00Z".into(),
                context: serde_json::from_value(json!({"approved":true}))?,
                user_message: None,
                metadata: None,
            },
        },
    };
    frame.args_hash = frame.arguments_hash()?;
    carrier(client, PayloadKind::Action, message, &frame.wire_bytes()?)
}

#[tokio::test]
async fn signed_surface_lifecycle_projects_hash_history_and_fallback() -> TestResult {
    let f = Fixture::new().await?;
    create(&f)?;
    let signed = carrier(
        &f.author,
        PayloadKind::Event,
        "stream",
        &event(
            2,
            C::AppendText(AppendText {
                surface_id: "s".into(),
                path: "/stream".into(),
                delta: "Working...".into(),
                final_: true,
            }),
        )?,
    )?;
    project(&f.author, &signed, "stream-author")?;
    project(&f.human, &signed, "stream-human")?;
    let before = f.author.surface_get("s", 0, None)?;
    let hash = before["surface_hash"].as_str().ok_or("hash")?;
    let decision = action(&f.human, "decision", 2, hash)?;
    assert!(project(&f.author, &decision, "decision-author")?.accepted);
    let mut after: SurfaceSnapshot = serde_json::from_value(before["snapshot"].clone())?;
    after.data_model["result"] = json!("Complete");
    after.fallback_text = "Completed result".into();
    let patch = C::Resync(after);
    let signed = carrier(&f.author, PayloadKind::Event, "patch", &event(3, patch)?)?;
    project(&f.author, &signed, "patch-author")?;
    project(&f.human, &signed, "patch-human")?;
    assert_eq!(
        f.human.surface_message_fallback("create-human")?,
        Some(("s".into(), super::fallback::render("author", "Completed result")))
    );
    let signed = carrier(
        &f.author,
        PayloadKind::Event,
        "close",
        &event(4, C::DeleteSurface(DeleteSurface { surface_id: "s".into() }))?,
    )?;
    project(&f.author, &signed, "close-author")?;
    project(&f.human, &signed, "close-human")?;
    let view = f.human.surface_get("s", 0, None)?;
    assert_eq!(view["version"], 4);
    assert_eq!(view["closed"], true);
    assert_eq!(view["hash_history"].as_array().map(Vec::len), Some(4));
    assert_eq!(view["snapshot"]["fallbackText"], "Completed result");
    Ok(())
}
#[tokio::test]
async fn only_author_updates_and_rejections_do_not_partially_change_snapshot() -> TestResult {
    let f = Fixture::new().await?;
    create(&f)?;
    let before = f.human.surface_get("s", 0, None)?;
    let wire = event(2, C::DeleteSurface(DeleteSurface { surface_id: "s".into() }))?;
    let signed = carrier(&f.human, PayloadKind::Event, "forged", &wire)?;
    assert!(!project(&f.human, &signed, "forged")?.accepted);
    let after = f.human.surface_get("s", 0, None)?;
    assert_eq!(after["snapshot"], before["snapshot"]);
    assert_eq!(after["version"], 1);
    assert_eq!(after["surface_hash"], before["surface_hash"]);
    assert_eq!(after["renderer_error"], before["renderer_error"]);
    assert!(!project(&f.author, &signed, "forged-remote")?.accepted);
    Ok(())
}
#[tokio::test]
async fn author_consumes_a_decision_once_across_message_and_payload_replays() -> TestResult {
    let mut f = Fixture::new().await?;
    create(&f)?;
    let view = f.author.surface_get("s", 0, None)?;
    let signed = action(&f.human, "decision", 1, view["surface_hash"].as_str().ok_or("hash")?)?;
    assert!(project(&f.author, &signed, "first")?.accepted);
    assert!(project(&f.author, &signed, "duplicate")?.accepted);
    assert_eq!(f.author.surface_get("s", 0, None)?["actions"].as_array().map(Vec::len), Some(1));
    f.author = RamfluxClient::new();
    f.author.open_account_index(&f.root)?;
    f.author.unlock_account("author", b"surface-test-secret")?;
    tokio::time::timeout(
        std::time::Duration::from_secs(30),
        f.author.initialize_born_v3_branch("author-device", f.vault.clone()),
    )
    .await??;
    let repeat =
        action(&f.human, "different-message", 1, view["surface_hash"].as_str().ok_or("hash")?)?;
    let rejected = project(&f.author, &repeat, "repeat")?;
    assert!(!rejected.accepted);
    assert_eq!(rejected.renderer_error.ok_or("renderer error")?["code"], "action_already_used");
    Ok(())
}
#[tokio::test]
async fn stale_actions_and_signature_tampering_are_rejected() -> TestResult {
    let f = Fixture::new().await?;
    create(&f)?;
    let before = f.author.surface_get("s", 0, None)?;
    assert!(
        action(&f.human, "stale", 0, before["surface_hash"].as_str().ok_or("hash")?).is_err(),
        "zero-version actions are refused before signing"
    );
    let mut signed = carrier(
        &f.author,
        PayloadKind::Event,
        "tamper",
        &event(2, C::DeleteSurface(DeleteSurface { surface_id: "s".into() }))?,
    )?;
    signed.wire_base64 = ramflux_protocol::encode_base64url(event(
        3,
        C::DeleteSurface(DeleteSurface { surface_id: "s".into() }),
    )?);
    assert!(!project(&f.human, &signed, "tamper")?.accepted);
    assert_eq!(f.human.surface_get("s", 0, None)?["version"], 1);
    Ok(())
}
#[tokio::test]
async fn surface_transaction_rolls_back_state_history_receipts_and_outbox() -> TestResult {
    let f = Fixture::new().await?;
    let signed =
        carrier(&f.author, PayloadKind::Event, "create", &event(1, C::CreateSurface(snapshot()))?)?;
    let db = f.human.account_db()?;
    let before = db.pending_outbox(256)?.len();
    let result: Result<(), SdkError> = db.surface_transaction(|| {
        project(&f.human, &signed, "rollback")?;
        Err(super::invalid("injected rollback"))
    });
    assert!(result.is_err());
    assert!(f.human.surface_get("s", 0, None)?.is_null());
    assert_eq!(db.pending_outbox(256)?.len(), before);
    assert!(project(&f.human, &signed, "retry")?.accepted);
    Ok(())
}
#[tokio::test]
async fn exact_protocol_bytes_and_current_projection_survive_account_reopen() -> TestResult {
    let mut f = Fixture::new().await?;
    let wire = event(1, C::CreateSurface(snapshot()))?;
    let signed = carrier(&f.author, PayloadKind::Event, "raw", &wire)?;
    assert!(project(&f.human, &signed, "raw")?.accepted);
    let before = f.human.surface_get("s", 0, None)?;
    let history: Vec<Value> = f.human.account_db()?.surface_history_page(
        &(key("history", &signed.surface_reference()?) + "/"),
        "",
        100,
    )?;
    assert_eq!(
        ramflux_protocol::decode_base64url(
            history[0]["carrier"]["wire_base64"].as_str().ok_or("wire")?
        )?,
        wire
    );
    f.human = RamfluxClient::new();
    f.human.open_account_index(&f.root)?;
    f.human.unlock_account("human", b"surface-test-secret")?;
    tokio::time::timeout(
        std::time::Duration::from_secs(30),
        f.human.initialize_born_v3_branch("human-device", f.vault.clone()),
    )
    .await??;
    assert_eq!(f.human.surface_get("s", 0, None)?, before);
    Ok(())
}
#[tokio::test]
async fn deferred_group_content_is_validated_before_fallback_is_published() -> TestResult {
    let f = Fixture::new().await?;
    f.human.create_group("g", "human-device")?;
    f.human.add_group_member("g", f.author.owned_device_identity()?.storage_key(), "member")?;
    f.human.account_db()?.persist_client_record(
        "conversation",
        "thread",
        &json!({"kind":"group","group_id":"g"}),
    )?;
    let signed = carrier(
        &f.author,
        PayloadKind::Event,
        "deferred",
        &event(1, C::CreateSurface(snapshot()))?,
    )?;
    f.human.send_direct_message("thread", "deferred", "author-device", b"encrypted")?;
    f.human.account_db()?.store_message_content("thread", "deferred", &signed.bytes()?)?;
    f.human.project_deferred_surface("thread", "deferred")?;
    assert_eq!(
        f.human.account_db()?.message_content("deferred")?,
        Some(super::fallback::render("author", "Working").into_bytes())
    );
    assert_eq!(f.human.surface_get("s", 0, None)?["version"], 1);
    Ok(())
}
#[tokio::test]
async fn surface_changed_metadata_never_contains_snapshots_fallback_or_action_values() -> TestResult
{
    let f = Fixture::new().await?;
    create(&f)?;
    let listing = f.author.surface_list("thread", "", 100)?;
    assert_eq!(listing["surfaces"][0]["surface_id"], "s");
    assert!(listing["surfaces"][0].get("snapshot").is_none());
    let metadata = super::surface_metadata(&f.author.surface_get("s", 0, None)?);
    assert!(metadata.get("snapshot").is_none());
    assert!(metadata.get("fallback_text").is_none());
    assert!(metadata.get("actions").is_none());
    assert_eq!(metadata["surface_id"], "s");
    Ok(())
}

#[tokio::test]
async fn replay_still_requires_authenticated_transport_bindings() -> TestResult {
    let f = Fixture::new().await?;
    let signed =
        carrier(&f.author, PayloadKind::Event, "create", &event(1, C::CreateSurface(snapshot()))?)?;
    assert!(project(&f.human, &signed, "first")?.accepted);
    assert!(project(&f.human, &signed, "second")?.accepted);
    assert_eq!(
        f.human.surface_message_fallback("second")?.ok_or("reference")?.1,
        super::fallback::render("author", "Working")
    );
    for (conversation, device) in [("other-thread", "author-device"), ("thread", "other-device")] {
        let rejected = f
            .human
            .project_surface_message(
                conversation,
                "spoofed",
                crate::client::surface::SurfaceSender {
                    principal: "author",
                    device,
                    envelope_id: "spoofed",
                    expires_at: None,
                    group_epoch: None,
                },
                &signed.bytes()?,
                false,
            )?
            .ok_or("outcome")?;
        assert!(!rejected.accepted);
    }
    assert_eq!(f.human.surface_get("s", 0, None)?["version"], 1);
    Ok(())
}
#[tokio::test]
async fn malformed_original_wire_cannot_be_normalized_by_carrier_ingress() -> TestResult {
    let f = Fixture::new().await?;
    let mut signed =
        carrier(&f.author, PayloadKind::Event, "create", &event(1, C::CreateSurface(snapshot()))?)?;
    let raw = String::from_utf8(ramflux_protocol::decode_base64url(&signed.wire_base64)?)?;
    let duplicated =
        raw.replace("\"surfaceVersion\":1", "\"surfaceVersion\":1,\"surfaceVersion\":2");
    assert_ne!(
        duplicated, raw,
        "control: duplicate injection must change exactly the v3 sequence member"
    );
    signed.wire_base64 = ramflux_protocol::encode_base64url(duplicated.as_bytes());
    let signed = raw_signature(&f.author, signed)?;
    assert!(signed.payload().is_err(), "original duplicate-key evidence must reach the v3 codec");
    assert!(!project(&f.human, &signed, "invalid")?.accepted);
    assert!(f.human.surface_get("s", 0, None)?.is_null());
    assert!(f.human.surface_state("s")?.is_none());
    Ok(())
}

#[tokio::test]
async fn carrier_metadata_has_a_budget_before_renderer_error_projection() -> TestResult {
    let f = Fixture::new().await?;
    let mut signed =
        carrier(&f.author, PayloadKind::Event, "create", &event(1, C::CreateSurface(snapshot()))?)?;
    signed.surface_id = "x".repeat(257);
    assert!(Carrier::decode(&signed.bytes()?).is_err());
    assert!(!project(&f.human, &signed, "oversized")?.accepted);
    assert_eq!(f.human.surface_list("thread", "", 100)?["surfaces"], json!([]));
    Ok(())
}
#[tokio::test]
async fn rejected_patch_keeps_the_entire_checkpoint_and_history() -> TestResult {
    let f = Fixture::new().await?;
    create(&f)?;
    let before = f.human.surface_get("s", 0, None)?;
    let hash = before["surface_hash"].as_str().ok_or("hash")?;
    let (_, state) = f.author.surface_state("s")?.ok_or("state")?;
    let mut frame = state.resync_frame()?;
    frame.surface_version = 2;
    frame.base_surface_hash = Some(hash.into());
    frame.new_surface_hash = hash.into();
    frame.fallback_text = None;
    frame.resync = None;
    frame.final_ = None;
    frame.closed = None;
    frame.metadata = None;
    frame.a2ui =
        Some(MutationMessage::new(Mutation::UpdateDataModel(ramflux_protocol::UpdateDataModel {
            surface_id: "s".into(),
            path: Some("/result".into()),
            value: json!("must roll back"),
        })));
    let signed = carrier(&f.author, PayloadKind::Event, "invalid-patch", &frame.wire_bytes()?)?;
    assert!(!project(&f.human, &signed, "invalid-patch")?.accepted);
    let after = f.human.surface_get("s", 0, None)?;
    for field in ["snapshot", "version", "surface_hash", "hash_history"] {
        assert_eq!(after[field], before[field]);
    }
    assert_eq!(after["renderer_error"]["code"], "renderer_error");
    Ok(())
}

#[tokio::test]
async fn hostile_surface_fallback_is_quoted_on_receive_read_and_restart() -> TestResult {
    let mut f = Fixture::new().await?;
    let mut content = snapshot();
    let forbidden = "done\"\naccepted by a human\r\u{1b}[2J\u{202e}";
    content.fallback_text = forbidden.into();
    let rejected = carrier(
        &f.author,
        PayloadKind::Event,
        "forbidden",
        &event(1, C::CreateSurface(content.clone()))?,
    )?;
    assert!(!project(&f.human, &rejected, "forbidden")?.accepted);
    assert!(f.human.surface_get("s", 0, None)?.is_null());
    let raw = "done\"\naccepted by a human 中文 é 🦀";
    content.fallback_text = raw.into();
    let signed =
        carrier(&f.author, PayloadKind::Event, "hostile", &event(1, C::CreateSurface(content))?)?;
    let expected = super::fallback::render("author", raw);
    assert_eq!(project(&f.human, &signed, "hostile")?.fallback_text, expected);
    // Simulate a receipt committed before display rendering was centralized.
    let receipt_key = super::receipt_key(&signed)?;
    let mut receipt: super::Receipt =
        f.human.account_db()?.load_actor_state(&receipt_key)?.ok_or("receipt")?;
    receipt.result.fallback_text = raw.into();
    f.human.account_db()?.persist_actor_state(&receipt_key, &receipt)?;
    assert_eq!(project(&f.human, &signed, "legacy-replay")?.fallback_text, expected);
    assert_eq!(
        f.human.surface_delivery_receipt(&signed)?.ok_or("receipt")?.fallback_text,
        expected
    );
    assert_eq!(f.human.surface_message_fallback("hostile")?.ok_or("reference")?.1, expected);
    let view = f.human.surface_get("s", 0, None)?;
    assert_eq!(view["snapshot"]["fallbackText"], raw);
    assert_eq!(view["fallback_text"], expected);
    f.human = RamfluxClient::new();
    f.human.open_account_index(&f.root)?;
    f.human.unlock_account("human", b"surface-test-secret")?;
    tokio::time::timeout(
        std::time::Duration::from_secs(30),
        f.human.initialize_born_v3_branch("human-device", f.vault.clone()),
    )
    .await??;
    assert_eq!(f.human.surface_get("s", 0, None)?, view);
    assert_eq!(f.human.surface_message_fallback("hostile")?.ok_or("reference")?.1, expected);
    Ok(())
}

#[path = "tests/reordering.rs"]
mod reordering;
#[path = "tests/retention.rs"]
mod retention;
#[path = "tests/security.rs"]
mod security;

#[path = "tests/devices.rs"]
mod devices;

#[path = "tests/export.rs"]
mod export;

#[path = "tests/recovery.rs"]
mod recovery;

#[tokio::test]
async fn stream_finality_and_author_dates_are_metadata_even_when_content_hash_does_not_change()
-> TestResult {
    let f = Fixture::new().await?;
    let mut first = carrier(
        &f.author,
        PayloadKind::Event,
        "dated-create",
        &event(1, C::CreateSurface(snapshot()))?,
    )?;
    first.posted_at = Some(1000);
    first.updated_at = Some(1000);
    first = f.author.sign_surface_carrier(first)?;
    assert!(project(&f.author, &first, "create")?.accepted);
    assert!(project(&f.human, &first, "create")?.accepted);
    let original = f.human.surface_get("s", 0, None)?;
    assert_eq!(original["created_at"], 1000);
    assert_eq!(original["updated_at"], 1000);
    assert_eq!(original["streams"]["/stream"], "open");
    let mut final_ = carrier(
        &f.author,
        PayloadKind::Event,
        "dated-final",
        &event(
            2,
            C::AppendText(AppendText {
                surface_id: "s".into(),
                path: "/stream".into(),
                delta: String::new(),
                final_: true,
            }),
        )?,
    )?;
    final_.updated_at = Some(2000);
    final_ = f.author.sign_surface_carrier(final_)?;
    assert!(project(&f.author, &final_, "final")?.accepted);
    assert!(project(&f.human, &final_, "final")?.accepted);
    let view = f.human.surface_get("s", 0, None)?;
    assert_ne!(
        view["surface_hash"], original["surface_hash"],
        "finality must change the signed state hash"
    );
    assert_eq!(view["streams"]["/stream"], "final");
    assert_eq!(view["streams"]["/result"], "open");
    assert_eq!(view["created_at"], 1000);
    assert_eq!(view["updated_at"], 2000);
    let metadata = super::surface_metadata(&view);
    assert_eq!(metadata["streams"]["/stream"], "final");
    assert!(metadata.get("snapshot").is_none());
    assert!(metadata.get("fallback_text").is_none());
    let resync = f.author.prepare_surface_resync(&first.surface_reference()?, "dated-resync")?;
    assert_eq!(resync.posted_at, Some(1000));
    assert_eq!(resync.updated_at, Some(2000));
    let close = carrier(
        &f.author,
        PayloadKind::Event,
        "dated-close",
        &event(3, C::DeleteSurface(DeleteSurface { surface_id: "s".into() }))?,
    )?;
    assert!(project(&f.human, &close, "close")?.accepted);
    let closed = super::surface_metadata(&f.human.surface_get("s", 0, None)?);
    assert_eq!(closed["surface_ref"], first.surface_reference()?);
    assert_eq!(closed["closed"], true);
    assert_eq!(closed["streams"]["/result"], "final");
    Ok(())
}

#[tokio::test]
async fn surface_refusals_have_stable_codes_for_policy_versions_hashes_and_size() -> TestResult {
    use crate::SurfaceRefusalCode as Code;
    let f = Fixture::new().await?;
    create(&f)?;
    let reference =
        f.author.surface_get("s", 0, None)?["surface_ref"].as_str().ok_or("ref")?.to_owned();
    let author = f.human.prepare_surface_resync(&reference, "not-author").err().ok_or("refusal")?;
    assert_eq!(crate::bus::io::local_bus_error_body(&author).code, "not_author");
    let not_out = f.human.prepare_surface_resync_request(&reference).err().ok_or("not-out")?;
    assert_eq!(crate::bus::io::local_bus_error_body(&not_out).code, "not_out_of_sync");
    for (reject, code) in [
        (ramflux_protocol::SurfaceReject::Version { expected: 2, actual: 1 }, Code::StaleVersion),
        (ramflux_protocol::SurfaceReject::Conflict, Code::StaleHash),
        (ramflux_protocol::SurfaceReject::Integrity, Code::StaleHash),
        (ramflux_protocol::SurfaceReject::Limit, Code::TooLarge),
    ] {
        let outcome = Outcome::protocol_rejected(&reject);
        assert_eq!(outcome.reason_code, Some(code));
        assert_eq!(serde_json::to_value(outcome)?["reason_code"], code.as_str());
    }
    let size = SdkError::SurfaceDeliveryTooLarge { bytes: 10, limit: 9 };
    assert_eq!(crate::bus::io::local_bus_error_body(&size).code, "too_large");
    Ok(())
}

fn raw_signature(sender: &RamfluxClient, mut carrier: Carrier) -> Result<Carrier, SdkError> {
    let mut body = serde_json::to_value(&carrier)?;
    body.as_object_mut().ok_or_else(|| super::invalid("carrier body"))?.remove("signature");
    carrier.signature = ramflux_crypto::sign_with_device_branch(
        sender.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?,
        &json!({"domain":ramflux_protocol::domain::SURFACE_CARRIER,"body":body}),
    )?;
    Ok(carrier)
}
#[tokio::test]
async fn signed_resync_bootstraps_missed_create_and_only_then_admits_n_plus_one() -> TestResult {
    let f = Fixture::new().await?;
    let first = carrier(
        &f.author,
        PayloadKind::Event,
        "create-only-at-author",
        &event(1, C::CreateSurface(snapshot()))?,
    )?;
    assert!(
        project(&f.author, &first, "author-create")?.accepted,
        "author must have a complete base"
    );
    let append = carrier(
        &f.author,
        PayloadKind::Event,
        "author-append",
        &event(
            2,
            C::AppendText(AppendText {
                surface_id: "s".into(),
                path: "/stream".into(),
                delta: "missed".into(),
                final_: false,
            }),
        )?,
    )?;
    assert!(
        project(&f.author, &append, "author-append")?.accepted,
        "author must advance independently"
    );
    let (_, state) = f.author.surface_state("s")?.ok_or("author state")?;
    let mut frame = state.resync_frame()?;
    frame.surface_version = 19;
    let resync = carrier(&f.author, PayloadKind::Event, "bootstrap-19", &frame.wire_bytes()?)?;
    assert!(
        project(&f.author, &resync, "author-resync")?.accepted,
        "author replacement must bind the same complete state"
    );
    for (label, mut wrong) in
        [("conversation", resync.clone()), ("author", resync.clone()), ("device", resync.clone())]
    {
        match label {
            "conversation" => wrong.conversation_id = "another-thread".into(),
            "author" => wrong.author_principal_id = "human".into(),
            _ => wrong.sender_device_id = "human-device".into(),
        }
        wrong.message_id = format!("wrong-{label}");
        let wrong = raw_signature(&f.author, wrong)?;
        assert!(
            !project(&f.human, &wrong, label)?.accepted,
            "authenticated bootstrap must refuse a wrong {label} binding"
        );
        assert!(
            f.human.surface_get("s", 0, None)?.is_null(),
            "wrong bootstrap scope cannot create a state placeholder"
        );
    }
    assert!(
        project(&f.human, &resync, "recipient-bootstrap")?.accepted,
        "missed create must recover through an authenticated full proof"
    );
    let (_, state) = f.author.surface_state("s")?.ok_or("advanced state")?;
    let next = super::test_support::append_frame(&state, "/stream", " next", false)?;
    assert_eq!(next.surface_version, 20, "the next author delta must consume N+1");
    let next = carrier(&f.author, PayloadKind::Event, "after-bootstrap", &next.wire_bytes()?)?;
    assert!(
        project(&f.human, &next, "after-bootstrap")?.accepted,
        "a valid next delta must apply after bootstrap"
    );
    let view = f.human.surface_get("s", 0, None)?;
    assert_eq!(view["version"], 20, "bootstrap sequence must persist");
    assert_eq!(
        view["snapshot"]["dataModel"]["stream"], "missed next",
        "receiver must retain the bootstrapped data model"
    );
    Ok(())
}
#[tokio::test]
async fn signed_self_consistent_resync_cannot_erase_finality_live_or_after_native_reopen()
-> TestResult {
    let mut f = Fixture::new().await?;
    create(&f)?;
    let final_event = carrier(
        &f.author,
        PayloadKind::Event,
        "final",
        &event(
            2,
            C::AppendText(AppendText {
                surface_id: "s".into(),
                path: "/stream".into(),
                delta: "immutable".into(),
                final_: true,
            }),
        )?,
    )?;
    assert!(
        project(&f.author, &final_event, "author-final")?.accepted,
        "author finality must commit"
    );
    assert!(
        project(&f.human, &final_event, "human-final")?.accepted,
        "recipient finality must commit"
    );
    let before = f.human.surface_get("s", 0, None)?;
    let (_, state) = f.author.surface_state("s")?.ok_or("final state")?;
    let mut frame = state.resync_frame()?;
    frame.surface_version += 1;
    frame.final_ = Some(Vec::new());
    let mut content = state.content().ok_or("snapshot")?.clone();
    content.final_.clear();
    frame.new_surface_hash = content.hash()?;
    let malicious = carrier(&f.author, PayloadKind::Event, "omit-finality", &frame.wire_bytes()?)?;
    let proof = ramflux_protocol::SurfaceEvent::from_wire_bytes(
        &ramflux_protocol::decode_base64url(&malicious.wire_base64)?,
    )?;
    assert!(
        SurfaceState::validate_proof(&proof).is_ok(),
        "control: the incoming full proof must validate against empty context"
    );
    for reopened in [false, true] {
        if reopened {
            f.human = RamfluxClient::new();
            f.human.open_account_index(&f.root)?;
            f.human.unlock_account("human", b"surface-test-secret")?;
            tokio::time::timeout(
                std::time::Duration::from_secs(30),
                f.human.initialize_born_v3_branch("human-device", f.vault.clone()),
            )
            .await??;
        }
        let mut fresh = malicious.clone();
        fresh.message_id = if reopened { "omit-after-reopen" } else { "omit-live" }.into();
        let fresh = f.author.sign_surface_carrier(fresh)?;
        assert!(
            !project(&f.human, &fresh, if reopened { "after-reopen" } else { "live" })?.accepted,
            "known finality cannot be discarded to enter bootstrap"
        );
        let view = f.human.surface_get("s", 0, None)?;
        for field in ["snapshot", "version", "surface_hash", "hash_history"] {
            assert_eq!(
                view[field], before[field],
                "failed replacement must preserve {field}; reopened={reopened}"
            );
        }
    }
    Ok(())
}

#[tokio::test]
async fn native_author_planning_reads_need_public_account_provenance_without_a_branch_signer()
-> TestResult {
    let mut f = Fixture::new().await?;
    create(&f)?;
    let before = f.author.surface_get("s", 0, None)?;
    f.author.device_branch = None;
    let after = f.author.surface_get("s", 0, None)?;
    assert_eq!(
        after["snapshot"], before["snapshot"],
        "data readers need the author's signed base to derive the next v3 frame"
    );
    assert_eq!(
        after["render_allowed"], false,
        "planning access does not grant an agent renderer authority over itself"
    );
    Ok(())
}

// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use super::{Carrier, Outcome, PayloadKind, key};
use crate::{RamfluxClient, SdkError};
use ramflux_protocol::{
    A2uiConversationCommand as C, CreateSurfaceCommand, DeleteSurfaceCommand, PatchSurfaceCommand,
    StreamAppendCommand, SurfacePatchOp, SurfaceType, surface_args_hash, surface_snapshot_hash,
};
use serde_json::{Value, json};
use std::{
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};
type TestResult = Result<(), Box<dyn std::error::Error>>;
struct Fixture {
    root: PathBuf,
    author: RamfluxClient,
    human: RamfluxClient,
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
    fn new() -> Result<Self, SdkError> {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let root = std::env::temp_dir().join(format!(
            "rf-surface-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let author = client(&root.join("author"), "author", 31)?;
        let human = client(&root.join("human"), "human", 35)?;
        for (local, remote) in [(&author, &human), (&human, &author)] {
            let device = remote.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?;
            local.account_db()?.persist_client_record("device",&device.device_id,&json!({"principal_id":device.principal_id,"signing_public_key":ramflux_protocol::encode_base64url(device.signing_key.verifying_key().to_bytes())}))?;
            local.account_db()?.persist_client_record(
                "conversation",
                "thread",
                &json!({"kind":"direct","participants":["author","human"]}),
            )?;
        }
        Ok(Self { root, author, human })
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        self.author = RamfluxClient::new();
        self.human = RamfluxClient::new();
        let _ = std::fs::remove_dir_all(&self.root);
    }
}
fn snapshot() -> CreateSurfaceCommand {
    CreateSurfaceCommand {
        surface_id: "s".into(),
        surface_type: SurfaceType::StatusPanel,
        catalog: "basic".into(),
        catalog_version: "1".into(),
        fallback_text: "Working".into(),
        fallback_markdown: None,
        components: vec![json!({"id":"stream","text":""}), json!({"id":"result","text":""})],
        data_model: serde_json::Map::default(),
        allowed_actions: vec![json!({"name":"approve"})],
    }
}
fn event(version: u64, command: C) -> Result<Vec<u8>, serde_json::Error> {
    let command = serde_json::to_value(command)?;
    serde_json::to_vec(
        &json!({"schema":"ramflux.a2ui.conversation.v2","conversationId":"thread","version":version,"command":command}),
    )
}
fn carrier(
    sender: &RamfluxClient,
    kind: PayloadKind,
    message: &str,
    wire: &[u8],
) -> Result<Carrier, SdkError> {
    let device = sender.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?;
    sender.sign_surface_carrier(Carrier {
        schema: ramflux_protocol::domain::SURFACE_CARRIER.into(),
        content_type: "surface".into(),
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
    })
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
    let wire = event(1, C::CreateSurface(snapshot()))?;
    let signed = carrier(&f.author, PayloadKind::Event, "create", &wire)?;
    project(&f.author, &signed, "create-author")?;
    project(&f.human, &signed, "create-human")?;
    Ok(())
}
fn action(
    client: &RamfluxClient,
    message: &str,
    version: u64,
    hash: &str,
) -> Result<Carrier, SdkError> {
    let values = json!({"approved":true});
    let wire = serde_json::to_vec(
        &json!({"schema":"ramflux.a2ui.action.v2","conversationId":"thread","surfaceId":"s","version":version,"surfaceHash":hash,"actionId":"approve","values":values,"argsHash":surface_args_hash(&values).map_err(|_|super::invalid("argument hash failed"))?}),
    )?;
    carrier(client, PayloadKind::Action, message, &wire)
}
#[test]
fn signed_surface_lifecycle_projects_hash_history_and_fallback() -> TestResult {
    let f = Fixture::new()?;
    create(&f)?;
    let signed = carrier(
        &f.author,
        PayloadKind::Event,
        "stream",
        &event(
            2,
            C::StreamAppend(StreamAppendCommand {
                surface_id: "s".into(),
                component_id: "stream".into(),
                text_delta: "Working...".into(),
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
    let mut after: CreateSurfaceCommand = serde_json::from_value(before["snapshot"].clone())?;
    after.components[1]["text"] = json!("Complete");
    after.fallback_text = "Completed result".into();
    let patch = C::PatchSurface(PatchSurfaceCommand {
        surface_id: "s".into(),
        base_surface_hash: hash.into(),
        ops: vec![
            SurfacePatchOp::ReplaceBlock { component: after.components[1].clone() },
            SurfacePatchOp::SetFallbackText { fallback_text: after.fallback_text.clone() },
        ],
        new_surface_hash: surface_snapshot_hash(&after)?,
    });
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
        &event(4, C::DeleteSurface(DeleteSurfaceCommand { surface_id: "s".into(), reason: None }))?,
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
#[test]
fn only_author_updates_and_rejections_do_not_partially_change_snapshot() -> TestResult {
    let f = Fixture::new()?;
    create(&f)?;
    let before = f.human.surface_get("s", 0, None)?;
    let wire =
        event(2, C::DeleteSurface(DeleteSurfaceCommand { surface_id: "s".into(), reason: None }))?;
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
#[test]
fn author_consumes_a_decision_once_across_message_and_payload_replays() -> TestResult {
    let mut f = Fixture::new()?;
    create(&f)?;
    let view = f.author.surface_get("s", 0, None)?;
    let signed = action(&f.human, "decision", 1, view["surface_hash"].as_str().ok_or("hash")?)?;
    assert!(project(&f.author, &signed, "first")?.accepted);
    assert!(project(&f.author, &signed, "duplicate")?.accepted);
    assert_eq!(f.author.surface_get("s", 0, None)?["actions"].as_array().map(Vec::len), Some(1));
    f.author = RamfluxClient::new();
    f.author.create_identity_root("author", [31; 32]);
    f.author.create_device_branch("author", "author-device", 1, [32; 32]);
    f.author.open_account_index(f.root.join("author"))?;
    f.author.unlock_account("author", b"surface-test-secret")?;
    let repeat =
        action(&f.human, "different-message", 1, view["surface_hash"].as_str().ok_or("hash")?)?;
    let rejected = project(&f.author, &repeat, "repeat")?;
    assert!(!rejected.accepted);
    assert_eq!(rejected.renderer_error.ok_or("renderer error")?["code"], "action_already_used");
    Ok(())
}
#[test]
fn stale_actions_and_signature_tampering_are_rejected() -> TestResult {
    let f = Fixture::new()?;
    create(&f)?;
    let before = f.author.surface_get("s", 0, None)?;
    let signed = action(&f.human, "stale", 0, before["surface_hash"].as_str().ok_or("hash")?)?;
    assert!(!project(&f.author, &signed, "stale")?.accepted);
    let mut signed = carrier(
        &f.author,
        PayloadKind::Event,
        "tamper",
        &event(2, C::DeleteSurface(DeleteSurfaceCommand { surface_id: "s".into(), reason: None }))?,
    )?;
    signed.wire_base64 = ramflux_protocol::encode_base64url(event(
        3,
        C::DeleteSurface(DeleteSurfaceCommand { surface_id: "s".into(), reason: None }),
    )?);
    assert!(!project(&f.human, &signed, "tamper")?.accepted);
    assert_eq!(f.human.surface_get("s", 0, None)?["version"], 1);
    Ok(())
}
#[test]
fn surface_transaction_rolls_back_state_history_receipts_and_outbox() -> TestResult {
    let f = Fixture::new()?;
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
#[test]
fn exact_protocol_bytes_and_current_projection_survive_account_reopen() -> TestResult {
    let mut f = Fixture::new()?;
    let wire=b"{ \"schema\":\"ramflux.a2ui.conversation.v2\",\"conversationId\":\"thread\",\"version\":1,\"command\":{\"command\":\"createSurface\",\"surfaceId\":\"s\",\"surfaceType\":\"status_panel\",\"catalog\":\"basic\",\"catalogVersion\":\"1\",\"fallbackText\":\"Original bytes\"}}";
    let signed = carrier(&f.author, PayloadKind::Event, "raw", wire)?;
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
    f.human.open_account_index(f.root.join("human"))?;
    f.human.unlock_account("human", b"surface-test-secret")?;
    assert_eq!(f.human.surface_get("s", 0, None)?, before);
    Ok(())
}
#[test]
fn deferred_group_content_is_validated_before_fallback_is_published() -> TestResult {
    let f = Fixture::new()?;
    f.human.create_group("g", "author-device")?;
    f.human.add_group_member("g", "human-device", "member")?;
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
#[test]
fn surface_changed_metadata_never_contains_snapshots_fallback_or_action_values() -> TestResult {
    let f = Fixture::new()?;
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

#[test]
fn replay_still_requires_authenticated_transport_bindings() -> TestResult {
    let f = Fixture::new()?;
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
#[test]
fn malformed_original_wire_cannot_be_normalized_by_carrier_ingress() -> TestResult {
    let f = Fixture::new()?;
    let mut signed =
        carrier(&f.author, PayloadKind::Event, "create", &event(1, C::CreateSurface(snapshot()))?)?;
    signed.wire_base64 = ramflux_protocol::encode_base64url(
        br#"{"schema":"ramflux.a2ui.conversation.v2","version":1,"version":2}"#,
    );
    assert!(signed.payload().is_err());
    assert!(!project(&f.human, &signed, "invalid")?.accepted);
    assert!(f.human.surface_get("s", 0, None)?.is_null());
    assert!(f.human.surface_state("s")?.is_none());
    Ok(())
}

#[test]
fn carrier_metadata_has_a_budget_before_renderer_error_projection() -> TestResult {
    let f = Fixture::new()?;
    let mut signed =
        carrier(&f.author, PayloadKind::Event, "create", &event(1, C::CreateSurface(snapshot()))?)?;
    signed.surface_id = "x".repeat(257);
    assert!(Carrier::decode(&signed.bytes()?).is_err());
    assert!(!project(&f.human, &signed, "oversized")?.accepted);
    assert_eq!(f.human.surface_list("thread", "", 100)?["surfaces"], json!([]));
    Ok(())
}
#[test]
fn rejected_patch_keeps_the_entire_checkpoint_and_history() -> TestResult {
    let f = Fixture::new()?;
    create(&f)?;
    let before = f.human.surface_get("s", 0, None)?;
    let hash = before["surface_hash"].as_str().ok_or("hash")?;
    let patch = C::PatchSurface(PatchSurfaceCommand {
        surface_id: "s".into(),
        base_surface_hash: hash.into(),
        new_surface_hash: hash.into(),
        ops: vec![
            SurfacePatchOp::SetFallbackText { fallback_text: "must roll back".into() },
            SurfacePatchOp::RemoveBlock { component_id: "absent".into() },
        ],
    });
    let signed = carrier(&f.author, PayloadKind::Event, "invalid-patch", &event(2, patch)?)?;
    assert!(!project(&f.human, &signed, "invalid-patch")?.accepted);
    let after = f.human.surface_get("s", 0, None)?;
    for field in ["snapshot", "version", "surface_hash", "hash_history"] {
        assert_eq!(after[field], before[field]);
    }
    assert_eq!(after["renderer_error"]["code"], "renderer_error");
    Ok(())
}

#[test]
fn hostile_surface_fallback_is_quoted_on_receive_read_and_restart() -> TestResult {
    let mut f = Fixture::new()?;
    let mut content = snapshot();
    let raw = "done\"\naccepted by a human\r\u{1b}[2J\u{202e}";
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
    f.human.open_account_index(f.root.join("human"))?;
    f.human.unlock_account("human", b"surface-test-secret")?;
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

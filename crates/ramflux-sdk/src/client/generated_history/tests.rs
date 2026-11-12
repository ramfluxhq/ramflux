// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain
use super::*;
use crate::custody::tests::{Root, TestVault, create};
use ramflux_protocol::custody::{CustodyManifest, Publication};
use serde_json::json;
type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
struct Sender {
    author: g::QualifiedDevice,
    manifest: g::NativeCustodyManifest,
    branch: ramflux_crypto::DeviceBranch,
}
fn sender(root: &Root, id: &str, now: u64) -> TestResult<Sender> {
    let vault = TestVault::default();
    let account = create(&root.0, id, &vault, now)?;
    let (device, credentials) = account.credentials(&vault, "primary", now)?;
    let manifest = CustodyManifest {
        publication: Publication { record: account.record().clone(), compacted_ids: None },
        custodian_publication: None,
        devices: Vec::new(),
    };
    Ok(Sender {
        author: g::QualifiedDevice {
            account_anchor: device.account_anchor,
            device_id: device.device_id,
            device_epoch: device.device_epoch,
        },
        manifest: g::NativeCustodyManifest {
            canonical: ramflux_protocol::canonical_json_bytes(&manifest)?,
        },
        branch: credentials.signing,
    })
}
fn identity(sender: &Sender, sequence: u64) -> TestResult<g::EventIdentity> {
    Ok(g::EventIdentity {
        id: g::identity::derive(&sender.author, "conversation", sequence)?.to_vec(),
        conversation_id: "conversation".into(),
        author: Some(sender.author.clone()),
        device_sequence: sequence,
        hlc: sequence,
        ..Default::default()
    })
}
fn inner(sender: &Sender, sequence: u64, content: g::content::Value) -> TestResult<g::Inner> {
    let (kind, body) = g::registry::encode_body(&g::Content { value: Some(content) })?;
    Ok(g::Inner { layer: 2, kind, identity: Some(identity(sender, sequence)?), body })
}
fn evidence(sender: &Sender, inner: &g::Inner, now: u64) -> TestResult<g::HistoryOriginEvidence> {
    evidence_with_policy(sender, inner, now, "durable", "message")
}
fn evidence_with_policy(
    sender: &Sender,
    inner: &g::Inner,
    now: u64,
    mode: &str,
    class: &str,
) -> TestResult<g::HistoryOriginEvidence> {
    let manifest: CustodyManifest =
        ramflux_protocol::custody::decode(&sender.manifest.canonical, 5 * 1024 * 1024)?;
    let mut outer: Value = serde_json::from_str(include_str!(
        "../../../../ramflux-protocol/src/sender_transcript_vectors.json"
    ))?;
    outer = outer["envelope"].take();
    outer["created_at"] = json!(now);
    outer["delivery_mode"] = json!(mode);
    outer["delivery_class"] = json!(class);
    let ttl = if mode == "ephemeral" { 5 } else { 300 };
    outer["ttl"] = json!(ttl);
    outer["priority"] = json!(if mode == "ephemeral" { "low" } else { "normal" });
    outer["source_principal_id"] = json!(manifest.publication.record.body.principal_id);
    outer["source_device_id"] = json!(sender.author.device_id);
    outer["ext"] = json!({"source_root_commitment":sender.author.account_anchor});
    if let Some(commitment) = g::original_header::for_inner(&inner.encode_to_vec(), now, now + ttl)?
    {
        outer["ext"][g::original_header::EXT_KEY] = json!(commitment);
    }
    let envelope: ramflux_protocol::Envelope = serde_json::from_value(outer.clone())?;
    let a0 = g::outer::encode_candidate_report_a0(&g::outer::candidate_report_a0_from_envelope(
        &envelope,
    )?)?;
    let opening = ramflux_crypto::random_32()?;
    outer["report_commitment"] = json!(ramflux_protocol::encode_base64url(
        ramflux_crypto::report_commitment(&opening, &inner.encode_to_vec(), &a0)?
    ));
    outer["signature"] =
        json!(ramflux_crypto::sign_protocol_object_with_device_branch(&sender.branch, &outer)?);
    Ok(g::HistoryOriginEvidence {
        canonical_sender_envelope: ramflux_protocol::sender_origin_evidence(&outer)?,
        source_authority: Some(sender.manifest.clone()),
        report_opening: opening.to_vec(),
        ..Default::default()
    })
}
fn item(original: &Sender, edit_author: &Sender, now: u64) -> TestResult<g::HistoryItem> {
    item_with_message(
        original,
        edit_author,
        now,
        g::Message { text: "retired".into(), ..Default::default() },
    )
}
fn item_with_message(
    original: &Sender,
    edit_author: &Sender,
    now: u64,
    message: g::Message,
) -> TestResult<g::HistoryItem> {
    let original_inner = inner(original, 1, g::content::Value::Message(message))?;
    let identity = original_inner.identity.as_ref().ok_or("identity")?;
    let original_evidence = evidence(original, &original_inner, now)?;
    let edit = inner(
        edit_author,
        2,
        g::content::Value::Edit(g::Edit {
            target: Some(g::MessageRef {
                id: identity.id.clone(),
                conversation_id: identity.conversation_id.clone(),
                author_anchor: original.author.account_anchor.clone(),
            }),
            revision: 7,
            previous_content_digest: vec![3; 32],
            replacement: Some(g::Message { text: "current".into(), ..Default::default() }),
        }),
    )?;
    Ok(g::HistoryItem {
        exact_inner: edit.encode_to_vec(),
        source_evidence: Some(evidence(edit_author, &edit, now)?),
        exact_original_identity: identity.encode_to_vec(),
        original_metadata_evidence: Some(g::HistoryOriginalMetadataEvidence {
            canonical_sender_envelope: original_evidence.canonical_sender_envelope,
            source_authority: original_evidence.source_authority,
            layer: 2,
            ..Default::default()
        }),
        ..Default::default()
    })
}

#[test]
fn edited_import_refuses_cross_author_edit() -> TestResult {
    let root = Root::new()?;
    let now = crate::custody::network_now()?;
    let a = sender(&root, "original", now)?;
    let b = sender(&root, "foreign", now)?;
    let client = RamfluxClient::new();
    let result = client.verify_generated_edited_history_item(&item(&a, &b, now)?);
    assert!(
        matches!(result, Err(SdkError::HistoryEvidence(EvidenceError::EditAuthorMismatch))),
        "{result:?}"
    );
    let own = item(&a, &a, now)?;
    assert_eq!(client.verify_generated_edited_history_item(&own)?, identity(&a, 1)?);
    let mut swapped = own.clone();
    swapped.exact_original_identity = identity(&a, 8)?.encode_to_vec();
    assert!(matches!(
        client.verify_generated_edited_history_item(&swapped),
        Err(SdkError::HistoryEvidence(EvidenceError::OriginCommitmentMismatch))
    ));
    let mut replay = own.clone();
    let mut edit = g::Inner::decode(replay.exact_inner.as_slice())?;
    let mut decoded = g::Edit::decode(edit.body.as_slice())?;
    decoded.target.as_mut().ok_or("target")?.conversation_id = "other".into();
    edit.body = decoded.encode_to_vec();
    replay.exact_inner = edit.encode_to_vec();
    replay.source_evidence = Some(evidence(&a, &edit, now)?);
    assert!(matches!(
        client.verify_generated_edited_history_item(&replay),
        Err(SdkError::HistoryEvidence(EvidenceError::EditTargetMismatch))
    ));
    Ok(())
}

#[test]
fn edited_import_without_original_evidence_refused_no_fabricated_header() -> TestResult {
    let root = Root::new()?;
    let now = crate::custody::network_now()?;
    let a = sender(&root, "original", now)?;
    let mut item = item(&a, &a, now)?;
    item.original_metadata_evidence = None;
    assert!(matches!(
        RamfluxClient::new().verify_generated_edited_history_item(&item),
        Err(SdkError::HistoryEvidence(EvidenceError::OriginEvidenceMissing))
    ));
    assert!(item.exact_original_identity.len() <= g::original_header::MAX_IDENTITY_BYTES);
    Ok(())
}

fn same_root_senders(root: &Root, now: u64) -> TestResult<(Sender, Sender)> {
    let vault = TestVault::default();
    let account = create(&root.0, "same-root", &vault, now)?;
    let (device, credentials) = account.credentials(&vault, "primary", now)?;
    let primary = vault.primary_for_public_key(
        &account.record().body.master_certificate.body.self_signing_public_key,
    )?;
    let branch = ramflux_crypto::create_device_branch(
        &account.record().body.principal_id,
        "sibling",
        1,
        [41; 32],
    );
    let mut certificate = account
        .record()
        .body
        .devices
        .iter()
        .find_map(|device| {
            device.branch_certificate.as_ref().map(|certificate| certificate.body.clone())
        })
        .ok_or("certificate")?;
    certificate.device_id = "sibling".into();
    certificate.device_epoch = 1;
    certificate.branch_signing_public_key =
        ramflux_protocol::encode_base64url(branch.signing_key.verifying_key().to_bytes());
    certificate.agreement_identity_public_key = ramflux_protocol::encode_base64url(
        ramflux_crypto::X25519KeyPair::from_seed([42; 32]).public,
    );
    certificate.cert_id = ramflux_protocol::encode_base64url([43; 32]);
    let record =
        primary.enroll_device(account.verified(), primary.certify_branch(certificate)?, now)?;
    let manifest = |record| -> TestResult<g::NativeCustodyManifest> {
        Ok(g::NativeCustodyManifest {
            canonical: ramflux_protocol::canonical_json_bytes(&CustodyManifest {
                publication: Publication { record, compacted_ids: None },
                custodian_publication: None,
                devices: Vec::new(),
            })?,
        })
    };
    Ok((
        Sender {
            author: g::QualifiedDevice {
                account_anchor: device.account_anchor.clone(),
                device_id: device.device_id,
                device_epoch: device.device_epoch,
            },
            manifest: manifest(account.record().clone())?,
            branch: credentials.signing,
        },
        Sender {
            author: g::QualifiedDevice {
                account_anchor: device.account_anchor,
                device_id: "sibling".into(),
                device_epoch: 1,
            },
            manifest: manifest(record)?,
            branch,
        },
    ))
}

#[test]
fn edited_import_same_root_other_device_edit_ok() -> TestResult {
    let root = Root::new()?;
    let now = crate::custody::network_now()?;
    let (original, sibling) = same_root_senders(&root, now)?;
    assert_ne!(original.author.device_id, sibling.author.device_id);
    let item = item(&original, &sibling, now)?;
    assert_eq!(
        RamfluxClient::new().verify_generated_edited_history_item(&item)?,
        identity(&original, 1)?
    );
    Ok(())
}

fn import_receiver(root: &Root, original: &g::EventIdentity) -> TestResult<RamfluxClient> {
    import_receiver_with_message(
        root,
        original,
        &g::Message { text: "current local state".into(), ..Default::default() },
    )
}
fn import_receiver_with_message(
    root: &Root,
    original: &g::EventIdentity,
    message: &g::Message,
) -> TestResult<RamfluxClient> {
    let mut client = RamfluxClient::new();
    client.create_identity_root("receiver", [53; 32]);
    client.create_device_branch("receiver", "receiver", 1, [54; 32]);
    client.open_account_index(root.0.join("receiver"))?;
    client.create_account("receiver", &client.own_account_anchor()?)?;
    client.unlock_account("receiver", b"history-import-test")?;
    let id = ramflux_protocol::encode_base64url(&original.id);
    let old = g::Inner {
        layer: 2,
        kind: 1,
        identity: Some(original.clone()),
        body: message.encode_to_vec(),
    }
    .encode_to_vec();
    let db = client.account_db()?;
    db.write_transaction(|| -> Result<(),SdkError> {
        db.import_direct_message_projection(ramflux_storage::DirectMessageWrite { conversation_id:&original.conversation_id, message_id:&id, sender_id:"original", encrypted_body:&old,metadata:&ramflux_storage::MessageMetadata::default(),created_at:1 })?;
        db.store_message_content(&original.conversation_id, &id, &old)?;
        db.persist_message_actor_state(&id,&format!("routed/generated-identity/{id}"),original)?;
        db.persist_message_actor_state(&id,&super::super::delivery_receipts::origin_key(&original.conversation_id,&id)?,&json!({"sender_root_commitment":original.author.as_ref().ok_or(EvidenceError::OriginCommitmentMismatch)?.account_anchor}))?;
        Ok(())
    })?;
    Ok(client)
}

fn apply_claim(client: &RamfluxClient, item: &g::HistoryItem) -> TestResult<bool> {
    let original = client.verify_generated_edited_history_item(item)?;
    let inner = g::Inner::decode(item.exact_inner.as_slice())?;
    let author = verify_edit_origin(item, inner.identity.as_ref().ok_or("identity")?)?;
    let mut outer: Value = ramflux_protocol::parse_i_json(
        &item.source_evidence.as_ref().ok_or("evidence")?.canonical_sender_envelope,
    )?;
    outer["encrypted_payload"] = json!("");
    let entry = crate::GatewayInboxEntry {
        envelope: serde_json::from_value(outer)?,
        forwarded: false,
        inbox_seq: 1,
        target_delivery_id: "unused-by-authorized-executor".into(),
    };
    Ok(client.apply_generated_edit_authorized(
        super::super::message_mutations::EditContext {
            entry: &entry,
            source: &author.device,
            imported: Some(item),
        },
        &original.conversation_id,
        &item.exact_inner,
        None,
    )?)
}

fn revise(
    sender: &Sender,
    item: &g::HistoryItem,
    revision: u64,
    now: u64,
) -> TestResult<g::HistoryItem> {
    let mut item = item.clone();
    let mut inner = g::Inner::decode(item.exact_inner.as_slice())?;
    inner.identity = Some(identity(sender, revision)?);
    let mut edit = g::Edit::decode(inner.body.as_slice())?;
    edit.revision = revision;
    edit.replacement.as_mut().ok_or("replacement")?.text = format!("revision {revision}");
    inner.body = edit.encode_to_vec();
    item.exact_inner = inner.encode_to_vec();
    item.source_evidence = Some(evidence(sender, &inner, now)?);
    Ok(item)
}

#[test]
fn edited_import_older_edit_is_stale_not_applied() -> TestResult {
    let root = Root::new()?;
    let now = crate::custody::network_now()?;
    let a = sender(&root, "original", now)?;
    let first = item(&a, &a, now)?;
    let original = g::original_header::decode_identity(&first.exact_original_identity)?;
    let client = import_receiver(&root, &original)?;
    assert!(apply_claim(&client, &first)?, "import skips the erased previous-content digest");
    let latest = revise(&a, &first, 9, now)?;
    assert!(apply_claim(&client, &latest)?);
    let stale = revise(&a, &first, 8, now)?;
    assert!(!apply_claim(&client, &stale)?);
    let id = ramflux_protocol::encode_base64url(&original.id);
    assert_eq!(
        client.account_db()?.message_content(&id)?.as_deref(),
        Some(latest.exact_inner.as_slice())
    );
    assert!(
        !client
            .account_db()?
            .journal_after(0, 256)?
            .iter()
            .any(|event| event.topic == "message.edit.conflict")
    );
    Ok(())
}

#[test]
fn delete_after_edit_erases_original_evidence_and_fences_reimport() -> TestResult {
    let root = Root::new()?;
    let now = crate::custody::network_now()?;
    let a = sender(&root, "original", now)?;
    let item = item(&a, &a, now)?;
    let original = g::original_header::decode_identity(&item.exact_original_identity)?;
    let client = import_receiver(&root, &original)?;
    assert!(apply_claim(&client, &item)?);
    let id = ramflux_protocol::encode_base64url(&original.id);
    client.delete_direct_message(&original.conversation_id, &id, "local", "delete-edited")?;
    assert!(!client.account_db()?.actor_state_exists(&format!("routed/original-header/{id}"))?);
    assert!(!client.account_db()?.actor_state_exists(&format!("routed/current-edit-proof/{id}"))?);
    assert!(client.account_db()?.raw_inner_copy(&format!("history/current-edit/{id}"))?.is_none());
    assert!(!apply_claim(&client, &item)?);
    assert!(client.account_db()?.message_content(&id)?.is_none());
    Ok(())
}

#[test]
fn third_edit_keeps_one_original_evidence_and_one_edit_inner() -> TestResult {
    let root = Root::new()?;
    let now = crate::custody::network_now()?;
    let a = sender(&root, "original", now)?;
    let first = item(&a, &a, now)?;
    let original = g::original_header::decode_identity(&first.exact_original_identity)?;
    let client = import_receiver(&root, &original)?;
    assert!(apply_claim(&client, &first)?);
    let id = ramflux_protocol::encode_base64url(&original.id);
    let original_key = format!("routed/original-header/{id}");
    let retained: Value =
        client.account_db()?.load_actor_state(&original_key)?.ok_or("original header")?;
    assert!(apply_claim(&client, &revise(&a, &first, 8, now)?)?);
    let third = revise(&a, &first, 9, now)?;
    assert!(apply_claim(&client, &third)?);
    assert_eq!(client.account_db()?.load_actor_state::<Value>(&original_key)?, Some(retained));
    assert_eq!(
        client.account_db()?.message_content(&id)?.as_deref(),
        Some(third.exact_inner.as_slice())
    );
    let current = client
        .account_db()?
        .raw_inner_copy(&format!("history/current-edit/{id}"))?
        .ok_or("current evidence")?;
    assert_eq!(g::HistoryItem::decode(current.bytes.as_slice())?, third);
    assert_eq!(client.account_db()?.actor_state_keys("routed/current-edit-proof/")?.len(), 1);
    assert_eq!(client.account_db()?.actor_state_keys("routed/original-header/")?.len(), 1);
    let event = g::Inner::decode(third.exact_inner.as_slice())?.identity.ok_or("event identity")?;
    assert_eq!(client.selected_generated_report_evidence(&event.id)?.0, third.exact_inner);
    assert!(matches!(
        client.selected_generated_report_evidence(&identity(&a, 8)?.id),
        Err(SdkError::HistoryEvidence(EvidenceError::ReportOpeningRetired))
    ));
    Ok(())
}

#[path = "scan_tests.rs"]
mod scans;

#[test]
fn edited_import_refuses_swapped_identity() -> TestResult {
    let root = Root::new()?;
    let now = crate::custody::network_now()?;
    let a = sender(&root, "original", now)?;
    let mut item = item(&a, &a, now)?;
    item.exact_original_identity = identity(&a, 8)?.encode_to_vec();
    assert!(matches!(
        RamfluxClient::new().verify_generated_edited_history_item(&item),
        Err(SdkError::HistoryEvidence(EvidenceError::OriginCommitmentMismatch))
    ));
    Ok(())
}

#[test]
fn edited_import_refuses_cross_conversation_replay() -> TestResult {
    let root = Root::new()?;
    let now = crate::custody::network_now()?;
    let a = sender(&root, "original", now)?;
    let mut item = item(&a, &a, now)?;
    let mut inner = g::Inner::decode(item.exact_inner.as_slice())?;
    let mut edit = g::Edit::decode(inner.body.as_slice())?;
    edit.target.as_mut().ok_or("target")?.conversation_id = "another conversation".into();
    inner.body = edit.encode_to_vec();
    item.exact_inner = inner.encode_to_vec();
    item.source_evidence = Some(evidence(&a, &inner, now)?);
    assert!(matches!(
        RamfluxClient::new().verify_generated_edited_history_item(&item),
        Err(SdkError::HistoryEvidence(EvidenceError::EditTargetMismatch))
    ));
    Ok(())
}

#[test]
fn edited_item_refuses_invalid_identity_bounds_and_tags_without_edit() -> TestResult {
    let root = Root::new()?;
    let now = crate::custody::network_now()?;
    let a = sender(&root, "original", now)?;
    let valid = item(&a, &a, now)?;
    for case in 0..5 {
        let mut candidate = valid.clone();
        match case {
            0 => candidate.exact_original_identity.extend([0x80, 0x01, 0x01]),
            1 => {
                candidate.exact_original_identity.splice(1..2, [0xa0, 0x00]);
            }
            2 => {
                candidate.exact_original_identity =
                    vec![1; g::original_header::MAX_IDENTITY_BYTES + 1];
            }
            3 => {
                candidate
                    .original_metadata_evidence
                    .as_mut()
                    .ok_or("evidence")?
                    .canonical_sender_envelope = vec![1; g::original_header::MAX_OUTER_BYTES + 1];
            }
            4 => {
                candidate.exact_inner = inner(
                    &a,
                    1,
                    g::content::Value::Message(g::Message {
                        text: "not an Edit".into(),
                        ..Default::default()
                    }),
                )?
                .encode_to_vec();
            }
            _ => return Err("unexpected retained-evidence test case".into()),
        }
        assert!(
            matches!(
                RamfluxClient::new().verify_generated_edited_history_item(&candidate),
                Err(SdkError::HistoryEvidence(EvidenceError::OriginCommitmentMismatch))
            ),
            "invalid retained evidence case {case}"
        );
    }
    Ok(())
}

#[test]
fn edited_history_never_promotes_ephemeral_or_call_wake_evidence_to_message_mutations() -> TestResult
{
    let root = Root::new()?;
    let now = crate::custody::network_now()?;
    let a = sender(&root, "original", now)?;
    for (mode, class) in [("ephemeral", "message"), ("durable", "call_wake")] {
        let mut current = item(&a, &a, now)?;
        let edit = g::Inner::decode(current.exact_inner.as_slice())?;
        current.source_evidence = Some(evidence_with_policy(&a, &edit, now, mode, class)?);
        assert!(matches!(
            RamfluxClient::new().verify_generated_edited_history_item(&current),
            Err(SdkError::HistoryEvidence(EvidenceError::OriginCommitmentMismatch))
        ));
        let mut original = item(&a, &a, now)?;
        let message = inner(
            &a,
            1,
            g::content::Value::Message(g::Message { text: "retired".into(), ..Default::default() }),
        )?;
        let proof = evidence_with_policy(&a, &message, now, mode, class)?;
        let retained = original.original_metadata_evidence.as_mut().ok_or("original evidence")?;
        retained.canonical_sender_envelope = proof.canonical_sender_envelope;
        assert!(matches!(
            RamfluxClient::new().verify_generated_edited_history_item(&original),
            Err(SdkError::HistoryEvidence(EvidenceError::OriginCommitmentMismatch))
        ));
    }
    Ok(())
}

#[test]
fn retained_origin_uses_first_hand_native_proof_and_rejects_body_identity_and_route_forgery()
-> TestResult {
    use crate::client::raw_inner_origin::RetainedOrigin;
    use crate::client::routed::{Kind, Routing};
    let root = Root::new()?;
    let now = crate::custody::network_now()?;
    let a = sender(&root, "retained-origin", now)?;
    let original = inner(
        &a,
        1,
        g::content::Value::Message(g::Message { text: "original".into(), ..Default::default() }),
    )?;
    let id = original.identity.as_ref().ok_or("identity")?;
    let proof = RetainedOrigin {
        evidence: evidence(&a, &original, now)?,
        reported_inner: Vec::new(),
        routing: Routing {
            kind: Kind::Direct,
            conversation_id: id.conversation_id.clone(),
            message_id: ramflux_protocol::encode_base64url(&id.id),
            group_id: None,
            group_message_id: None,
            attachments: false,
        },
    };
    let raw = original.encode_to_vec();
    let verified = proof.verify(id, &raw)?;
    assert_eq!(verified.author.root, a.author.account_anchor);
    assert_eq!(verified.author.device.device_id(), a.author.device_id);
    assert_eq!(verified.outer.encrypted_payload, "");
    let outer: Value = ramflux_protocol::parse_i_json(&proof.evidence.canonical_sender_envelope)?;
    assert!(outer.get("encrypted_payload").is_none(), "evidence verifies without ciphertext");
    let changed = inner(
        &a,
        1,
        g::content::Value::Message(g::Message { text: "forged".into(), ..Default::default() }),
    )?;
    assert!(proof.verify(id, &changed.encode_to_vec()).is_err());
    let mut claimed = id.clone();
    claimed.device_sequence += 1;
    assert!(proof.verify(&claimed, &raw).is_err());
    let mut changed = proof.clone();
    changed.routing.conversation_id = "other".into();
    assert!(changed.verify(id, &raw).is_err());
    let mut changed = proof.clone();
    changed.evidence.report_opening[0] ^= 1;
    assert!(changed.verify(id, &raw).is_err());
    let mut changed = proof.clone();
    let mut outer = outer;
    outer["payload_hash"] = json!(ramflux_protocol::encode_base64url([99; 32]));
    changed.evidence.canonical_sender_envelope = ramflux_protocol::canonical_json_bytes(&outer)?;
    assert!(changed.verify(id, &raw).is_err());
    Ok(())
}

fn retain_upgrade_candidate(
    client: &RamfluxClient,
    sender: &Sender,
    candidate: &g::Inner,
    mode: &str,
    now: u64,
) -> TestResult<String> {
    use crate::client::{
        raw_inner_origin::RetainedOrigin,
        routed::{Kind, Routing},
    };
    let identity = candidate.identity.as_ref().ok_or("candidate identity")?;
    let id = ramflux_protocol::encode_base64url(&identity.id);
    let route = Routing {
        kind: Kind::Direct,
        conversation_id: identity.conversation_id.clone(),
        message_id: id.clone(),
        group_id: None,
        group_message_id: None,
        attachments: false,
    };
    let origin = RetainedOrigin {
        evidence: evidence_with_policy(sender, candidate, now, mode, "message")?,
        reported_inner: Vec::new(),
        routing: route.clone(),
    };
    let proof_id = origin.copy_id()?;
    let envelope = origin.verify(identity, &candidate.encode_to_vec())?.outer;
    let copy_id = format!("upgrade/{id}/{mode}");
    let provenance = crate::client::routed::generated_receive::Provenance {
        source: ramflux_protocol::qualified_device_id(
            &sender.author.account_anchor,
            &sender.author.device_id,
        )?,
        conversation: identity.conversation_id.clone(),
        message: id.clone(),
        envelope_id: envelope.envelope_id,
        payload_hash: envelope.payload_hash,
        expires_at: envelope.created_at + i64::from(envelope.ttl),
        original_mode: mode.into(),
        source_epoch: sender.author.device_epoch,
        original_route: serde_json::to_string(&route)?,
        outer_receipt_key: copy_id.clone(),
        source_evidence_copy: Some(proof_id.clone()),
        received_erasure_generation: client.account_db()?.privacy_erasure_generation()?,
    };
    let db = client.account_db()?;
    db.write_transaction(|| -> TestResult {
        client.retain_raw_origin_copy(
            &id,
            &sender.author.account_anchor,
            &proof_id,
            &origin,
            None,
        )?;
        db.put_unsupported_raw_copy(ramflux_storage::RawInnerCopyWrite {
            owner_id: &id,
            verified_source_anchor: &sender.author.account_anchor,
            copy_id: &copy_id,
            kind: ramflux_storage::RawInnerCopyKind::OuterInner,
            bytes: &candidate.encode_to_vec(),
            bounded_metadata: &serde_json::to_vec(&provenance)?,
        })?;
        db.import_direct_message_projection(ramflux_storage::DirectMessageWrite {
            conversation_id: &identity.conversation_id,
            message_id: &id,
            sender_id: "original",
            encrypted_body: &[],
            metadata: &ramflux_storage::MessageMetadata::default(),
            created_at: 1,
        })?;
        client.persist_generated_unsupported_view(
            &id,
            &copy_id,
            &g::validation::scan_inner(&candidate.encode_to_vec())?,
        )?;
        Ok(())
    })?;
    Ok(id)
}

#[test]
fn reparse_preserves_original_channel_and_authority() -> TestResult {
    let _guard = ramflux_protocol::schema_profile::SchemaV1LiveGuard::enter();
    for mode in ["ephemeral", "durable"] {
        let root = Root::new()?;
        let now = crate::custody::network_now()?;
        let author = sender(&root, "upgrade-author", now)?;
        let original = identity(&author, 1)?;
        let mut client = import_receiver(&root, &original)?;
        let db = client.account_db()?;
        db.persist_client_record(
            "conversation",
            "conversation",
            &json!({
                "kind":"direct", "group_id":null,
                "participant_roots":[client.own_account_anchor()?,author.author.account_anchor],
            }),
        )?;
        let target = g::MessageRef {
            id: original.id.clone(),
            conversation_id: original.conversation_id.clone(),
            author_anchor: author.author.account_anchor.clone(),
        };
        let delete_identity = identity(&author, 2)?;
        let deletion = inner(
            &author,
            2,
            g::content::Value::Delete(g::Delete {
                targets: vec![target.clone()],
                scope: g::DeleteScope::Everyone as i32,
                tombstone_id: g::identity::delete_tombstone(&delete_identity.id)?.to_vec(),
                ..Default::default()
            }),
        )?;
        let delete_id = retain_upgrade_candidate(&client, &author, &deletion, mode, now)?;
        let pin = inner(
            &author,
            3,
            g::content::Value::Service(g::Service {
                action: g::ServiceAction::ServicePinAdded as i32,
                target: Some(target),
                ..Default::default()
            }),
        )?;
        let pin_id = retain_upgrade_candidate(&client, &author, &pin, "durable", now)?;
        let before = db.journal_bounds()?.head_seq;
        client.active_account_db = None;
        client.unlock_account("receiver", b"history-import-test")?;
        let progress = client.reparse_raw_inner_page()?;
        let db = client.account_db()?;
        assert_eq!(progress.projected, usize::from(mode == "durable"));
        assert_eq!(
            db.message_is_deleted(&ramflux_protocol::encode_base64url(&original.id))?,
            mode == "durable",
            "original channel must gate Delete effects"
        );
        assert!(!db.actor_state_exists(&format!("routed/generated-identity/{pin_id}"))?);
        assert_eq!(db.actor_state_keys("self-sync/pin/")?, Vec::<String>::new());
        assert!(!db.actor_state_exists(&format!("routed/origin-evidence/{pin_id}"))?);
        if mode == "ephemeral" {
            assert_eq!(db.journal_bounds()?.head_seq, before);
            assert!(!db.actor_state_exists(&format!("routed/generated-identity/{delete_id}"))?);
        }
        assert_eq!(db.unsupported_raw_quota(None)?.owners, 0);
        assert_eq!(
            db.actor_state_keys("routed/raw-handle/")?,
            Vec::<String>::new(),
            "discarded content retained actionable raw handles"
        );
        assert_eq!(
            db.load_actor_state::<g::UnsupportedView>(&format!("routed/unsupported/{pin_id}"))?
                .ok_or("non-actionable diagnostic")?
                .raw_handle,
            Vec::<u8>::new()
        );
        assert_eq!(client.reparse_raw_inner_page()?.projected, 0);
    }
    Ok(())
}

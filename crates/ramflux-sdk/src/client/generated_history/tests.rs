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
    let manifest: CustodyManifest =
        ramflux_protocol::custody::decode(&sender.manifest.canonical, 5 * 1024 * 1024)?;
    let mut outer: Value = serde_json::from_str(include_str!(
        "../../../../ramflux-protocol/src/sender_transcript_vectors.json"
    ))?;
    outer = outer["envelope"].take();
    outer["created_at"] = json!(now);
    outer["source_principal_id"] = json!(manifest.publication.record.body.principal_id);
    outer["source_device_id"] = json!(sender.author.device_id);
    outer["ext"] = json!({"source_root_commitment":sender.author.account_anchor});
    if let Some(commitment) = g::original_header::for_inner(&inner.encode_to_vec(), now, now + 300)?
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
    item_with_message(original, edit_author, now, g::Message { text: "retired".into(), ..Default::default() })
}
fn item_with_message(original: &Sender, edit_author: &Sender, now: u64, message: g::Message) -> TestResult<g::HistoryItem> {
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
    import_receiver_with_message(root, original, &g::Message { text:"current local state".into(), ..Default::default() })
}
fn import_receiver_with_message(root: &Root, original: &g::EventIdentity, message: &g::Message) -> TestResult<RamfluxClient> {
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
    assert!(matches!(client.selected_generated_report_evidence(&identity(&a,8)?.id), Err(SdkError::HistoryEvidence(EvidenceError::ReportOpeningRetired))));
    Ok(())
}

#[path = "scan_tests.rs"]
mod scans;

#[test]
fn edited_import_refuses_swapped_identity() -> TestResult {
    let root=Root::new()?; let now=crate::custody::network_now()?; let a=sender(&root,"original",now)?;
    let mut item=item(&a,&a,now)?; item.exact_original_identity=identity(&a,8)?.encode_to_vec();
    assert!(matches!(RamfluxClient::new().verify_generated_edited_history_item(&item),Err(SdkError::HistoryEvidence(EvidenceError::OriginCommitmentMismatch))));
    Ok(())
}

#[test]
fn edited_import_refuses_cross_conversation_replay() -> TestResult {
    let root=Root::new()?; let now=crate::custody::network_now()?; let a=sender(&root,"original",now)?;
    let mut item=item(&a,&a,now)?; let mut inner=g::Inner::decode(item.exact_inner.as_slice())?;
    let mut edit=g::Edit::decode(inner.body.as_slice())?; edit.target.as_mut().ok_or("target")?.conversation_id="another conversation".into();
    inner.body=edit.encode_to_vec(); item.exact_inner=inner.encode_to_vec(); item.source_evidence=Some(evidence(&a,&inner,now)?);
    assert!(matches!(RamfluxClient::new().verify_generated_edited_history_item(&item),Err(SdkError::HistoryEvidence(EvidenceError::EditTargetMismatch))));
    Ok(())
}

#[test]
fn edited_item_refuses_invalid_identity_bounds_and_tags_without_edit() -> TestResult {
    let root=Root::new()?; let now=crate::custody::network_now()?; let a=sender(&root,"original",now)?;
    let valid=item(&a,&a,now)?;
    for case in 0..5 {
        let mut candidate=valid.clone();
        match case {
            0 => candidate.exact_original_identity.extend([0x80,0x01,0x01]),
            1 => { candidate.exact_original_identity.splice(1..2,[0xa0,0x00]); }
            2 => candidate.exact_original_identity=vec![1;g::original_header::MAX_IDENTITY_BYTES+1],
            3 => candidate.original_metadata_evidence.as_mut().ok_or("evidence")?.canonical_sender_envelope=vec![1;g::original_header::MAX_OUTER_BYTES+1],
            4 => candidate.exact_inner=inner(&a,1,g::content::Value::Message(g::Message { text:"not an Edit".into(),..Default::default() }))?.encode_to_vec(),
            _ => unreachable!(),
        }
        assert!(matches!(RamfluxClient::new().verify_generated_edited_history_item(&candidate),Err(SdkError::HistoryEvidence(EvidenceError::OriginCommitmentMismatch))),"invalid retained evidence case {case}");
    }
    Ok(())
}

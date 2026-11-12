// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Own-root attestations retain original identities and never become peer origin proofs.
use super::{
    DirectMessageWrite, GatewayInboxEntry, MessageMetadata, OwnSentInput, RamfluxClient, SdkError,
    SentMessage, g, invalid, now_unix_timestamp,
};
use crate::client::identity_authority::{HeadUse, NativeOperation};
use prost::Message as _;

fn own_sent_erasure_owners(
    identity: &g::EventIdentity,
    content: &g::Content,
) -> Result<Vec<String>, SdkError> {
    let ids = match content.value.as_ref() {
        Some(g::content::Value::Message(_)) => vec![identity.id.clone()],
        Some(g::content::Value::Edit(edit)) => {
            edit.target.iter().map(|target| target.id.clone()).collect()
        }
        Some(g::content::Value::Reaction(reaction)) => {
            reaction.target.iter().map(|target| target.id.clone()).collect()
        }
        Some(g::content::Value::Delete(delete)) => {
            delete.targets.iter().map(|target| target.id.clone()).collect()
        }
        _ => return Err(invalid("own sent content is not a permitted plaintext event")),
    };
    Ok(ids.into_iter().map(ramflux_protocol::encode_base64url).collect())
}

impl RamfluxClient {
    pub(crate) fn authorize_generated_own_sent(
        &self,
        source: &ramflux_crypto::RootQualifiedDeviceRef,
        conversation: &str,
        sent: &g::OwnSentMessage,
    ) -> Result<g::EventIdentity, SdkError> {
        if source.root_commitment() != self.own_account_anchor()? {
            return Err(invalid("own sent requires same-root attestation"));
        }
        self.require_native_operation(source, NativeOperation::Sync)?;
        self.require_native_operation(&self.owned_device_identity()?, NativeOperation::Sync)?;
        let packet = SentMessage::from_generated(sent)?;
        let group = packet.context.group.as_ref().map(|group| group.group_id.as_str());
        packet.validate_route(&sent.envelope_id, conversation, group)?;
        self.validate_own_context_namespace(&packet.context)?;
        let scanned = g::validation::scan_inner(&sent.exact_inner)
            .map_err(|_| invalid("own sent Inner malformed"))?;
        let inner = g::Inner::decode(sent.exact_inner.as_slice())
            .map_err(|_| invalid("own sent Inner missing"))?;
        let identity = inner.identity.ok_or_else(|| invalid("own sent identity missing"))?;
        g::identity::verify(&identity).map_err(|_| invalid("own sent event id mismatch"))?;
        let author = identity.author.as_ref().ok_or_else(|| invalid("own sent author missing"))?;
        if author.account_anchor != source.root_commitment()
            || identity.device_sequence & (1 << 63) != 0
            || identity.conversation_id != conversation
            || identity.group_id.as_deref() != group
            || ramflux_protocol::encode_base64url(&identity.id) != sent.message_id
            || !matches!(scanned.kind, 1 | 3 | 4 | 5)
        {
            return Err(invalid("own sent original identity or kind mismatch"));
        }
        let original = self.device_identity_for_root(&author.account_anchor, &author.device_id)?;
        let record = self
            .account_db()?
            .client_device_record(&original)?
            .ok_or_else(|| invalid("own sent original device authority missing"))?;
        if record["device_epoch"].as_u64() != Some(author.device_epoch) {
            return Err(invalid("own sent original epoch mismatch"));
        }
        self.trusted_device(HeadUse::NewAuthorization, &original)?;
        if let Some(group) = group {
            self.require_generated_group_epoch(
                group,
                &original,
                identity.group_epoch.ok_or_else(|| invalid("own sent group epoch missing"))?,
                false,
            )?;
            let local = self.owned_device_identity()?;
            self.require_generated_group_epoch(
                group,
                &local,
                identity.group_epoch.unwrap_or(0),
                false,
            )?;
            let state = self
                .account_db()?
                .shared_group_state(group)?
                .ok_or_else(|| SdkError::InboundPending("own sent group state missing".into()))?;
            if state.snapshot().genesis.conversation_id != conversation {
                return Err(invalid("own sent group conversation mismatch"));
            }
        }
        if scanned.kind == 4 {
            let delete = g::Delete::decode(scanned.body)
                .map_err(|_| invalid("own sent Delete malformed"))?;
            if delete.scope != g::DeleteScope::Everyone as i32 {
                return Err(invalid("own sent only permits EVERYONE Delete"));
            }
        }
        Ok(identity)
    }

    pub(crate) fn receive_generated_own_sent(
        &self,
        entry: &GatewayInboxEntry,
        source: &ramflux_crypto::RootQualifiedDeviceRef,
        copy_created_at: i64,
        sent: &g::OwnSentMessage,
    ) -> Result<bool, SdkError> {
        let packet = SentMessage::from_generated(sent)?;
        let conversation = &packet.context.conversation_id;
        let identity = self.authorize_generated_own_sent(source, conversation, sent)?;
        let scanned = g::validation::scan_inner(&sent.exact_inner)
            .map_err(|_| invalid("own sent Inner malformed"))?;
        // Check the content-free fence after source/original authorization, before an
        // unsupported old Message can be parked with its erased body and nonce.
        if scanned.kind == 1
            && self
                .account_db()?
                .load_actor_state::<bool>(&format!(
                    "routed/report-opening-retired/{}",
                    sent.message_id
                ))?
                .unwrap_or(false)
        {
            return Ok(true);
        }
        if scanned.outcome != g::validation::ScanOutcome::Supported {
            return Err(SdkError::InboundPending(
                "own sent unsupported attestation retention pending".into(),
            ));
        }
        let (_, content) = Self::decode_generated_inner(&sent.exact_inner)?;
        let original =
            identity.author.as_ref().ok_or_else(|| invalid("own sent author missing"))?;
        let original =
            self.device_identity_for_root(&original.account_anchor, &original.device_id)?;
        self.account_db()?.write_transaction(|| {
            self.bind_generated_own_sent_context(&packet, &identity)?;
            let owners = own_sent_erasure_owners(&identity, &content)?;
            let Some(replay) =
                self.own_sent_logical_replay(&original, &identity, &sent.exact_inner, owners)?
            else {
                return Ok(true);
            };
            match content.value.as_ref() {
                Some(g::content::Value::Message(message)) if message.sealed_group.is_none() => {
                    self.project_generated_own_sent_message(
                        &original,
                        &identity,
                        sent,
                        &packet,
                        copy_created_at,
                    )?;
                }
                Some(g::content::Value::Edit(_)) => {
                    self.apply_generated_edit_authorized(
                        crate::client::message_mutations::EditContext {
                            entry,
                            source: &original,
                            imported: None,
                            own_sent: true,
                        },
                        conversation,
                        &sent.exact_inner,
                        None,
                    )?;
                }
                Some(g::content::Value::Delete(delete)) => {
                    self.apply_generated_delete_authorized(
                        &original,
                        &identity,
                        conversation,
                        delete,
                    )?;
                }
                Some(g::content::Value::Reaction(reaction)) => {
                    self.apply_generated_reaction_authorized(
                        &original,
                        &identity,
                        conversation,
                        reaction,
                    )?;
                }
                _ => return Err(invalid("own sent content is not a permitted plaintext event")),
            }
            self.commit_own_sent_logical_replay(&replay)?;
            Ok(true)
        })
    }

    fn bind_generated_own_sent_context(
        &self,
        packet: &SentMessage,
        identity: &g::EventIdentity,
    ) -> Result<(), SdkError> {
        let db = self.account_db()?;
        let thread = db.client_record("conversation", &identity.conversation_id)?;
        if let Some(group) = identity.group_id.as_deref() {
            // Named native GROUP_STATE owns authority. A copied cosmetic snapshot never
            // installs membership, routes, joined floors or roles.
            if thread.as_ref().is_some_and(|thread| {
                thread["kind"] != "group" || thread["group_id"].as_str() != Some(group)
            }) {
                return Err(invalid("own sent conflicts with bound group scope"));
            }
            self.merge_routed_group_link(group, &identity.conversation_id)?;
        } else {
            let thread = thread.ok_or_else(|| {
                SdkError::InboundPending(
                    "own sent direct context awaits native contact bootstrap".into(),
                )
            })?;
            let participants = packet
                .context
                .participants
                .iter()
                .map(String::as_str)
                .collect::<std::collections::BTreeSet<_>>();
            let bound = thread["participants"].as_array().map(|values| {
                values
                    .iter()
                    .filter_map(serde_json::Value::as_str)
                    .collect::<std::collections::BTreeSet<_>>()
            });
            if thread["kind"] != "direct"
                || !thread["group_id"].is_null()
                || packet.context.participants.len() != 2
                || participants.len() != 2
                || bound.as_ref() != Some(&participants)
            {
                return Err(invalid("own sent conflicts with bound direct participants"));
            }
        }
        Ok(())
    }

    fn project_generated_own_sent_message(
        &self,
        source: &ramflux_crypto::RootQualifiedDeviceRef,
        identity: &g::EventIdentity,
        sent: &g::OwnSentMessage,
        packet: &SentMessage,
        copy_created_at: i64,
    ) -> Result<(), SdkError> {
        let db = self.account_db()?;
        let id = ramflux_protocol::encode_base64url(&identity.id);
        if db.message_is_deleted(&id)? || self.apply_generated_delete_fence(identity)? {
            return Ok(());
        }
        if db
            .load_actor_state::<bool>(&format!("routed/report-opening-retired/{id}"))?
            .unwrap_or(false)
        {
            return Ok(());
        }
        if let Some(stored) = db.message_content(&id)? {
            if stored != sent.exact_inner {
                return Err(SdkError::ReplayMismatch);
            }
            return Ok(());
        }
        // Suppression is safe only once the identical original effect is durably present.
        if packet
            .original_recipients
            .contains(&self.owned_device_identity()?.device_id().to_owned())
        {
            return Err(SdkError::InboundPending(format!("message_target:{id}")));
        }
        db.import_direct_message_projection(DirectMessageWrite {
            conversation_id: &identity.conversation_id,
            message_id: &id,
            sender_id: source.device_id(),
            encrypted_body: &[],
            metadata: &MessageMetadata::default(),
            created_at: packet.authored_at.unwrap_or(copy_created_at),
        })?;
        db.replace_generated_message_content(
            &identity.conversation_id,
            &id,
            &sent.exact_inner,
            &MessageMetadata::default(),
        )?;
        db.persist_message_actor_state(&id, &format!("routed/generated-identity/{id}"), identity)?;
        db.persist_message_actor_state(
            &id,
            &format!("routed/generated-order/{id}"),
            &identity.hlc,
        )?;
        db.persist_message_actor_state(
            &id,
            &format!("routed/generated-display-hlc/{id}"),
            &crate::client::generated_identity::order_hlc(
                identity.hlc,
                crate::client::generated_identity::now_ms(),
            ),
        )?;
        self.record_own_sent_projection(
            source,
            OwnSentInput {
                envelope: &packet.envelope_id,
                conversation: &identity.conversation_id,
                message: &id,
                sender: &packet.sender_id,
                original_recipients: &packet.original_recipients,
                group: identity.group_id.as_deref(),
                peer: None,
                body: &sent.exact_inner,
                ciphertext: &[],
                at: packet.authored_at.unwrap_or(copy_created_at),
            },
            &id,
            packet.ciphertext_hash.as_deref(),
        )?;
        self.resolve_generated_pending_edit(&identity.conversation_id, &id)?;
        let row = self
            .direct_message_by_id(&id)?
            .ok_or_else(|| invalid("own sent projection missing"))?;
        let update = self.generated_message_update(&row, &identity.conversation_id, 0)?;
        db.append_message_update(
            &format!("own-sent/{id}"),
            "message.received",
            &update,
            now_unix_timestamp(),
        )?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::native_test_support::{Fixture, TestResult};
    use serde_json::json;

    async fn fixture() -> TestResult<(Fixture, g::OwnSentMessage)> {
        let own = Fixture::new("generated-own-sent").await?;
        let peer = Fixture::new("generated-own-sent-peer").await?;
        let own_root = own.client.own_account_anchor()?;
        let peer_root = peer.client.own_account_anchor()?;
        let conversation = g::dm_scope::derive(&own_root, &peer_root)?;
        let participants =
            vec![own.manifest.principal_id.clone(), peer.manifest.principal_id.clone()];
        own.client.account_db()?.persist_client_record("conversation", &conversation, &json!({
            "kind":"direct", "group_id":null, "participants":participants, "participant_roots":[own_root,peer_root],
        }))?;
        let identity = own.client.allocate_generated_identity(&conversation, 1000, false)?;
        let exact_inner = RamfluxClient::encode_generated_inner(
            identity.clone(),
            &g::Content {
                value: Some(g::content::Value::Message(g::Message {
                    text: "private sent body".into(),
                    ..Default::default()
                })),
            },
        )?;
        let sent = g::OwnSentMessage {
            envelope_id: "original-envelope".into(),
            message_id: ramflux_protocol::encode_base64url(identity.id),
            sender_id: "authored label".into(),
            original_recipients: Vec::new(),
            ciphertext_digest: None,
            authored_at: Some(0),
            exact_inner,
            context: Some(g::OwnContext {
                conversation_id: conversation,
                participants,
                ..Default::default()
            }),
        };
        Ok((own, sent))
    }

    fn entry() -> TestResult<GatewayInboxEntry> {
        let vectors: serde_json::Value = serde_json::from_str(include_str!(
            "../../../../ramflux-protocol/src/sender_transcript_vectors.json"
        ))?;
        Ok(GatewayInboxEntry {
            envelope: serde_json::from_value(vectors["envelope"].clone())?,
            forwarded: false,
            inbox_seq: 1,
            target_delivery_id: "unused-by-message-executor".into(),
        })
    }

    #[tokio::test]
    async fn native_own_sent_uses_original_id_and_never_fabricates_peer_evidence() -> TestResult {
        let (own, sent) = fixture().await?;
        let source = own.client.owned_device_identity()?;
        assert!(own.client.receive_generated_own_sent(&entry()?, &source, 42, &sent)?);
        let row =
            own.client.direct_message_by_id(&sent.message_id)?.ok_or("canonical original row")?;
        assert_eq!(row.created_at, 0, "authored_at presence must preserve zero");
        assert_eq!(own.client.direct_messages(&row.conversation_id)?.len(), 1);
        assert_eq!(
            own.client.account_db()?.message_content(&sent.message_id)?,
            Some(sent.exact_inner.clone())
        );
        assert!(
            own.client
                .export_generated_history_item(&ramflux_protocol::decode_base64url(
                    &sent.message_id
                )?)
                .is_err(),
            "own-root attestation is not original peer evidence"
        );
        assert!(own.client.receive_generated_own_sent(&entry()?, &source, 42, &sent)?);
        let mut changed = sent.clone();
        let mut inner = g::Inner::decode(changed.exact_inner.as_slice())?;
        let mut body = g::Message::decode(inner.body.as_slice())?;
        body.text = "changed same event".into();
        inner.body = body.encode_to_vec();
        changed.exact_inner = inner.encode_to_vec();
        assert!(matches!(
            own.client.receive_generated_own_sent(&entry()?, &source, 42, &changed),
            Err(SdkError::ReplayMismatch)
        ));
        own.client.account_db()?.delete_direct_message(
            &row.conversation_id,
            &sent.message_id,
            "self",
            "erase-own-sent",
        )?;
        assert!(own.client.receive_generated_own_sent(&entry()?, &source, 42, &sent)?);
        assert!(own.client.account_db()?.message_content(&sent.message_id)?.is_none());
        Ok(())
    }

    #[tokio::test]
    async fn native_own_sent_checks_original_epoch_kind_and_original_recipient_effect() -> TestResult
    {
        let (own, sent) = fixture().await?;
        let source = own.client.owned_device_identity()?;
        let conversation = &sent.context.as_ref().ok_or("context")?.conversation_id;
        let mut invalid = sent.clone();
        let mut inner = g::Inner::decode(invalid.exact_inner.as_slice())?;
        let identity = inner.identity.as_mut().ok_or("identity")?;
        let author = identity.author.as_mut().ok_or("author")?;
        author.device_epoch += 1;
        identity.id = g::identity::derive(author, conversation, identity.device_sequence)?.to_vec();
        invalid.message_id = ramflux_protocol::encode_base64url(&identity.id);
        invalid.exact_inner = inner.encode_to_vec();
        assert!(own.client.authorize_generated_own_sent(&source, conversation, &invalid).is_err());
        let mut invalid = sent.clone();
        let mut inner = g::Inner::decode(invalid.exact_inner.as_slice())?;
        inner.kind = 6;
        inner.body = g::Receipt::default().encode_to_vec();
        invalid.exact_inner = inner.encode_to_vec();
        assert!(own.client.authorize_generated_own_sent(&source, conversation, &invalid).is_err());
        let mut suppressed = sent.clone();
        suppressed.original_recipients.push(source.device_id().into());
        assert!(matches!(
            own.client.receive_generated_own_sent(&entry()?, &source, 42, &suppressed),
            Err(SdkError::InboundPending(_))
        ));
        assert!(own.client.account_db()?.message_content(&sent.message_id)?.is_none());
        assert!(own.client.receive_generated_own_sent(&entry()?, &source, 42, &sent)?);
        assert!(own.client.receive_generated_own_sent(&entry()?, &source, 42, &suppressed)?);
        Ok(())
    }
    #[tokio::test]
    async fn native_own_sent_context_never_grants_friend_authority() -> TestResult {
        let (own, mut sent) = fixture().await?;
        let own_root = own.client.own_account_anchor()?;
        let context = sent.context.as_mut().ok_or("context")?;
        let thread = own
            .client
            .account_db()?
            .client_record("conversation", &context.conversation_id)?
            .ok_or("thread")?;
        let peer = thread["participant_roots"]
            .as_array()
            .ok_or("roots")?
            .iter()
            .filter_map(serde_json::Value::as_str)
            .find(|root| *root != own_root)
            .ok_or("peer root")?;
        context.friend = Some(g::FriendLinkRecord {
            link_id: "not-a-contact-grant".into(),
            requester_id: own_root,
            target_id: peer.into(),
            state: "accepted".into(),
            ..Default::default()
        });
        assert!(own.client.account_db()?.find_friend_link("not-a-contact-grant")?.is_none());
        assert!(own.client.receive_generated_own_sent(
            &entry()?,
            &own.client.owned_device_identity()?,
            42,
            &sent
        )?);
        assert!(
            own.client.account_db()?.find_friend_link("not-a-contact-grant")?.is_none(),
            "copied context is not native CONTACT authorization"
        );
        Ok(())
    }
    #[tokio::test]
    async fn native_own_sent_absent_authored_time_uses_signed_copy_time() -> TestResult {
        let (own, mut sent) = fixture().await?;
        sent.authored_at = None;
        assert!(own.client.receive_generated_own_sent(
            &entry()?,
            &own.client.owned_device_identity()?,
            42,
            &sent
        )?);
        assert_eq!(own.client.direct_message_by_id(&sent.message_id)?.ok_or("row")?.created_at, 42);
        Ok(())
    }

    #[tokio::test]
    async fn own_sent_retired_unsupported_original_is_settled_without_retention() -> TestResult {
        let (own, mut sent) = fixture().await?;
        let source = own.client.owned_device_identity()?;
        own.client.receive_generated_own_sent(&entry()?, &source, 42, &sent)?;
        let conversation = sent.context.as_ref().ok_or("context")?.conversation_id.clone();
        let target = g::MessageRef {
            id: ramflux_protocol::decode_base64url(&sent.message_id)?,
            conversation_id: conversation.clone(),
            author_anchor: source.root_commitment().into(),
        };
        let digest =
            crate::client::message_mutations::previous_content_digest(&target, &sent.exact_inner)?;
        let identity = own.client.allocate_generated_identity(&conversation, 1001, false)?;
        let mut edit = sent.clone();
        edit.message_id = ramflux_protocol::encode_base64url(&identity.id);
        edit.exact_inner = RamfluxClient::encode_generated_inner(
            identity,
            &g::Content {
                value: Some(g::content::Value::Edit(g::Edit {
                    target: Some(target),
                    revision: 1,
                    previous_content_digest: digest.to_vec(),
                    replacement: Some(g::Message {
                        text: "current replacement".into(),
                        ..Default::default()
                    }),
                })),
            },
        )?;
        own.client.receive_generated_own_sent(&entry()?, &source, 43, &edit)?;
        let db = own.client.account_db()?;
        let current = db.message_content(&sent.message_id)?.ok_or("replacement")?;
        assert!(
            db.load_actor_state::<bool>(&format!(
                "routed/report-opening-retired/{}",
                sent.message_id
            ))?
            .unwrap_or(false)
        );
        let mut inner = g::Inner::decode(sent.exact_inner.as_slice())?;
        inner.body.extend_from_slice(&[0xf8, 0x07, 1]);
        sent.exact_inner = inner.encode_to_vec();
        assert_ne!(
            g::validation::scan_inner(&sent.exact_inner)?.outcome,
            g::validation::ScanOutcome::Supported
        );
        assert!(
            own.client.receive_generated_own_sent(&entry()?, &source, 44, &sent)?,
            "an authorized retired original must settle before unsupported retention"
        );
        assert_eq!(db.message_content(&sent.message_id)?, Some(current));
        assert_eq!(db.unsupported_raw_quota(None)?.owners, 0);
        let mut forged = sent.clone();
        let mut inner = g::Inner::decode(forged.exact_inner.as_slice())?;
        let identity = inner.identity.as_mut().ok_or("identity")?;
        identity.author.as_mut().ok_or("author")?.device_epoch += 1;
        identity.id = g::identity::derive(
            identity.author.as_ref().ok_or("author")?,
            &conversation,
            identity.device_sequence,
        )?
        .to_vec();
        forged.message_id = ramflux_protocol::encode_base64url(&identity.id);
        forged.exact_inner = inner.encode_to_vec();
        assert!(
            own.client.receive_generated_own_sent(&entry()?, &source, 45, &forged).is_err(),
            "retirement never bypasses original device authority"
        );
        Ok(())
    }

    #[tokio::test]
    async fn own_sent_erased_event_cannot_retarget_another_message() -> TestResult {
        let (own, first) = fixture().await?;
        let source = own.client.owned_device_identity()?;
        let conversation = &first.context.as_ref().ok_or("context")?.conversation_id;
        own.client.receive_generated_own_sent(&entry()?, &source, 42, &first)?;
        let mut second = first.clone();
        let identity = own.client.allocate_generated_identity(conversation, 1001, false)?;
        second.message_id = ramflux_protocol::encode_base64url(&identity.id);
        second.exact_inner = RamfluxClient::encode_generated_inner(
            identity,
            &g::Content {
                value: Some(g::content::Value::Message(g::Message {
                    text: "surviving target".into(),
                    ..Default::default()
                })),
            },
        )?;
        own.client.receive_generated_own_sent(&entry()?, &source, 42, &second)?;
        let mut edited = first.clone();
        let identity = own.client.allocate_generated_identity(conversation, 1002, false)?;
        edited.message_id = ramflux_protocol::encode_base64url(&identity.id);
        edited.exact_inner = RamfluxClient::encode_generated_inner(
            identity,
            &g::Content {
                value: Some(g::content::Value::Edit(g::Edit {
                    target: Some(g::MessageRef {
                        id: ramflux_protocol::decode_base64url(&first.message_id)?,
                        conversation_id: conversation.clone(),
                        author_anchor: source.root_commitment().into(),
                    }),
                    revision: 1,
                    previous_content_digest: vec![1; 32],
                    replacement: Some(g::Message {
                        text: "erased replacement".into(),
                        ..Default::default()
                    }),
                })),
            },
        )?;
        own.client.receive_generated_own_sent(&entry()?, &source, 42, &edited)?;
        let db = own.client.account_db()?;
        db.delete_direct_message(conversation, &first.message_id, "self", "erase-own-edit")?;
        let mut inner = g::Inner::decode(edited.exact_inner.as_slice())?;
        let mut edit = g::Edit::decode(inner.body.as_slice())?;
        edit.target.as_mut().ok_or("target")?.id =
            ramflux_protocol::decode_base64url(&second.message_id)?;
        inner.body = edit.encode_to_vec();
        edited.exact_inner = inner.encode_to_vec();
        assert!(own.client.receive_generated_own_sent(&entry()?, &source, 42, &edited)?);
        assert_eq!(db.message_content(&second.message_id)?, Some(second.exact_inner));
        assert!(db.message_content(&first.message_id)?.is_none());
        assert_eq!(db.actor_state_usage("own-device/sent-event/")?.0, 3);
        assert_eq!(
            db.actor_state_usage("own-device/sent-event-body/")?.0,
            1,
            "only the surviving target may retain a plaintext fingerprint"
        );
        Ok(())
    }
}

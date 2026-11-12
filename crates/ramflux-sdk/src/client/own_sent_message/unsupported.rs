// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Opaque own-root Message attestations have their own private reparse authority.
use super::attestation::OwnSentAttestation;
use super::{OwnSentInput, RamfluxClient, SdkError, SentMessage, g, invalid};
use crate::client::identity_authority::HeadUse;
use ramflux_storage::{DirectMessageWrite, MessageMetadata, RawInnerReparseRow};

impl RamfluxClient {
    pub(super) fn commit_unsupported_own_message(
        &self,
        packet: &SentMessage,
        identity: &g::EventIdentity,
        sent: &g::OwnSentMessage,
    ) -> Result<bool, SdkError> {
        self.account_db()?.write_transaction(|| {
            let author =
                identity.author.as_ref().ok_or_else(|| invalid("own Message author missing"))?;
            let source =
                self.device_identity_for_root(&author.account_anchor, &author.device_id)?;
            let Some(replay) = self.own_sent_logical_replay(
                &source,
                identity,
                &sent.exact_inner,
                vec![sent.message_id.clone()],
            )?
            else {
                return Ok(true);
            };
            self.bind_generated_own_sent_context(packet, identity)?;
            self.commit_own_sent_logical_replay(&replay)?;
            Ok(true)
        })
    }

    pub(super) fn retain_unsupported_own_sent_view(
        &self,
        owner: &str,
        identity: &g::EventIdentity,
        sent: &g::OwnSentMessage,
        proof: &OwnSentAttestation,
    ) -> Result<(), SdkError> {
        let db = self.account_db()?;
        let key = format!(
            "routed/own-sent-attestation/{owner}/{}",
            ramflux_protocol::encode_base64url(&identity.id)
        );
        if db.raw_inner_copy(&key)?.is_none() || db.message_content(owner)?.is_some() {
            return Ok(());
        }
        let packet = SentMessage::from_generated(sent)?;
        let copy = proof.enclosing_copy()?;
        let author =
            identity.author.as_ref().ok_or_else(|| invalid("own Message author missing"))?;
        let original = self.device_identity_for_root(&author.account_anchor, &author.device_id)?;
        self.bind_generated_own_sent_context(&packet, identity)?;
        let scanned = g::validation::scan_inner(&sent.exact_inner)
            .map_err(|_| invalid("own Message malformed"))?;
        let inner_key = format!("{key}/inner");
        db.put_unsupported_raw_copy(ramflux_storage::RawInnerCopyWrite {
            owner_id: owner,
            verified_source_anchor: &self.own_account_anchor()?,
            copy_id: &inner_key,
            kind: ramflux_storage::RawInnerCopyKind::OuterInner,
            bytes: &sent.exact_inner,
            bounded_metadata: &[],
        })?;
        self.persist_generated_unsupported_view(owner, &inner_key, &scanned)?;
        db.import_direct_message_projection(DirectMessageWrite {
            conversation_id: &identity.conversation_id,
            message_id: owner,
            sender_id: original.device_id(),
            encrypted_body: &[],
            metadata: &MessageMetadata::default(),
            created_at: packet.authored_at.unwrap_or(copy.created_at),
        })?;
        db.persist_message_actor_state(
            owner,
            &format!("routed/generated-identity/{owner}"),
            identity,
        )?;
        self.record_own_sent_projection(
            &original,
            OwnSentInput {
                envelope: &packet.envelope_id,
                conversation: &identity.conversation_id,
                message: owner,
                sender: &packet.sender_id,
                original_recipients: &packet.original_recipients,
                group: identity.group_id.as_deref(),
                peer: None,
                body: &sent.exact_inner,
                ciphertext: &[],
                at: packet.authored_at.unwrap_or(copy.created_at),
            },
            owner,
            packet.ciphertext_hash.as_deref(),
        )?;
        Ok(())
    }

    pub(crate) fn reparse_own_sent_attestation(
        &self,
        row: &RawInnerReparseRow,
    ) -> Result<bool, SdkError> {
        let proof: OwnSentAttestation = serde_json::from_slice(&row.copy.bytes)?;
        let copy = proof.enclosing_copy()?;
        let Some(g::own_message_copy::Payload::Sent(sent)) = copy.payload.as_ref() else {
            return Err(invalid("own attestation has no sent Message"));
        };
        let sent = proof.verify(&sent.exact_inner, &self.own_account_anchor()?)?;
        let scanned = g::validation::scan_inner(&sent.exact_inner)
            .map_err(|_| invalid("own reparse malformed"))?;
        if scanned.kind != 1 || scanned.outcome != g::validation::ScanOutcome::Supported {
            return Ok(false);
        }
        let source = copy.source.as_ref().ok_or_else(|| invalid("own reparse source missing"))?;
        let source = self.device_identity_for_root(&source.account_anchor, &source.device_id)?;
        let identity = self.authorize_generated_own_sent(
            &source,
            &sent
                .context
                .as_ref()
                .ok_or_else(|| invalid("own reparse context missing"))?
                .conversation_id,
            &sent,
        )?;
        let owner = ramflux_protocol::encode_base64url(&identity.id);
        if row.copy.owner_id != owner
            || row.source_anchor != self.own_account_anchor()?
            || row.copy.copy_id != format!("routed/own-sent-attestation/{owner}/{owner}")
        {
            return Err(invalid("own reparse evidence owner mismatch"));
        }
        self.require_cached_root_authority(HeadUse::NewAuthorization, &source)?;
        let db = self.account_db()?;
        if db.message_is_deleted(&owner)?
            || db
                .load_actor_state::<bool>(&format!("routed/report-opening-retired/{owner}"))?
                .unwrap_or(false)
            || db.message_content(&owner)?.is_some()
        {
            return Ok(false);
        }
        let packet = SentMessage::from_generated(&sent)?;
        let author =
            identity.author.as_ref().ok_or_else(|| invalid("own reparse author missing"))?;
        let original = self.device_identity_for_root(&author.account_anchor, &author.device_id)?;
        db.write_transaction(|| {
            self.bind_generated_own_sent_context(&packet, &identity)?;
            self.project_generated_own_sent_message(
                &original,
                &identity,
                &sent,
                &packet,
                super::generated::MessageProjection::Reparse(copy.created_at),
            )?;
            self.remove_generated_unsupported_view(&owner)?;
            db.finish_raw_inner_reparse(&format!("{}/inner", row.copy.copy_id))?;
            Ok(true)
        })
    }
}

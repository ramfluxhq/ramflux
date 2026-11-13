// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Verify immutable original headers before admitting any incoming dependent revision.
use super::backup_database::BackupDatabase;
use crate::StorageError;
use ramflux_protocol::message::{self as g, original_header as h};
use rusqlite::params;
use serde::Deserialize;
use std::collections::BTreeMap;

const PREFIX: &str = "routed/original-header/";

#[derive(Deserialize)]
struct Original {
    exact_identity: Vec<u8>,
    evidence: g::HistoryOriginalMetadataEvidence,
}

fn mismatch<T>() -> Result<T, h::EvidenceError> {
    Err(h::EvidenceError::OriginCommitmentMismatch)
}

/// Signatures, historical native authority, group membership and the original-header
/// commitment all precede comparison. Recipient-specific envelope bytes are excluded.
fn verified_preimage(target: &str, bytes: &[u8]) -> Result<Vec<u8>, h::EvidenceError> {
    let bad = h::EvidenceError::OriginCommitmentMismatch;
    let original: Original = ramflux_protocol::parse_i_json(bytes).map_err(|_| bad)?;
    let identity = h::decode_identity(&original.exact_identity)?;
    if ramflux_protocol::encode_base64url(&identity.id) != target {
        return mismatch();
    }
    let evidence = original.evidence;
    if evidence.canonical_sender_envelope.len() > h::MAX_OUTER_BYTES {
        return mismatch();
    }
    let outer: serde_json::Value =
        ramflux_protocol::parse_i_json(&evidence.canonical_sender_envelope).map_err(|_| bad)?;
    if ramflux_protocol::canonical_json_bytes(&outer).map_err(|_| bad)?
        != evidence.canonical_sender_envelope
        || outer["delivery_mode"] != "durable"
        || outer["delivery_class"] != "message"
    {
        return mismatch();
    }
    let issued = outer["created_at"].as_u64().ok_or(bad)?;
    let expires = issued.checked_add(outer["ttl"].as_u64().ok_or(bad)?).ok_or(bad)?;
    let manifest: ramflux_protocol::custody::CustodyManifest = ramflux_protocol::custody::decode(
        &evidence.source_authority.as_ref().ok_or(bad)?.canonical,
        5 * 1024 * 1024,
    )
    .map_err(|_| bad)?;
    let human = manifest
        .custodian_publication
        .as_ref()
        .map(|publication| {
            ramflux_crypto::custody::verify_record(
                &publication.record,
                issued,
                publication.compacted_ids.as_deref(),
                None,
            )
        })
        .transpose()
        .map_err(|_| bad)?;
    let publication = &manifest.publication;
    let authority = ramflux_crypto::custody::verify_record(
        &publication.record,
        issued,
        publication.compacted_ids.as_deref(),
        human.as_ref(),
    )
    .map_err(|_| bad)?;
    let author = identity.author.as_ref().ok_or(bad)?;
    let body = &authority.envelope().body;
    if author.account_anchor != body.account_anchor
        || outer["source_device_id"].as_str() != Some(author.device_id.as_str())
        || outer["source_principal_id"].as_str() != Some(body.principal_id.as_str())
        || outer["ext"]["source_root_commitment"].as_str() != Some(body.account_anchor.as_str())
    {
        return mismatch();
    }
    let device = ramflux_protocol::custody::DeviceRef {
        account_anchor: author.account_anchor.clone(),
        device_id: author.device_id.clone(),
        device_epoch: author.device_epoch,
    };
    let certificate = authority.authorize(&device, "message", issued).map_err(|_| bad)?;
    ramflux_protocol::verify_sender_signature(
        &outer,
        ramflux_protocol::SenderTranscriptMode::Evidence,
        &certificate.branch_signing_public_key,
    )
    .map_err(|_| bad)?;
    verify_group(&identity, &evidence, &authority, issued)?;
    let header = h::Header {
        layer: evidence.layer,
        kind: 1,
        exact_identity: &original.exact_identity,
        issued_at: issued,
        expires_at: expires,
        group: evidence.group_binding.as_ref(),
    };
    let ext = ramflux_protocol::Ext {
        ext: serde_json::from_value(outer["ext"].clone()).map_err(|_| bad)?,
    };
    h::verify_extension(&ext, 1, Some(&header))?;
    h::transcript(&header)
}

fn verify_group(
    identity: &g::EventIdentity,
    evidence: &g::HistoryOriginalMetadataEvidence,
    authority: &ramflux_crypto::custody::VerifiedRecord,
    issued: u64,
) -> Result<(), h::EvidenceError> {
    let bad = h::EvidenceError::OriginCommitmentMismatch;
    let Some(binding) = evidence.group_binding.as_ref() else {
        return if identity.group_id.is_none() && evidence.group_membership.is_none() {
            Ok(())
        } else {
            mismatch()
        };
    };
    let author = identity.author.as_ref().ok_or(bad)?;
    authority
        .authorize(
            &ramflux_protocol::custody::DeviceRef {
                account_anchor: author.account_anchor.clone(),
                device_id: author.device_id.clone(),
                device_epoch: author.device_epoch,
            },
            "group",
            issued,
        )
        .map_err(|_| bad)?;
    let snapshot = evidence.group_membership.as_ref().ok_or(bad)?;
    let parsed =
        ramflux_protocol::group_state::GroupStateSnapshot::from_wire_bytes(&snapshot.canonical)
            .map_err(|_| bad)?;
    if ramflux_protocol::canonical_json_bytes(&parsed).map_err(|_| bad)? != snapshot.canonical {
        return mismatch();
    }
    let verified = ramflux_crypto::verify_group_state_snapshot(parsed).map_err(|_| bad)?;
    let state = verified.snapshot();
    if state.group_id != binding.group_id
        || state.epoch != binding.key_epoch
        || state.genesis.conversation_id != identity.conversation_id
        || ramflux_protocol::decode_base64url(&state.state_hash).map_err(|_| bad)?
            != binding.group_state_hash
        || verified.view().effective_role(&author.account_anchor, &author.device_id).is_none()
    {
        return mismatch();
    }
    Ok(())
}

fn headers(
    db: &rusqlite::Connection,
    database: &str,
) -> Result<BTreeMap<String, Vec<u8>>, StorageError> {
    let mut query = db.prepare(&format!("SELECT substr(state_kind,length(?1)+1),state_json FROM {database}.runtime_actor_state WHERE substr(state_kind,1,length(?1))=?1"))?;
    let rows = query
        .query_map([PREFIX], |row| Ok((row.get(0)?, row.get(1)?)))?
        .collect::<rusqlite::Result<BTreeMap<_, _>>>()?;
    Ok(rows)
}

impl BackupDatabase {
    pub(super) fn merge_original_header_agreement(
        &self,
    ) -> Result<Vec<super::backup_merge::BackupItemRefusal>, StorageError> {
        let local = headers(&self.db, "main")?;
        let incoming = headers(&self.db, "incoming")?;
        let mut verified = BTreeMap::new();
        for (target, bytes) in &local {
            let preimage = verified_preimage(target, bytes)
                .map_err(|_| StorageError::Integrity("invalid local original-header evidence"))?;
            verified.insert(target, preimage);
        }
        let mut refused = Vec::new();
        for target in local.keys().filter(|target| !incoming.contains_key(*target)) {
            let unproven: bool = self.db.query_row(
                "SELECT EXISTS(SELECT 1 FROM incoming.runtime_actor_state WHERE state_kind=?1)",
                [format!("routed/edit-revision/{target}")],
                |row| row.get(0),
            )?;
            if unproven {
                self.exclude_conflicting_original(target)?;
                refused.push(super::backup_merge::BackupItemRefusal {
                    message_id: target.clone(),
                    code: h::EvidenceError::OriginCommitmentMismatch,
                });
            }
        }
        for (target, bytes) in &incoming {
            let candidate = verified_preimage(target, bytes);
            if candidate.as_ref().is_err()
                || verified
                    .get(target)
                    .is_some_and(|ours| candidate.as_ref().is_ok_and(|theirs| ours != theirs))
            {
                self.exclude_conflicting_original(target)?;
                refused.push(super::backup_merge::BackupItemRefusal {
                    message_id: target.clone(),
                    code: h::EvidenceError::OriginCommitmentMismatch,
                });
            } else if local.contains_key(target) {
                self.preserve_equivalent_original_copy(target, bytes)?;
            }
        }
        Ok(refused)
    }

    fn exclude_conflicting_original(&self, target: &str) -> Result<(), StorageError> {
        let db = &self.db;
        // A conflict fences the entire incoming item's owned subtree before archive preservation.
        let copies = super::backup_edit_register::revision_copies(db, "incoming", target)?;
        super::backup_edit_register::exclude_incoming_content(db, target, &copies)?;
        for table in [
            "direct_message_projection",
            "runtime_message_content",
            "raw_inner_evidence",
            "message_footprint",
        ] {
            super::backup_edit_register::exclude(db, table, "message_id", target)?;
        }
        let mut query = db.prepare(
            "SELECT locator FROM incoming.message_footprint WHERE message_id=?1 AND kind='actor'",
        )?;
        let actors = query
            .query_map([target], |row| row.get::<_, String>(0))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        for key in actors
            .into_iter()
            .chain([format!("{PREFIX}{target}"), format!("routed/edit-revision/{target}")])
        {
            super::backup_edit_register::exclude(db, "runtime_actor_state", "state_kind", &key)?;
        }
        super::backup_edit_register::exclude(db, "raw_inner_copy", "owner_id", target)?;
        Ok(())
    }

    fn preserve_equivalent_original_copy(
        &self,
        target: &str,
        bytes: &[u8],
    ) -> Result<(), StorageError> {
        let digest = ramflux_protocol::encode_base64url(blake3::hash(bytes).as_bytes());
        let locator = format!("routed/original-header-copy/{target}/{digest}");
        self.db.execute(
            "INSERT OR IGNORE INTO main.runtime_actor_state(state_kind,state_json) VALUES(?1,?2)",
            params![locator, bytes],
        )?;
        self.db.execute("INSERT OR IGNORE INTO main.message_footprint(message_id,kind,locator) VALUES(?1,'actor',?2)", params![target,locator])?;
        self.db.execute("INSERT OR IGNORE INTO backup_erased_copy SELECT 'incoming','raw_inner_copy',i.rowid FROM incoming.raw_inner_copy i JOIN main.raw_inner_copy l USING(copy_id) WHERE i.copy_id=?1 AND i.raw_bytes<>l.raw_bytes", [format!("history/original-header/{target}")])?;
        Ok(())
    }
}

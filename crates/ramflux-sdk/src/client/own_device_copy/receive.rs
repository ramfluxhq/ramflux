// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Own-copy receipt lookup and local verification are shared by direct and background receive.

use super::{DOMAIN, MAX_PACKET_BYTES, OwnDeviceMessage, PREFIX, RECEIPTS, TOO_LARGE, invalid};
use crate::client::identity_authority::HeadUse;
use crate::client::identity_authority::NativeOperation;
use crate::prelude::{dm_device_id_hash, now_unix_timestamp};
use crate::{
    GatewayInboxEntry, GatewaySessionConfig, RamfluxClient, SdkDeviceManifestResponse, SdkError,
};
use zeroize::Zeroize;

struct Pending {
    packet: OwnDeviceMessage,
    root: String,
    receipt_key: String,
    fingerprint: String,
    now: i64,
}
enum Check {
    Other,
    Pending(Box<Pending>),
}
impl RamfluxClient {
    pub(crate) fn own_device_receive_manifest_request(
        &self,
        entry: &GatewayInboxEntry,
    ) -> Result<Option<String>, SdkError> {
        Ok(match self.prepare_own_receive(entry)? {
            Check::Other => None,
            Check::Pending(pending) => Some(pending.root),
        })
    }

    pub(crate) async fn receive_own_device_message(
        &self,
        gateway: &GatewaySessionConfig,
        entry: &GatewayInboxEntry,
    ) -> Result<bool, SdkError> {
        match self.prepare_own_receive(entry)? {
            Check::Other => Ok(false),
            Check::Pending(pending) => {
                let manifest = self
                    .cache_verified_device_manifest(
                        gateway,
                        &pending.root,
                        "own_device_message_receive",
                    )
                    .await?;
                self.apply_own_receive(entry, *pending, &manifest)
            }
        }
    }

    pub(crate) fn receive_prepared_own_device_message(
        &self,
        entry: &GatewayInboxEntry,
        manifest: SdkDeviceManifestResponse,
    ) -> Result<bool, SdkError> {
        match self.prepare_own_receive(entry)? {
            Check::Other => Ok(false),
            Check::Pending(pending) => {
                let manifest = self.accept_fetched_device_manifest(
                    manifest,
                    &pending.root,
                    "own_device_message_receive",
                )?;
                self.apply_own_receive(entry, *pending, &manifest)
            }
        }
    }

    fn prepare_own_receive(&self, entry: &GatewayInboxEntry) -> Result<Check, SdkError> {
        if entry.envelope.schema == "ramflux.envelope.v2" {
            ramflux_protocol::sender_signed_transcript(
                &entry.envelope,
                ramflux_protocol::SenderTranscriptMode::WithCiphertext,
            )?;
        }
        let bytes = ramflux_protocol::decode_base64url(&entry.envelope.encrypted_payload)
            .map_err(|_| invalid("own-device encoding"))?;
        if bytes.starts_with(b"ramflux.own_device_message.v1\n") {
            return Err(invalid("legacy own-device message requires a fresh copy"));
        }
        let Some(raw) = bytes.strip_prefix(PREFIX) else { return Ok(Check::Other) };
        if bytes.len() > MAX_PACKET_BYTES {
            return Err(invalid(TOO_LARGE));
        }
        let packet: OwnDeviceMessage = ramflux_protocol::parse_i_json(raw)?;
        packet.validate(entry)?;
        let local = self.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?;
        if entry.envelope.source_principal_id != local.principal_id {
            return Err(invalid("own-device principal mismatch"));
        }
        let root = self.surface_local_root_commitment()?;
        let now = now_unix_timestamp();
        let receipt_key = format!("{RECEIPTS}{}", packet.id);
        let fingerprint = ramflux_protocol::hash_base64url(DOMAIN, &bytes);
        Ok(Check::Pending(Box::new(Pending { packet, root, receipt_key, fingerprint, now })))
    }

    fn apply_own_receive(
        &self,
        entry: &GatewayInboxEntry,
        pending: Pending,
        manifest: &SdkDeviceManifestResponse,
    ) -> Result<bool, SdkError> {
        let Pending { packet, root, receipt_key, fingerprint, now } = pending;
        let local = self.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?;
        let db = self.account_db()?;
        self.require_native_operation(&self.owned_device_identity()?, NativeOperation::Sync)?;
        self.require_native_operation(
            &self.device_identity_for_root(&root, &entry.envelope.source_device_id)?,
            NativeOperation::Sync,
        )?;
        packet.verify_source(entry, manifest, &local.device_id)?;
        let bytes = ramflux_protocol::decode_base64url(&entry.envelope.encrypted_payload)
            .map_err(|_| invalid("own-device encoding"))?;
        let replay = self.own_copy_replay(entry, &packet, &bytes, now)?;
        if replay.committed {
            return Ok(true);
        }
        let recipient = packet.recipient_slot(&local.device_id)?;
        let slot = recipient.object_slot(&packet.id, &manifest.principal_commitment);
        if slot.ciphertext.sender_device_id_hash
            != dm_device_id_hash(&entry.envelope.source_device_id)
        {
            return Err(invalid("own-device key slot scope mismatch"));
        }
        let mut deferred = match self.decrypt_object_key_slot(&slot) {
            Ok(deferred) => deferred,
            Err(SdkError::PairRecoveryRequired) => {
                self.begin_pair_recovery(
                    &self.owned_device_identity()?,
                    &self.authenticated_device_identity(HeadUse::NewAuthorization, entry)?,
                    now,
                )?;
                return Err(SdkError::PairRecoveryRequired);
            }
            Err(error) => return Err(error),
        };
        let key = zeroize::Zeroizing::new(deferred.object_key);
        deferred.object_key.zeroize();
        let (context, body) = packet.open(&key)?;
        context.validate(
            &packet.id,
            &local.principal_id,
            &root,
            &entry.envelope.source_device_id,
            now,
        )?;
        db.write_transaction(|| {
            self.commit_own_copy_writes(OwnCopyCommit {
                db,
                entry,
                replay: &replay,
                receipt_key: &receipt_key,
                fingerprint,
                root: &root,
                context: &context,
                body: &body,
                slot: &slot,
                key: &key,
                local_device_id: &local.device_id,
                now,
            })
        })?;
        Ok(true)
    }

    fn commit_own_copy_writes(&self, work: OwnCopyCommit<'_>) -> Result<(), SdkError> {
        // The packet signature and root-signed active set above authenticate this source;
        // generic envelope signatures are not the own-device packet's signature scheme.
        let source_identity =
            self.device_identity_for_root(work.root, &work.entry.envelope.source_device_id)?;
        super::receipts::remember(
            work.db,
            &work.replay.key,
            &work.replay.fingerprint,
            work.context.expires_at,
            false,
            work.now,
        )?;
        let scope = self.apply_own_device_control(
            work.entry,
            &source_identity,
            work.context,
            work.body,
            work.local_device_id,
        )?;
        self.commit_inline_pair_key_slot(work.slot, work.key)?;
        self.persist_own_device_receipt(
            work.receipt_key,
            work.context,
            work.fingerprint,
            scope,
            &source_identity,
        )?;
        Ok(())
    }

    /// Decrypts a pending own-copy packet and runs the durable writes (joins an open writer).
    pub(crate) fn commit_own_copy_from_entry(
        &self,
        entry: &GatewayInboxEntry,
        manifest: &SdkDeviceManifestResponse,
    ) -> Result<bool, SdkError> {
        match self.prepare_own_receive(entry)? {
            Check::Other => Ok(false),
            Check::Pending(pending) => self.apply_own_receive(entry, *pending, manifest),
        }
    }
}

struct OwnCopyCommit<'a> {
    db: &'a ramflux_storage::AccountDb,
    entry: &'a GatewayInboxEntry,
    replay: &'a super::receipts::Replay,
    receipt_key: &'a str,
    fingerprint: String,
    root: &'a str,
    context: &'a super::PrivateContext,
    body: &'a [u8],
    slot: &'a crate::SdkObjectKeySlot,
    key: &'a [u8; 32],
    local_device_id: &'a str,
    now: i64,
}

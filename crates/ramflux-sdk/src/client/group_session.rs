// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

#![allow(clippy::missing_errors_doc)]
#![allow(clippy::wildcard_imports)]
use crate::prelude::*;

impl RamfluxClient {
    pub(crate) fn load_group_sender_key_state(
        &self,
        group_id: &str,
        sender: &ramflux_crypto::RootQualifiedDeviceRef,
        group_key_epoch: u64,
        direction: &str,
    ) -> Result<SdkGroupSenderKeyState, SdkError> {
        let checkpoint =
            group_sender_key_checkpoint_name(group_id, sender, group_key_epoch, direction)?;
        let sender_id = sender.device_id();
        let event_id = self.projection_checkpoint(&checkpoint)?.ok_or_else(|| {
            SdkError::LocalBus(format!(
                "missing group sender key for {group_id}/{sender_id}/epoch {group_key_epoch}/{direction}"
            ))
        })?;
        let bytes = self.event_body(&event_id)?.ok_or_else(|| {
            SdkError::LocalBus(format!("missing group sender key event {event_id}"))
        })?;
        let state: SdkGroupSenderKeyState = serde_json::from_slice(&bytes)?;
        if state.group_id != group_id
            || state.group_key_epoch != group_key_epoch
            || state.sender_id != sender.device_id()
            || state.principal_commitment.as_deref() != Some(sender.root_commitment())
        {
            return Err(SdkError::InboundRejected("group sender state root mismatch".into()));
        }
        Ok(state)
    }

    pub(crate) fn persist_group_sender_key_state(
        &self,
        state: &SdkGroupSenderKeyState,
        sender: &ramflux_crypto::RootQualifiedDeviceRef,
        direction: &str,
        event_suffix: &str,
    ) -> Result<(), SdkError> {
        if state.sender_id != sender.device_id()
            || state.principal_commitment.as_deref() != Some(sender.root_commitment())
        {
            return Err(SdkError::InboundRejected("group sender state root mismatch".into()));
        }
        let checkpoint = group_sender_key_checkpoint_name(
            &state.group_id,
            sender,
            state.group_key_epoch,
            direction,
        )?;
        let event_id = format!(
            "{checkpoint}/chain/{}/{}",
            state.session_snapshot.session_id(),
            ramflux_protocol::hash_base64url(
                "ramflux.sdk.group.sender.event.v2",
                event_suffix.as_bytes()
            )
        );
        self.append_event(&event_id, "group.sender_key.state", &serde_json::to_vec(state)?)?;
        if let Some(previous) = self.projection_checkpoint(&checkpoint)?
            && let Some(bytes) = self.event_body(&previous)?
            && let Ok(old) = serde_json::from_slice::<SdkGroupSenderKeyState>(&bytes)
        {
            self.set_projection_checkpoint(
                &format!("{checkpoint}/chain/{}", old.session_snapshot.session_id()),
                &previous,
            )?;
        }
        self.set_projection_checkpoint(
            &format!("{checkpoint}/chain/{}", state.session_snapshot.session_id()),
            &event_id,
        )?;
        self.set_projection_checkpoint(&checkpoint, &event_id)
    }

    pub(crate) fn ensure_own_group_sender_key(
        &self,
        group_id: &str,
        sender: &ramflux_crypto::RootQualifiedDeviceRef,
        group_key_epoch: u64,
    ) -> Result<SdkGroupSenderKeyState, SdkError> {
        if *sender != self.owned_device_identity()? {
            return Err(SdkError::InboundRejected("group sender differs from owned device".into()));
        }
        self.pin_local_group_member(group_id)?;
        let sender_id = sender.device_id();
        if self
            .projection_checkpoint(&group_sender_key_checkpoint_name(
                group_id,
                sender,
                group_key_epoch,
                "send",
            )?)?
            .is_some()
        {
            return self.load_group_sender_key_state(group_id, sender, group_key_epoch, "send");
        }
        let root_seed = ramflux_crypto::random_32()?;
        let local_hash = group_sender_device_hash(group_id, sender_id, "local");
        let remote_hash = group_sender_device_hash(group_id, sender_id, "remote");
        // Every new chain binds its fresh seed, including a group first learned through merge.
        let transcript_hash =
            fresh_group_transcript(group_id, sender_id, group_key_epoch, &root_seed)?;
        let chain_version = 3;
        let state = SdkGroupSenderKeyState {
            chain_version,
            principal_commitment: Some(sender.root_commitment().to_owned()),
            group_id: group_id.to_owned(),
            sender_id: sender_id.to_owned(),
            group_key_epoch,
            session_snapshot: ramflux_crypto::DmSession::initiator(
                root_seed,
                local_hash,
                remote_hash,
                transcript_hash,
            )?
            .snapshot(),
        };
        self.persist_group_sender_key_state(&state, sender, "send", "initial")?;
        Ok(state)
    }

    /// # Errors
    /// Returns an error when group membership, sender-key generation, or serialization fails.
    pub fn export_group_sender_key_distribution(
        &self,
        group_id: &str,
        sender_id: &str,
    ) -> Result<Vec<u8>, SdkError> {
        let group = self.group_state(group_id)?;
        if !group.members.contains(sender_id) {
            return Err(SdkError::from(StorageError::GroupPermissionDenied));
        }
        let state = self.ensure_own_group_sender_key(
            group_id,
            &self.local_device_identity(sender_id)?,
            group.group_epoch,
        )?;
        let sender_device_signing_public_key = self
            .device_branch
            .as_ref()
            .filter(|branch| branch.device_id == sender_id)
            .map(|branch| {
                ramflux_protocol::encode_base64url(branch.signing_key.verifying_key().to_bytes())
            });
        if sender_device_signing_public_key.is_none() {
            return Err(SdkError::LocalBus(
                "distribution requires the local sender signing key".into(),
            ));
        }
        let distribution = SdkGroupSenderKeyDistribution {
            schema: if state.chain_version == 3 {
                "ramflux.sdk.group_sender_key.distribution.v3"
            } else {
                "ramflux.sdk.group_sender_key.distribution.v2"
            }
            .to_owned(),
            version: if state.chain_version == 3 { 3 } else { 2 },
            group_id: group_id.to_owned(),
            sender_id: sender_id.to_owned(),
            group_key_epoch: group.group_epoch,
            sender_key_seed: state.session_snapshot.root_key_bytes(),
            sender_device_signing_public_key,
        };
        Ok(serde_json::to_vec(&distribution)?)
    }

    /// # Errors
    /// Returns an error when the distribution is malformed or cannot be persisted.
    pub fn import_group_sender_key_distribution(
        &self,
        distribution_bytes: &[u8],
    ) -> Result<SdkGroupSenderKeyDistribution, SdkError> {
        let (distribution, _pending) =
            self.import_group_sender_key_distribution_inner(distribution_bytes, true)?;
        Ok(distribution)
    }

    pub(crate) fn import_group_sender_key_distribution_inner(
        &self,
        distribution_bytes: &[u8],
        retry_pending: bool,
    ) -> Result<(SdkGroupSenderKeyDistribution, Vec<SdkGroupPendingPlaintext>), SdkError> {
        self.import_group_key_with_source(distribution_bytes, retry_pending, None)
    }

    pub(crate) fn import_group_key_for_identity(
        &self,
        distribution_bytes: &[u8],
        source: &ramflux_crypto::RootQualifiedDeviceRef,
        retry_pending: bool,
    ) -> Result<(SdkGroupSenderKeyDistribution, Vec<SdkGroupPendingPlaintext>), SdkError> {
        self.import_group_key_with_source(distribution_bytes, retry_pending, Some(source))
    }

    fn import_group_key_with_source(
        &self,
        distribution_bytes: &[u8],
        retry_pending: bool,
        identity: Option<&ramflux_crypto::RootQualifiedDeviceRef>,
    ) -> Result<(SdkGroupSenderKeyDistribution, Vec<SdkGroupPendingPlaintext>), SdkError> {
        let distribution: SdkGroupSenderKeyDistribution =
            serde_json::from_slice(distribution_bytes)?;
        if !matches!(
            (distribution.schema.as_str(), distribution.version),
            ("ramflux.sdk.group_sender_key.distribution.v3", 3)
                | ("ramflux.sdk.group_sender_key.distribution.v2", 2)
                | ("ramflux.sdk.group_sender_key.distribution.v1", 1)
        ) {
            return Err(SdkError::LocalBus(format!(
                "unsupported group sender key distribution schema: {}",
                distribution.schema
            )));
        }
        self.assert_group_sender_key_epoch_allowed(&distribution)?;
        let public_key = distribution
            .sender_device_signing_public_key
            .as_ref()
            .filter(|key| !key.is_empty())
            .ok_or_else(|| {
                SdkError::InboundRejected(
                    "distribution requires a pinned sender signing key".into(),
                )
            })?;
        let source = if let Some(identity) = identity {
            if identity.device_id() != distribution.sender_id {
                return Err(SdkError::InboundRejected("group distribution device mismatch".into()));
            }
            identity.clone()
        } else {
            self.device_identity(
                &self.group_device_reference(&distribution.group_id, &distribution.sender_id)?,
            )?
        };
        if identity.is_some() {
            self.require_cached_root_authority(&source)?;
        }
        if self.account_db()?.group_member_device_key(&distribution.group_id, &source)?.as_ref()
            != Some(public_key)
        {
            return Err(SdkError::InboundRejected(
                "safety: distribution signing key differs from member pin".into(),
            ));
        }
        let state = SdkGroupSenderKeyState {
            chain_version: distribution.version,
            principal_commitment: Some(source.root_commitment().to_owned()),
            group_id: distribution.group_id.clone(),
            sender_id: distribution.sender_id.clone(),
            group_key_epoch: distribution.group_key_epoch,
            session_snapshot: ramflux_crypto::DmSession::recipient(
                distribution.sender_key_seed,
                group_sender_device_hash(&distribution.group_id, &distribution.sender_id, "remote"),
                group_sender_device_hash(&distribution.group_id, &distribution.sender_id, "local"),
                if distribution.version == 3 {
                    fresh_group_transcript(
                        &distribution.group_id,
                        &distribution.sender_id,
                        distribution.group_key_epoch,
                        &distribution.sender_key_seed,
                    )?
                } else {
                    group_sender_transcript_hash(
                        &distribution.group_id,
                        &distribution.sender_id,
                        distribution.group_key_epoch,
                    )
                },
            )?
            .snapshot(),
        };
        let known = self.knows_identical_group_chain(&state, &source)?;
        if !known {
            self.persist_group_sender_key_state(&state, &source, "recv", "import")?;
        }
        let pending = if retry_pending {
            self.retry_pending_group_messages(&distribution.group_id, distribution.group_key_epoch)?
        } else {
            Vec::new()
        };
        Ok((distribution, pending))
    }

    fn knows_identical_group_chain(
        &self,
        state: &SdkGroupSenderKeyState,
        source: &ramflux_crypto::RootQualifiedDeviceRef,
    ) -> Result<bool, SdkError> {
        let base = group_sender_key_checkpoint_name(
            &state.group_id,
            source,
            state.group_key_epoch,
            "recv",
        )?;
        let checkpoint = self.projection_checkpoint(&format!(
            "{base}/chain/{}",
            state.session_snapshot.session_id()
        ))?;
        let old = if let Some(checkpoint) = checkpoint {
            self.event_body(&checkpoint)?
                .map(|bytes| serde_json::from_slice::<SdkGroupSenderKeyState>(&bytes))
                .transpose()?
        } else {
            self.load_group_sender_key_state(&state.group_id, source, state.group_key_epoch, "recv")
                .ok()
                .filter(|old| {
                    old.session_snapshot.session_id() == state.session_snapshot.session_id()
                })
        };
        let known = if let Some(old) = old {
            if old.session_snapshot.root_key_bytes() != state.session_snapshot.root_key_bytes() {
                return Err(SdkError::InboundRejected(
                    "group sender chain id reused with different key material".into(),
                ));
            }
            true
        } else {
            false
        };
        Ok(known)
    }

    fn assert_group_sender_key_epoch_allowed(
        &self,
        distribution: &SdkGroupSenderKeyDistribution,
    ) -> Result<(), SdkError> {
        let local = self.owned_device_identity()?;
        let local_device_id = local.device_id();
        let joined_epoch = self
            .account_db()?
            .group_member_joined_epoch(&distribution.group_id, &local)?
            .ok_or_else(|| SdkError::from(StorageError::GroupPermissionDenied))?;
        if distribution.group_key_epoch < joined_epoch {
            return Err(SdkError::LocalBus(format!(
                "group sender key epoch {} is below local joined epoch {} for {}/{}",
                distribution.group_key_epoch, joined_epoch, distribution.group_id, local_device_id
            )));
        }
        Ok(())
    }

    pub(crate) fn retry_pending_group_messages(
        &self,
        group_id: &str,
        group_key_epoch: u64,
    ) -> Result<Vec<SdkGroupPendingPlaintext>, SdkError> {
        let pending = self.account_db()?.group_pending_undecrypted(group_id, group_key_epoch)?;
        let mut decrypted = Vec::new();
        for record in pending {
            if self
                .direct_messages(&record.conversation_id)?
                .iter()
                .any(|message| message.message_id == record.message_id)
            {
                self.account_db()?.remove_group_pending_undecrypted(&record.message_id)?;
                continue;
            }
            let (entry, encrypted_body) = super::group_pending::decode(&record.envelope_json)?;
            if let Err(error) = self.authenticated_device_identity(&entry).and_then(|source| {
                self.require_group_sender_pin(
                    group_id,
                    &entry.envelope.source_principal_id,
                    &source,
                )
            }) {
                if matches!(error, SdkError::InboundPending(_) | SdkError::InboundRejected(_)) {
                    continue;
                }
                return Err(error);
            }
            let envelope: SdkGroupEncryptedEnvelope = serde_json::from_slice(&encrypted_body)?;
            if envelope.group_id != group_id || envelope.group_key_epoch != group_key_epoch {
                continue;
            }
            if let Err(error) =
                self.require_group_payload_sender(group_id, &envelope.sender_id, &entry)
            {
                if matches!(error, SdkError::InboundPending(_) | SdkError::InboundRejected(_)) {
                    continue;
                }
                return Err(error);
            }
            if self.group_sender_key_counter_seen(
                &envelope,
                &self.authenticated_device_identity(&entry)?,
            )? {
                self.account_db()?.remove_group_pending_undecrypted(&record.message_id)?;
                continue;
            }
            match self.append_or_pending_group_message(
                &record.conversation_id,
                &record.message_id,
                &entry,
                &encrypted_body,
                &envelope,
            ) {
                Ok(plaintext) => {
                    if self.direct_message_by_id(&record.message_id)?.is_none() {
                        continue;
                    }
                    decrypted.push(SdkGroupPendingPlaintext {
                        group_id: record.group_id,
                        conversation_id: record.conversation_id,
                        message_id: record.message_id,
                        plaintext,
                    });
                }
                Err(error) if is_missing_group_sender_key_error(&error) => {}
                Err(error) => return Err(error),
            }
        }
        Ok(decrypted)
    }

    /// # Errors
    /// Returns an error when the sender cannot send or encryption/persistence fails.
    pub fn encrypt_group_message(
        &self,
        group_id: &str,
        sender_id: &str,
        plaintext: &[u8],
    ) -> Result<Vec<u8>, SdkError> {
        self.require_backup_outbound_ready()?;
        let group = self.group_state(group_id)?;
        if !group.members.contains(sender_id) {
            return Err(SdkError::from(StorageError::GroupPermissionDenied));
        }
        let mut state = self.ensure_own_group_sender_key(
            group_id,
            &self.local_device_identity(sender_id)?,
            group.group_epoch,
        )?;
        let associated_data = group_associated_data(group_id, sender_id, group.group_epoch);
        let mut session = ramflux_crypto::DmSession::from_snapshot(state.session_snapshot.clone())?;
        let ciphertext = session.encrypt(plaintext, &associated_data)?;
        state.session_snapshot = session.snapshot();
        self.persist_group_sender_key_state(
            &state,
            &self.local_device_identity(sender_id)?,
            "send",
            &format!("send:{}", ciphertext.counter),
        )?;
        Ok(serde_json::to_vec(&SdkGroupEncryptedEnvelope {
            schema: "ramflux.sdk.group_sender_key.message.v1".to_owned(),
            version: 1,
            group_id: group_id.to_owned(),
            sender_id: sender_id.to_owned(),
            group_key_epoch: group.group_epoch,
            ciphertext,
        })?)
    }

    /// # Errors
    /// Returns an error when the sender key is missing, the message is malformed, or decryption
    /// fails.
    pub fn decrypt_group_message(
        &self,
        conversation_id: &str,
        message_id: &str,
    ) -> Result<Vec<u8>, SdkError> {
        let message = self
            .direct_messages(conversation_id)?
            .into_iter()
            .find(|message| message.message_id == message_id)
            .ok_or_else(|| SdkError::from(StorageError::MessageNotFound(message_id.to_owned())))?;
        let envelope: SdkGroupEncryptedEnvelope = serde_json::from_slice(&message.encrypted_body)?;
        self.decrypt_group_envelope(&envelope, message_id)
    }

    pub(crate) fn decrypt_group_envelope(
        &self,
        envelope: &SdkGroupEncryptedEnvelope,
        message_id: &str,
    ) -> Result<Vec<u8>, SdkError> {
        if envelope.schema != "ramflux.sdk.group_sender_key.message.v1" {
            return Err(SdkError::LocalBus(format!(
                "unsupported group message schema: {}",
                envelope.schema
            )));
        }
        let sender = self.device_identity(
            &self.group_device_reference(&envelope.group_id, &envelope.sender_id)?,
        )?;
        let base = group_sender_key_checkpoint_name(
            &envelope.group_id,
            &sender,
            envelope.group_key_epoch,
            "recv",
        )?;
        let mut state = if let Some(event) =
            self.projection_checkpoint(&format!("{base}/chain/{}", envelope.ciphertext.session_id))?
        {
            serde_json::from_slice::<SdkGroupSenderKeyState>(
                &self.event_body(&event)?.ok_or_else(|| {
                    SdkError::InboundPending("archived group chain missing".into())
                })?,
            )?
        } else {
            self.load_group_sender_key_state(
                &envelope.group_id,
                &sender,
                envelope.group_key_epoch,
                "recv",
            )?
        };
        let associated_data = group_associated_data(
            &envelope.group_id,
            &envelope.sender_id,
            envelope.group_key_epoch,
        );
        let mut session = ramflux_crypto::DmSession::from_snapshot(state.session_snapshot.clone())?;
        let plaintext = session.decrypt(&envelope.ciphertext, &associated_data)?;
        state.session_snapshot = session.snapshot();
        if !self.record_group_sender_key_counter(
            envelope,
            &self.device_identity(
                &self.group_device_reference(&envelope.group_id, &envelope.sender_id)?,
            )?,
            message_id,
        )? {
            return Err(SdkError::LocalBus(format!(
                "replayed group sender-key counter for {}/{}/epoch {}/counter {}",
                envelope.group_id,
                envelope.sender_id,
                envelope.group_key_epoch,
                envelope.ciphertext.counter
            )));
        }
        self.persist_group_sender_key_state(
            &state,
            &self.device_identity(
                &self.group_device_reference(&envelope.group_id, &envelope.sender_id)?,
            )?,
            "recv",
            &format!("recv:{}", envelope.ciphertext.counter),
        )?;
        Ok(plaintext)
    }
}

fn fresh_group_transcript(
    group: &str,
    sender: &str,
    epoch: u64,
    seed: &[u8; 32],
) -> Result<[u8; 32], SdkError> {
    Ok(ramflux_crypto::blake3_256(
        "ramflux.group.sender.chain.v3",
        &ramflux_protocol::canonical_json_bytes(&(
            group,
            sender,
            epoch,
            ramflux_crypto::blake3_256("ramflux.group.sender.seed-id.v3", seed),
        ))?,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_root(test_name: &str) -> PathBuf {
        let nanos =
            SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |elapsed| elapsed.as_nanos());
        std::env::temp_dir()
            .join(format!("ramflux-sdk-group-session-{test_name}-{}-{nanos}", std::process::id()))
    }

    #[test]
    fn group_sender_key_import_rejects_epoch_below_local_joined_epoch() -> Result<(), SdkError> {
        let root = temp_root("epoch-floor");
        let mut client = RamfluxClient::new();
        client.create_identity_root("principal_floor", [0x91; 32]);
        client.create_device_branch("principal_floor", "local_device", 1, [0x92; 32]);
        client.open_account_index(&root)?;
        client.create_account("acct", "principal_floor")?;
        client.set_active_account("acct")?;
        client.unlock_account("acct", b"secret")?;
        client.create_group("group_floor", "owner_device")?;
        client.add_group_member("group_floor", "local_device", "member")?;
        let joined_epoch = client
            .account_db()?
            .group_member_joined_epoch_metadata("group_floor", "local_device")?
            .unwrap_or(0);
        assert!(joined_epoch > 1);
        let distribution = SdkGroupSenderKeyDistribution {
            schema: "ramflux.sdk.group_sender_key.distribution.v1".to_owned(),
            version: 1,
            group_id: "group_floor".to_owned(),
            sender_id: "owner_device".to_owned(),
            group_key_epoch: joined_epoch.saturating_sub(1),
            sender_key_seed: [0x93; 32],
            sender_device_signing_public_key: None,
        };
        let encoded = serde_json::to_vec(&distribution)?;
        let Err(error) = client.import_group_sender_key_distribution(&encoded) else {
            return Err(SdkError::LocalBus("low epoch sender key imported".to_owned()));
        };
        assert!(error.to_string().contains("below local joined epoch"));
        std::fs::remove_dir_all(root)?;
        Ok(())
    }
}

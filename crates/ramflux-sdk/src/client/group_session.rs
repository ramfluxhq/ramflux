// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

#![allow(clippy::missing_errors_doc)]
#![allow(clippy::wildcard_imports)]
use crate::client::identity_authority::HeadUse;
use crate::client::identity_authority::NativeOperation;
use crate::prelude::*;

impl RamfluxClient {
    pub(crate) fn current_group_key_head(
        &self,
        group: &str,
        epoch: u64,
    ) -> Result<Option<String>, SdkError> {
        let Some(state) = self.account_db()?.shared_group_state(group)? else {
            return Ok(None);
        };
        if state.view().epoch != epoch {
            return Err(SdkError::InboundPending("shared group key epoch is not current".into()));
        }
        Ok(Some(state.snapshot().state_hash.clone()))
    }
    pub(crate) fn validate_group_key_head(
        &self,
        group: &str,
        epoch: u64,
        head: Option<&str>,
    ) -> Result<(), SdkError> {
        let shared = self.account_db()?.shared_group_state(group)?;
        if shared.is_some() != head.is_some()
            || head.is_some_and(|head| {
                ramflux_protocol::decode_base64url(head).map_or(true, |bytes| {
                    bytes.len() != 32 || ramflux_protocol::encode_base64url(bytes) != head
                })
            })
        {
            return Err(SdkError::InboundRejected(
                "group key head does not match its group mode".into(),
            ));
        }
        if shared.is_some()
            && !self.account_db()?.knows_shared_group_head(
                group,
                epoch,
                head.ok_or_else(|| SdkError::InboundRejected("group key head missing".into()))?,
            )?
        {
            return Err(SdkError::InboundPending(
                "shared group state head is not verified locally".into(),
            ));
        }
        Ok(())
    }
    pub(crate) fn load_group_sender_key_state(
        &self,
        group_id: &str,
        sender: &ramflux_crypto::RootQualifiedDeviceRef,
        group_key_epoch: u64,
        direction: &str,
    ) -> Result<SdkGroupSenderKeyState, SdkError> {
        let head = self.current_group_key_head(group_id, group_key_epoch)?;
        self.load_group_key_at_head(group_id, sender, group_key_epoch, direction, head.as_deref())
    }
    pub(crate) fn load_group_key_at_head(
        &self,
        group_id: &str,
        sender: &ramflux_crypto::RootQualifiedDeviceRef,
        group_key_epoch: u64,
        direction: &str,
        head: Option<&str>,
    ) -> Result<SdkGroupSenderKeyState, SdkError> {
        let checkpoint =
            crate::group::group_key_checkpoint(group_id, sender, group_key_epoch, direction, head)?;
        let sender_id = sender.device_id();
        let event_id = self.projection_checkpoint(&checkpoint)?.ok_or_else(|| {
            SdkError::InboundPending(format!(
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
            || state.group_state_hash.as_deref() != head
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
        self.persist_group_chain(state, sender, direction, event_suffix, false)
    }
    fn persist_group_chain(
        &self,
        state: &SdkGroupSenderKeyState,
        sender: &ramflux_crypto::RootQualifiedDeviceRef,
        direction: &str,
        event_suffix: &str,
        preserve_active: bool,
    ) -> Result<(), SdkError> {
        if state.sender_id != sender.device_id()
            || state.principal_commitment.as_deref() != Some(sender.root_commitment())
        {
            return Err(SdkError::InboundRejected("group sender state root mismatch".into()));
        }
        let checkpoint = crate::group::group_key_checkpoint(
            &state.group_id,
            sender,
            state.group_key_epoch,
            direction,
            state.group_state_hash.as_deref(),
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
        let mut is_active = true;
        if let Some(previous) = self.projection_checkpoint(&checkpoint)?
            && let Some(bytes) = self.event_body(&previous)?
            && let Ok(old) = serde_json::from_slice::<SdkGroupSenderKeyState>(&bytes)
        {
            is_active = old.session_snapshot.session_id() == state.session_snapshot.session_id();
            self.set_projection_checkpoint(
                &format!("{checkpoint}/chain/{}", old.session_snapshot.session_id()),
                &previous,
            )?;
        }
        self.set_projection_checkpoint(
            &format!("{checkpoint}/chain/{}", state.session_snapshot.session_id()),
            &event_id,
        )?;
        if !preserve_active || is_active {
            self.set_projection_checkpoint(&checkpoint, &event_id)?;
        }
        if state.group_state_hash.is_some() {
            let scope = ramflux_protocol::hash_base64url(
                "ramflux.group.key-scope.v1",
                &ramflux_protocol::canonical_json_bytes(&(
                    &state.group_id,
                    sender.storage_key(),
                    direction,
                ))?,
            );
            self.account_db()?.retain_group_key_checkpoint(&scope, &checkpoint)?;
        }
        Ok(())
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
        self.require_native_operation(sender, NativeOperation::Group)?;
        self.pin_local_group_member(group_id)?;
        let sender_id = sender.device_id();
        let head = self.current_group_key_head(group_id, group_key_epoch)?;
        if self
            .projection_checkpoint(&crate::group::group_key_checkpoint(
                group_id,
                sender,
                group_key_epoch,
                "send",
                head.as_deref(),
            )?)?
            .is_some()
        {
            return self.load_group_key_at_head(
                group_id,
                sender,
                group_key_epoch,
                "send",
                head.as_deref(),
            );
        }
        let root_seed = ramflux_crypto::random_32()?;
        let local_hash = group_sender_device_hash(group_id, sender_id, "local");
        let remote_hash = group_sender_device_hash(group_id, sender_id, "remote");
        // Every new chain binds its fresh seed, including a group first learned through merge.
        let transcript_hash =
            fresh_group_transcript(group_id, sender_id, group_key_epoch, &root_seed)?;
        let chain_version = if head.is_some() { 4 } else { 3 };
        let state = SdkGroupSenderKeyState {
            chain_version,
            principal_commitment: Some(sender.root_commitment().to_owned()),
            group_id: group_id.to_owned(),
            sender_id: sender_id.to_owned(),
            group_key_epoch,
            group_state_hash: head,
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
        self.assert_shared_group_send_capacity(group_id, sender_id)?;
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
        let version = if state.group_state_hash.is_some() {
            if state.chain_version == 4 { 4 } else { 3 }
        } else if state.chain_version == 3 {
            3
        } else {
            2
        };
        let mut distribution = SdkGroupSenderKeyDistribution {
            schema: format!("ramflux.sdk.group_sender_key.distribution.v{version}"),
            version,
            group_id: group_id.to_owned(),
            sender_id: sender_id.to_owned(),
            group_key_epoch: group.group_epoch,
            group_state_hash: state.group_state_hash.clone(),
            sender_key_seed: state.session_snapshot.root_key_bytes(),
            sender_key_signature: None,
            sender_device_signing_public_key,
        };
        if version == 4 {
            self.sign_group_distribution(&mut distribution)?;
        }
        Ok(serde_json::to_vec(&distribution)?)
    }

    /// # Errors
    /// Returns an error when the distribution is malformed or cannot be persisted.
    pub fn import_group_sender_key_distribution(
        &self,
        distribution_bytes: &[u8],
    ) -> Result<SdkGroupSenderKeyDistribution, SdkError> {
        self.import_group_key_with_source(distribution_bytes, None)
    }

    pub(crate) fn import_group_key_for_identity(
        &self,
        distribution_bytes: &[u8],
        source: &ramflux_crypto::RootQualifiedDeviceRef,
    ) -> Result<SdkGroupSenderKeyDistribution, SdkError> {
        self.import_group_key_with_source(distribution_bytes, Some(source))
    }

    fn import_group_key_with_source(
        &self,
        distribution_bytes: &[u8],
        identity: Option<&ramflux_crypto::RootQualifiedDeviceRef>,
    ) -> Result<SdkGroupSenderKeyDistribution, SdkError> {
        let distribution: SdkGroupSenderKeyDistribution =
            serde_json::from_slice(distribution_bytes)?;
        if !matches!(
            (
                distribution.schema.as_str(),
                distribution.version,
                distribution.group_state_hash.is_some()
            ),
            ("ramflux.sdk.group_sender_key.distribution.v4", 4, true)
        ) {
            return Err(SdkError::InboundRejected(
                "unsupported group key distribution schema or head".into(),
            ));
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
            self.require_cached_root_authority(HeadUse::NewAuthorization, &source)?;
        }
        if self.account_db()?.group_member_device_key(&distribution.group_id, &source)?.as_ref()
            != Some(public_key)
        {
            return Err(SdkError::InboundRejected(
                "safety: distribution signing key differs from member pin".into(),
            ));
        }
        Self::verify_group_distribution_auth(&distribution, &source)?;
        self.validate_group_key_head(
            &distribution.group_id,
            distribution.group_key_epoch,
            distribution.group_state_hash.as_deref(),
        )?;
        if self.reuse_shared_group_key(&distribution, &source)? {
            return Ok(distribution);
        }
        let state = SdkGroupSenderKeyState {
            chain_version: distribution.version,
            principal_commitment: Some(source.root_commitment().to_owned()),
            group_id: distribution.group_id.clone(),
            sender_id: distribution.sender_id.clone(),
            group_key_epoch: distribution.group_key_epoch,
            group_state_hash: distribution.group_state_hash.clone(),
            session_snapshot: ramflux_crypto::DmSession::recipient(
                distribution.sender_key_seed,
                group_sender_device_hash(&distribution.group_id, &distribution.sender_id, "remote"),
                group_sender_device_hash(&distribution.group_id, &distribution.sender_id, "local"),
                if distribution.version == 4
                    || (distribution.version == 3 && distribution.group_state_hash.is_none())
                {
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
        Ok(distribution)
    }

    fn knows_identical_group_chain(
        &self,
        state: &SdkGroupSenderKeyState,
        source: &ramflux_crypto::RootQualifiedDeviceRef,
    ) -> Result<bool, SdkError> {
        let base = crate::group::group_key_checkpoint(
            &state.group_id,
            source,
            state.group_key_epoch,
            "recv",
            state.group_state_hash.as_deref(),
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

    fn reuse_shared_group_key(
        &self,
        distribution: &SdkGroupSenderKeyDistribution,
        source: &ramflux_crypto::RootQualifiedDeviceRef,
    ) -> Result<bool, SdkError> {
        if distribution.group_state_hash.is_none() || distribution.version == 4 {
            return Ok(false);
        }
        let checkpoint = crate::group::group_key_checkpoint(
            &distribution.group_id,
            source,
            distribution.group_key_epoch,
            "recv",
            distribution.group_state_hash.as_deref(),
        )?;
        if self.projection_checkpoint(&checkpoint)?.is_some() {
            let existing = self.load_group_key_at_head(
                &distribution.group_id,
                source,
                distribution.group_key_epoch,
                "recv",
                distribution.group_state_hash.as_deref(),
            )?;
            if existing.session_snapshot.root_key_bytes() != distribution.sender_key_seed {
                return Err(SdkError::InboundRejected(
                    "shared group key changed at an existing head".into(),
                ));
            }
            return Ok(true);
        }
        Ok(false)
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

    pub(super) fn encrypt_prepared_group_message(
        &self,
        group_id: &str,
        sender_id: &str,
        plaintext: &[u8],
    ) -> Result<SdkGroupEncryptedEnvelope, SdkError> {
        self.account_db()?
            .write_transaction(|| self.encrypt_group_message_in(group_id, sender_id, plaintext))
    }

    fn encrypt_group_message_in(
        &self,
        group_id: &str,
        sender_id: &str,
        plaintext: &[u8],
    ) -> Result<SdkGroupEncryptedEnvelope, SdkError> {
        self.require_backup_outbound_ready()?;
        self.assert_shared_group_send_capacity(group_id, sender_id)?;
        let logical_event_id =
            crate::client::target_selection::group_logical_event_id(group_id, None)?;
        let _ = self.candidate_group_target_plan(
            group_id,
            sender_id,
            &logical_event_id,
            ramflux_protocol::message::KindId::KindMessage,
        )?;
        let group = self.group_state(group_id)?;
        if !group.members.contains(sender_id) {
            return Err(SdkError::from(StorageError::GroupPermissionDenied));
        }
        let mut state = self.ensure_own_group_sender_key(
            group_id,
            &self.local_device_identity(sender_id)?,
            group.group_epoch,
        )?;
        let associated_data = crate::group::group_key_associated_data(
            group_id,
            &self.local_device_identity(sender_id)?,
            group.group_epoch,
            state.group_state_hash.as_deref(),
        )?;
        if state.group_state_hash.is_none() {
            return Err(SdkError::GeneratedRefused {
                code: crate::GeneratedRefusalCode::Authority,
                reason: "verified native group head required".into(),
            });
        }
        let mut session = ramflux_crypto::DmSession::from_snapshot(state.session_snapshot.clone())?;
        self.capture_own_authored_group(group_id, sender_id, plaintext)?;
        let ciphertext = session.encrypt(plaintext, &associated_data)?;
        state.session_snapshot = session.snapshot();
        self.persist_group_sender_key_state(
            &state,
            &self.local_device_identity(sender_id)?,
            "send",
            &format!("send:{}", ciphertext.counter),
        )?;
        Ok(SdkGroupEncryptedEnvelope {
            schema: "ramflux.sdk.group_sender_key.message.v2".into(),
            version: 2,
            group_id: group_id.to_owned(),
            sender_id: sender_id.to_owned(),
            group_key_epoch: group.group_epoch,
            group_state_hash: state.group_state_hash.clone(),
            ciphertext,
        })
    }

    #[cfg(test)]
    pub(crate) fn decrypt_group_envelope_for_identity(
        &self,
        envelope: &SdkGroupEncryptedEnvelope,
        message_id: &str,
        source: &ramflux_crypto::RootQualifiedDeviceRef,
    ) -> Result<Vec<u8>, SdkError> {
        let mut output = self.decrypt_group_envelope_with_opening(envelope, message_id, source)?;
        Ok(std::mem::take(&mut output.plaintext))
    }

    pub(crate) fn decrypt_group_envelope_with_opening(
        &self,
        envelope: &SdkGroupEncryptedEnvelope,
        message_id: &str,
        source: &ramflux_crypto::RootQualifiedDeviceRef,
    ) -> Result<ramflux_crypto::DmDecryptionOutput, SdkError> {
        if source.device_id() != envelope.sender_id {
            return Err(SdkError::InboundRejected("group sender identity mismatch".into()));
        }
        if !matches!(
            (envelope.schema.as_str(), envelope.version, envelope.group_state_hash.is_some()),
            ("ramflux.sdk.group_sender_key.message.v2", 2, true)
        ) {
            return Err(SdkError::InboundRejected(
                "unsupported group message schema or head".into(),
            ));
        }
        self.validate_group_key_head(
            &envelope.group_id,
            envelope.group_key_epoch,
            envelope.group_state_hash.as_deref(),
        )?;
        let base = crate::group::group_key_checkpoint(
            &envelope.group_id,
            source,
            envelope.group_key_epoch,
            "recv",
            envelope.group_state_hash.as_deref(),
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
            self.load_group_key_at_head(
                &envelope.group_id,
                source,
                envelope.group_key_epoch,
                "recv",
                envelope.group_state_hash.as_deref(),
            )?
        };
        if state.group_id != envelope.group_id
            || state.sender_id != source.device_id()
            || state.principal_commitment.as_deref() != Some(source.root_commitment())
            || state.group_key_epoch != envelope.group_key_epoch
            || state.group_state_hash != envelope.group_state_hash
            || state.session_snapshot.session_id() != envelope.ciphertext.session_id
        {
            return Err(SdkError::InboundRejected("archived group chain scope mismatch".into()));
        }
        let associated_data = crate::group::group_key_associated_data(
            &envelope.group_id,
            source,
            envelope.group_key_epoch,
            envelope.group_state_hash.as_deref(),
        )?;
        let mut session = ramflux_crypto::DmSession::from_snapshot(state.session_snapshot.clone())?;
        let plaintext =
            session.decrypt_with_franking_keys(&envelope.ciphertext, &associated_data)?;
        state.session_snapshot = session.snapshot();
        if !self.record_group_sender_key_counter(envelope, source, message_id)? {
            return Err(SdkError::LocalBus(format!(
                "replayed group sender-key counter for {}/{}/epoch {}/counter {}",
                envelope.group_id,
                envelope.sender_id,
                envelope.group_key_epoch,
                envelope.ciphertext.counter
            )));
        }
        self.persist_group_chain(
            &state,
            source,
            "recv",
            &format!("recv:{}", envelope.ciphertext.counter),
            true,
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

    #[tokio::test(flavor = "current_thread")]
    async fn group_sender_key_import_rejects_epoch_below_local_joined_epoch()
    -> crate::client::native_test_support::TestResult {
        crate::client::native_test_support::watchdog::within(async {
            use crate::client::native_test_support::Fixture;
            let owner = Fixture::with_device("epoch-floor-owner", "owner").await?;
            let peer = Fixture::with_device("epoch-floor-peer", "peer").await?;
            owner.client.persist_observed_identity_directory_now(&peer.manifest)?;
            peer.client.persist_observed_identity_directory_now(&owner.manifest)?;
            let primary = owner
                .client
                .born_v3_account
                .as_ref()
                .ok_or("native owner")?
                .group_primary(owner.vault.as_ref())?;
            owner.client.shared_group_create_with_primary(
                "group_floor",
                "floor-thread",
                None,
                &owner.config.target_delivery_id,
                Some(&primary),
            )?;
            let old = owner.client.export_group_sender_key_distribution("group_floor", "owner")?;
            let state = owner.client.shared_group_change_with_primary(
                "group_floor",
                &owner.config.target_delivery_id,
                ramflux_protocol::GroupStateChange::Add {
                    member: peer
                        .client
                        .owned_group_actor(&peer.config.target_delivery_id)?
                        .identity,
                    role: ramflux_protocol::SharedGroupRole::Member,
                },
                Some(&primary),
            )?;
            peer.client.accept_shared_group_state(&state, &peer.config.target_delivery_id)?;
            let joined = peer
                .client
                .account_db()?
                .group_member_joined_epoch("group_floor", &peer.client.owned_device_identity()?)?
                .ok_or("native joined epoch")?;
            assert!(joined > 1, "the real peer must join after the first key epoch");
            let error = peer
                .client
                .import_group_sender_key_distribution(&old)
                .err()
                .ok_or("pre-join sender key imported")?;
            assert!(error.to_string().contains("below local joined epoch"), "{error}");
            let current =
                owner.client.export_group_sender_key_distribution("group_floor", "owner")?;
            peer.client.import_group_sender_key_distribution(&current)?;
            Ok(())
        })
        .await?
    }
}

#[cfg(test)]
#[path = "group_chain_tests.rs"]
mod group_chain_tests;

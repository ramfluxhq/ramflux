// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! The Snapshot arm selects the existing native snapshot and seed codecs explicitly.
use super::{bootstrap::SharedGroupPacket, invalid};
use crate::{SdkError, SdkGroupSenderKeyDistribution};
use prost::Message as _;
use ramflux_protocol::{group_state::GroupStateSnapshot, message as g};
use zeroize::{Zeroize, Zeroizing};

pub(super) fn decode(bytes: &[u8]) -> Result<Option<SharedGroupPacket>, SdkError> {
    if !crate::client::target_selection::schema_v1_selected() {
        return Ok(None);
    }
    if bytes.first() != Some(&8) {
        return Ok(None);
    }
    g::validation::scan_inner(bytes).map_err(|_| invalid("group snapshot wire malformed"))?;
    let inner = g::Inner::decode(bytes).map_err(|_| invalid("group snapshot Inner malformed"))?;
    if inner.kind != 8 {
        return Ok(None);
    }
    let body = Zeroizing::new(inner.body);
    let control = SeedControl(
        g::Control::decode(body.as_slice())
            .map_err(|_| invalid("group snapshot Control malformed"))?,
    );
    let Some(g::control::Payload::GroupState(state)) = control.payload.as_ref() else {
        return Ok(None);
    };
    let Some(g::group_control_body::Value::Snapshot(snapshot)) =
        state.body.as_ref().and_then(|body| body.value.as_ref())
    else {
        return Ok(None);
    };
    crate::client::generated_control::validate_control_native(&control)?;
    if state.schema != super::bootstrap::PACKET_SCHEMA {
        return Err(invalid("group snapshot schema mismatch"));
    }
    let canonical =
        &snapshot.snapshot.as_ref().ok_or_else(|| invalid("snapshot missing"))?.canonical;
    let parsed = GroupStateSnapshot::from_wire_bytes(canonical)?;
    if ramflux_protocol::canonical_json_bytes(&parsed)? != *canonical {
        return Err(invalid("group snapshot must retain exact canonical native bytes"));
    }
    let distribution_base64 = snapshot
        .distribution
        .as_ref()
        .map(distribution_bytes)
        .transpose()?
        .map(|bytes| Zeroizing::new(ramflux_protocol::encode_base64url(bytes)));
    Ok(Some(SharedGroupPacket {
        schema: super::bootstrap::PACKET_SCHEMA.into(),
        snapshot_base64: ramflux_protocol::encode_base64url(canonical),
        distribution_base64,
    }))
}

fn distribution_bytes(value: &g::GroupKeyDistribution) -> Result<Zeroizing<Vec<u8>>, SdkError> {
    if value.encoded_len() > 4096
        || value.sender_key_seed.len() != 32
        || !matches!(
            (value.schema.as_str(), value.version),
            ("ramflux.sdk.group_sender_key.distribution.v3", 3)
                | ("ramflux.sdk.group_sender_key.distribution.v4", 4)
        )
    {
        return Err(invalid("group snapshot distribution grammar invalid"));
    }
    let mut native = SdkGroupSenderKeyDistribution {
        schema: value.schema.clone(),
        version: value.version,
        group_id: value.group_id.clone(),
        sender_id: value.sender_id.clone(),
        group_key_epoch: value.group_key_epoch,
        group_state_hash: value.group_state_hash.clone(),
        sender_key_seed: value
            .sender_key_seed
            .as_slice()
            .try_into()
            .map_err(|_| invalid("group snapshot seed length"))?,
        sender_key_signature: value.sender_key_signature.clone(),
        sender_device_signing_public_key: value.sender_device_signing_public_key.clone(),
    };
    let bytes = ramflux_protocol::canonical_json_bytes(&native);
    native.sender_key_seed.zeroize();
    Ok(Zeroizing::new(bytes?))
}

impl crate::RamfluxClient {
    pub(super) fn authorize_native_snapshot_state(
        &self,
        state: &ramflux_crypto::VerifiedGroupState,
        entry: &crate::GatewayInboxEntry,
        route: &crate::client::routed::Routing,
    ) -> Result<(), SdkError> {
        use crate::client::identity_authority::{HeadUse, NativeOperation};
        if route.kind != crate::client::routed::Kind::GroupControl
            || route.group_id.as_deref() != Some(state.view().group_id.as_str())
            || route.conversation_id != state.view().conversation_id
        {
            return Err(invalid("group snapshot route mismatch"));
        }
        self.confirm_group_actor_transport(&state.snapshot().issuer, entry)?;
        let source = self.authenticated_device_identity(HeadUse::NewAuthorization, entry)?;
        self.require_native_operation(&source, NativeOperation::Group)?;
        self.require_native_operation(&self.owned_device_identity()?, NativeOperation::Group)?;
        let trusted = self.trusted_device(HeadUse::NewAuthorization, &source)?;
        if trusted["signing_public_key"] != state.snapshot().issuer.identity.signing_public_key {
            return Err(invalid("group snapshot issuer signing key mismatch"));
        }
        self.ensure_shared_group_device(state, &source)?;
        self.group_snapshot_requires_consent(state)?;
        match self.account_db()?.validate_shared_group_removal_continuity(state) {
            Ok(()) => Ok(()),
            Err(ramflux_storage::StorageError::Protocol(
                ramflux_protocol::ProtocolError::GroupTransferRequiresSync,
            )) if self.can_repair_group_removals(state)? => Ok(()),
            Err(error) => Err(error.into()),
        }
    }
}

impl crate::RamfluxClient {
    pub(crate) fn shared_group_packet_for_recipient(
        &self,
        state: &ramflux_crypto::VerifiedGroupState,
        recipient: &ramflux_crypto::RootQualifiedDeviceRef,
    ) -> Result<Vec<u8>, SdkError> {
        use crate::client::identity_authority::{HeadUse, NativeOperation};
        self.trusted_device(HeadUse::NewAuthorization, recipient)?;
        let own = self.owned_device_identity()?;
        if state.snapshot().issuer.identity.root_commitment != own.root_commitment()
            || state.snapshot().issuer.identity.device_id != own.device_id()
        {
            return Err(invalid("snapshot producer must be its transport issuer"));
        }
        let eligible = state
            .view()
            .effective_role(recipient.root_commitment(), recipient.device_id())
            .is_some();
        if eligible {
            self.require_native_operation(recipient, NativeOperation::Group)?;
            self.ensure_shared_group_device(state, recipient)?;
        }
        let packet = Zeroizing::new(self.shared_group_packet(state, eligible)?);
        if !crate::client::target_selection::schema_v1_selected() {
            return Ok(packet.to_vec());
        }
        let packet: SharedGroupPacket = ramflux_protocol::parse_i_json(&packet)?;
        let distribution = packet
            .distribution_base64
            .as_ref()
            .map(|encoded| {
                let bytes = Zeroizing::new(
                    ramflux_protocol::decode_base64url(encoded)
                        .map_err(|_| invalid("distribution encoding invalid"))?,
                );
                let mut native: SdkGroupSenderKeyDistribution =
                    ramflux_protocol::parse_i_json(&bytes)?;
                let generated = g::GroupKeyDistribution {
                    schema: native.schema.clone(),
                    version: native.version,
                    group_id: native.group_id.clone(),
                    sender_id: native.sender_id.clone(),
                    group_key_epoch: native.group_key_epoch,
                    group_state_hash: native.group_state_hash.clone(),
                    sender_key_seed: native.sender_key_seed.to_vec(),
                    sender_key_signature: native.sender_key_signature.clone(),
                    sender_device_signing_public_key: native
                        .sender_device_signing_public_key
                        .clone(),
                };
                native.sender_key_seed.zeroize();
                Ok::<_, SdkError>(generated)
            })
            .transpose()?;
        let control = SeedControl(g::Control {
            operation: 4,
            payload: Some(g::control::Payload::GroupState(g::GroupStateControl {
                schema: super::bootstrap::PACKET_SCHEMA.into(),
                body: Some(g::GroupControlBody {
                    value: Some(g::group_control_body::Value::Snapshot(
                        g::GroupControlBodySnapshot {
                            snapshot: Some(g::NativeGroupSnapshot {
                                canonical: ramflux_protocol::decode_base64url(
                                    &packet.snapshot_base64,
                                )
                                .map_err(|_| invalid("snapshot encoding invalid"))?,
                            }),
                            distribution,
                        },
                    )),
                }),
            })),
        });
        self.generated_snapshot_inner(state, &control)
    }

    fn generated_snapshot_inner(
        &self,
        state: &ramflux_crypto::VerifiedGroupState,
        control: &g::Control,
    ) -> Result<Vec<u8>, SdkError> {
        let own = self.owned_device_identity()?;
        let epoch = self.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?.device_epoch;
        let key = format!(
            "group-state/generated-identity/{}/{}/{}/{}",
            ramflux_protocol::encode_base64url(&state.view().group_id),
            own.storage_key(),
            epoch,
            ramflux_protocol::hash_base64url(
                "ramflux.group-state.generated-control.v1",
                &control.encode_to_vec()
            )
        );
        let db = self.account_db()?;
        db.write_transaction(|| {
            let identity = if let Some(identity) = db.load_actor_state::<g::EventIdentity>(&key)? {
                identity
            } else {
                let mut identity = self.allocate_generated_identity(
                    &state.view().conversation_id,
                    crate::client::generated_identity::now_ms(),
                    false,
                )?;
                identity.group_id = Some(state.view().group_id.clone());
                identity.group_epoch = Some(state.view().epoch);
                db.persist_actor_state(&key, &identity)?;
                identity
            };
            let bytes = g::Inner {
                layer: g::registry::COMPILED_LAYER,
                kind: 8,
                identity: Some(identity),
                body: control.encode_to_vec(),
            }
            .encode_to_vec();
            g::validation::scan_inner(&bytes).map_err(|_| invalid("snapshot encoding invalid"))?;
            Ok(bytes)
        })
    }
}

impl crate::RamfluxClient {
    pub(crate) fn shared_group_packet_message_id(
        bytes: &[u8],
        fallback: &str,
    ) -> Result<String, SdkError> {
        if !crate::client::target_selection::schema_v1_selected() {
            return Ok(fallback.into());
        }
        let inner = g::Inner::decode(bytes).map_err(|_| invalid("snapshot identity missing"))?;
        let identity =
            inner.identity.as_ref().ok_or_else(|| invalid("snapshot identity missing"))?;
        g::identity::verify(identity).map_err(|_| invalid("snapshot identity invalid"))?;
        Ok(ramflux_protocol::encode_base64url(&identity.id))
    }
}

pub(super) struct SeedControl(pub(super) g::Control);
impl std::ops::Deref for SeedControl {
    type Target = g::Control;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
impl Drop for SeedControl {
    fn drop(&mut self) {
        if let Some(g::control::Payload::GroupState(state)) = self.0.payload.as_mut()
            && let Some(g::group_control_body::Value::Snapshot(snapshot)) =
                state.body.as_mut().and_then(|body| body.value.as_mut())
            && let Some(distribution) = snapshot.distribution.as_mut()
        {
            distribution.sender_key_seed.zeroize();
        }
    }
}

pub(super) struct NativeDistribution(pub(super) SdkGroupSenderKeyDistribution);
impl std::ops::Deref for NativeDistribution {
    type Target = SdkGroupSenderKeyDistribution;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
impl Drop for NativeDistribution {
    fn drop(&mut self) {
        self.0.sender_key_seed.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::native_test_support::{Fixture, TestResult};

    fn frame(
        source: &Fixture,
        canonical: Vec<u8>,
        distribution: Option<g::GroupKeyDistribution>,
    ) -> TestResult<Vec<u8>> {
        let mut identity =
            source.client.allocate_generated_identity("snapshot-thread", 1000, false)?;
        identity.group_id = Some("snapshot-group".into());
        identity.group_epoch = Some(1);
        Ok(g::Inner {
            layer: g::registry::COMPILED_LAYER,
            kind: 8,
            identity: Some(identity),
            body: g::Control {
                operation: 4,
                payload: Some(g::control::Payload::GroupState(g::GroupStateControl {
                    schema: super::super::bootstrap::PACKET_SCHEMA.into(),
                    body: Some(g::GroupControlBody {
                        value: Some(g::group_control_body::Value::Snapshot(
                            g::GroupControlBodySnapshot {
                                snapshot: Some(g::NativeGroupSnapshot { canonical }),
                                distribution,
                            },
                        )),
                    }),
                })),
            }
            .encode_to_vec(),
        }
        .encode_to_vec())
    }

    #[tokio::test]
    async fn generated_snapshot_roundtrip_requires_exact_canonical_state_and_seed_grammar()
    -> TestResult {
        let _gate = ramflux_protocol::schema_profile::SchemaV1LiveGuard::enter();
        let source = Box::pin(Fixture::new("generated-snapshot-owner")).await?;
        let primary = source
            .client
            .born_v3_account
            .as_ref()
            .ok_or("account")?
            .group_primary(source.vault.as_ref())?;
        source.client.shared_group_create_with_primary(
            "snapshot-group",
            "snapshot-thread",
            None,
            &source.config.target_delivery_id,
            Some(&primary),
        )?;
        let state =
            source.client.account_db()?.shared_group_state("snapshot-group")?.ok_or("state")?;
        let canonical = ramflux_protocol::canonical_json_bytes(state.snapshot())?;
        let bytes = frame(&source, canonical.clone(), None)?;
        assert!(
            super::super::generated::decode(&bytes)?.is_none(),
            "snapshot never uses mutation codec"
        );
        let decoded = super::super::bootstrap::decode_packet(&bytes)?.ok_or("snapshot")?;
        assert_eq!(decoded.snapshot(), state.snapshot());
        assert!(matches!(
            source.client.prepare_shared_group_payload(decoded, &bytes)?,
            super::super::bootstrap::PreparedSharedGroup::Snapshot(_)
        ));
        let raw = Zeroizing::new(
            source.client.export_group_sender_key_distribution("snapshot-group", "primary")?,
        );
        let mut native: SdkGroupSenderKeyDistribution = ramflux_protocol::parse_i_json(&raw)?;
        let distribution = g::GroupKeyDistribution {
            schema: native.schema.clone(),
            version: native.version,
            group_id: native.group_id.clone(),
            sender_id: native.sender_id.clone(),
            group_key_epoch: native.group_key_epoch,
            group_state_hash: native.group_state_hash.clone(),
            sender_key_seed: native.sender_key_seed.to_vec(),
            sender_key_signature: native.sender_key_signature.clone(),
            sender_device_signing_public_key: native.sender_device_signing_public_key.clone(),
        };
        native.sender_key_seed.zeroize();
        let valid = frame(&source, canonical.clone(), Some(distribution.clone()))?;
        source.client.prepare_shared_group_payload(state.clone(), &valid)?;
        for index in 0..5 {
            let mut altered = distribution.clone();
            match index {
                0 => altered.sender_id = "other-device".into(),
                1 => altered.group_key_epoch += 1,
                2 => altered.group_state_hash = Some("other-head".into()),
                3 => altered.sender_key_seed[0] ^= 1,
                _ => altered.sender_key_signature = Some("invalid".into()),
            }
            let bytes = frame(&source, canonical.clone(), Some(altered))?;
            assert!(
                source.client.prepare_shared_group_payload(state.clone(), &bytes).is_err(),
                "tampered distribution {index}"
            );
        }
        let mut spaced = canonical.clone();
        spaced.push(b' ');
        assert!(decode(&frame(&source, spaced, None)?).is_err());
        assert!(decode(&frame(&source, Vec::new(), None)?).is_err());
        assert!(
            decode(&frame(&source, canonical.clone(), Some(g::GroupKeyDistribution::default()))?)
                .is_err()
        );
        for size in [0, 31, 33] {
            let distribution = g::GroupKeyDistribution {
                schema: "ramflux.sdk.group_sender_key.distribution.v4".into(),
                version: 4,
                group_id: "snapshot-group".into(),
                sender_id: "primary".into(),
                group_key_epoch: 1,
                sender_key_seed: vec![1; size],
                ..Default::default()
            };
            assert!(decode(&frame(&source, canonical.clone(), Some(distribution))?).is_err());
        }
        Ok(())
    }

    #[tokio::test]
    async fn generated_snapshot_recipient_keys_and_invitation_do_not_install_before_consent()
    -> TestResult {
        let _gate = ramflux_protocol::schema_profile::SchemaV1LiveGuard::enter();
        let source = Box::pin(Fixture::new("snapshot-consent-source")).await?;
        let receiver = Box::pin(Fixture::new("snapshot-consent-receiver")).await?;
        source.client.persist_fetched_identity_directory(&receiver.manifest)?;
        receiver.client.persist_fetched_identity_directory(&source.manifest)?;
        let primary = source
            .client
            .born_v3_account
            .as_ref()
            .ok_or("account")?
            .group_primary(source.vault.as_ref())?;
        source.client.shared_group_create_with_primary(
            "snapshot-group",
            "snapshot-thread",
            None,
            &source.config.target_delivery_id,
            Some(&primary),
        )?;
        source.client.shared_group_change_with_primary(
            "snapshot-group",
            &source.config.target_delivery_id,
            ramflux_protocol::GroupStateChange::Add {
                member: receiver
                    .client
                    .owned_group_actor(&receiver.config.target_delivery_id)?
                    .identity,
                role: ramflux_protocol::SharedGroupRole::Member,
            },
            Some(&primary),
        )?;
        let state =
            source.client.account_db()?.shared_group_state("snapshot-group")?.ok_or("state")?;
        let recipient = receiver.client.owned_device_identity()?;
        let bytes =
            Zeroizing::new(source.client.shared_group_packet_for_recipient(&state, &recipient)?);
        let retry =
            Zeroizing::new(source.client.shared_group_packet_for_recipient(&state, &recipient)?);
        assert_eq!(*bytes, *retry, "retry preserves the logical EventIdentity");
        let packet = decode(&bytes)?.ok_or("typed snapshot")?;
        assert!(packet.distribution_base64.is_some());
        assert!(receiver.client.group_snapshot_requires_consent(&state)?);
        receiver.client.prepare_shared_group_payload(state.clone(), &bytes)?;
        receiver.client.apply_prepared_shared_group(
            &super::super::bootstrap::PreparedSharedGroup::Invitation {
                state: state.clone(),
                body: Zeroizing::new(bytes.to_vec()),
            },
            &receiver.config.target_delivery_id,
        )?;
        assert!(receiver.client.account_db()?.shared_group_state("snapshot-group")?.is_none());
        assert!(receiver.client.group_snapshot_requires_consent(&state)?);
        source.client.shared_group_change_with_primary(
            "snapshot-group",
            &source.config.target_delivery_id,
            ramflux_protocol::GroupStateChange::Remove {
                root_commitment: recipient.root_commitment().into(),
                device_id: recipient.device_id().into(),
            },
            Some(&primary),
        )?;
        let removed =
            source.client.account_db()?.shared_group_state("snapshot-group")?.ok_or("removed")?;
        let terminal =
            Zeroizing::new(source.client.shared_group_packet_for_recipient(&removed, &recipient)?);
        assert!(
            decode(&terminal)?.ok_or("terminal snapshot")?.distribution_base64.is_none(),
            "terminal recipient never receives seed bytes"
        );
        Ok(())
    }
}

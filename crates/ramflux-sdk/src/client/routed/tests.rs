// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use super::*;
use crate::client::identity_authority::HeadUse;
fn assert_a2i_authority_refused<T>(result: Result<T, SdkError>) {
    let error = result.err();
    assert!(
        matches!(
            &error,
            Some(SdkError::GeneratedRefused {
                code: crate::error::GeneratedRefusalCode::Authority,
                ..
            })
        ),
        "A2I authority refusal missing: {error:?}"
    );
}

struct Fixture {
    client: RamfluxClient,
    id: String,
    root: ramflux_test_support::TestPath,
    native: Option<Box<crate::client::native_test_support::Fixture>>,
}
impl Fixture {
    fn new(id: &str, seed: u8) -> Result<Self, SdkError> {
        Self::owned(id, id, seed, seed + 1)
    }
    fn owned(id: &str, principal: &str, root_seed: u8, device_seed: u8) -> Result<Self, SdkError> {
        Self::owned_epoch(id, principal, root_seed, device_seed, 1)
    }
    fn owned_epoch(
        id: &str,
        principal: &str,
        root_seed: u8,
        device_seed: u8,
        epoch: u64,
    ) -> Result<Self, SdkError> {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let sequence = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let now = SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |time| time.as_nanos());
        let root = ramflux_test_support::TestPath::new()
            .expect("test: allocate fixture directory")
            .child(format!("ramflux-routed-{id}-{}-{sequence}-{now}", std::process::id()));
        let mut client = RamfluxClient::new();
        client.create_identity_root(principal, [root_seed; 32]);
        client.create_device_branch(principal, id, epoch, [device_seed; 32]);
        client.open_account_index(&root)?;
        client.create_account(id, id)?;
        client.unlock_account(id, b"routed-test")?;
        client.initialize_and_publish_prekey_bundle(principal, id, id, [device_seed; 32], None)?;
        Ok(Self { root, client, id: id.to_owned(), native: None })
    }
    async fn native(id: &str, _seed: u8) -> Result<Self, SdkError> {
        let mut fixture =
            Box::pin(crate::client::native_test_support::Fixture::with_device(id, id))
                .await
                .map_err(|error| invalid(&format!("native routed fixture: {error}")))?;
        let client = std::mem::take(&mut fixture.client);
        Ok(Self {
            root: fixture.root.0.clone(),
            client,
            id: id.into(),
            native: Some(Box::new(fixture)),
        })
    }
    async fn native_named(id: &str, _seed: u8) -> Result<Self, SdkError> {
        let mut fixture =
            Box::pin(crate::client::native_test_support::Fixture::with_principal(id, id, id))
                .await
                .map_err(|error| invalid(&format!("native named fixture: {error}")))?;
        let client = std::mem::take(&mut fixture.client);
        Ok(Self {
            root: fixture.root.0.clone(),
            client,
            id: id.into(),
            native: Some(Box::new(fixture)),
        })
    }
    async fn native_principal(id: &str, principal: &str) -> Result<Self, SdkError> {
        let mut fixture = Box::pin(crate::client::native_test_support::Fixture::with_principal(
            id, id, principal,
        ))
        .await
        .map_err(|error| invalid(&format!("native principal fixture: {error}")))?;
        let client = std::mem::take(&mut fixture.client);
        Ok(Self {
            root: fixture.root.0.clone(),
            client,
            id: id.into(),
            native: Some(Box::new(fixture)),
        })
    }
    async fn native_same_home(source: &Self, id: &str) -> Result<Self, SdkError> {
        let mut fixture = source
            .native
            .as_ref()
            .ok_or_else(|| invalid("native source"))?
            .peer_at_same_home(id, id, id)
            .await
            .map_err(|error| invalid(&format!("native shared home: {error}")))?;
        let client = std::mem::take(&mut fixture.client);
        Ok(Self {
            root: fixture.root.0.clone(),
            client,
            id: id.into(),
            native: Some(Box::new(fixture)),
        })
    }
    async fn reopen_native(&mut self) -> Result<(), SdkError> {
        let vault = self.native.as_ref().ok_or_else(|| invalid("native fixture"))?.vault.clone();
        self.client.active_account_db = None;
        self.client.unlock_account(&self.id, b"native fixture data passphrase")?;
        self.client.initialize_born_v3_branch(&self.id, vault).await?;
        self.client.persist_fetched_identity_directory(&self.manifest()?)?;
        Ok(())
    }
    fn create_shared_group(
        &self,
        group: &str,
        conversation: &str,
    ) -> Result<ramflux_crypto::VerifiedGroupState, SdkError> {
        let native = self.native.as_ref().ok_or_else(|| invalid("native group fixture"))?;
        let primary = self
            .client
            .born_v3_account
            .as_ref()
            .ok_or(SdkError::CustodySetupInvalid)?
            .group_primary(native.vault.as_ref())?;
        self.client.shared_group_create_with_primary(
            group,
            conversation,
            None,
            &self.config()?.target_delivery_id,
            Some(&primary),
        )
    }
    fn change_shared_group(
        &self,
        group: &str,
        change: ramflux_protocol::GroupStateChange,
    ) -> Result<ramflux_crypto::VerifiedGroupState, SdkError> {
        let native = self.native.as_ref().ok_or_else(|| invalid("native group fixture"))?;
        let primary = self
            .client
            .born_v3_account
            .as_ref()
            .ok_or(SdkError::CustodySetupInvalid)?
            .group_primary(native.vault.as_ref())?;
        self.client.shared_group_change_with_primary(
            group,
            &self.config()?.target_delivery_id,
            change,
            Some(&primary),
        )
    }
    fn manifest(&self) -> Result<SdkDeviceManifestResponse, SdkError> {
        if let Some(native) = &self.native {
            return Ok(native.manifest.clone());
        }
        crate::client::identity_authority::test_support::manifest(&self.client)
    }
    fn reference(&self) -> Result<String, SdkError> {
        self.client.local_device_reference(&self.id)
    }
    fn config(&self) -> Result<GatewaySessionConfig, SdkError> {
        if let Some(native) = &self.native {
            let mut config = native.config.clone().with_account_identity(&self.client)?;
            config.device_branch = Some(std::sync::Arc::new(
                self.client.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?.clone(),
            ));
            config.source_identity = Some(self.client.owned_device_identity()?);
            return Ok(config);
        }
        GatewaySessionConfig::quic(GatewayQuicEndpointConfig {
            bind_addr: "127.0.0.1:0".parse().map_err(|_| invalid("address"))?,
            gateway_addr: "127.0.0.1:1".parse().map_err(|_| invalid("address"))?,
            server_name: "test".to_owned(),
            ca_cert: self.root.join("ca.pem"),
            principal_id: self
                .client
                .device_branch
                .as_ref()
                .ok_or(SdkError::IdentityRootMissing)?
                .principal_id
                .clone(),
            device_id: self.id.clone(),
            target_delivery_id: self.id.clone(),
            prekey_http_url: None,
        })
        .with_account_identity(&self.client)
    }
}
// Resolve the explicit principal convention of each fixture, never a by-name candidate.
// Native fixture accounts publish principal-<device>; primitive fixtures share both names.
fn fixture_peer_reference(client: &RamfluxClient, principal: &str) -> Result<String, SdkError> {
    let principal_id = if client.born_v3_account.is_some() {
        format!("principal-{principal}")
    } else {
        principal.into()
    };
    let owner = client
        .account_db()?
        .client_record("identity", &principal_id)?
        .ok_or_else(|| invalid("fixture peer identity"))?;
    let root = owner["contact_identity_commitment"]
        .as_str()
        .ok_or_else(|| invalid("fixture peer root"))?;
    Ok(ramflux_protocol::qualified_device_id(root, principal)?)
}
// Fixture callers name the intended member explicitly; no directory name lookup grants authority.
fn fixture_member(client: &RamfluxClient, group: &str, member: &Fixture) -> Result<(), SdkError> {
    let manifest = member.manifest()?;
    client.observe_device_manifest_json(
        serde_json::to_value(&manifest)?,
        &manifest.principal_commitment,
    )?;
    client.add_group_member(group, &member.reference()?, "member")?;
    Ok(())
}
fn fixture_group(client: &RamfluxClient, group: &str, owner: &Fixture) -> Result<(), SdkError> {
    let manifest = owner.manifest()?;
    client.observe_device_manifest_json(
        serde_json::to_value(&manifest)?,
        &manifest.principal_commitment,
    )?;
    client.create_group(group, &owner.reference()?)?;
    Ok(())
}
fn message(id: &str, conversation: &str) -> GatewayDirectMessage {
    GatewayDirectMessage {
        conversation_id: conversation.to_owned(),
        message_id: id.to_owned(),
        envelope_id: id.to_owned(),
        source_principal_id: "alice".to_owned(),
        sender_id: "alice".to_owned(),
        recipient_device_id: Some("bob".to_owned()),
        recipient_principal_commitment: None,
        target_delivery_id: "bob".to_owned(),
        encrypted_body: Vec::new(),
        created_at: now_unix_timestamp(),
        ttl: 3600,
    }
}
struct GeneratedDelivery {
    conversation: String,
    message: String,
    entry: GatewayInboxEntry,
}
fn generated_delivery(
    sender: &Fixture,
    receiver: &Fixture,
    operation: &str,
    text: &str,
) -> Result<GeneratedDelivery, SdkError> {
    review::trust(sender, receiver)?;
    review::trust(receiver, sender)?;
    let own = sender.config()?;
    let target = receiver.config()?;
    let conversation = sender
        .client
        .generated_direct_conversation_id(&receiver.client.owned_device_identity()?)?;
    let mut request = GatewayDirectMessage {
        conversation_id: conversation.clone(),
        message_id: operation.into(),
        envelope_id: format!("wire-{operation}"),
        source_principal_id: own.principal_id.clone(),
        sender_id: own.device_id.clone(),
        recipient_device_id: Some(target.device_id.clone()),
        recipient_principal_commitment: Some(receiver.client.own_account_anchor()?),
        target_delivery_id: target.target_delivery_id.clone(),
        encrypted_body: Vec::new(),
        created_at: now_unix_timestamp(),
        ttl: sender.client.content_ttl()?,
    };
    let prepared = sender.client.prepare_authored_message(
        &mut request,
        None,
        &ramflux_protocol::message::Message { text: text.into(), ..Default::default() },
    )?;
    let message = request.message_id.clone();
    let (mut request, sealed) =
        seal_native_fixture(sender, receiver, request, &prepared.wire, Route::direct())?;
    let envelope = crate::dm::gateway_generated_envelope_from_sealed(&own, &mut request, sealed)?;
    sender.client.project_authored_message(&request, &prepared.exact, &[])?;
    Ok(GeneratedDelivery {
        conversation,
        message,
        entry: GatewayInboxEntry {
            forwarded: false,
            inbox_seq: 1,
            target_delivery_id: target.target_delivery_id,
            envelope,
        },
    })
}

async fn receive_generated(
    receiver: &mut Fixture,
    entry: &GatewayInboxEntry,
) -> Result<(), SdkError> {
    let mut engine =
        GatewaySessionEngine::with_test_transport(receiver.config()?, Box::new(NoNetwork));
    receiver.client.apply_routed_entry(&mut engine, &review::pool()?, entry, false).await?;
    Ok(())
}

fn seal(
    sender: &Fixture,
    receiver: &Fixture,
    message: GatewayDirectMessage,
    body: &[u8],
) -> Result<GatewayInboxEntry, SdkError> {
    seal_as(sender, receiver, message, body, Route::direct())
}
fn seal_nested(
    sender: &Fixture,
    receiver: &Fixture,
    mut message: GatewayDirectMessage,
    body: &[u8],
    route: Route,
) -> Result<(GatewayDirectMessage, SealedRouted), SdkError> {
    if receiver
        .client
        .account_db()?
        .client_record("device", &sender.client.local_device_reference(&sender.id)?)?
        .is_none()
    {
        review::trust(receiver, sender)?;
    }
    if sender
        .client
        .account_db()?
        .client_record("device", &receiver.client.local_device_reference(&receiver.id)?)?
        .is_none()
    {
        review::trust(sender, receiver)?;
    }
    message.recipient_principal_commitment = Some(receiver.client.own_account_anchor()?);
    if let Some(native) = &receiver.native {
        message.target_delivery_id = native.config.target_delivery_id.clone();
    }
    if sender.native.is_some() {
        return seal_native_fixture(sender, receiver, message, body, route);
    }
    let bundle = receiver
        .client
        .load_x3dh_private_state(&receiver.client.local_device_identity(&receiver.id)?)?
        .bundle;
    let hash = prekey_bundle_hash(&bundle)?;
    let existing = sender.client.send_pair_session_from_url(
        &sender.client.local_device_identity(&sender.id)?,
        &message,
        None,
    );
    let (mut session, header, hash) = if let Ok(value) = existing {
        value
    } else {
        let aad = associated_data(&message.envelope_id, &sender.id, &receiver.id, &hash)?;
        let (session, header) = sender.client.create_send_dm_session_with_aad(
            &message,
            &receiver.id,
            bundle,
            &sender.id,
            Some(&aad),
        )?;
        (session, header, hash)
    };
    let sealed = sender.client.seal_routed_with_route(
        &message,
        body,
        route,
        SealPair {
            local: &sender.id,
            remote: &receiver.reference()?,
            session: &mut session,
            header,
            bundle: hash,
        },
    )?;
    Ok((message, sealed))
}
fn seal_native_fixture(
    sender: &Fixture,
    receiver: &Fixture,
    mut message: GatewayDirectMessage,
    body: &[u8],
    route: Route,
) -> Result<(GatewayDirectMessage, SealedRouted), SdkError> {
    let config = sender.config()?;
    if message.source_principal_id == sender.id {
        message.source_principal_id.clone_from(&config.principal_id);
    }
    let recipient = receiver.client.owned_device_identity()?;
    let request = sender.client.routed_send_material_request(&config, &message)?;
    let material = SendMaterial {
        manifest: if request.root.is_some() {
            Some((recipient.root_commitment().into(), receiver.manifest()?))
        } else {
            None
        },
        bundle: if request.prekey.is_some() {
            Some(receiver.client.load_x3dh_private_state(&recipient)?.bundle)
        } else {
            None
        },
    };
    sender.client.account_db()?.write_transaction(|| {
        let (mut session, header, bundle) = sender.client.prepared_send_pair(
            &config,
            &message,
            material,
            crate::client::target_selection::kind_id_for_route(&route.kind),
        )?;
        let sealed = sender.client.seal_routed_with_route(
            &message,
            body,
            route,
            SealPair {
                local: &sender.id,
                remote: recipient.storage_key(),
                session: &mut session,
                header,
                bundle,
            },
        )?;
        Ok((message, sealed))
    })
}
fn seal_as(
    sender: &Fixture,
    receiver: &Fixture,
    message: GatewayDirectMessage,
    body: &[u8],
    route: Route,
) -> Result<GatewayInboxEntry, SdkError> {
    let (mut message, sealed) = super::report::with_invalid_header_fixture(|| {
        seal_nested(sender, receiver, message, body, route)
    })?;
    message.encrypted_body = serde_json::to_vec(&sealed.packet)?;
    let mut envelope = gateway_direct_message_envelope_sealed(
        &sender.config()?,
        &message,
        None,
        sealed.committed_a0.as_deref(),
    )?;
    crate::dm::add_message_metadata_commitment(
        &sender.config()?,
        &mut envelope,
        sealed.metadata_commitment,
    )?;
    // Adversarial fixtures can deliberately claim an owner the production sender cannot emit.
    envelope.source_principal_id.clone_from(&message.source_principal_id);
    envelope.signed.signature = ramflux_crypto::sign_protocol_object_with_device_branch(
        sender.client.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?,
        &envelope,
    )?;
    Ok(GatewayInboxEntry {
        forwarded: false,
        inbox_seq: 1,
        target_delivery_id: receiver.config()?.target_delivery_id,
        envelope,
    })
}

#[tokio::test(flavor = "current_thread")]
async fn first_unknown_conversation_decrypts_and_outer_frame_has_no_route()
-> crate::client::native_test_support::TestResult {
    use crate::client::native_test_support::{Fixture as Native, watchdog};
    watchdog::within(async {
        let source = Native::new("unknown-conversation-source").await?;
        let target = Native::new("unknown-conversation-target").await?;
        source.accept_peer(&target)?;
        target.accept_peer(&source)?;
        let conversation = ramflux_protocol::message::dm_scope::derive(
            &source.client.own_account_anchor()?,
            &target.client.own_account_anchor()?,
        )?;
        let identity = source.client.allocate_generated_identity(
            &conversation,
            crate::client::generated_identity::now_ms(),
            false,
        )?;
        let exact = RamfluxClient::encode_generated_inner(
            identity,
            &ramflux_protocol::message::Content {
                value: Some(ramflux_protocol::message::content::Value::Message(
                    ramflux_protocol::message::Message {
                        text: "hello first generated message".into(),
                        erasure_nonce: ramflux_crypto::random_32()?.to_vec(),
                        ..Default::default()
                    },
                )),
            },
        )?;
        let envelope = source.seal_inner_to(&target, &exact)?;
        let entry = GatewayInboxEntry {
            forwarded: false,
            inbox_seq: 1,
            target_delivery_id: target.config.target_delivery_id.clone(),
            envelope,
        };
        let opened = target.client.open_routed(&entry, &target.config.device_id)?;
        assert_eq!(opened.routing.conversation_id, conversation);
        assert_eq!(opened.body.as_slice(), exact);
        let outer = serde_json::to_string(&entry.envelope)?;
        assert!(!outer.contains(&conversation));
        let wrapper = ramflux_protocol::decode_base64url(&entry.envelope.encrypted_payload)?;
        assert!(!String::from_utf8_lossy(&wrapper).contains(&conversation));
        assert!(!String::from_utf8_lossy(&wrapper).contains("hello first generated message"));
        Ok(())
    })
    .await?
}

fn assert_compact_frame_admitted(entry: &GatewayInboxEntry) -> Result<(), SdkError> {
    let decoded = ramflux_protocol::decode_base64url(&entry.envelope.encrypted_payload)
        .map_err(|_| invalid("payload"))?;
    assert!(decoded.starts_with(&ramflux_protocol::message::outer::COMPACT_CRYPTOBOX_MAGIC));
    let frame = ramflux_node_core::single_entry_frame_size(&entry.envelope)
        .map_err(|error| invalid(&error.to_string()))?;
    assert!(frame <= ramflux_node_core::ENTRY_FRAME_BYTE_CAP);
    ramflux_node_core::check_entry_bound(&entry.envelope)
        .map_err(|error| invalid(&error.to_string()))?;
    let sizes =
        ramflux_protocol::message::outer::IngressSizes::measure_wire(&entry.envelope, 0, &[], &[])
            .map_err(|error| invalid(&error.to_string()))?;
    ramflux_protocol::message::outer::check_ingress_caps(sizes)
        .map_err(|error| invalid(&error.to_string()))?;
    assert!(sizes.ciphertext_bytes < decoded.len());
    assert!(sizes.ciphertext_bytes <= ramflux_protocol::message::outer::MAX_CIPHERTEXT_BYTES);
    assert!(
        sizes.complete_frame_bytes <= ramflux_protocol::message::outer::MAX_COMPLETE_FRAME_BYTES
    );
    assert!(sizes.bootstrap_capsule_bytes > 0);
    assert_ne!(entry.envelope.source_device_id, "");
    assert_ne!(entry.envelope.source_device_id, "local");
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn fresh_receiver_commits_first_dm_and_replays_without_ratchet_advance()
-> crate::client::native_test_support::TestResult {
    use crate::client::native_test_support::{Fixture as Native, watchdog};
    watchdog::within(async {
        let source = Native::new("first-commit-source").await?;
        let mut target = Native::new("first-commit-target").await?;
        source.accept_peer(&target)?;
        target.accept_peer(&source)?;
        let conversation = ramflux_protocol::message::dm_scope::derive(
            &source.client.own_account_anchor()?,
            &target.client.own_account_anchor()?,
        )?;
        assert_eq!(target.client.direct_messages(&conversation)?.len(), 0);
        let identity = source.client.allocate_generated_identity(
            &conversation,
            crate::client::generated_identity::now_ms(),
            false,
        )?;
        let id = ramflux_protocol::encode_base64url(&identity.id);
        let exact = RamfluxClient::encode_generated_inner(
            identity,
            &ramflux_protocol::message::Content {
                value: Some(ramflux_protocol::message::content::Value::Message(
                    ramflux_protocol::message::Message {
                        text: "first committed generated message".into(),
                        erasure_nonce: ramflux_crypto::random_32()?.to_vec(),
                        ..Default::default()
                    },
                )),
            },
        )?;
        let envelope = source.seal_inner_to(&target, &exact)?;
        target.receive(envelope.clone(), 1).await?;
        assert_eq!(
            target.client.generated_message_detail(&conversation, &id)?.message.text.as_deref(),
            Some("first committed generated message")
        );
        let checkpoint = target.client.persisted_pair_snapshot(
            &target.client.owned_device_identity()?,
            &source.client.owned_device_identity()?,
        )?;
        target.receive(envelope, 1).await?;
        assert_eq!(target.client.direct_messages(&conversation)?.len(), 1);
        assert_eq!(
            target.client.persisted_pair_snapshot(
                &target.client.owned_device_identity()?,
                &source.client.owned_device_identity()?
            )?,
            checkpoint,
            "replaying the exact first envelope advanced the native receive ratchet"
        );
        Ok(())
    })
    .await?
}
struct NoNetwork;
impl ramflux_transport::GatewaySessionFrameSink for NoNetwork {
    fn send_frame<'a>(
        &'a mut self,
        _: &'a [u8],
    ) -> std::pin::Pin<
        Box<dyn Future<Output = Result<(), ramflux_transport::TransportError>> + Send + 'a>,
    > {
        Box::pin(async {
            Err(ramflux_transport::TransportError::Quic("unexpected network".to_owned()))
        })
    }
    fn finish(&mut self) -> Result<(), ramflux_transport::TransportError> {
        Ok(())
    }
}
impl ramflux_transport::GatewaySessionFrameSource for NoNetwork {
    fn recv_frame(
        &mut self,
    ) -> std::pin::Pin<
        Box<dyn Future<Output = Result<Vec<u8>, ramflux_transport::TransportError>> + Send + '_>,
    > {
        Box::pin(async {
            Err(ramflux_transport::TransportError::Quic("unexpected network".to_owned()))
        })
    }
}

#[tokio::test(flavor = "current_thread")]
async fn group_control_and_message_route_without_conversation_hint_and_reject_conflicting_link()
-> Result<(), SdkError> {
    use ramflux_protocol::message as g;
    let a = Fixture::native_named("alice", 101).await?;
    let mut b = Fixture::native_named("bob", 111).await?;
    let group = "private-group";
    let conversation = "private-group-conversation";
    effect_marker_tests::group_ready(&a, &mut b, group)?;
    let control = effect_marker_tests::group_control_entry(&a, &b, group, conversation)?;
    let outer = serde_json::to_string(&control)?;
    assert!(!outer.contains(conversation));
    assert!(!outer.contains(group));
    let mut engine = GatewaySessionEngine::with_test_transport(b.config()?, Box::new(NoNetwork));
    let delivery =
        b.client.apply_routed_entry(&mut engine, &review::pool()?, &control, false).await?;
    assert_eq!(delivery.routing.ok_or_else(|| invalid("control route"))?.kind, Kind::GroupControl);
    let identity = a.client.allocate_generated_identity(
        conversation,
        crate::client::generated_identity::now_ms(),
        false,
    )?;
    let id = ramflux_protocol::encode_base64url(&identity.id);
    let exact = a.client.encrypt_generated_group_inner(
        group,
        &a.id,
        identity,
        &g::Message { text: "private group text".into(), ..Default::default() },
    )?;
    let mut entry =
        effect_marker_tests::generated_control_entry(&a, &b, &exact, Route::group_message(group))?;
    entry.inbox_seq = 2;
    let delivery =
        b.client.apply_routed_entry(&mut engine, &review::pool()?, &entry, false).await?;
    assert_eq!(delivery.routing.ok_or_else(|| invalid("message route"))?.kind, Kind::GroupMessage);
    assert_eq!(
        b.client.generated_message_detail(conversation, &id)?.message.text.as_deref(),
        Some("private group text")
    );
    let mut metadata = b
        .client
        .account_db()?
        .client_record("group", group)?
        .ok_or_else(|| invalid("group record"))?;
    metadata["conversation_id"] = serde_json::json!("conflicting-conversation");
    metadata["conversation_ids"] = serde_json::json!(["conflicting-conversation"]);
    b.client.account_db()?.persist_client_record("group", group, &metadata)?;
    let identity = a.client.allocate_generated_identity(
        conversation,
        crate::client::generated_identity::now_ms(),
        false,
    )?;
    let exact = a.client.encrypt_generated_group_inner(
        group,
        &a.id,
        identity,
        &g::Message { text: "second group text".into(), ..Default::default() },
    )?;
    let mut next =
        effect_marker_tests::generated_control_entry(&a, &b, &exact, Route::group_message(group))?;
    next.inbox_seq = 3;
    assert!(
        b.client.apply_routed_entry(&mut engine, &review::pool()?, &next, false).await.is_err()
    );
    assert_eq!(b.client.direct_messages(conversation)?.len(), 1);
    Ok(())
}

struct ReceivingGateway {
    queued: VecDeque<GatewayServerFrame>,
    entry: Option<GatewayInboxEntry>,
    last: Option<GatewayClientFrame>,
    reader: AccountDb,
    receipt_key: String,
    acks: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    mailbox: String,
}
impl ramflux_transport::GatewaySessionFrameSink for ReceivingGateway {
    fn send_frame<'a>(
        &'a mut self,
        bytes: &'a [u8],
    ) -> std::pin::Pin<
        Box<dyn Future<Output = Result<(), ramflux_transport::TransportError>> + Send + 'a>,
    > {
        Box::pin(async move {
            let frame: GatewayClientFrame = serde_json::from_slice(bytes)
                .map_err(|e| ramflux_transport::TransportError::Quic(e.to_string()))?;
            if let GatewayClientFrame::Ack { .. } = &frame {
                assert!(
                    self.reader
                        .load_actor_state::<super::committed::Committed>(&self.receipt_key)
                        .map_err(|e| ramflux_transport::TransportError::Quic(e.to_string()))?
                        .is_some(),
                    "ACK preceded the durable receive commit"
                );
                self.acks.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            }
            self.last = Some(frame);
            Ok(())
        })
    }
    fn finish(&mut self) -> Result<(), ramflux_transport::TransportError> {
        Ok(())
    }
}
impl ramflux_transport::GatewaySessionFrameSource for ReceivingGateway {
    fn recv_idle_frame(&mut self) -> ramflux_transport::GatewaySessionFrameFuture<'_, Vec<u8>> {
        // This fixture emits solicited replies only; an idle reader waits for a request.
        Box::pin(std::future::pending())
    }

    fn recv_frame(
        &mut self,
    ) -> std::pin::Pin<
        Box<dyn Future<Output = Result<Vec<u8>, ramflux_transport::TransportError>> + Send + '_>,
    > {
        Box::pin(async move {
            if let Some(frame) = self.queued.pop_front() {
                return serde_json::to_vec(&frame)
                    .map_err(|e| ramflux_transport::TransportError::Quic(e.to_string()));
            }
            let frame = match self.last.take() {
                Some(GatewayClientFrame::Heartbeat { now }) => {
                    GatewayServerFrame::Heartbeat { now }
                }
                Some(GatewayClientFrame::Resume { .. }) => {
                    GatewayServerFrame::Resume { entries: self.entry.take().into_iter().collect() }
                }
                Some(GatewayClientFrame::Ack { ack }) => {
                    self.queued.push_back(GatewayServerFrame::Cursor { cursor: None });
                    GatewayServerFrame::Ack {
                        cursor: GatewayCursor {
                            target_delivery_id: self.mailbox.clone(),
                            inbox_seq: 1,
                            last_envelope_id: Some(ack.envelope_id.clone()),
                            acked_envelope_ids: vec![ack.envelope_id],
                            nacked_envelope_ids: BTreeMap::new(),
                        },
                    }
                }
                _ => GatewayServerFrame::Nack { reason: "unexpected frame".to_owned() },
            };
            serde_json::to_vec(&frame)
                .map_err(|e| ramflux_transport::TransportError::Quic(e.to_string()))
        })
    }
}
#[tokio::test(flavor = "current_thread")]
async fn generated_receive_acks_after_commit_and_serves_durable_reader()
-> crate::client::native_test_support::TestResult {
    use crate::client::native_test_support::{Fixture as Native, watchdog};
    use ramflux_protocol::message as g;
    watchdog::within(async {
        let a = Native::with_principal("alice", "alice", "alice").await?;
        let b = Native::with_principal("bob", "bob", "bob").await?;
        a.accept_peer(&b)?;
        b.accept_peer(&a)?;
        let conversation =
            g::dm_scope::derive(&a.client.own_account_anchor()?, &b.client.own_account_anchor()?)?;
        let mut message = GatewayDirectMessage {
            conversation_id: conversation.clone(),
            message_id: "ack-operation".into(),
            envelope_id: "ack-wire".into(),
            source_principal_id: a.config.principal_id.clone(),
            sender_id: a.config.device_id.clone(),
            recipient_device_id: Some(b.config.device_id.clone()),
            recipient_principal_commitment: Some(b.client.own_account_anchor()?),
            target_delivery_id: b.config.target_delivery_id.clone(),
            encrypted_body: Vec::new(),
            created_at: now_unix_timestamp(),
            ttl: a.client.content_ttl()?,
        };
        let prepared = a.client.prepare_authored_message(
            &mut message,
            None,
            &g::Message { text: "committed before native ACK".into(), ..Default::default() },
        )?;
        let envelope = a.seal_inner_to_with_id(&b, &prepared.wire, &message.envelope_id)?;
        let entry = GatewayInboxEntry {
            forwarded: false,
            inbox_seq: 1,
            target_delivery_id: b.config.target_delivery_id.clone(),
            envelope,
        };
        let acks = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let engine = GatewaySessionEngine::with_test_transport(
            b.config.clone(),
            Box::new(ReceivingGateway {
                queued: VecDeque::new(),
                receipt_key: b
                    .client
                    .authenticated_committed_key(HeadUse::NewAuthorization, &entry)?,
                entry: Some(entry),
                last: None,
                reader: b.client.account_db()?.open_reader()?,
                acks: std::sync::Arc::clone(&acks),
                mailbox: b.config.target_delivery_id.clone(),
            }),
        );
        let commitment = b.client.own_account_anchor()?;
        let mut state = LocalBusDaemonState {
            config: LocalBusConfig::new(b.root.0.join("bus.sock"), &b.root.0),
            nodes: crate::node::NodeStore::default(),
            account_index: None,
            accounts: BTreeMap::from([(
                "bob".to_owned(),
                LocalBusAccountState::new(b.client, engine, commitment),
            )]),
            active_account_id: Some("bob".into()),
            attended_accounts: BTreeSet::new(),
            subscribers: BTreeMap::new(),
        };
        let (tx, _rx) = mpsc::channel(8);
        let connection = LocalBusConnectionState::new(1, tx);
        let request = LocalBusFrame::request(
            "receive",
            Some("bob".into()),
            "message",
            "message.receive",
            serde_json::json!({"conversation_id":conversation,"limit":10}),
        );
        for _ in 0..2 {
            let reply = crate::bus::dispatch::message::dispatch_message_receive_request(
                &request,
                &mut state,
                &connection,
            )
            .await?;
            assert_eq!(reply.response_body["durable_reader"], "message.read");
            let client = &state.accounts.get("bob").ok_or("account")?.client;
            assert_eq!(
                client
                    .generated_message_detail(&conversation, &message.message_id)?
                    .message
                    .text
                    .as_deref(),
                Some("committed before native ACK")
            );
            assert_eq!(client.direct_messages(&conversation)?.len(), 1);
            assert_eq!(acks.load(std::sync::atomic::Ordering::SeqCst), 1);
        }
        Ok(())
    })
    .await?
}

#[path = "review_tests.rs"]
mod review;

#[path = "r4_tests.rs"]
mod r4;

#[path = "r5_tests.rs"]
mod r5;

#[path = "session_record_tests.rs"]
mod session_record;

#[path = "recovery_policy_tests.rs"]
mod recovery_policy;

#[path = "device_revocation_tests.rs"]
mod device_revocation;

#[path = "reset_refusal_tests.rs"]
mod reset_refusal;

#[path = "retirement_guard_tests.rs"]
mod retirement_guard;

#[path = "r9_tests.rs"]
mod r9;

#[path = "legacy_group_auth_tests.rs"]
mod legacy_group_auth;

#[path = "contact_resolution_tests.rs"]
mod contact_resolution;
#[path = "discovery_tests.rs"]
mod discovery;
#[path = "legacy_admission_tests.rs"]
mod legacy_admission;

#[path = "participant_tests.rs"]
mod participants;

#[path = "root_identity_keys_tests.rs"]
mod root_identity_keys;

#[path = "root_ack_tests.rs"]
mod root_ack;

#[path = "call_tests.rs"]
mod calls;
#[path = "recipient_context_tests.rs"]
mod recipient_context;

#[path = "backup_tests.rs"]
mod backup;

#[test]
fn r5_direct_messages_cannot_preclaim_group_ids() -> Result<(), SdkError> {
    let alice = Fixture::new("alice", 11)?;
    let bob = Fixture::new("bob", 21)?;
    let entry = seal(&alice, &bob, message("wire", "thread"), b"hello")?;
    let direct = bob.client.projection_id_for(&entry, "groupmsg:reserved")?;
    assert!(direct.starts_with("routed:"));
    Ok(())
}
#[test]
fn r5_legacy_group_messages_have_a_seven_day_upgrade_window() -> Result<(), SdkError> {
    let alice = Fixture::new("alice", 11)?;
    let bob = Fixture::new("bob", 21)?;
    let entry = seal(&alice, &bob, message("wire", "thread"), b"hello")?;
    let mut route = routing(&message("legacy", "thread"), Route::group_message("g"));
    route.group_message_id = None;
    let legacy = entry.clone();
    let start = legacy.envelope.created_at;
    let installed = bob
        .client
        .account_db()?
        .load_actor_state::<i64>("group-message/upgrade-start")?
        .ok_or(SdkError::IdentityRootMissing)?;
    assert!(installed <= start);
    bob.client.account_db()?.persist_actor_state("group-message/upgrade-start", &start)?;
    let actual = bob.client.projection_id(&legacy, &route)?;
    let source = bob.client.authenticated_device_identity(HeadUse::NewAuthorization, &legacy)?;
    assert_eq!(
        actual,
        ramflux_protocol::group_message_id(
            "g",
            source.root_commitment(),
            source.device_id(),
            &legacy.envelope.envelope_id
        )?
    );
    bob.client
        .account_db()?
        .persist_actor_state("group-message/upgrade-start", &(start - 8 * 86400))?;
    assert!(bob.client.projection_id(&legacy, &route).is_err());
    route.group_message_id = Some("modern".into());
    assert!(bob.client.projection_id(&legacy, &route).is_ok());
    Ok(())
}
#[tokio::test]
async fn r5_outsider_controls_are_rejected_before_directory_io() -> Result<(), SdkError> {
    use crate::client::shared_group::{GroupControlBody, GroupControlPacket};
    let outsider = Fixture::new("alice", 11)?;
    let owner = Fixture::new("bob", 21)?;
    owner.client.shared_group_create("g", "thread", None, "bob")?;
    let entry = seal(&outsider, &owner, message("outsider", "thread"), b"hello")?;
    let packet = GroupControlPacket::new(GroupControlBody::DeviceSet {
        group_id: "g".into(),
        actor: outsider.client.owned_group_actor("alice")?,
        device_set_epoch: 1,
    });
    let engine = GatewaySessionEngine::with_test_transport(owner.config()?, Box::new(NoNetwork));
    let route = routing(&message("outsider", "thread"), Route::group_control("g"));
    assert!(matches!(
        owner.client.prepare_group_control(&engine, &entry, &route, &packet).await,
        Err(SdkError::Storage(StorageError::GroupPermissionDenied))
    ));
    owner.client.shared_group_change(
        "g",
        "bob",
        ramflux_protocol::GroupStateChange::Add {
            member: outsider.client.owned_group_actor("alice")?.identity,
            role: ramflux_protocol::SharedGroupRole::Member,
        },
    )?;
    let key =
        format!("group-control:{}", outsider.client.owned_device_identity()?.root_commitment());
    for _ in 0..32 {
        assert!(owner.client.account_db()?.charge_contact_request(
            &key,
            32,
            60,
            now_unix_timestamp()
        )?);
    }
    assert!(matches!(owner.client.prepare_group_control(&engine, &entry, &route, &packet).await,
        Err(SdkError::InboundPending(reason)) if reason == "group control source rate exceeded"));
    Ok(())
}

#[path = "candidate_nested_decode_tests.rs"]
mod candidate_nested_decode;

#[path = "candidate_binding_tests.rs"]
mod candidate_binding;

#[path = "candidate_report_tests.rs"]
mod candidate_report;

#[path = "native_group_conversation_tests.rs"]
mod native_group_conversation;

#[path = "revocation_receive_tests.rs"]
mod revocation_receive_tests;

#[path = "effect_marker_tests.rs"]
mod effect_marker_tests;

#[test]
fn legacy_override_cannot_admit_v1_with_an_active_pair() -> Result<(), SdkError> {
    const CHILD: &str = "RAMFLUX_TEST_LEGACY_OVERRIDE_GUARD_CHILD";
    if std::env::var_os(CHILD).is_none() {
        let status = std::process::Command::new(std::env::current_exe()?)
            .args([
                "--exact",
                "client::routed::tests::legacy_override_cannot_admit_v1_with_an_active_pair",
                "--nocapture",
            ])
            .env(CHILD, "1")
            .env("RAMFLUX_ALLOW_LEGACY_V1", "1")
            .status()?;
        assert!(status.success(), "legacy override admitted a v1 path");
        return Ok(());
    }
    let alice = Fixture::new("alice", 21)?;
    let bob = Fixture::new("bob", 31)?;
    let _ = seal(&alice, &bob, message("current-pair", "thread"), b"current route")?;
    assert!(alice.client.v2_blocks_legacy(&bob.reference()?)?);
    Ok(())
}
#[path = "candidate_ephemeral_tests.rs"]
pub(super) mod candidate_ephemeral;

#[path = "native_pair_tests.rs"]
mod native_pair_tests;

#[path = "retired_receive_tests.rs"]
mod retired_receive;

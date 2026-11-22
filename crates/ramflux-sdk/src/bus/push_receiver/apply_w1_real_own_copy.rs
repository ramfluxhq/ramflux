// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Real generated own copies for the W1 receive tests: native source, peer and sibling
//! accounts; the entry is sealed by the sibling exactly as production seals it.
#![allow(clippy::expect_used)]

use crate::bus::connection_manager::ReceiveEntry;
use crate::bus::state::LocalBusAccountState;
use crate::client::native_test_support::{
    Fixture as Native, activation_send::tests::publish_layer_four, bus,
};
use crate::client::own_device_copy::OwnMessageInput;
use crate::client::routed::SendMaterial;
use crate::prelude::*;
use prost::Message as _;
use ramflux_protocol::message as g;
use ramflux_storage::{AccountDb, ObjectReferenceAdmission, ObjectReferenceOwner};
use serde_json::json;

/// Account id of the receiving device; `reopen` unlocks it again.
const ACCOUNT: &str = "sender";
type Case<T = ()> = Result<T, Box<dyn std::error::Error>>;

/// What the receiving account needs beside its own state: the sealed copy and the
/// sibling and peer accounts whose directories and roots must stay alive.
pub(super) struct Real {
    pub(super) entry: ReceiveEntry,
    /// The projected logical message id the sibling authored.
    pub(super) message: String,
    /// The canonical direct conversation of the copy.
    pub(super) conversation: String,
    _sibling: Box<LocalBusAccountState>,
    _peer: Box<LocalBusAccountState>,
}

struct Quiet;

impl ramflux_transport::GatewaySessionFrameSink for Quiet {
    fn send_frame<'a>(
        &'a mut self,
        _: &'a [u8],
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<Output = Result<(), ramflux_transport::TransportError>>
                + Send
                + 'a,
        >,
    > {
        Box::pin(async {
            Err(ramflux_transport::TransportError::Quic("test: unexpected network".into()))
        })
    }
    fn finish(&mut self) -> Result<(), ramflux_transport::TransportError> {
        Ok(())
    }
}

impl ramflux_transport::GatewaySessionFrameSource for Quiet {
    fn recv_frame(
        &mut self,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<Output = Result<Vec<u8>, ramflux_transport::TransportError>>
                + Send
                + '_,
        >,
    > {
        Box::pin(async {
            Err(ramflux_transport::TransportError::Quic("test: unexpected network".into()))
        })
    }
}

/// Opens the receiving device with a real sibling-sealed own copy. `activate` installs the
/// receive ledger for the account's target the way the calling module does.
pub(super) async fn open(
    activate: fn(&AccountDb, &str) -> Result<(), SdkError>,
) -> Result<(LocalBusAccountState, Real), SdkError> {
    Box::pin(build(activate)).await.map_err(|error| SdkError::LocalBus(format!("test: {error}")))
}

/// A native account holding a real peer-authored message whose sender root it has never
/// fetched: the peer's manifest is returned, not cached, so the receive must fetch it.
pub(super) async fn open_peer_authored(
    activate: fn(&AccountDb, &str) -> Result<(), SdkError>,
) -> Result<(LocalBusAccountState, ReceiveEntry, crate::SdkDeviceManifestResponse), SdkError> {
    Box::pin(build_peer_authored(activate))
        .await
        .map_err(|error| SdkError::LocalBus(format!("test: {error}")))
}

async fn build_peer_authored(
    activate: fn(&AccountDb, &str) -> Result<(), SdkError>,
) -> Case<(LocalBusAccountState, ReceiveEntry, crate::SdkDeviceManifestResponse)> {
    let mut native_source =
        Box::pin(Native::with_principal(ACCOUNT, "device-sender", ACCOUNT)).await?;
    Box::pin(publish_layer_four(&mut native_source)).await?;
    let mut source = native_source.into_bus();
    let mut native_peer = Box::pin(Native::with_principal("peer", "device-peer", "peer")).await?;
    Box::pin(publish_layer_four(&mut native_peer)).await?;
    let peer = native_peer.into_bus();
    let own = source.client.native_bus_fixture.as_ref().ok_or("native source")?.manifest.clone();
    let remote = peer.client.native_bus_fixture.as_ref().ok_or("native peer")?.manifest.clone();
    source.principal_commitment.clone_from(&own.principal_commitment);
    let conversation = ramflux_protocol::message::dm_scope::derive(
        &own.principal_commitment,
        &remote.principal_commitment,
    )?;
    // Only the peer knows both directories; the receiver has an accepted relationship and the
    // pair session, but no cached authority for the sender's root.
    peer.client.persist_observed_identity_directory_now(&own)?;
    for local in [&source, &peer] {
        local.client.account_db()?.establish_friend_link(
            "test-friend",
            &own.principal_commitment,
            &remote.principal_commitment,
        )?;
    }
    bus::seed_pair(&source.client, &peer.client)?;
    let engine_config = bus::config_for(&peer.client, &source.gateway_config)?;
    let mut sender_engine = crate::GatewaySessionEngine::with_test_transport(
        engine_config,
        Box::new(crate::bus::dispatch::surface_transport::fixture::RecordingGateway::new(
            std::sync::Arc::default(),
        )),
    );
    let target = source.client.owned_device_identity()?;
    let ttl = peer.client.content_ttl()?;
    let sent = peer
        .client
        .send_plaintext_direct_message_via_gateway(
            &mut sender_engine,
            GatewayDirectMessage {
                conversation_id: conversation,
                message_id: "peer-authored".into(),
                envelope_id: "peer-authored-envelope".into(),
                source_principal_id: "peer".into(),
                sender_id: "device-peer".into(),
                recipient_device_id: Some(target.device_id().into()),
                recipient_principal_commitment: Some(own.principal_commitment.clone()),
                target_delivery_id: target.storage_key().into(),
                encrypted_body: Vec::new(),
                created_at: now_unix_timestamp(),
                ttl,
            },
            b"peer authored for the manifest wait",
        )
        .await?;
    let mut config = source.gateway_config.clone();
    config.tcp_gateway_addr = Some("127.0.0.1:1".parse()?);
    let mut engine = crate::GatewaySessionEngine::with_test_transport(config, Box::new(Quiet));
    engine.mode = crate::gateway::session_push::SessionMode::Push {
        incarnation: crate::gateway::session_push::IncarnationId::try_from(
            "0123456789abcdef0123456789abcdef".to_owned(),
        )?,
    };
    source.install_test_session(engine);
    let target_id = source.target_delivery_id.clone();
    activate(source.client.account_db()?, &target_id)?;
    let entry = GatewayInboxEntry {
        forwarded: false,
        inbox_seq: 1,
        target_delivery_id: sent.envelope.target_delivery_id.clone(),
        envelope: sent.envelope,
    };
    if entry.target_delivery_id != target_id {
        return Err("test: sealed message is not addressed to the receiving device".into());
    }
    drop(peer);
    Ok((source, ReceiveEntry { entry, retry_key: None, replay: false, turn: None }, remote))
}

/// Restarts the receiving device from its stored account data.
pub(super) fn reopen(account: &mut LocalBusAccountState) -> Result<(), SdkError> {
    bus::reopen_account(account, ACCOUNT)
}

async fn build(
    activate: fn(&AccountDb, &str) -> Result<(), SdkError>,
) -> Case<(LocalBusAccountState, Real)> {
    let mut native_source =
        Box::pin(Native::with_principal(ACCOUNT, "device-sender", ACCOUNT)).await?;
    Box::pin(publish_layer_four(&mut native_source)).await?;
    let mut source = native_source.into_bus();
    let mut native_peer = Box::pin(Native::with_principal("peer", "device-peer", "peer")).await?;
    Box::pin(publish_layer_four(&mut native_peer)).await?;
    let mut peer = native_peer.into_bus();
    let sibling = Box::pin(bus::sibling(&mut source, ACCOUNT, "device-sibling")).await?;
    let own = source.client.native_bus_fixture.as_ref().ok_or("native source")?.manifest.clone();
    let remote = peer.client.native_bus_fixture.as_ref().ok_or("native peer")?.manifest.clone();
    let native_source = Native::take_bus(&mut source)?;
    let native_peer = Native::take_bus(&mut peer)?;
    native_source.accept_peer(&native_peer)?;
    native_peer.accept_peer(&native_source)?;
    source = native_source.into_bus();
    peer = native_peer.into_bus();
    source.principal_commitment.clone_from(&own.principal_commitment);
    let conversation = ramflux_protocol::message::dm_scope::derive(
        &own.principal_commitment,
        &remote.principal_commitment,
    )?;
    for local in [&source, &peer, &sibling] {
        local.client.persist_observed_identity_directory_now(&own)?;
        local.client.persist_observed_identity_directory_now(&remote)?;
        local.client.account_db()?.establish_friend_link(
            "test-friend",
            &own.principal_commitment,
            &remote.principal_commitment,
        )?;
        local
            .client
            .account_db()?
            .persist_actor_state("fixture/direct-conversation", &conversation)?;
        local.client.account_db()?.persist_client_record(
            "conversation",
            &conversation,
            &json!({"kind":"direct","group_id":null,"participants":[ACCOUNT,"peer"],"participant_roots":[own.principal_commitment,remote.principal_commitment]}),
        )?;
    }
    bus::seed_pair(&source.client, &sibling.client)?;
    // The receive path joins the seed engine only when a directory endpoint is configured.
    // Every directory answer is already cached, so nothing is dialled.
    let mut config = source.gateway_config.clone();
    config.tcp_gateway_addr = Some("127.0.0.1:1".parse()?);
    let mut engine = crate::GatewaySessionEngine::with_test_transport(config, Box::new(Quiet));
    engine.mode = crate::gateway::session_push::SessionMode::Push {
        incarnation: crate::gateway::session_push::IncarnationId::try_from(
            "0123456789abcdef0123456789abcdef".to_owned(),
        )?,
    };
    source.install_test_session(engine);
    let target = source.target_delivery_id.clone();
    activate(source.client.account_db()?, &target)?;
    let (entry, message) = own_copy(&source, &sibling, &remote, &own, &conversation)?;
    if entry.target_delivery_id != target {
        return Err("test: sealed copy is not addressed to the receiving device".into());
    }
    Ok((
        source,
        Real {
            entry: ReceiveEntry { entry, retry_key: None, replay: false, turn: None },
            message,
            conversation,
            _sibling: Box::new(sibling),
            _peer: Box::new(peer),
        },
    ))
}

/// The sibling's real generated sent-message copy for the receiving device, sequence 1.
fn own_copy(
    source: &LocalBusAccountState,
    sibling: &LocalBusAccountState,
    remote: &crate::SdkDeviceManifestResponse,
    own: &crate::SdkDeviceManifestResponse,
    conversation: &str,
) -> Case<(GatewayInboxEntry, String)> {
    let sibling_client = &sibling.client;
    let config = bus::config_for(sibling_client, &source.gateway_config)?;
    let event = sibling_client.allocate_generated_identity(
        conversation,
        u64::try_from(now_unix_timestamp())?.saturating_mul(1000),
        false,
    )?;
    let message = ramflux_protocol::encode_base64url(&event.id);
    let exact = RamfluxClient::encode_generated_inner(
        event,
        &g::Content {
            value: Some(g::content::Value::Message(g::Message {
                text: "sibling author for the receive sweep".into(),
                ..Default::default()
            })),
        },
    )?;
    let body = g::OwnSentMessage {
        envelope_id: "incoming-sibling-envelope".into(),
        message_id: message.clone(),
        sender_id: sibling_client.owned_device_identity()?.device_id().into(),
        original_recipients: vec![],
        ciphertext_digest: None,
        context: Some(g::OwnContext {
            conversation_id: conversation.to_owned(),
            participants: vec![own.principal_id.clone(), remote.principal_id.clone()],
            group: None,
            friend: None,
        }),
        authored_at: Some(now_unix_timestamp()),
        exact_inner: exact,
    }
    .encode_to_vec();
    let draft = sibling_client
        .prepare_own_copy_draft(
            &config,
            OwnMessageInput {
                payload_kind: crate::client::own_device_copy::OwnPayloadKind::Sent,
                id: "incoming-sibling-envelope",
                created_at: now_unix_timestamp(),
                conversation,
                group: None,
                body: &body,
            },
            own.clone(),
        )?
        .ok_or("copy draft")?;
    let requests = sibling_client.own_copy_material_requests(&config, &draft)?;
    if requests.len() != 1 {
        return Err("test: one own-copy material request required".into());
    }
    let envelopes = sibling_client.seal_own_copy_generated(
        &crate::bus::connection_manager::SessionMetadata::sealing_config_for(&config)?,
        draft,
        requests.into_iter().map(|_| SendMaterial { manifest: None, bundle: None }).collect(),
    )?;
    let [(_, envelope)] = envelopes.as_slice() else {
        return Err("test: one sibling envelope required".into());
    };
    let envelope = envelope.clone();
    Ok((
        GatewayInboxEntry {
            forwarded: false,
            inbox_seq: 1,
            target_delivery_id: envelope.target_delivery_id.clone(),
            envelope,
        },
        message,
    ))
}

/// Erases `owner` of `conversation` through the real object-retention trigger (the same
/// generation bump as `erase_support`, for a conversation other than `thread`).
pub(super) fn erase_message_in(
    db: &AccountDb,
    conversation: &str,
    owner: &str,
) -> Result<(), SdkError> {
    let before = db.privacy_erasure_generation()?;
    let alias = format!("erase-alias-{before}");
    let hash = format!("erase-ref-{before}");
    let wire = format!("erase-wire-{before}");
    db.register_object_reference(
        ObjectReferenceAdmission::FreshMessage,
        &ObjectReferenceOwner {
            reference_hash: &hash,
            wire_id: &wire,
            manifest_hash: "manifest",
            selector: &alias,
            message_id: owner,
            reference: &json!({"object_id": wire.as_str(), "slot": hash.as_str()}),
            metadata: &json!({"object_id": alias.as_str(), "message_id": owner}),
        },
    )?;
    db.persist_actor_state(
        &format!("attachment/reference/{alias}"),
        &json!({"reference":{"object_id": wire, "manifest_hash":"manifest"}}),
    )?;
    db.set_object_tombstoned(&alias)?;
    let slot = format!("attachment/reference-by-slot/{alias}");
    db.persist_actor_state(&slot, &json!(alias))?;
    db.register_object_reference_actor(&hash, &slot)?;
    db.delete_direct_message(conversation, owner, "local", "erase-tombstone")?;
    assert!(db.privacy_erasure_generation()? > before, "real erase advances the generation");
    Ok(())
}

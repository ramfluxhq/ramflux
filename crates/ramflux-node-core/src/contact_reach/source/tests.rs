// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Real snapshot-builder proof from signed local fixtures, not HTTP/TLS or activation acceptance.
use super::*;
use crate::{CustodyPublication, MigrationEndpoints, MigrationNode};
use ramflux_crypto::custody::SelfSigningKey;
use ramflux_protocol::{
    contact_reach::{Operation, ReachMode, ReachPolicy},
    home_migration::{HomeDeclarationV1, HomeRecord},
};
use redb::TableDefinition;
type TestResult<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;
const NOW: u64 = 1_700_000_100;
const HOME: &str = "snapshot.example";
struct Fixture {
    store: RouterRedbStore,
    router: RouterCore,
    service: ReachService,
    discovery: Discovery,
    query: Query,
    _dir: tempfile::TempDir,
}
fn digest(n: u8) -> String {
    ramflux_protocol::encode_base64url([n; 32])
}
fn fixture() -> TestResult<Fixture> {
    let dir = tempfile::TempDir::new()?;
    let store = RouterRedbStore::open_without_wal(dir.path().join("snapshot.redb"))?;
    let router = RouterCore::new();
    let home = signed_home()?;
    let authority = ramflux_crypto::custody::verify_record(
        &home.authority.record,
        NOW,
        home.authority.compacted_ids.as_deref(),
        None,
    )?;
    let primary = SelfSigningKey::from_vault_seed(&zeroize::Zeroizing::new([2; 32]));
    router.publish_custody_record(
        &CustodyPublication {
            record: home.authority.record.clone(),
            compacted_ids: home.authority.compacted_ids.clone(),
        },
        NOW,
        &store,
    )?;
    let root = &authority.envelope().body.account_anchor;
    let tx = store.begin_write()?;
    tx.open_table(TableDefinition::<&str, &[u8]>::new("home_head_v1"))?
        .insert(root.as_str(), serde_json::to_vec(&home)?.as_slice())?;
    tx.open_table(TableDefinition::<&str, &[u8]>::new("home_records_v1"))?;
    tx.commit()?;
    let node = MigrationNode::new(
        home.node_record,
        [8; 32],
        MigrationEndpoints {
            gateway_tcp_addr: format!("{HOME}:443"),
            federation_endpoint: format!("https://{HOME}"),
            discovery_hash: digest(71),
            server_record_hash: digest(72),
        },
        NOW,
    )?;
    let policy = primary.sign_reach_policy(
        ReachPolicy {
            version: 1,
            operation_id: digest(73),
            account_anchor: root.clone(),
            home_head_hash: ramflux_protocol::home_migration::record_hash(&home.record)?,
            expected_revision: 0,
            revision: 1,
            mode: ReachMode::ContactsOnly,
            authority_head_hash: custody::object_hash(authority.envelope())?,
            master_certificate_hash: custody::object_hash(
                &authority.envelope().body.master_certificate,
            )?,
            actor: authority.envelope().body.master_certificate.body.primary_device_ref.clone(),
            issued_at: NOW,
            expires_at: NOW + 300,
        },
        &authority,
        NOW,
    )?;
    store.reach_owner_commit(
        super::super::ReachOwner { recipient_root: root, actor: &policy.body.actor },
        &Operation::Policy { update: policy.clone() },
        NOW,
    )?;
    let discovery = discovery(&node)?;
    Ok(Fixture {
        store,
        router,
        service: ReachService::new(node)?,
        discovery,
        query: Query {
            version: 1,
            source_node: "reader.example".into(),
            target_node: HOME.into(),
            account_anchor: root.clone(),
            card_hash: None,
            nonce: digest(74),
            base: None,
            device_ref: None,
        },
        _dir: dir,
    })
}
fn signed_home() -> TestResult<RecordEvidence> {
    let vector: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../ramflux-crypto/tests/fixtures/home_migration_v1.json"
    ))?;
    let mut home: RecordEvidence =
        serde_json::from_value(vector.get("genesis").ok_or("genesis")?.clone())?;
    let authority = ramflux_crypto::custody::verify_record(
        &home.authority.record,
        NOW,
        home.authority.compacted_ids.as_deref(),
        None,
    )?;
    let primary = SelfSigningKey::from_vault_seed(&zeroize::Zeroizing::new([2; 32]));
    let key = ed25519_dalek::SigningKey::from_bytes(&[8; 32]);
    let public = ramflux_protocol::encode_base64url(key.verifying_key().to_bytes());
    let mut node = home.node_record.body.clone();
    node.node_id = HOME.into();
    node.node_signing_public_key = public;
    home.node_record = ramflux_crypto::custody::sign_node_identity_record(&key, node)?;
    let HomeRecord::Genesis { genesis } = &mut home.record else {
        return Err("genesis required".into());
    };
    let mut body = genesis.body.clone();
    body.home_node = HOME.into();
    body.home_node_key = home.node_record.body.node_signing_public_key.clone();
    body.home_declaration = Box::new(primary.sign_home_declaration(
        HomeDeclarationV1 {
            version: 1,
            principal_id: authority.envelope().body.principal_id.clone(),
            account_anchor: authority.envelope().body.account_anchor.clone(),
            home_node: HOME.into(),
            created_at: body.registered_at,
            nonce: digest(70),
        },
        &authority,
        body.registered_at,
    )?);
    **genesis = ramflux_crypto::home_migration::sign_node(body, HOME, &key)?;
    Ok(home)
}

fn discovery(node: &MigrationNode) -> TestResult<Discovery> {
    let mut client = ramflux_protocol::WellKnownClientRecord {
        schema: ramflux_protocol::WELL_KNOWN_CLIENT_SCHEMA.into(),
        node_id: HOME.into(),
        node_public_key: node.public_key().into(),
        node_ca_cert_pem: "fixture-public-ca".into(),
        gateway_quic_addr: format!("{HOME}:443"),
        gateway_tcp_addr: format!("{HOME}:443"),
        gateway_server_name: HOME.into(),
        relay_quic_addr: format!("{HOME}:443"),
        relay_server_name: HOME.into(),
        prekey_http_url: format!("https://{HOME}"),
        signaling_turn_addr: format!("{HOME}:443"),
        protocol_versions: vec!["v1".into()],
        client_capabilities: vec![wire::CAPABILITY.into(), wire::EPHEMERAL_CAPABILITY.into()],
        updated_at: NOW,
        expires_at: NOW + 60,
        signature: String::new(),
    };
    client.signature = ramflux_crypto::sign_canonical_bytes_with_seed(
        &ramflux_protocol::client_discovery_signing_bytes(&client)?,
        [8; 32],
    );
    let mut server = crate::FederationServerRecord {
        schema: "ramflux.well_known_server.v1".into(),
        node_id: HOME.into(),
        node_public_key: node.public_key().into(),
        node_ca_cert_pem: client.node_ca_cert_pem.clone(),
        node_endpoint: format!("https://{HOME}"),
        protocol_versions: vec!["v1".into()],
        transport_backends: vec!["quic".into()],
        node_capabilities: vec![wire::CAPABILITY.into(), wire::EPHEMERAL_CAPABILITY.into()],
        node_policy_hash: digest(75),
        updated_at: NOW,
        expires_at: NOW + 60,
        attachment_authority: None,
        signature: String::new(),
    };
    crate::sign_federation_server_record_with_seed(&mut server, [8; 32])?;
    Ok(Discovery { client, server: serde_json::to_value(server)? })
}
impl Fixture {
    fn context(&self) -> ReachSnapshotContext<'_> {
        ReachSnapshotContext {
            router: &self.router,
            store: &self.store,
            discovery: &self.discovery,
            continuity: &[],
            peer_node: &self.query.source_node,
            now: NOW,
            deadline: std::time::Instant::now() + std::time::Duration::from_secs(10),
        }
    }
}
#[test]
fn cr_public_snapshot_builder_hashes_original_evidence_without_card_possession() -> TestResult {
    let f = fixture()?;
    let first = f.service.assemble_public_snapshot(f.context(), &f.query)?;
    let peer = ramflux_crypto::contact_reach::verify_peer_reply(
        &first,
        &f.query,
        f.service.node.public_key(),
        None,
        NOW,
    )?;
    assert_eq!(
        peer.root(),
        f.query.account_anchor,
        "the peer proof must bind the actual account authority"
    );
    assert!(first.payload.prekey.is_none(), "an ordinary public snapshot must allocate no prekey");
    assert_eq!(
        first.payload.reach.body.mode,
        ReachMode::ContactsOnly,
        "public routing does not open messaging"
    );
    let mut query = f.query.clone();
    query.card_hash = Some(digest(99));
    let other = f.service.assemble_public_snapshot(f.context(), &query)?;
    assert_eq!(
        first.payload, other.payload,
        "an arbitrary card correlation hash is not a possession test"
    );
    assert_ne!(
        first.snapshot.body.request_hash, other.snapshot.body.request_hash,
        "the original Q must remain covered"
    );
    Ok(())
}

/// Full currently signed snapshot for sibling component controls; no pre-verified test wrapper.
pub(in crate::contact_reach) fn verified_source()
-> TestResult<ramflux_crypto::contact_reach::VerifiedPeer> {
    let fixture = fixture()?;
    let reply = fixture.service.assemble_public_snapshot(fixture.context(), &fixture.query)?;
    Ok(ramflux_crypto::contact_reach::verify_peer_reply(
        &reply,
        &fixture.query,
        fixture.service.node.public_key(),
        None,
        NOW,
    )?)
}

// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Real born-v3 authority and encrypted storage at the presence/seal crash boundary.
use super::*;
use crate::custody::{
    memory_vault::MemoryPrimaryVault,
    tests::{Root, create},
};
use ramflux_crypto::home_migration as crypto;
use ramflux_protocol::{
    custody::{BindingMode, NodeIdentityRecord},
    encode_base64url,
};
use ramflux_storage::{AccountDbKey, AccountIndex};
type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;
const NOW: u64 = 1_700_000_000;
fn hash(n: u8) -> String {
    encode_base64url([n; 32])
}
struct Fixture {
    _root: Root,
    index: AccountIndex,
    account: BornAccount,
    db: AccountDb,
    key: AccountDbKey,
    vault: MemoryPrimaryVault,
    home: crypto::VerifiedHome,
    actor: DeviceRef,
}
impl Fixture {
    fn new() -> Result<Self> {
        let root = Root::new()?;
        let vault = MemoryPrimaryVault::default();
        let account = create(&root.0, "human", &vault, NOW)?;
        let index = AccountIndex::open(&root.0)?;
        let key = AccountDbKey::generate()?;
        let db = AccountDb::open(&index, "human", &key)?;
        let (actor, _) = account.credentials(&vault, "primary", NOW)?;
        let keypair = ramflux_crypto::fixture_signing_key();
        let public = encode_base64url(keypair.verifying_key().to_bytes());
        let node = ramflux_crypto::custody::sign_node_identity_record(
            &keypair,
            NodeIdentityRecord {
                schema: ramflux_protocol::domain::CUSTODY_NODE_RECORD.into(),
                version: 1,
                node_id: "source".into(),
                node_signing_public_key: public.clone(),
                client_tls_certificate_sha256: Some(hash(9)),
                epoch: 1,
                previous_record_hash: None,
                issued_at: NOW,
                receipt_keys: vec![],
                revoked_receipt_key_ids: vec![],
                proxy_keys: vec![],
                revoked_proxy_key_ids: vec![],
                channel_binding_modes: vec![BindingMode::DirectExporter],
            },
        )?;
        let genesis = crypto::sign_node(
            wire::Genesis {
                version: 1,
                account_anchor: actor.account_anchor.clone(),
                home_epoch: 0,
                home_node: "source".into(),
                home_node_key: public.clone(),
                custody_record_hash: object_hash(account.record())?,
                registered_at: NOW,
            },
            "source",
            &keypair,
        )?;
        let evidence = wire::RecordEvidence {
            authority: ramflux_protocol::custody::Publication {
                record: account.record().clone(),
                compacted_ids: None,
            },
            record: wire::HomeRecord::Genesis { genesis: Box::new(genesis) },
            management_certificate_chain: vec![],
            actor_certificate: None,
            node_record: node,
        };
        let home = crypto::verify_home_chain(
            &wire::ResolveResult { home: evidence, predecessors: vec![] },
            &crypto::HomeTrust {
                account_anchor: &actor.account_anchor,
                node_id: "source",
                node_key: &public,
                home_epoch: 0,
                home_hash: None,
                cached_manager_range: 0,
                cached_manager_certificate_hash: None,
            },
            NOW,
        )?;
        Ok(Self { _root: root, index, account, db, key, vault, home, actor })
    }
    fn journal(&self) -> Result<HomeMigrationJournal<'_>> {
        Ok(HomeMigrationJournal::new(&self.db, &self.index, &self.account)?)
    }
    fn target() -> Result<ramflux_protocol::WellKnownClientRecord> {
        let mut record = ramflux_protocol::WellKnownClientRecord {
            schema: ramflux_protocol::WELL_KNOWN_CLIENT_SCHEMA.into(),
            node_id: "destination".into(),
            node_public_key: encode_base64url(
                ramflux_crypto::fixture_signing_key().verifying_key().to_bytes(),
            ),
            node_ca_cert_pem: "fixture CA".into(),
            gateway_quic_addr: "destination.example:443".into(),
            gateway_tcp_addr: "destination.example:443".into(),
            gateway_server_name: "destination.example".into(),
            relay_quic_addr: "destination.example:444".into(),
            relay_server_name: "destination.example".into(),
            prekey_http_url: "https://destination.example/prekeys".into(),
            signaling_turn_addr: "destination.example:3478".into(),
            protocol_versions: vec!["v3".into()],
            client_capabilities: vec!["home_migration".into()],
            updated_at: NOW,
            expires_at: NOW + 3600,
            signature: String::new(),
        };
        record.signature = ramflux_crypto::sign_canonical_bytes(
            &ramflux_protocol::client_discovery_signing_bytes(&record)?,
        );
        Ok(record)
    }
    fn intent() -> Result<MigrationIntent> {
        Ok(MigrationIntent {
            operation_id: hash(1),
            target_discovery_url: "https://destination.example/.well-known/ramflux-client".into(),
            expected_node_fingerprint: ramflux_protocol::hash_hex(
                ramflux_protocol::CLIENT_DISCOVERY_DOMAIN,
                Self::target()?.node_public_key.as_bytes(),
            ),
        })
    }
    fn prepare(&self) -> Result<wire::Signed<wire::Prepare>> {
        let journal = self.journal()?;
        journal.begin(Self::intent()?, self.actor.clone(), &self.home, NOW)?;
        let target = Self::target()?;
        let (_, credentials) = self.account.credentials(&self.vault, "primary", NOW)?;
        let prepare = crypto::sign_actor(
            wire::Prepare {
                version: 1,
                migration_id: hash(1),
                account_anchor: self.actor.account_anchor.clone(),
                actor: self.actor.clone(),
                authority_record_hash: object_hash(self.account.record())?,
                branch_certificate_hash: object_hash(
                    self.account.record().body.devices[0]
                        .branch_certificate
                        .as_ref()
                        .ok_or("actor")?,
                )?,
                previous_home_hash: self.home.hash().into(),
                previous_home_epoch: 0,
                old_node: "source".into(),
                destination_node: target.node_id.clone(),
                destination_key: target.node_public_key.clone(),
                discovery_hash: hash(2),
                delivery_map_hash: hash(3),
                nonce: hash(4),
                issued_at: NOW,
                expires_at: NOW + 300,
            },
            &credentials.signing,
            self.account.verified(),
            NOW,
        )?;
        Ok(journal.prepare(&hash(1), target, prepare, NOW)?)
    }
    fn offer(&self) -> Result<String> {
        self.accept_prepare(&self.prepare()?)
    }
    fn accept_prepare(&self, prepare: &wire::Signed<wire::Prepare>) -> Result<String> {
        Ok(self.journal()?.offer(&hash(1), Self::offer_reply(prepare)?, NOW)?)
    }
    fn offer_reply(prepare: &wire::Signed<wire::Prepare>) -> Result<wire::Signed<wire::Offer>> {
        let target = Self::target()?;
        let p = &prepare.body;
        Ok(crypto::sign_node(
            wire::Offer {
                version: 1,
                migration_id: p.migration_id.clone(),
                account_anchor: p.account_anchor.clone(),
                prepare_hash: wire::message_hash(prepare)?,
                authority_record_hash: p.authority_record_hash.clone(),
                previous_home_hash: p.previous_home_hash.clone(),
                next_home_epoch: 1,
                old_node: p.old_node.clone(),
                destination_node: p.destination_node.clone(),
                destination_key: p.destination_key.clone(),
                discovery_hash: p.discovery_hash.clone(),
                server_record_hash: hash(5),
                gateway_tcp_addr: target.gateway_tcp_addr,
                federation_endpoint: "https://destination.example/federation".into(),
                delivery_map_hash: p.delivery_map_hash.clone(),
                admission_id: hash(6),
                nonce: hash(7),
                issued_at: NOW,
                accept_until: NOW + 600,
                max_commit_delay: 600,
                forward_seconds: 86400,
            },
            "destination",
            &ramflux_crypto::fixture_signing_key(),
        )?)
    }
}
#[test]
fn home_migration_restart_resumes_identical_intent_and_rejects_changed_target() -> Result {
    let f = Fixture::new()?;
    let first = f.journal()?.begin(Fixture::intent()?, f.actor.clone(), &f.home, NOW)?;
    assert_eq!(first, f.journal()?.begin(Fixture::intent()?, f.actor.clone(), &f.home, NOW)?);
    let mut changed = Fixture::intent()?;
    changed.target_discovery_url = "https://other.example".into();
    assert!(f.journal()?.begin(changed, f.actor.clone(), &f.home, NOW).is_err());
    let db = AccountDb::open(&f.index, "human", &f.key)?;
    assert_eq!(HomeMigrationJournal::new(&db, &f.index, &f.account)?.status(&hash(1))?, first);
    Ok(())
}
#[test]
fn home_migration_cancel_during_presence_discards_the_returned_signature() -> Result {
    let f = Fixture::new()?;
    let digest = f.offer()?;
    let plan = f.journal()?.approval_plan(&hash(1), &digest)?;
    assert_eq!(plan.proposal_digest(), digest);
    assert_eq!(plan.destination_fingerprint(), Fixture::intent()?.expected_node_fingerprint);
    f.journal()?.cancel(&hash(1), NOW)?;
    f.vault.approve_migration_once_for_test("human", &hash(1))?;
    let result = plan.sign(&f.vault, NOW)?;
    assert!(f.journal()?.authorize(result, NOW).is_err());
    assert_eq!(f.journal()?.status(&hash(1))?.phase, MigrationPhase::AbortPending);
    f.journal()?.require_recovery_allowed()?;
    Ok(())
}
#[test]
fn home_migration_lost_seal_reply_cancels_with_authorization_alone_and_never_releases_guard_on_timeout()
-> Result {
    let f = Fixture::new()?;
    let digest = f.offer()?;
    let plan = f.journal()?.approval_plan(&hash(1), &digest)?;
    f.vault.approve_migration_once_for_test("human", &hash(1))?;
    let signature = plan.sign(&f.vault, NOW)?;
    let authorization = f.journal()?.authorize(signature, NOW)?;
    assert_eq!(f.journal()?.status(&hash(1))?.phase, MigrationPhase::SealSent);
    assert!(f.journal()?.require_recovery_allowed().is_err());
    let db = AccountDb::open(&f.index, "human", &f.key)?;
    let recovered = HomeMigrationJournal::new(&db, &f.index, &f.account)?;
    assert!(recovered.require_recovery_allowed().is_err());
    assert_eq!(recovered.cancel(&hash(1), NOW + 1)?.phase, MigrationPhase::NeedsAttention);
    assert_eq!(recovered.cancellation_authorization(&hash(1))?, authorization);
    let later = recovered.retry_later(&hash(1), NOW + 86400)?;
    assert_eq!(later.phase, MigrationPhase::NeedsAttention);
    assert!(recovered.require_recovery_allowed().is_err());
    assert!(recovered.retry_later(&hash(1), NOW + 86400).is_err());
    let row = db.home_migration_job(&hash(1))?.ok_or("journal")?;
    assert!(row.recovery_blocked);
    assert!(!serde_json::to_string(&row.progress)?.contains("authorization"));
    assert!(!serde_json::to_string(&row.progress)?.contains("admission"));
    Ok(())
}

#[test]
fn home_migration_only_the_source_authorization_bound_fence_releases_a_lost_seal_guard() -> Result {
    let f = Fixture::new()?;
    let digest = f.offer()?;
    let plan = f.journal()?.approval_plan(&hash(1), &digest)?;
    f.vault.approve_migration_once_for_test("human", &hash(1))?;
    let authorization = f.journal()?.authorize(plan.sign(&f.vault, NOW)?, NOW)?;
    assert!(f.journal()?.commit_evidence(&hash(1), NOW).is_err());
    assert!(f.journal()?.activation_evidence(&hash(1)).is_err());
    f.journal()?.cancel(&hash(1), NOW)?;
    let body = wire::NoncommitFence {
        version: 1,
        migration_id: hash(1),
        authorization_hash: wire::message_hash(&authorization)?,
        // Authorization alone is sufficient when B's reply was lost.
        seal_hash: None,
        fenced_at: NOW,
    };
    let wrong_node =
        crypto::sign_node(body.clone(), "destination", &ramflux_crypto::fixture_signing_key())?;
    assert!(f.journal()?.noncommit(&hash(1), wrong_node, NOW).is_err());
    let mut other_authorization = body.clone();
    other_authorization.authorization_hash = hash(43);
    let wrong_authorization =
        crypto::sign_node(other_authorization, "source", &ramflux_crypto::fixture_signing_key())?;
    assert!(f.journal()?.noncommit(&hash(1), wrong_authorization, NOW).is_err());
    assert!(f.journal()?.require_recovery_allowed().is_err());
    let fence = crypto::sign_node(body, "source", &ramflux_crypto::fixture_signing_key())?;
    assert_eq!(
        f.journal()?.noncommit(&hash(1), fence.clone(), NOW)?.phase,
        MigrationPhase::Aborted
    );
    let seq = f.journal()?.status(&hash(1))?.seq;
    assert_eq!(f.journal()?.noncommit(&hash(1), fence, NOW)?.seq, seq);
    f.journal()?.require_recovery_allowed()?;
    assert!(f.journal()?.activation_evidence(&hash(1)).is_err());
    Ok(())
}

#[cfg(not(target_os = "macos"))]
#[test]
fn home_migration_unsupported_native_provider_refuses_with_presence_code_before_branch_loading()
-> Result {
    let f = Fixture::new()?;
    let digest = f.offer()?;
    let plan = f.journal()?.approval_plan(&hash(1), &digest)?;
    assert!(matches!(
        plan.sign(&crate::custody::NativePrimaryVault, NOW),
        Err(SdkError::HomeMigrationRefused(wire::Refusal::CustodyUserPresenceUnavailable))
    ));
    assert_eq!(f.journal()?.status(&hash(1))?.phase, MigrationPhase::AwaitingCustodyUnlock);
    Ok(())
}

mod outcomes;

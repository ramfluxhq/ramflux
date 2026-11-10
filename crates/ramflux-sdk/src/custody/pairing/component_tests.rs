// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Separate SDK stores and real node durability through the shared ceremony.

use super::*;
use crate::SdkError;
use ramflux_node_core::pairing_relay::{
    PairingClock, PairingRelayConfig, PairingRelayStore, TestPairingClock,
};
use ramflux_node_core::{CustodyPublication, RouterCore, RouterRedbStore};
use ramflux_protocol::custody::pairing::local_dto::{
    Approve, Begin, Confirm, Join, LocalResult, Outcome,
};
use ramflux_protocol::custody::{CustodyAuthority, Publication, object_hash};
use std::sync::{Arc, Mutex};

type TestResult = Result<(), Box<dyn std::error::Error>>;

struct Node {
    core: RouterCore,
    disk: RouterRedbStore,
}

impl NodeHeadPersist for Node {
    fn persist_head(&self, publication: &Publication, now: u64) -> Result<String, SdkError> {
        let record = self
            .core
            .publish_custody_record(
                &CustodyPublication {
                    record: publication.record.clone(),
                    compacted_ids: publication.compacted_ids.clone(),
                },
                now,
                &self.disk,
            )
            .map_err(|error| SdkError::LocalBus(error.to_string()))?;
        Ok(object_hash(&record)?)
    }
}

impl PairingAuthorityQuery for Node {
    fn current_authority(&self, anchor: &str) -> Result<CustodyAuthority, SdkError> {
        let publication = self
            .core
            .custody_record(anchor, crate::custody::network_now()?)
            .map_err(|error| SdkError::LocalBus(error.to_string()))?
            .ok_or(SdkError::PairingCode("NotFound"))?;
        Ok(CustodyAuthority {
            publication: Publication {
                record: publication.record,
                compacted_ids: publication.compacted_ids,
            },
            custodian_publication: None,
        })
    }
}

fn phase(result: LocalResult) -> Result<String, SdkError> {
    match result.outcome {
        Outcome::Update { value } => Ok(value.phase),
        _ => Err(SdkError::PairingCode("WrongContext")),
    }
}

struct Rig {
    primary: PairingActor,
    secondary: PairingActor,
    clock: Arc<TestPairingClock>,
    participant_b: Arc<LocalPairingParticipant>,
    recipient_root: tempfile::TempDir,
    original_devices: Vec<ramflux_protocol::custody::Device>,
    now: u64,
    _source: crate::client::native_test_support::Fixture,
    _node_root: tempfile::TempDir,
    _clock: crate::time::FixedClock,
}

impl Rig {
    async fn open() -> Result<Self, Box<dyn std::error::Error>> {
        let now = crate::custody::network_now()?;
        let fixed_clock = crate::time::FixedClock::set(i64::try_from(now)?);
        let mut source =
            crate::client::native_test_support::Fixture::new("component-source").await?;
        let recipient_root = tempfile::tempdir()?;
        let node_root = tempfile::tempdir()?;
        let node = Arc::new(Node {
            core: RouterCore::new(),
            disk: RouterRedbStore::open_without_wal(node_root.path().join("authority.redb"))?,
        });
        let source_account = crate::custody::load_account(&source.root.0, "component-source", now)?;
        node.persist_head(&source_account.publication(), now)?;
        let original_devices = source_account.record().body.devices.clone();
        let account_ref =
            source_account.record().body.master_certificate.body.primary_device_ref.clone();
        let clock = TestPairingClock::new(now);
        let relay_store = Arc::new(Mutex::new(PairingRelayStore::new(PairingRelayConfig {
            clock: clock.clone() as Arc<dyn PairingClock>,
            node_seed: [7; 32],
            public_origin: "https://relay.example:443".into(),
        })?));
        let relay = Arc::new(super::tests::MemoryRelay { store: relay_store.clone() });
        let native = Arc::new(super::tests::StoreNative { store: relay_store });
        let participant_a = Arc::new(LocalPairingParticipant {
            root: source.root.0.clone(),
            account_id: "component-source".into(),
            vault: source.vault.clone(),
            provider: Arc::new(super::recipient::tests::Phrase::setup(
                b"component-source-passphrase",
            )),
            db: Mutex::new(None),
            persist: node.clone(),
            query: node.clone(),
        });
        participant_a.take_client(&mut source.client)?;
        let participant_b = Arc::new(LocalPairingParticipant {
            root: recipient_root.path().to_path_buf(),
            account_id: "component-recipient".into(),
            vault: Arc::new(super::recipient::tests::DiskVault::open(
                recipient_root.path().join("branch-vault"),
            )?),
            provider: Arc::new(super::recipient::tests::Phrase::setup(
                b"component-recipient-passphrase",
            )),
            db: Mutex::new(None),
            persist: node.clone(),
            query: node.clone(),
        });
        let config = PairingConfig { enabled: true, extra_root_ca_pem: None };
        let mut primary = PairingActor::new(
            PairingIdentity {
                account_id: "component-source".into(),
                local_ref: account_ref,
                master_public_key: Some(
                    source_account.record().body.master_certificate.body.master_public_key.clone(),
                ),
                base_record_hash: object_hash(source_account.record())?,
                base_epoch: source_account.record().body.device_set_epoch,
                is_primary: true,
            },
            Some(native),
            relay.clone(),
            config.clone(),
        );
        primary.set_participant(participant_a.clone());
        let mut secondary = PairingActor::new(
            PairingIdentity {
                account_id: "component-recipient".into(),
                local_ref: ramflux_protocol::custody::DeviceRef {
                    account_anchor: String::new(),
                    device_id: "uncommitted".into(),
                    device_epoch: 1,
                },
                master_public_key: None,
                base_record_hash: ramflux_protocol::encode_base64url([0; 32]),
                base_epoch: 1,
                is_primary: false,
            },
            None,
            relay,
            config,
        );
        secondary.set_participant(participant_b.clone());
        Ok(Self {
            primary,
            secondary,
            clock,
            participant_b,
            recipient_root,
            original_devices,
            now,
            _source: source,
            _node_root: node_root,
            _clock: fixed_clock,
        })
    }
}

#[tokio::test(flavor = "current_thread")]
async fn pairing_recipient_activates_only_exact_durable_publication() -> TestResult {
    let Rig {
        mut primary,
        mut secondary,
        clock,
        participant_b,
        recipient_root,
        original_devices,
        now,
        _source,
        _node_root,
        _clock,
    } = Rig::open().await?;
    let begun = primary
        .begin(Begin {
            schema: "ramflux.pairing.Begin.v2".into(),
            version: 2,
            capabilities: vec!["group".into(), "message".into(), "register".into(), "sync".into()],
            lease_not_before: now,
            lease_expires_at: now + 86_400,
            display_name: "Primary".into(),
        })
        .await?;
    let Outcome::Begin { value: begun } = begun.outcome else {
        return Err("begin".into());
    };
    let operation_id = begun.operation_id.clone();
    secondary
        .join(Join {
            schema: "ramflux.pairing.Join.v2".into(),
            version: 2,
            token: begun.invite_token,
            display_name: "Second".into(),
        })
        .await?;
    for _ in 0..8 {
        clock.advance_ms(1001);
        primary.sync_relay().await?;
        clock.advance_ms(1001);
        secondary.sync_relay().await?;
        if primary.displayed_transcript().is_ok() && secondary.displayed_transcript().is_ok() {
            break;
        }
    }
    assert_eq!(primary.displayed_transcript()?, secondary.displayed_transcript()?);
    assert!(!ordinary_session_admitted_for_participant(&participant_b)?);
    for actor in [&mut primary, &mut secondary] {
        clock.advance_ms(1001);
        actor
            .confirm(&Confirm {
                schema: "ramflux.pairing.Confirm.v2".into(),
                version: 2,
                operation_id: operation_id.clone(),
                generation: 1,
                transcript_hash: actor.displayed_transcript()?,
                r#match: true,
            })
            .await?;
    }
    for _ in 0..8 {
        clock.advance_ms(1001);
        let state = phase(primary.sync_relay().await?)?;
        clock.advance_ms(1001);
        secondary.sync_relay().await?;
        if state == "proposal_pending" {
            break;
        }
    }
    clock.advance_ms(1001);
    primary
        .approve(&Approve {
            schema: "ramflux.pairing.Approve.v2".into(),
            version: 2,
            operation_id,
            generation: 1,
            transcript_hash: primary.displayed_transcript()?,
            proposal_hash: primary.displayed_proposal()?,
            approved: true,
        })
        .await?;
    for _ in 0..8 {
        clock.advance_ms(1001);
        let source_phase = phase(primary.sync_relay().await?)?;
        clock.advance_ms(1001);
        let target_phase = phase(secondary.sync_relay().await?)?;
        if source_phase == "completed" && target_phase == "completed" {
            break;
        }
    }
    assert!(ordinary_session_admitted_for_participant(&participant_b)?);
    let mut target = crate::RamfluxClient::new();
    participant_b.return_client(&mut target)?;
    let admitted = crate::custody::load_account(recipient_root.path(), "component-recipient", now)?;
    assert_retained_roster(&admitted, original_devices, participant_b.vault.as_ref());
    assert_adoption_refs(&target)?;
    assert_missing_marker_refuses(recipient_root.path(), now)?;
    Ok(())
}

fn ordinary_session_admitted_for_participant(
    participant: &LocalPairingParticipant,
) -> Result<bool, SdkError> {
    let slot = participant.db.lock().map_err(|_| SdkError::PairingCode("Busy"))?;
    let Some(db) = slot.as_ref() else { return Ok(false) };
    let Some(installed) =
        install_store::read_installed(&participant.root, &participant.account_id)?
    else {
        return Ok(false);
    };
    let Some(adopted) = db.pairing_adoption()? else { return Ok(false) };
    Ok(super::activate::adoption(&installed)? == adopted)
}

fn assert_adoption_refs(target: &crate::RamfluxClient) -> TestResult {
    let adopted = target.account_db()?.pairing_adoption()?.ok_or("adoption")?;
    let mut corrupt = adopted.clone();
    corrupt.data_vault_ref = "foreign-data-owner".into();
    target.account_db()?.put_pairing_adoption(&corrupt)?;
    assert!(!ordinary_session_admitted(target, "component-recipient")?);
    target.account_db()?.put_pairing_adoption(&adopted)?;
    assert!(ordinary_session_admitted(target, "component-recipient")?);
    Ok(())
}

fn assert_missing_marker_refuses(
    root: &std::path::Path,
    now: u64,
) -> Result<(), Box<dyn std::error::Error>> {
    let path = super::install_store::installed_path(root, "component-recipient");
    let saved = std::fs::read(&path)?;
    std::fs::remove_file(&path)?;
    assert!(matches!(
        crate::custody::load_account(root, "component-recipient", now),
        Err(crate::SdkError::PairingCode("PublicationPending"))
    ));
    std::fs::write(&path, saved)?;
    crate::custody::load_account(root, "component-recipient", now)?;
    Ok(())
}

fn assert_retained_roster(
    admitted: &crate::custody::BornAccount,
    original_devices: Vec<ramflux_protocol::custody::Device>,
    vault: &dyn crate::custody::PrimaryVault,
) {
    for old in original_devices {
        assert!(admitted.record().body.devices.contains(&old));
    }
    assert_eq!(admitted.record().body.devices.len(), 2);
    assert_eq!(admitted.primary_vault_ref(), "");
    assert!(admitted.group_primary(vault).is_err());
}

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

mod full_relay;

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
    participant_a: Arc<LocalPairingParticipant>,
    node: Arc<Node>,
    full_hellos:
        Arc<Mutex<Vec<ramflux_protocol::custody::pairing::full_transfer::relay::HelloFull>>>,
    recipient_root: tempfile::TempDir,
    original_devices: Vec<ramflux_protocol::custody::Device>,
    now: u64,
    source: ComponentSource,
    _node_root: tempfile::TempDir,
    _clock: crate::time::FixedClock,
}

// A fresh native account before its first ordinary network initialization. The full-profile
// test exports all of its actual rows; the separately tested initialized account remains refused
// for undeclared local events/actors. No rows are deleted or skipped to admit either source.
struct ComponentSource {
    client: crate::RamfluxClient,
    vault: Arc<crate::custody::tests::TestVault>,
    root: crate::custody::tests::Root,
}
impl ComponentSource {
    async fn open(full: bool, now: u64) -> Result<Self, Box<dyn std::error::Error>> {
        if !full {
            let fixture =
                crate::client::native_test_support::Fixture::new("component-source").await?;
            return Ok(Self { client: fixture.client, vault: fixture.vault, root: fixture.root });
        }
        let root = crate::custody::tests::Root::new()?;
        let vault = Arc::new(crate::custody::tests::TestVault::default());
        let account = crate::custody::tests::create_with_device(
            &root.0,
            "component-source",
            "primary",
            vault.as_ref(),
            now,
        )?;
        let mut client = crate::RamfluxClient::new();
        client.open_account_index(&root.0)?;
        client.seal_new_account_data(
            "component-source",
            &account.record().body.account_anchor,
            b"fresh-source-data",
        )?;
        client.unlock_account("component-source", b"fresh-source-data")?;
        Ok(Self { client, vault, root })
    }
}

type FixtureTransports = (
    Arc<dyn PairingNative>,
    Arc<dyn PairingTransport>,
    Option<ramflux_crypto::custody::VerifiedNodeRecord>,
    Arc<Mutex<Vec<ramflux_protocol::custody::pairing::full_transfer::relay::HelloFull>>>,
);
fn fixture_transports(
    full: bool,
    now: u64,
    clock: Arc<TestPairingClock>,
    node: Arc<Node>,
) -> Result<FixtureTransports, Box<dyn std::error::Error>> {
    let relay_store = Arc::new(Mutex::new(PairingRelayStore::new(PairingRelayConfig {
        clock: if full { full_relay::clock(clock) } else { clock as Arc<dyn PairingClock> },
        node_seed: if full { ramflux_crypto::fixture_signing_key().to_bytes() } else { [7; 32] },
        public_origin: "https://relay.example:443".into(),
    })?));
    let relay = Arc::new(super::tests::MemoryRelay { store: relay_store.clone() });
    let verified_node = if full {
        Some(
            crate::custody::network_tests::node(now, ramflux_protocol::encode_base64url([29; 32]))
                .map_err(|error| error.to_string())?,
        )
    } else {
        None
    };
    let full_hellos = Arc::new(Mutex::new(Vec::new()));
    let (native, relay): (Arc<dyn PairingNative>, Arc<dyn PairingTransport>) = match &verified_node
    {
        Some(identity) => {
            let full = Arc::new(FullNativeFixture {
                store: relay_store,
                node,
                identity: identity.clone(),
                full_hellos: full_hellos.clone(),
            });
            (full.clone(), full)
        }
        None => (Arc::new(super::tests::StoreNative { store: relay_store }), relay),
    };
    Ok((native, relay, verified_node, full_hellos))
}

impl Rig {
    async fn open() -> Result<Self, Box<dyn std::error::Error>> {
        Self::open_profile(false).await
    }
    async fn open_profile(full: bool) -> Result<Self, Box<dyn std::error::Error>> {
        let now = crate::custody::network_now()?;
        let fixed_clock = crate::time::FixedClock::set(i64::try_from(now)?);
        let mut source = ComponentSource::open(full, now).await?;
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
        let (native, relay, verified_node, full_hellos) =
            fixture_transports(full, now, clock.clone(), node.clone())?;
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
        if let Some(identity) = verified_node {
            primary.set_full_node(identity.clone());
            secondary.set_full_node(identity);
        }

        Ok(Self {
            primary,
            secondary,
            clock,
            participant_b,
            participant_a,
            node,
            full_hellos,
            recipient_root,
            original_devices,
            now,
            source,
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
        participant_a: _,
        node: _,
        full_hellos: _,
        recipient_root,
        original_devices,
        now,
        source: _source,
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
    assert_adoption_refs(&target, participant_b.vault.as_ref())?;
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

fn assert_adoption_refs(
    target: &crate::RamfluxClient,
    vault: &dyn crate::custody::PrimaryVault,
) -> TestResult {
    let root = target.account_index()?.root();
    let now = crate::custody::network_now()?;
    let account = crate::custody::load_account(root, "component-recipient", now)?;
    let mut network = crate::custody::CustodyNetworkConfig {
        pairing_admission: Some(Arc::new(target.account_db()?.pairing_admission_reader())),
        account_root: root.into(),
        account_id: "component-recipient".into(),
        device_id: account.local_device_id()?.into(),
        gateway_address: "127.0.0.1:1".parse()?,
        server_name: "localhost".into(),
        ca_certificate: root.join("unused.pem"),
        node_id: "fixture".into(),
        node_public_key: ramflux_protocol::encode_base64url([1; 32]),
        audience: "fixture".into(),
        binding_mode: ramflux_protocol::custody::BindingMode::DirectExporter,
        allow_no_channel_binding: false,
        timeout: std::time::Duration::from_secs(5),
    };
    super::admission::require_network_admission(&network, &account, vault, now)?;
    let adopted = target.account_db()?.pairing_adoption()?.ok_or("adoption")?;
    let mut corrupt = adopted.clone();
    corrupt.data_vault_ref = "foreign-data-owner".into();
    target.account_db()?.put_pairing_adoption(&corrupt)?;
    assert!(!ordinary_session_admitted(target, "component-recipient")?);
    assert!(super::admission::require_network_admission(&network, &account, vault, now).is_err());
    target.account_db()?.put_pairing_adoption(&adopted)?;
    assert!(ordinary_session_admitted(target, "component-recipient")?);
    super::admission::require_network_admission(&network, &account, vault, now)?;
    network.pairing_admission = None;
    assert!(super::admission::require_network_admission(&network, &account, vault, now).is_err());
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

/// Real native lease verifier/current `RouterCore` owner; the fixture relay remains in-process.
#[derive(Clone)]
struct FullNativeFixture {
    store: Arc<Mutex<PairingRelayStore>>,
    node: Arc<Node>,
    identity: ramflux_crypto::custody::VerifiedNodeRecord,
    full_hellos:
        Arc<Mutex<Vec<ramflux_protocol::custody::pairing::full_transfer::relay::HelloFull>>>,
}
impl PairingNative for FullNativeFixture {
    fn issue(
        &self,
        spec: ramflux_protocol::custody::pairing::native::CreateSpec,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<
                    Output = Result<ramflux_protocol::custody::pairing::native::Issued, SdkError>,
                > + Send,
        >,
    > {
        PairingNative::issue(&super::tests::StoreNative { store: self.store.clone() }, spec)
    }
    fn create(
        &self,
        request: ramflux_protocol::custody::pairing::native::Create,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<
                    Output = Result<ramflux_protocol::custody::pairing::native::Created, SdkError>,
                > + Send,
        >,
    > {
        PairingNative::create(&super::tests::StoreNative { store: self.store.clone() }, request)
    }
    fn full_node(
        &self,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<
                    Output = Result<ramflux_crypto::custody::VerifiedNodeRecord, SdkError>,
                > + Send,
        >,
    > {
        let identity = self.identity.clone();
        Box::pin(async move { Ok(identity) })
    }
    fn data_lease(
        &self,
        request: ramflux_protocol::custody::pairing::full_transfer::lease::LeaseRequest,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<
                    Output = Result<
                        ramflux_protocol::custody::Envelope<
                            ramflux_protocol::custody::pairing::full_transfer::lease::DataLease,
                        >,
                        SdkError,
                    >,
                > + Send,
        >,
    > {
        let node = self.node.clone();
        let store = self.store.clone();
        let identity = self.identity.clone();
        Box::pin(async move {
            let anchor = request.grant.source_ref.account_anchor.clone();
            node.core
                .with_current_pairing_authority(
                    &anchor,
                    crate::custody::network_now()?,
                    |current| {
                        store
                            .lock()
                            .map_err(|_| {
                                ramflux_node_core::pairing_relay::PairingRelayError::WrongContext
                            })?
                            .issue_data_lease(&request, current, &identity)
                    },
                )
                .map_err(|error| SdkError::LocalBus(error.to_string()))
        })
    }
}
#[tokio::test(flavor = "current_thread")]
async fn pairing_full_actor_bootstrap_commits_data_only_stages_before_a3() -> TestResult {
    let (mut rig, operation, anchor) = Box::pin(bootstrap_full_rig()).await?;
    assert_full_bootstrap_preserves_uncertain_rows(&rig, &operation, &anchor)?;
    assert_full_cancel_fences_stage(&mut rig, &operation).await?;
    Ok(())
}

async fn bootstrap_full_rig() -> Result<(Rig, String, String), Box<dyn std::error::Error>> {
    let mut rig = Rig::open_profile(true).await?;
    assert_declared_full_source(&rig.participant_a)?;
    let result = rig.primary.begin_full(full_begin(rig.now)).await?;
    let Outcome::Begin { value: begun } = result.outcome else { return Err("full begin".into()) };
    let anchor = begun.invite_token.invitation.body.account_anchor.clone();
    let operation = begun.operation_id.clone();
    let generation = begun.generation;
    rig.secondary
        .join(Join {
            schema: "ramflux.pairing.Join.v2".into(),
            version: 2,
            token: begun.invite_token,
            display_name: "Target".into(),
        })
        .await?;
    let request = ramflux_protocol::custody::pairing::local_dto::StatusRequest {
        schema: "ramflux.pairing.StatusRequest.v2".into(),
        version: 2,
        operation_id: operation.clone(),
        generation,
    };
    for _ in 0..32 {
        rig.clock.advance_ms(1001);
        checked_full_status(&mut rig.primary, &request, "source").await?;
        rig.clock.advance_ms(1001);
        checked_full_status(&mut rig.secondary, &request, "target").await?;
        if rig.primary.displayed_transcript().is_ok()
            && rig.secondary.displayed_transcript().is_ok()
        {
            break;
        }
    }
    let th = rig.primary.displayed_transcript().map_err(|error| format!("source SAS: {error}"))?;
    assert_eq!(th, rig.secondary.displayed_transcript()?);
    let confirm = Confirm {
        schema: "ramflux.pairing.Confirm.v2".into(),
        version: 2,
        operation_id: operation.clone(),
        generation,
        transcript_hash: th,
        r#match: true,
    };
    rig.clock.advance_ms(1001);
    rig.primary.confirm(&confirm).await?;
    rig.clock.advance_ms(1001);
    rig.secondary.confirm(&confirm).await?;
    let mut linked = false;
    for _ in 0..32 {
        rig.clock.advance_ms(1001);
        checked_full_status(&mut rig.primary, &request, "source").await?;
        rig.clock.advance_ms(1001);
        checked_full_status(&mut rig.secondary, &request, "target").await?;
        let references = |participant: &LocalPairingParticipant| -> Result<_, SdkError> {
            let slot = participant.db.lock().map_err(|_| SdkError::PairingCode("Busy"))?;
            let row = slot
                .as_ref()
                .ok_or(SdkError::AccountDbNotUnlocked)?
                .pairing_live_rows()?
                .into_iter()
                .find(|row| row.operation_id == operation)
                .ok_or(SdkError::PairingCode("NotFound"))?;
            Ok(row.full_stage_reference()?)
        };
        if references(&rig.participant_a)?.is_some() && references(&rig.participant_b)?.is_some() {
            linked = true;
            break;
        }
    }
    assert!(linked, "bootstrap did not commit both actual data-only stage links");
    assert_eq!(
        rig.original_devices,
        rig.node.current_authority(&anchor)?.publication.record.body.devices,
        "data-only bootstrap changed native authority"
    );
    assert_full_data_stages(&rig, &operation)?;
    Ok((rig, operation, anchor))
}

fn assert_full_data_stages(rig: &Rig, operation: &str) -> TestResult {
    use ramflux_protocol::custody::pairing::PairingWire;
    for (participant, role) in [
        (&rig.participant_a, ramflux_crypto::custody::pairing::PairingRole::Initiator),
        (&rig.participant_b, ramflux_crypto::custody::pairing::PairingRole::Responder),
    ] {
        let slot = participant.db.lock().map_err(|_| "DB")?;
        let db = slot.as_ref().ok_or("DB")?;
        let stage = db.open_full_transfer_stage(operation, role, rig.now)?;
        let record = stage.resume_record()?;
        assert_eq!(record.role, role);
        let _: ramflux_protocol::custody::pairing::context_v3::TranscriptV3 =
            ramflux_protocol::custody::pairing::context_v3::TranscriptV3::from_wire_bytes(
                &record.transcript,
            )?;
        assert!(db.pairing_adoption()?.is_none(), "data-only stage granted installation");
    }
    Ok(())
}

fn assert_full_bootstrap_preserves_uncertain_rows(
    rig: &Rig,
    operation: &str,
    anchor: &str,
) -> TestResult {
    use ramflux_crypto::custody::pairing::{FullResumeTrust, PairingRole};
    let participant = &rig.participant_b;
    let (record, original) = {
        let slot = participant.db.lock().map_err(|_| "DB")?;
        let db = slot.as_ref().ok_or("DB")?;
        let stage = db.open_full_transfer_stage(operation, PairingRole::Responder, rig.now)?;
        let record = stage.resume_record()?;
        let row = db
            .pairing_live_rows()?
            .into_iter()
            .find(|row| row.operation_id == operation)
            .ok_or("live row")?;
        (record, row)
    };
    let node =
        crate::custody::network_tests::node(rig.now, ramflux_protocol::encode_base64url([29; 32]))
            .map_err(|error| error.to_string())?;
    let own_ref = record.grant.destination_ref.clone();
    let own_key = record.grant.branch_keys.destination.clone();
    let trust = FullResumeTrust::restore_local_stage(record, &node, &own_ref, &own_key, rig.now)?;
    let base =
        ramflux_crypto::custody::verify_publication(&rig.node.current_authority(anchor)?, rig.now)?;
    for phase in ["mutually_confirmed", "prepared", "submitted", "cancelled", "expired", "rejected"]
    {
        let mut row = original.clone();
        row.phase = phase.into();
        if phase != "mutually_confirmed" {
            row.candidate_id = Some(operation.into());
            row.proposal_hash = Some(ramflux_protocol::encode_base64url([91; 32]));
        }
        {
            let slot = participant.db.lock().map_err(|_| "DB")?;
            slot.as_ref().ok_or("DB")?.put_pairing_live(&row)?;
        }
        assert!(
            matches!(
                participant.retain_full_data_stage(operation, row.generation, &trust, &base, None),
                Err(SdkError::PairingCode("WrongContext"))
            ),
            "fresh bootstrap replaced a linked or uncertain row: {phase}"
        );
        let slot = participant.db.lock().map_err(|_| "DB")?;
        let db = slot.as_ref().ok_or("DB")?;
        let retained = db
            .pairing_live_rows()?
            .into_iter()
            .find(|row| row.operation_id == operation)
            .ok_or("live row")?;
        assert_eq!(retained, row, "bootstrap changed uncertainty metadata");
        db.put_pairing_live(&original)?;
    }
    Ok(())
}

fn assert_declared_full_source(participant: &LocalPairingParticipant) -> TestResult {
    let slot = participant.db.lock().map_err(|_| "DB")?;
    let db = slot.as_ref().ok_or("DB")?;
    let rules = ramflux_storage::full_transfer_catalog();
    let schema = db.inspect_full_transfer_schema(rules)?;
    let undeclared: Vec<_> = schema
        .families
        .iter()
        .zip(rules)
        .filter(|(family, rule)| family.source_rows.0 > 0 && rule.require_typed_codec().is_err())
        .map(|(family, _)| family.id.as_str())
        .collect();
    assert!(undeclared.is_empty(), "fixture contains undeclared owners: {undeclared:?}");
    Ok(())
}

async fn assert_full_cancel_fences_stage(rig: &mut Rig, operation: &str) -> TestResult {
    rig.secondary.lock().await?;
    {
        let slot = rig.participant_b.db.lock().map_err(|_| "DB")?;
        let db = slot.as_ref().ok_or("DB")?;
        let row = db
            .pairing_live_rows()?
            .into_iter()
            .find(|row| row.operation_id == operation)
            .ok_or("live row")?;
        assert_eq!(row.phase, "cancelled");
        assert!(row.full_stage_reference()?.is_some(), "cancel erased resume uncertainty");
        assert!(
            db.open_full_transfer_stage(
                operation,
                ramflux_crypto::custody::pairing::PairingRole::Responder,
                rig.now,
            )
            .is_err(),
            "cancelled actor left a reopenable data stage"
        );
    }
    Ok(())
}

fn full_begin(now: u64) -> ramflux_protocol::custody::pairing::local_dto::FullTransferBegin {
    use ramflux_protocol::custody::pairing::{
        context_v3::{DataSelectionV3, FullAccountData, TransferProfile},
        local_dto::FullTransferBegin,
    };
    FullTransferBegin {
        schema: "ramflux.pairing.TransferBegin.v3".into(),
        version: 3,
        recipient_mode: "new".into(),
        destination_ref: None,
        capabilities: vec!["group".into(), "message".into(), "register".into(), "sync".into()],
        lease_not_before: now,
        lease_expires_at: now + 604_800,
        data_selection: DataSelectionV3::FullAccountDataV1(FullAccountData {}),
        transfer_profile: TransferProfile::FullAccountDataV1,
        display_name: "Source".into(),
    }
}

#[tokio::test(flavor = "current_thread")]
async fn pairing_full_network_initialized_source_refuses_undeclared_events_and_actors() -> TestResult
{
    let mut rig = Rig::open().await?;
    assert!(matches!(
        rig.primary.begin_full(full_begin(rig.now)).await,
        Err(SdkError::PairingField("UnsupportedRecord"))
    ));
    assert!(rig.primary.displayed_transcript().is_err());
    let slot = rig.participant_a.db.lock().map_err(|_| "DB")?;
    let db = slot.as_ref().ok_or("DB")?;
    let schema = db.inspect_full_transfer_schema(ramflux_storage::full_transfer_catalog())?;
    for family in ["sql/local_event_log", "sql/runtime_actor_state"] {
        assert!(
            schema.families.iter().any(|item| item.id == family && item.source_rows.0 > 0),
            "fixture no longer exercises undeclared owner {family}"
        );
    }
    Ok(())
}

async fn checked_full_status(
    actor: &mut PairingActor,
    request: &ramflux_protocol::custody::pairing::local_dto::StatusRequest,
    role: &str,
) -> TestResult {
    actor.status(request).await?;
    let value = actor.sync_relay().await?;
    let Outcome::Update { value } = value.outcome else {
        return Err("full status".into());
    };
    if matches!(value.phase.as_str(), "rejected" | "expired" | "cancelled") {
        return Err(format!("{role} terminal: {} / {:?}", value.phase, value.result).into());
    }
    Ok(())
}

// Keep paused time from jumping over local database/vault worker work. This follows the
// SDK actor test hold; each protocol timer advance below is explicit.
struct ClockHold {
    release: Option<std::sync::mpsc::Sender<()>>,
    worker: Option<tokio::task::JoinHandle<()>>,
}
impl ClockHold {
    fn new() -> Self {
        let (release, wait) = std::sync::mpsc::channel();
        let worker = tokio::task::spawn_blocking(move || {
            let _ = wait.recv();
        });
        Self { release: Some(release), worker: Some(worker) }
    }
    async fn finish(mut self) -> TestResult {
        self.release.take();
        self.worker.take().ok_or("clock hold")?.await?;
        Ok(())
    }
}
impl Drop for ClockHold {
    fn drop(&mut self) {
        self.release.take();
    }
}

#[tokio::test(start_paused = true)]
async fn pairing_full_initial_epoch_uses_a3_with_sas_keys() -> TestResult {
    use ramflux_protocol::custody::pairing::{PairingWire, context_v3::TranscriptV3};
    let hold = ClockHold::new();
    let (mut rig, operation, _) = Box::pin(bootstrap_full_rig()).await?;
    let frozen = {
        let slot = rig.participant_a.db.lock().map_err(|_| "DB")?;
        let stage = slot.as_ref().ok_or("DB")?.open_full_transfer_stage(
            &operation,
            ramflux_crypto::custody::pairing::PairingRole::Initiator,
            rig.now,
        )?;
        TranscriptV3::from_wire_bytes(&stage.resume_record()?.transcript)?
    };
    rig.primary.sync_relay().await?;
    // Actual frontend handback: the background signer must not need a parked DB loan.
    rig.participant_a.return_client(&mut rig.source.client)?;
    assert!(rig.participant_a.db.lock().map_err(|_| "DB")?.is_none());
    rig.secondary.sync_relay().await?;
    let mut ready = false;
    for _ in 0..16 {
        rig.primary.sync_relay().await?;
        rig.secondary.sync_relay().await?;
        let (sent, received) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            let _ = sent.send(());
        });
        received.await?;
        if rig.primary.full_epoch_ready_for_test() && rig.secondary.full_epoch_ready_for_test() {
            ready = true;
            break;
        }
        tokio::time::advance(std::time::Duration::from_millis(500)).await;
    }
    assert!(ready, "actual native A3/original-proof/HPKE/Ready did not complete");
    {
        let seen = rig.full_hellos.lock().map_err(|_| "hello observations")?;
        assert_eq!(seen.len(), 2);
        for (role, key) in [
            ("initiator", frozen.initiator.hpke_key.as_deref().ok_or("source HPKE")?),
            ("responder", frozen.responder.hpke_key.as_deref().ok_or("target HPKE")?),
        ] {
            assert!(
                seen.iter().any(|hello| hello.role == role && hello.hpke_key == key),
                "initial A3 key differs from own frozen SAS key: {role}"
            );
        }
    }

    assert!(rig.source.client.account_db()?.pairing_adoption()?.is_none());
    hold.finish().await?;
    Ok(())
}

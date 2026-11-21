// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Enrollment-history proof fixture on the generation-1 own-device carriers: received history
//! travels as exact-item pages, own-authored group history as authored copies. The retired group
//! codec and own-sync importer are deleted and never return.
use super::*;
use crate::client::generated_history::producer::Outgoing;
use crate::client::routed::SendMaterial;
use crate::custody::PrimaryVault;
use crate::custody::tests::{Root, TestVault};
use ramflux_protocol::message as g;
use ramflux_protocol::{GroupStateChange, SharedGroupRole};
use std::sync::Arc;

const GROUP: &str = "enrollment-history-group";
const THREAD: &str = "enrollment-history-thread";
const DM_TEXT: &str = "native first-hand history";
const ERASED_DM_TEXT: &str = "own-authored message erased before pairing";
const OWN_DM_TEXT: &str = "own-authored history before pairing";
const GROUP_TEXT: &str = "historical group message";
const MAX_STEPS: usize = 16;

/// What `seed` authored or received before the enrollment.
pub(crate) struct Seeded {
    peer: Fixture,
    dm_id: Vec<u8>,
    own_dm_id: Vec<u8>,
    erased_dm_id: Vec<u8>,
    dm_conversation: String,
    group_owner: String,
    group_state: ramflux_crypto::VerifiedGroupState,
    peer_sessions: Vec<String>,
}

impl Fixture {
    /// Wrap an already initialized native client in the feature-test fixture surface. The vault,
    /// root and manifest are rebuilt from the account's current authority record; callers take the
    /// client back with `into_client` and the temporary directory is released.
    pub(crate) fn adopt(
        client: RamfluxClient,
        id: &str,
        device: &str,
        record: ramflux_protocol::custody::Envelope<ramflux_protocol::custody::DeviceSet>,
    ) -> TestResult<Self> {
        let account_root = client.account_index()?.root().to_path_buf();
        Self::ready_in(
            client,
            Home { root: Root::new()?, account_root: &account_root },
            Arc::new(TestVault::default()),
            id,
            device,
            record,
        )
    }
    pub(crate) fn into_client(self) -> RamfluxClient {
        self.client
    }
}

/// Seed one received first-hand DM and one own-authored group message, before any enrollment.
pub(crate) async fn seed(source: &mut Fixture, vault: &dyn PrimaryVault) -> TestResult<Seeded> {
    let mut peer = Fixture::new("enrollment-history-peer").await?;
    let (dm, _, dm_conversation) = Box::pin(history::receive_first_hand(source, &peer)).await?;
    let own_dm =
        Box::pin(history::author_first_hand(source, &mut peer, &dm_conversation, OWN_DM_TEXT, 1))
            .await?;
    // An own message erased before pairing must never reach the enrolled device.
    let erased = Box::pin(history::author_first_hand(
        source,
        &mut peer,
        &dm_conversation,
        ERASED_DM_TEXT,
        2,
    ))
    .await?;
    source.client.account_db()?.delete_direct_message(
        &dm_conversation,
        &ramflux_protocol::encode_base64url(&erased.id),
        "everyone",
        &ramflux_protocol::encode_base64url(ramflux_crypto::random_32()?),
    )?;
    let primary = source
        .client
        .born_v3_account
        .as_ref()
        .ok_or("test: native source account")?
        .group_primary(vault)?;
    source.client.shared_group_create_with_primary(
        GROUP,
        THREAD,
        Some("Enrollment history".into()),
        &source.config.target_delivery_id,
        Some(&primary),
    )?;
    let group_state = source.client.shared_group_change_with_primary(
        GROUP,
        &source.config.target_delivery_id,
        GroupStateChange::Add {
            member: peer.client.owned_group_actor(&peer.config.target_delivery_id)?.identity,
            role: SharedGroupRole::Member,
        },
        Some(&primary),
    )?;
    drop(primary);
    let identity = source.client.allocate_generated_identity(
        THREAD,
        crate::client::generated_identity::now_ms(),
        false,
    )?;
    let group_owner = ramflux_protocol::encode_base64url(&identity.id);
    source.client.encrypt_generated_group_inner(
        GROUP,
        &source.config.device_id,
        identity,
        &g::Message { text: GROUP_TEXT.into(), ..Default::default() },
    )?;
    let peer_sessions = source.client.account_db()?.actor_state_keys("dm-pair/")?;
    assert!(!peer_sessions.is_empty(), "test: the source holds no live pair session to protect");
    Ok(Seeded {
        peer,
        dm_id: dm.id,
        own_dm_id: own_dm.id,
        erased_dm_id: erased.id,
        dm_conversation,
        group_owner,
        group_state,
        peer_sessions,
    })
}

fn due(client: &RamfluxClient) -> TestResult {
    let db = client.account_db()?;
    db.write_transaction(|| {
        for key in db.actor_state_keys("history-out/transfer/")? {
            let mut row =
                db.load_actor_state::<Outgoing>(&key)?.ok_or(crate::SdkError::ReplayMismatch)?;
            row.next_at = 0;
            db.persist_actor_state(&key, &row)?;
        }
        Ok::<(), crate::SdkError>(())
    })?;
    Ok(())
}

/// Deliver every history page to the target through the production courier plan, seal and
/// complete steps, one gateway-accepted page at a time. Returns the number of pages delivered.
pub(crate) async fn deliver_pages(
    source: &Fixture,
    target: &mut Fixture,
    stop_after: Option<usize>,
    first_sequence: u64,
) -> TestResult<usize> {
    let mut delivered = 0;
    for _ in 0..MAX_STEPS {
        due(&source.client)?;
        let Some(plan) = source.client.prepare_generated_history_delivery(&source.config)? else {
            break;
        };
        let material = if plan.envelope.is_some() {
            SendMaterial { manifest: None, bundle: None }
        } else {
            source.material_for(target)?
        };
        let Some((plan, envelope)) =
            source.client.seal_generated_history_delivery(&source.config, plan, material)?
        else {
            continue;
        };
        if stop_after == Some(delivered) {
            // Sealed and retained but never accepted: the source is killed here.
            return Ok(delivered);
        }
        let sequence = first_sequence + u64::try_from(delivered)?;
        target.receive(envelope, sequence).await?;
        source.client.complete_generated_history_delivery(&plan)?;
        delivered += 1;
    }
    Ok(delivered)
}

/// The enrolled device reads the pre-enrollment history through the generation-1 read model,
/// holds none of the source's pair sessions and keeps its own prekey identity.
pub(crate) async fn verify(source: &Fixture, target: &mut Fixture, seeded: &Seeded) -> TestResult {
    let own = target.client.owned_device_identity()?;
    let prekeys_before = serde_json::to_value(target.client.load_x3dh_private_state(&own)?.bundle)?;
    target.client.persist_observed_identity_directory_now(&source.manifest)?;
    source.client.persist_observed_identity_directory_now(&target.manifest)?;
    assert!(
        source.client.start_generated_history_transfer(&target.config.device_id)?,
        "test: no history transfer was staged for the enrolled device"
    );
    assert!(
        source.client.prepare_authored_history(&source.config)?.is_none(),
        "test: an authored copy was prepared while the history pages for its target are pending"
    );
    let pages = deliver_pages(source, target, None, 1).await?;
    assert!(pages > 0, "test: no history page reached the enrolled device");
    assert_eq!(
        source.client.generated_history_transfer_done(&own_ref(source, target)?)?,
        Some(true),
        "test: the transfer row is not done after every page was accepted"
    );
    // The enrollment job ends once every page is accepted, which is what releases authored copies.
    let db = source.client.account_db()?;
    if let Some(job) = db.next_pairing_own_sync()? {
        assert!(db.claim_pairing_own_sync(&job)?, "test: the enrollment history job was claimed");
        db.finish_pairing_own_sync(&job, None)?;
    }
    let dm_owner = ramflux_protocol::encode_base64url(&seeded.dm_id);
    let dm = target.client.generated_message_detail(&seeded.dm_conversation, &dm_owner)?;
    assert_eq!(
        dm.message.text.as_deref(),
        Some(DM_TEXT),
        "test: the enrolled device cannot read the pre-enrollment DM"
    );
    // Own-authored group history travels as an authored copy once the target holds the signed
    // group state, exactly as the sibling group tests install it.
    target
        .client
        .accept_shared_group_state(&seeded.group_state, &target.config.target_delivery_id)?;
    // Every own-authored capture (the group message and the direct message) travels as an
    // authored copy; drain the courier plan exactly as the background courier would.
    let mut copies = 0_u64;
    for _ in 0..MAX_STEPS {
        let Some(plan) = source.client.prepare_authored_history(&source.config)? else { break };
        let Some((plan, packet)) = source.client.seal_authored_history(
            &source.config,
            plan,
            source.material_for(target)?,
        )?
        else {
            continue;
        };
        target.receive(packet, 1_000 + copies).await?;
        source.client.complete_authored_history(&plan)?;
        copies += 1;
    }
    assert!(copies > 0, "test: no authored history was staged for the enrolled device");
    let group = target.client.generated_message_detail(THREAD, &seeded.group_owner)?;
    assert_eq!(
        group.message.text.as_deref(),
        Some(GROUP_TEXT),
        "test: the enrolled device cannot read the pre-enrollment group message"
    );
    assert_own_history(source, target, seeded)?;
    let target_sessions = target.client.account_db()?.actor_state_keys("dm-pair/")?;
    for session in &seeded.peer_sessions {
        assert!(
            !target_sessions.contains(session),
            "test: the enrolled device holds a source pair session {session}"
        );
    }
    assert_eq!(
        serde_json::to_value(target.client.load_x3dh_private_state(&own)?.bundle)?,
        prekeys_before,
        "test: history import replaced the enrolled device's own prekey identity"
    );
    for (name, client) in [("source", &source.client), ("enrolled", &target.client)] {
        full_transfer_inventory(name, client)?;
    }
    assert!(
        !seeded.peer.client.own_account_anchor()?.is_empty(),
        "test: the peer fixture stayed alive for the whole proof"
    );
    Ok(())
}

/// The owner's own pre-enrollment text is present, an erased one is absent, and the enrolled
/// conversation keeps the source's own and peer order.
fn assert_own_history(source: &Fixture, target: &Fixture, seeded: &Seeded) -> TestResult {
    let own_owner = ramflux_protocol::encode_base64url(&seeded.own_dm_id);
    let own_dm = target.client.generated_message_detail(&seeded.dm_conversation, &own_owner)?;
    assert_eq!(
        own_dm.message.text.as_deref(),
        Some(OWN_DM_TEXT),
        "test: the enrolled device cannot read the owner's own pre-enrollment DM"
    );
    let erased_owner = ramflux_protocol::encode_base64url(&seeded.erased_dm_id);
    assert!(
        target.client.direct_message_by_id(&erased_owner)?.is_none_or(|row| row.deleted),
        "test: an own message erased before pairing reappeared on the enrolled device"
    );
    let texts = |fixture: &Fixture| -> TestResult<Vec<String>> {
        Ok(fixture
            .client
            .generated_message_view_page(&seeded.dm_conversation, None, 10)?
            .messages
            .into_iter()
            .filter_map(|message| message.text)
            .collect())
    };
    let enrolled = texts(target)?;
    assert_eq!(enrolled.len(), 2, "test: the enrolled conversation must hold exactly two rows");
    assert_eq!(
        enrolled,
        texts(source)?,
        "test: own and peer rows must keep the source's order on the enrolled device"
    );
    Ok(())
}

pub(crate) fn own_ref(
    source: &Fixture,
    target: &Fixture,
) -> TestResult<ramflux_crypto::RootQualifiedDeviceRef> {
    Ok(source
        .client
        .device_identity_for_root(&source.client.own_account_anchor()?, &target.config.device_id)?)
}

#[tokio::test(flavor = "current_thread")]
async fn history_transfer_resumes_after_the_source_dies_between_pages() -> TestResult {
    watchdog::within(Box::pin(resume())).await?
}

async fn resume() -> TestResult {
    let mut source = Fixture::new("resume-source").await?;
    let mut target = source.enroll_sibling("resume-target", "resume-device").await?;
    let first_peer = Fixture::new("resume-peer-a").await?;
    let second_peer = Fixture::new("resume-peer-b").await?;
    let (first, _, _) = Box::pin(history::receive_first_hand(&mut source, &first_peer)).await?;
    let (second, _, _) = Box::pin(history::receive_first_hand(&mut source, &second_peer)).await?;
    let id = own_ref(&source, &target)?;
    assert!(source.client.start_generated_history_transfer(&target.config.device_id)?);
    assert_eq!(
        source.client.generated_history_transfer_done(&id)?,
        Some(false),
        "test: a staged transfer must be pending, not finished"
    );
    // Page 0 is durably accepted; page 1 is sealed and retained, then the source dies before the
    // gateway accepts it.
    assert_eq!(deliver_pages(&source, &mut target, Some(1), 1).await?, 1);
    assert_eq!(
        source.client.generated_history_transfer_done(&id)?,
        Some(false),
        "test: the job must stay pending while a page is not durably accepted"
    );
    source.restart_authored_source().await?;
    assert_eq!(
        source.client.generated_history_transfer_done(&id)?,
        Some(false),
        "test: a restart must not finish the transfer"
    );
    assert_eq!(
        deliver_pages(&source, &mut target, None, 10).await?,
        1,
        "test: the resumed source must send exactly the one remaining page"
    );
    assert_eq!(source.client.generated_history_transfer_done(&id)?, Some(true));
    let row = source
        .client
        .account_db()?
        .load_actor_state::<Outgoing>(&format!("history-out/transfer/{}", id.storage_key()))?
        .ok_or("test: transfer row")?;
    assert_eq!((row.next_page, row.exported), (2, 2), "test: one complete set of pages");
    for owner in [&first.id, &second.id] {
        assert!(
            target
                .client
                .account_db()?
                .message_content(&ramflux_protocol::encode_base64url(owner))?
                .is_some(),
            "test: a history message is missing after the resumed transfer"
        );
    }
    assert_eq!(
        target.client.account_db()?.all_direct_messages()?.len(),
        2,
        "test: the resumed transfer duplicated or dropped a message"
    );
    Ok(())
}

/// A generation-1 account that holds history, original-header evidence, transfer rows and raw
/// copies passes main's full-transfer schema inventory: every table is classified. Its actor
/// rows keep the OVP-12 refusal at typed-owner admission (Q3 typed-owners follow-up); no family
/// is silently skipped or declared transferable here.
fn full_transfer_inventory(name: &str, client: &RamfluxClient) -> TestResult {
    let rules = ramflux_storage::full_transfer_catalog();
    let db = client.account_db()?;
    let schema = db.inspect_full_transfer_schema(rules).map_err(|error| {
        format!("test: {name} generation-1 account failed the inventory: {error}")
    })?;
    assert!(
        !db.actor_state_keys("routed/")?.is_empty(),
        "test: {name} holds no activation actor state, so the inventory proves nothing"
    );
    assert!(
        matches!(
            schema.require_typed_owners(rules),
            Err(ramflux_storage::StorageError::PairingField("UnsupportedRecord"))
        ),
        "test: {name} actor rows must keep the OVP-12 typed-owner refusal"
    );
    Ok(())
}

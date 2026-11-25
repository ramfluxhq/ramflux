// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Native human and primary-approved agent authority for v3 surface tests.
use crate::custody::tests::{TestVault, words};
use crate::custody::{CreateInput, CreationCeremony, PrimaryVault};
use crate::{RamfluxClient, SdkError};
use ramflux_protocol::PrincipalKind;
use std::{path::Path, sync::Arc};
pub(super) type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
pub(crate) async fn owned_pair(
    root: &Path,
    human: &str,
    agent: &str,
) -> TestResult<(RamfluxClient, RamfluxClient)> {
    let (human, agent, _vault) = owned_pair_with_vault(root, human, agent).await?;
    Ok((human, agent))
}
pub(crate) async fn owned_pair_with_vault(
    root: &Path,
    human: &str,
    agent: &str,
) -> TestResult<(RamfluxClient, RamfluxClient, Arc<TestVault>)> {
    std::fs::create_dir_all(root)?;
    let now = crate::custody::network_now()?;
    let vault = Arc::new(TestVault::default());
    let input = |id: &str, kind, custodian| CreateInput {
        local_account_id: id.into(),
        principal_id: id.into(),
        device_id: format!("{id}-device"),
        display_name: id.into(),
        principal_kind: kind,
        custodian_account_id: custodian,
    };
    let mut ceremony =
        CreationCeremony::begin(root, input(human, PrincipalKind::Human, None), now)?;
    let phrase = ceremony.show_once()?;
    let positions = ceremony.hidden_challenge()?;
    ceremony.confirm_with_passphrase(
        &words(&phrase, positions)?,
        vault.as_ref(),
        now,
        b"662207",
    )?;
    crate::custody::tests::mark_live(root, human, now)?;
    let created = crate::custody::agent_creation::test_agent::create_test_agent(
        &crate::custody::agent_creation::test_agent::AgentRequest {
            root,
            human_account_id: human,
            human_principal: human,
            human_vault: vault.as_ref(),
            arm_approval: &|plan_hash| vault.arm_agent_decision(plan_hash),
            agent_vault: vault.as_ref(),
            agent_principal: agent,
            display_name: agent,
            request_id: "surface-agent",
        },
        now,
    )?;
    let initialize =
        async |id: &str, device: &str, passphrase: &[u8]| -> TestResult<RamfluxClient> {
            let mut client = RamfluxClient::new();
            client.open_account_index(root)?;
            client.unlock_account(id, passphrase)?;
            let vault: Arc<dyn PrimaryVault> = vault.clone();
            client.initialize_born_v3_branch(device, vault).await?;
            Ok(client)
        };
    let (human_client, agent_client) =
        tokio::time::timeout(std::time::Duration::from_secs(30), async {
            Ok::<_, Box<dyn std::error::Error>>((
                initialize(human, &format!("{human}-device"), b"662207").await?,
                initialize(&created.account_id, &created.device_id, created.passphrase.as_bytes())
                    .await?,
            ))
        })
        .await??;
    let human_manifest = native_manifest(&human_client)?;
    let agent_manifest = native_manifest(&agent_client)?;
    for client in [&human_client, &agent_client] {
        client.persist_observed_identity_directory_now(&human_manifest)?;
        client.persist_observed_identity_directory_now(&agent_manifest)?;
    }
    seed_own_agent_record(&human_client, &agent_client)?;
    Ok((human_client, agent_client, vault))
}
/// Rendering and acceptance read the owner's agent record next to the pinned publication. The
/// creation writes it on completion and every own device receives it; this fixture completes
/// without an intent, so the record is seeded on each owner terminal.
pub(crate) fn seed_own_agent_record(owner: &RamfluxClient, agent: &RamfluxClient) -> TestResult {
    let author = owner
        .born_v3_account
        .as_ref()
        .map(|account| account.record().body.master_certificate.body.primary_device_ref.clone())
        .ok_or("owner account")?;
    let anchor = agent
        .born_v3_account
        .as_ref()
        .map(|account| account.record().body.account_anchor.clone())
        .ok_or("agent account")?;
    crate::agent_record::seed_for_test(&owner.agent_record_store()?, &anchor, &author, 1)?;
    Ok(())
}
pub(crate) fn create_frame(
    conversation: &str,
    snapshot: &ramflux_protocol::SurfaceSnapshot,
) -> Result<ramflux_protocol::EventFrame, SdkError> {
    use ramflux_protocol::{EVENT_SCHEMA, EventFrame, Mutation, MutationMessage, SurfaceState};
    Ok(SurfaceState::default().prepare_event(EventFrame {
        schema: EVENT_SCHEMA.into(),
        conversation_id: conversation.into(),
        surface_version: 1,
        base_surface_hash: None,
        new_surface_hash: String::new(),
        fallback_text: Some(snapshot.fallback_text.clone()),
        close_reason: None,
        a2ui: Some(MutationMessage::new(Mutation::CreateSurface(snapshot.create()))),
        append_text: None,
        resync: None,
        final_: None,
        closed: None,
        metadata: None,
    })?)
}

pub(crate) fn text_snapshot(
    surface: &str,
    fallback: &str,
    text: &str,
) -> ramflux_protocol::SurfaceSnapshot {
    ramflux_protocol::SurfaceSnapshot {
        surface_id: surface.into(),
        catalog_id: ramflux_protocol::CATALOG_ID.into(),
        fallback_text: fallback.into(),
        metadata: None,
        components: vec![
            serde_json::json!({"id":"root","component":"Column","children":["result"]}),
            serde_json::json!({"id":"result","component":"Text","text":{"@path":"/result"}}),
        ],
        data_model: serde_json::json!({"result":text}),
        final_: Vec::new(),
        closed: false,
    }
}

pub(crate) fn append_frame(
    state: &ramflux_protocol::SurfaceState,
    path: &str,
    delta: &str,
    final_: bool,
) -> Result<ramflux_protocol::EventFrame, SdkError> {
    let mut frame = state.resync_frame()?;
    frame.surface_version = state.version() + 1;
    frame.base_surface_hash = state.hash().map(str::to_owned);
    frame.fallback_text = None;
    frame.resync = None;
    frame.final_ = None;
    frame.closed = None;
    frame.metadata = None;
    frame.append_text = Some(ramflux_protocol::AppendText {
        surface_id: state
            .content()
            .ok_or_else(|| super::invalid("test state missing"))?
            .surface_id
            .clone(),
        path: path.into(),
        delta: delta.into(),
        final_,
    });
    Ok(state.prepare_event(frame)?)
}

pub(crate) async fn owned_terminals(root: &Path) -> TestResult<Vec<RamfluxClient>> {
    Ok(owned_terminals_with_vault(root).await?.0)
}

pub(crate) async fn owned_terminals_with_vault(
    root: &Path,
) -> TestResult<(Vec<RamfluxClient>, Arc<TestVault>)> {
    let (mut human, mut agent, vault) = owned_pair_with_vault(root, "human", "author").await?;
    let secondary = root.join("secondary");
    std::fs::create_dir_all(&secondary)?;
    let human_two =
        enroll_surface_sibling(&secondary, &mut human, &vault, "human", "human-two").await?;
    let author_two =
        enroll_surface_sibling(&secondary, &mut agent, &vault, "author", "author-two").await?;
    seed_own_agent_record(&human_two, &agent)?;
    let clients = vec![agent, author_two, human, human_two];
    let mut by_root =
        std::collections::BTreeMap::<String, ramflux_protocol::custody::CustodyManifest>::new();
    for client in &clients {
        let manifest = native_manifest(client)?;
        let native = *manifest.custody.ok_or("terminal native manifest")?;
        if let Some(full) = by_root.get_mut(&manifest.principal_commitment) {
            assert_eq!(
                ramflux_protocol::custody::object_hash(&full.publication.record)?,
                ramflux_protocol::custody::object_hash(&native.publication.record)?,
                "all enrolled terminals must observe the same actual custody head"
            );
            full.devices.extend(native.devices);
        } else {
            by_root.insert(manifest.principal_commitment, native);
        }
    }
    let manifests = by_root
        .into_values()
        .map(crate::prekey::SdkDeviceManifestResponse::from_native)
        .collect::<Result<Vec<_>, _>>()?;
    for client in &clients {
        for manifest in &manifests {
            client.persist_observed_identity_directory_now(manifest)?;
        }
        client.account_db()?.persist_client_record(
            "conversation",
            "thread",
            &serde_json::json!({"kind":"direct","participants":["author","human"]}),
        )?;
    }
    Ok((clients, vault))
}
/// Open a sibling's account data through its device-bound code wrap.
fn open_device_bound(
    root: &Path,
    vault: &TestVault,
    account_id: &str,
) -> TestResult<RamfluxClient> {
    let mut client = RamfluxClient::new();
    client.open_account_index(root)?;
    client.bind_device_unlock(
        root,
        vault,
        account_id,
        crate::client::device_unlock::DeviceSecret::Load,
    )?;
    client.unlock_account(account_id, b"662207")?;
    Ok(client)
}

async fn enroll_surface_sibling(
    root: &Path,
    source: &mut RamfluxClient,
    vault: &Arc<TestVault>,
    account_id: &str,
    device: &str,
) -> TestResult<RamfluxClient> {
    let mut native = source.local_own_copy_manifest()?.custody.ok_or("native manifest")?;
    let primary = vault.primary_for_public_key(
        &native.publication.record.body.master_certificate.body.self_signing_public_key,
    )?;
    let now = crate::custody::network_now()?;
    native.custodian_publication = source
        .born_v3_account
        .as_ref()
        .ok_or("native account")?
        .custodian_publication(source.account_index()?.root(), now)?;
    let custodian = native
        .custodian_publication
        .as_ref()
        .map(|publication| {
            ramflux_crypto::custody::verify_record(
                &publication.record,
                now,
                publication.compacted_ids.as_deref(),
                None,
            )
        })
        .transpose()?;
    let current = ramflux_crypto::custody::verify_record(
        &native.publication.record,
        now,
        native.publication.compacted_ids.as_deref(),
        custodian.as_ref(),
    )?;
    let mut seeds = zeroize::Zeroizing::new([0u8; 64]);
    getrandom::fill(&mut *seeds).map_err(|_| SdkError::CustodyRandomUnavailable)?;
    let signing: [u8; 32] = seeds.get(..32).ok_or("signing seed")?.try_into()?;
    let agreement: [u8; 32] = seeds.get(32..).ok_or("agreement seed")?.try_into()?;
    let branch = ramflux_crypto::create_device_branch(
        &native.publication.record.body.principal_id,
        device,
        1,
        signing,
    );
    let agreement = ramflux_crypto::X25519KeyPair::from_seed(agreement);
    let mut certificate = native
        .publication
        .record
        .body
        .devices
        .first()
        .and_then(|d| d.branch_certificate.as_ref())
        .ok_or("primary certificate")?
        .body
        .clone();
    certificate.device_id = device.into();
    certificate.branch_signing_public_key =
        ramflux_protocol::encode_base64url(branch.signing_key.verifying_key().as_bytes());
    certificate.agreement_identity_public_key =
        ramflux_protocol::encode_base64url(agreement.public);
    certificate.cert_id = ramflux_protocol::encode_base64url(ramflux_crypto::random_32()?);
    let message_layer = ramflux_crypto::custody::sign_enrollment_layer(&branch, &certificate)?;
    native.publication.record = primary.enroll_device(
        &current,
        primary.certify_branch(certificate)?,
        message_layer,
        now,
    )?;
    let source_id = source.account_db()?.local_account_id.clone();
    crate::custody::accept_publication(
        source.account_index()?.root(),
        &source_id,
        &ramflux_protocol::custody::CustodyAuthority {
            publication: native.publication.clone(),
            custodian_publication: native.custodian_publication.clone(),
        },
        now,
    )?;
    let source_device = source.owned_device_identity()?.device_id().to_owned();
    source.initialize_born_v3_branch_for_fixture(&source_device, vault.as_ref())?;
    let sibling_vault = Arc::new(TestVault::default());
    crate::custody::install_sibling_fixture(crate::custody::SiblingSetup {
        root,
        id: account_id,
        device,
        record: native.publication.record.clone(),
        branch: &seeds,
        vault: sibling_vault.as_ref(),
        passphrase: b"662207",
        now,
    })?;
    let mut client = open_device_bound(root, sibling_vault.as_ref(), account_id)?;
    tokio::time::timeout(
        std::time::Duration::from_secs(30),
        client.initialize_born_v3_branch(device, sibling_vault),
    )
    .await??;
    let manifest = native_manifest(&client)?;
    native.devices.extend(manifest.custody.ok_or("sibling native manifest")?.devices);
    let full = crate::prekey::SdkDeviceManifestResponse::from_native(*native)?;
    source.persist_observed_identity_directory_now(&full)?;
    client.persist_observed_identity_directory_now(&full)?;
    Ok(client)
}

fn native_manifest(client: &RamfluxClient) -> TestResult<crate::prekey::SdkDeviceManifestResponse> {
    use ramflux_protocol::custody::{CustodyManifest, CustodyManifestDevice, DeviceRef};
    let identity = client.owned_device_identity()?;
    let branch = client.device_branch.as_ref().ok_or("certified branch")?;
    let account = client.born_v3_account.as_ref().ok_or("native account")?;
    let manifest = crate::prekey::SdkDeviceManifestResponse::from_native(CustodyManifest {
        publication: account.publication(),
        custodian_publication: account.custodian_publication(
            client.account_index()?.root(),
            crate::custody::network_now()?,
        )?,
        devices: vec![CustodyManifestDevice {
            device_ref: DeviceRef {
                account_anchor: identity.root_commitment().into(),
                device_id: identity.device_id().into(),
                device_epoch: branch.device_epoch,
            },
            target_delivery_id: identity.storage_key().into(),
            prekey_bundle: serde_json::to_value(client.load_x3dh_private_state(&identity)?.bundle)?,
            message_layer: None,
        }],
    })?;
    client.persist_observed_identity_directory_now(&manifest)?;
    Ok(manifest)
}

/// Install the already certified native branch for pair-transport feature fixtures. These
/// fixtures do not perform, or claim to test, the gateway's native proof handshake.
pub(crate) fn native_transport_config(
    mut config: crate::GatewaySessionConfig,
    client: &RamfluxClient,
) -> Result<crate::GatewaySessionConfig, SdkError> {
    let identity = client.owned_device_identity()?;
    let branch = client.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?;
    config.principal_id.clone_from(&branch.principal_id);
    config.device_id.clone_from(&branch.device_id);
    config.device_epoch = branch.device_epoch;
    config.target_delivery_id = identity.storage_key().into();
    config.device_branch = Some(Arc::new(branch.clone()));
    config.source_identity = Some(identity);
    Ok(config)
}

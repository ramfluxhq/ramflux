// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Phrase-created human/agent authority for v3 surface tests; no ownership flags are forged.
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
pub(super) async fn owned_pair_with_vault(
    root: &Path,
    human: &str,
    agent: &str,
) -> TestResult<(RamfluxClient, RamfluxClient, Arc<TestVault>)> {
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
        b"surface-test-secret",
    )?;
    crate::custody::tests::mark_live(root, human, now)?;
    let mut ceremony = CreationCeremony::begin(
        root,
        input(agent, PrincipalKind::HeadlessAi, Some(human.into())),
        now,
    )?;
    let phrase = ceremony.show_once()?;
    let positions = ceremony.hidden_challenge()?;
    ceremony.confirm_with_passphrase(
        &words(&phrase, positions)?,
        vault.as_ref(),
        now,
        b"surface-test-secret",
    )?;
    let initialize = async |id: &str| -> TestResult<RamfluxClient> {
        let mut client = RamfluxClient::new();
        client.open_account_index(root)?;
        client.unlock_account(id, b"surface-test-secret")?;
        let vault: Arc<dyn PrimaryVault> = vault.clone();
        client.initialize_born_v3_branch(&format!("{id}-device"), vault).await?;
        Ok(client)
    };
    let (human_client, agent_client) =
        tokio::time::timeout(std::time::Duration::from_secs(30), async {
            Ok::<_, Box<dyn std::error::Error>>((
                initialize(human).await?,
                initialize(agent).await?,
            ))
        })
        .await??;
    let human_manifest = human_client.local_own_copy_manifest()?;
    let agent_manifest = agent_client.local_own_copy_manifest()?;
    human_client.persist_fetched_identity_directory(&agent_manifest)?;
    agent_client.persist_fetched_identity_directory(&human_manifest)?;
    Ok((human_client, agent_client, vault))
}
pub(super) fn state_from_snapshot(
    conversation: &str,
    version: u64,
    snapshot: &ramflux_protocol::SurfaceSnapshot,
) -> Result<ramflux_protocol::SurfaceState, SdkError> {
    let mut object = serde_json::to_value(snapshot)?
        .as_object()
        .cloned()
        .ok_or_else(|| super::invalid("snapshot object missing"))?;
    object.insert("conversationId".into(), serde_json::json!(conversation));
    object.insert("surfaceVersion".into(), serde_json::json!(version));
    Ok(ramflux_protocol::SurfaceState::from_checkpoint_bytes(
        &ramflux_protocol::canonical_json_bytes(&object)?,
    )?)
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
    let (mut human, mut agent, vault) = owned_pair_with_vault(root, "human", "author").await?;
    let human_two =
        enroll_surface_sibling(root, &mut human, &vault, "human-secondary", "human-two").await?;
    let author_two =
        enroll_surface_sibling(root, &mut agent, &vault, "author-secondary", "author-two").await?;
    let clients = vec![agent, author_two, human, human_two];
    let manifests = [
        clients.first().ok_or("author client")?.local_own_copy_manifest()?,
        clients.get(2).ok_or("human client")?.local_own_copy_manifest()?,
    ];
    for client in &clients {
        for manifest in &manifests {
            client.persist_fetched_identity_directory(manifest)?;
        }
        client.account_db()?.persist_client_record(
            "conversation",
            "thread",
            &serde_json::json!({"kind":"direct","participants":["author","human"]}),
        )?;
    }
    Ok(clients)
}
async fn enroll_surface_sibling(
    root: &Path,
    source: &mut RamfluxClient,
    vault: &Arc<TestVault>,
    account_id: &str,
    device: &str,
) -> TestResult<RamfluxClient> {
    use ramflux_protocol::custody::CustodyAuthority;
    use zeroize::Zeroizing;
    let mut native = source.local_own_copy_manifest()?.custody.ok_or("native manifest")?;
    let primary = vault.primary_for_public_key(
        &native.publication.record.body.master_certificate.body.self_signing_public_key,
    )?;
    let now = crate::custody::network_now()?;
    let current =
        ramflux_crypto::custody::verify_record(&native.publication.record, now, None, None)?;
    let mut seeds = Zeroizing::new([0u8; 64]);
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
    native.publication.record =
        primary.enroll_device(&current, primary.certify_branch(certificate)?, now)?;
    let source_id = source.account_db()?.local_account_id.clone();
    crate::custody::accept_publication(
        root,
        &source_id,
        &CustodyAuthority {
            publication: native.publication.clone(),
            custodian_publication: native.custodian_publication.clone(),
        },
        now,
    )?;
    let sibling_vault = Arc::new(TestVault::default());
    crate::custody::install_sibling_fixture(crate::custody::SiblingSetup {
        root,
        id: account_id,
        device,
        record: native.publication.record.clone(),
        branch: &seeds,
        vault: sibling_vault.as_ref(),
        passphrase: b"surface-test-secret",
        now,
    })?;
    let mut client = RamfluxClient::new();
    client.open_account_index(root)?;
    client.unlock_account(account_id, b"surface-test-secret")?;
    tokio::time::timeout(
        std::time::Duration::from_secs(30),
        client.initialize_born_v3_branch(device, sibling_vault),
    )
    .await??;
    let manifest = client.local_own_copy_manifest()?;
    native.devices.extend(manifest.custody.ok_or("sibling native manifest")?.devices);
    let full = crate::prekey::SdkDeviceManifestResponse::from_native(*native)?;
    source.persist_fetched_identity_directory(&full)?;
    client.persist_fetched_identity_directory(&full)?;
    Ok(client)
}

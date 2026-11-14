// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Phrase-created human/agent authority for v3 surface tests; no ownership flags are forged.
use crate::custody::tests::{TestVault, words};
use crate::custody::{CreateInput, CreationCeremony, PrimaryVault};
use crate::{RamfluxClient, SdkError};
use ramflux_protocol::PrincipalKind;
use std::{path::Path, sync::Arc};
pub(super) type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
pub(super) async fn owned_pair(
    root: &Path,
    human: &str,
    agent: &str,
) -> TestResult<(RamfluxClient, RamfluxClient)> {
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
    Ok((human_client, agent_client))
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

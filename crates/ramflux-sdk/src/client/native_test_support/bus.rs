// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Native authority and cleanup ownership retained by public-bus transport fixtures.
use super::*;
use crate::bus::state::LocalBusAccountState;

pub(crate) struct Material {
    pub(crate) root: Root,
    pub(crate) vault: Arc<TestVault>,
    primary_vault: Arc<TestVault>,
    pub(crate) manifest: SdkDeviceManifestResponse,
}

impl Fixture {
    pub(crate) fn into_bus(mut self) -> LocalBusAccountState {
        let anchor = self.manifest.principal_commitment.clone();
        let mut setup =
            crate::LocalBusConfig::new(self.root.0.join("fixture.sock"), self.root.0.to_path_buf());
        setup.custody_vault = Some(self.vault.clone());
        self.client.native_bus_fixture = Some(Box::new(Material {
            root: self.root,
            primary_vault: self.vault.clone(),
            vault: self.vault,
            manifest: self.manifest,
        }));
        let mut account = LocalBusAccountState::disconnected(self.client, self.config, anchor);
        account.native_setup = Some(setup);
        account
    }

    pub(crate) fn take_bus(account: &mut LocalBusAccountState) -> TestResult<Self> {
        let material = *account.client.native_bus_fixture.take().ok_or("native bus fixture")?;
        Ok(Self {
            client: std::mem::take(&mut account.client),
            root: material.root,
            vault: material.vault,
            manifest: material.manifest,
            config: account.gateway_config.clone(),
        })
    }
}

pub(crate) async fn sibling(
    source: &mut LocalBusAccountState,
    id: &str,
    device: &str,
) -> TestResult<LocalBusAccountState> {
    let mut native = Fixture::take_bus(source)?;
    let mut sibling = Box::pin(native.enroll_sibling(id, device)).await?;
    let vault = native.vault.clone();
    Box::pin(activation_send::tests::publish_layer_four(&mut native)).await?;
    sibling.manifest = native.manifest.clone();
    sibling.client.persist_fetched_identity_directory(&sibling.manifest)?;
    Box::pin(activation_send::tests::publish_layer_four_with_primary(&mut sibling, vault)).await?;
    let now = crate::custody::network_now()?;
    let account_id = native.client.account_db()?.local_account_id.clone();
    let publication = sibling.manifest.custody.as_ref().ok_or("sibling native publication")?;
    crate::custody::accept_publication(
        &native.root.0,
        &account_id,
        &ramflux_protocol::custody::CustodyAuthority {
            publication: publication.publication.clone(),
            custodian_publication: publication.custodian_publication.clone(),
        },
        now,
    )?;
    native.manifest = sibling.manifest.clone();
    native
        .client
        .initialize_born_v3_branch_for_fixture(&native.config.device_id, native.vault.as_ref())?;
    native.client.persist_fetched_identity_directory(&native.manifest)?;
    let primary_vault = native.vault.clone();
    *source = native.into_bus();
    let mut sibling = sibling.into_bus();
    sibling.client.native_bus_fixture.as_mut().ok_or("native sibling material")?.primary_vault =
        primary_vault;
    Ok(sibling)
}

pub(crate) async fn receive_copy(
    client: &mut RamfluxClient,
    config: &GatewaySessionConfig,
    entry: &crate::GatewayInboxEntry,
) -> Result<bool, crate::SdkError> {
    let mut engine = crate::GatewaySessionEngine::with_test_transport(
        config.clone(),
        Box::new(super::sibling::NoNetwork),
    );
    let pool = ramflux_transport::RelayQuicPool::new(
        ramflux_transport::RelayQuicPoolConfig::functional_default().map_err(|error| {
            crate::SdkError::LocalBus(format!("test: relay pool config: {error}"))
        })?,
    );
    let received = Box::pin(client.apply_routed_entry(&mut engine, &pool, entry, false)).await?;
    Ok(received.routing.is_some())
}

/// Run the actual generated prepare/decrypt path with the caller's W1 persistence cut.
pub(crate) async fn receive_copy_joining(
    client: &mut RamfluxClient,
    config: &GatewaySessionConfig,
    entry: &crate::GatewayInboxEntry,
    persist: impl FnOnce(
        &RamfluxClient,
        crate::client::routed::JoinedW1<'_>,
    ) -> Result<(Option<Vec<u8>>, Vec<usize>), crate::SdkError>,
) -> Result<(), crate::SdkError> {
    let mut engine = crate::GatewaySessionEngine::with_test_transport(
        config.clone(),
        Box::new(super::sibling::NoNetwork),
    );
    let pool = ramflux_transport::RelayQuicPool::new(
        ramflux_transport::RelayQuicPoolConfig::functional_default()
            .map_err(|error| crate::SdkError::LocalBus(error.to_string()))?,
    );
    Box::pin(client.apply_routed_entry_joining(&mut engine, &pool, entry, None, persist)).await?;
    Ok(())
}

pub(crate) fn seed_pair(a: &RamfluxClient, b: &RamfluxClient) -> Result<(), crate::SdkError> {
    let own = a.owned_device_identity()?;
    let peer = b.owned_device_identity()?;
    let send = ramflux_crypto::DmSession::initiator(
        [17; 32],
        crate::dm::dm_device_id_hash(own.device_id()),
        crate::dm::dm_device_id_hash(peer.device_id()),
        [3; 32],
    )?
    .with_collapse_key_from_x3dh_sk(&[17; 32], &[4; 32])?;
    let receive = ramflux_crypto::DmSession::recipient(
        [17; 32],
        crate::dm::dm_device_id_hash(peer.device_id()),
        crate::dm::dm_device_id_hash(own.device_id()),
        [3; 32],
    )?
    .with_collapse_key_from_x3dh_sk(&[17; 32], &[4; 32])?;
    a.persist_pair(&own, &peer, &[4; 32], &send)?;
    b.persist_pair(&peer, &own, &[4; 32], &receive)?;
    Ok(())
}

impl RamfluxClient {
    fn fixture_group_target(&self, target: &str) -> Result<String, crate::SdkError> {
        if self.native_bus_fixture.is_none() || target.starts_with("root~") {
            return Ok(target.into());
        }
        let branch = self.device_branch.as_ref().ok_or(crate::SdkError::IdentityRootMissing)?;
        if target != branch.principal_id
            && target != branch.device_id
            && target != self.owned_device_identity()?.storage_key()
        {
            return Err(crate::SdkError::LocalBus(
                "test: fixture selector is not the owned device".into(),
            ));
        }
        Ok(self.owned_device_identity()?.storage_key().into())
    }

    pub(crate) fn fixture_group_actor(
        &self,
        target: &str,
    ) -> Result<ramflux_protocol::group_state::GroupStateActor, crate::SdkError> {
        self.owned_group_actor(&self.fixture_group_target(target)?)
    }

    pub(crate) fn fixture_accept_group_state(
        &self,
        state: &ramflux_crypto::VerifiedGroupState,
        target: &str,
    ) -> Result<bool, crate::SdkError> {
        let target = self.fixture_group_target(target)?;
        let accepted = self.accept_shared_group_state(state, &target)?;
        // A creator-fork repair is deferred until the primary is available; the fixture holds it.
        if !self.has_pending_creator_repairs()? {
            return Ok(accepted);
        }
        let primary = self.fixture_primary()?;
        Ok(accepted || self.redrive_creator_repairs(primary.as_ref())? > 0)
    }

    pub(crate) fn fixture_primary(
        &self,
    ) -> Result<Option<ramflux_crypto::custody::SelfSigningKey>, crate::SdkError> {
        self.native_bus_fixture
            .as_ref()
            .map(|material| {
                let account =
                    self.born_v3_account.as_ref().ok_or(crate::SdkError::CustodySetupInvalid)?;
                material.primary_vault.primary_for_public_key(
                    &account.record().body.master_certificate.body.self_signing_public_key,
                )
            })
            .transpose()
    }

    pub(crate) fn fixture_group_create(
        &self,
        group: &str,
        conversation: &str,
        name: Option<String>,
        target: &str,
    ) -> Result<ramflux_crypto::VerifiedGroupState, crate::SdkError> {
        let primary = self.fixture_primary()?;
        self.shared_group_create_with_primary(
            group,
            conversation,
            name,
            &self.fixture_group_target(target)?,
            primary.as_ref(),
        )
    }

    pub(crate) fn fixture_group_change(
        &self,
        group: &str,
        target: &str,
        change: ramflux_protocol::group_state::GroupStateChange,
    ) -> Result<ramflux_crypto::VerifiedGroupState, crate::SdkError> {
        let primary = self.fixture_primary()?;
        self.shared_group_change_with_primary(
            group,
            &self.fixture_group_target(target)?,
            change,
            primary.as_ref(),
        )
    }
}

/// Retain each account's actual vault and branch while sharing a loopback directory endpoint.
pub(crate) fn config_for(
    client: &RamfluxClient,
    base: &GatewaySessionConfig,
) -> Result<GatewaySessionConfig, crate::SdkError> {
    let material =
        client.native_bus_fixture.as_ref().ok_or(crate::SdkError::CustodySetupInvalid)?;
    let branch = client.device_branch.as_ref().ok_or(crate::SdkError::IdentityRootMissing)?;
    let node = base.custody.as_ref().ok_or(crate::SdkError::CustodySetupInvalid)?;
    let mut config = base.clone().with_native_custody(crate::GatewayCustodyConfig {
        account_root: material.root.0.to_path_buf(),
        account_id: client.account_db()?.local_account_id.clone(),
        node_id: node.node_id.clone(),
        node_public_key: node.node_public_key.clone(),
        vault: material.vault.clone(),
    });
    config.principal_id.clone_from(&branch.principal_id);
    config.device_id.clone_from(&branch.device_id);
    config.target_delivery_id = client.owned_device_identity()?.storage_key().into();
    config = config.with_account_identity(client)?;
    config.device_branch = Some(Arc::new(branch.clone()));
    config.source_identity = Some(client.owned_device_identity()?);
    Ok(config)
}

/// Apply an actual primary-signed revocation and reload the still-active local branch.
pub(crate) fn revoke_device(account: &mut LocalBusAccountState, device: &str) -> TestResult {
    let mut fixture = Fixture::take_bus(account)?;
    let mut native = fixture.manifest.custody.clone().ok_or("native manifest")?;
    let now = crate::custody::network_now()?.max(native.publication.record.body.issued_at);
    let current = fixture
        .client
        .current_custody_authority(&fixture.manifest.principal_commitment, now)?
        .ok_or("native authority")?;
    let primary = fixture.vault.primary_for_public_key(
        &native.publication.record.body.master_certificate.body.self_signing_public_key,
    )?;
    native.publication.record = primary.revoke_device(&current, device, now)?;
    native.devices.retain(|entry| entry.device_ref.device_id != device);
    fixture.manifest.devices.retain(|entry| entry.device_id != device);
    fixture.manifest.custody = Some(native.clone());
    let id = fixture.client.account_db()?.local_account_id.clone();
    crate::custody::accept_publication(
        &fixture.root.0,
        &id,
        &ramflux_protocol::custody::CustodyAuthority {
            publication: native.publication,
            custodian_publication: native.custodian_publication,
        },
        now,
    )?;
    fixture
        .client
        .initialize_born_v3_branch_for_fixture(&fixture.config.device_id, fixture.vault.as_ref())?;
    fixture.client.persist_fetched_identity_directory(&fixture.manifest)?;
    let updated = fixture.into_bus();
    account.client = updated.client;
    account.native_setup = updated.native_setup;
    account.gateway_config = updated.gateway_config;
    Ok(())
}

/// Reopen account storage and load the actual native branch from its retained test vault.
pub(crate) fn reopen_account(
    account: &mut LocalBusAccountState,
    id: &str,
) -> Result<(), crate::SdkError> {
    account.client.born_v3_account.as_ref().ok_or(crate::SdkError::IdentityRootMissing)?;
    account.client.active_account_db = None;
    account.client.unlock_account(id, b"native fixture data passphrase")?;
    {
        let custody = account
            .gateway_config
            .custody
            .as_ref()
            .ok_or(crate::SdkError::CustodyVaultUnavailable)?;
        account.client.initialize_born_v3_branch_for_fixture(
            &account.gateway_config.device_id,
            custody.vault.as_ref(),
        )?;
    }
    // The old config still holds the admission reader of the database that was just closed;
    // bind networking to the reopened database.
    account.gateway_config.pairing_admission =
        Some(std::sync::Arc::new(account.client.account_db()?.pairing_admission_reader()));
    Ok(())
}

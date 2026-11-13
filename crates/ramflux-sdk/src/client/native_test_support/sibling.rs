// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Independently vaulted native siblings and their authenticated pair transport.
use super::*;
use crate::client::routed::SendMaterial;
use crate::{GatewayInboxEntry, GatewaySessionEngine, SdkError};
use ramflux_protocol::message as g;
use std::future::Future;
use std::pin::Pin;
use zeroize::Zeroizing;

impl Fixture {
    pub(crate) async fn enroll_sibling(&mut self, id: &str, device: &str) -> TestResult<Self> {
        let mut native = self.manifest.custody.as_ref().ok_or("native authority")?.clone();
        let primary = self.vault.primary_for_public_key(
            &native.publication.record.body.master_certificate.body.self_signing_public_key,
        )?;
        let now = crate::custody::network_now()?;
        let current =
            ramflux_crypto::custody::verify_record(&native.publication.record, now, None, None)?;
        let mut seeds = Zeroizing::new([0; 64]);
        getrandom::fill(&mut *seeds).map_err(|_| SdkError::CustodyRandomUnavailable)?;
        let signing: [u8; 32] = seeds[..32].try_into()?;
        let agreement: [u8; 32] = seeds[32..].try_into()?;
        let branch =
            ramflux_crypto::create_device_branch(&self.manifest.principal_id, device, 1, signing);
        let agreement = ramflux_crypto::X25519KeyPair::from_seed(agreement);
        let mut certificate = native.publication.record.body.devices[0]
            .branch_certificate
            .as_ref()
            .ok_or("certificate")?
            .body
            .clone();
        certificate.device_id = device.into();
        certificate.branch_signing_public_key =
            ramflux_protocol::encode_base64url(branch.signing_key.verifying_key().as_bytes());
        certificate.agreement_identity_public_key =
            ramflux_protocol::encode_base64url(&agreement.public);
        certificate.cert_id = ramflux_protocol::encode_base64url(ramflux_crypto::random_32()?);
        native.publication.record =
            primary.enroll_device(&current, primary.certify_branch(certificate)?, now)?;
        let account_id = self.client.account_db()?.local_account_id.clone();
        crate::custody::accept_publication(
            &self.root.0,
            &account_id,
            &ramflux_protocol::custody::CustodyAuthority {
                publication: native.publication.clone(),
                custodian_publication: None,
            },
            now,
        )?;
        let root = Root::new()?;
        let vault = Arc::new(TestVault::default());
        crate::custody::install_sibling_fixture(crate::custody::SiblingSetup {
            root: &root.0,
            id,
            device,
            record: native.publication.record.clone(),
            branch: &seeds,
            vault: vault.as_ref(),
            passphrase: b"native sibling data passphrase",
            now,
        })?;
        let mut client = RamfluxClient::new();
        client.open_account_index(&root.0)?;
        client.unlock_account(id, b"native sibling data passphrase")?;
        client.initialize_born_v3_branch(device, vault.clone()).await?;
        let mut sibling =
            Self::ready(client, root, vault, id, device, native.publication.record.clone())?;
        native
            .devices
            .extend(sibling.manifest.custody.as_ref().ok_or("sibling manifest")?.devices.clone());
        let full = SdkDeviceManifestResponse::from_native((*native).clone())?;
        self.client.persist_fetched_identity_directory(&full)?;
        sibling.client.persist_fetched_identity_directory(&full)?;
        self.manifest = full.clone();
        sibling.manifest = full;
        Ok(sibling)
    }

    pub(crate) fn material_for(&self, target: &Self) -> Result<SendMaterial, SdkError> {
        self.client.persist_fetched_identity_directory(&target.manifest)?;
        let reference = target.client.owned_device_identity()?;
        Ok(SendMaterial {
            manifest: Some((reference.root_commitment().into(), target.manifest.clone())),
            bundle: Some(target.client.load_x3dh_private_state(&reference)?.bundle),
        })
    }

    pub(crate) async fn receive(
        &mut self,
        envelope: ramflux_protocol::Envelope,
        sequence: u64,
    ) -> TestResult {
        ramflux_node_core::check_entry_bound(&envelope)?;
        let entry = GatewayInboxEntry {
            forwarded: false,
            inbox_seq: sequence,
            target_delivery_id: self.config.target_delivery_id.clone(),
            envelope,
        };
        let mut engine =
            GatewaySessionEngine::with_test_transport(self.config.clone(), Box::new(NoNetwork));
        let pool = ramflux_transport::RelayQuicPool::new(
            ramflux_transport::RelayQuicPoolConfig::functional_default()?,
        );
        self.client.apply_routed_entry(&mut engine, &pool, &entry, false).await?;
        Ok(())
    }
}

struct NoNetwork;
impl ramflux_transport::GatewaySessionFrameSink for NoNetwork {
    fn send_frame<'a>(
        &'a mut self,
        _: &'a [u8],
    ) -> Pin<Box<dyn Future<Output = Result<(), ramflux_transport::TransportError>> + Send + 'a>>
    {
        Box::pin(async {
            Err(ramflux_transport::TransportError::Quic(
                "unexpected network in prepared native fixture".into(),
            ))
        })
    }
    fn finish(&mut self) -> Result<(), ramflux_transport::TransportError> {
        Ok(())
    }
}
impl ramflux_transport::GatewaySessionFrameSource for NoNetwork {
    fn recv_frame(
        &mut self,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, ramflux_transport::TransportError>> + Send + '_>>
    {
        Box::pin(async {
            Err(ramflux_transport::TransportError::Quic(
                "unexpected network in prepared native fixture".into(),
            ))
        })
    }
}

#[tokio::test(flavor = "current_thread")]
async fn native_sibling_self_sync_defers_without_authenticated_floor_bootstrap() -> TestResult {
    let mut source = Fixture::new("native-sync-source").await?;
    let sibling = source.enroll_sibling("native-sync-sibling", "sibling").await?;
    assert!(sibling.client.identity_root.is_none());
    assert_eq!(sibling.vault.entry_count()?, 1, "the sibling has only its branch seeds");
    assert_eq!(
        sibling.client.born_v3_account.as_ref().ok_or("native sibling")?.primary_vault_ref(),
        ""
    );
    let _live = ramflux_protocol::schema_profile::SchemaV1LiveGuard::enter();
    let value = source.client.change_self_sync(
        "native-thread",
        g::SelfSync { operation: 6, mute: true, ..Default::default() },
    )?;
    assert!(matches!(
        source.client.bootstrap_self_sync(&sibling.client.owned_device_identity()?),
        Err(SdkError::InboundPending(_))
    ));
    assert!(source.client.prepare_self_sync_repair(&source.config)?.is_none());
    assert!(sibling.client.self_sync_state("native-thread", &value)?.is_none());
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn self_sync_all_erased_source_never_bootstraps_a_floorless_third_sibling() -> TestResult {
    let mut source = Fixture::new("floor-erased-source").await?;
    let _second = source.enroll_sibling("floor-second", "second").await?;
    let third = source.enroll_sibling("floor-third", "third").await?;
    let draft = g::SelfSync {
        operation: 2,
        revision: 1,
        draft: Some(g::Message { text: "stale draft".into(), ..Default::default() }),
        ..Default::default()
    };
    let value = source.client.change_self_sync("floor-thread", draft)?;
    {
        let _effect_profile = ramflux_protocol::schema_profile::SchemaV1LiveGuard::enter();
        source.client.erase_self_sync_conversation("floor-thread")?;
    }
    assert_eq!(source.client.account_db()?.actor_state_keys("self-sync/state/")?.len(), 0);
    let _live = ramflux_protocol::schema_profile::SchemaV1LiveGuard::enter();
    assert!(matches!(
        source.client.bootstrap_self_sync(&third.client.owned_device_identity()?),
        Err(SdkError::InboundPending(_))
    ));
    let mut old = value;
    old.revision = u64::MAX - 2;
    assert!(matches!(
        third.client.account_db()?.write_transaction(|| third.client.apply_self_sync_in(
            &source.client.owned_device_identity()?,
            "floor-thread",
            &old
        )),
        Err(SdkError::InboundPending(_))
    ));
    assert!(third.client.self_sync_state("floor-thread", &old)?.is_none());
    assert_eq!(third.client.account_db()?.actor_state_keys("self-sync/bootstrap/")?.len(), 0);
    Ok(())
}

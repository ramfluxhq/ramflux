// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Pairing endpoints backed by ordinary product gateway connections and local vaults.
use super::*;
use ramflux_sdk::{
    GatewayCustodyConfig, GatewayQuicEndpointConfig, GatewaySessionConfig, NodeProfile,
};
impl Device {
    pub(in super::super) async fn create_network(
        profile: &NodeProfile,
        stack: &super::super::process_stack::Stack,
        id: &str,
        primary: bool,
        config: &PairingConfig,
    ) -> TestResult<(PairingActor, Self)> {
        let local = Arc::new(Local {
            root: tempfile::tempdir()?,
            id: id.into(),
            vault: Arc::new(vault::Vault::default()),
            connection: encode_base64url(random_32()?),
        });
        let Initial { mut client, identity, phrase } = initial(&local, primary)?;
        let credential = Arc::new(Credential::default());
        let session = session_config(&local, profile, stack, &identity.local_ref)?;
        let network = custody::CustodyNetworkConfig {
            pairing_admission: None,
            account_root: local.root.path().into(),
            account_id: id.into(),
            device_id: identity.local_ref.device_id.clone(),
            gateway_address: stack.gateway_public.parse()?,
            server_name: "localhost".into(),
            ca_certificate: stack.root.join("certs/ca.pem"),
            node_id: profile.node_id.clone(),
            node_public_key: profile.node_public_key.clone(),
            audience: profile.node_id.clone(),
            binding_mode: BindingMode::HomeRelayReceipt,
            allow_no_channel_binding: false,
            timeout: Duration::from_secs(10),
        };
        if primary {
            drop(
                Box::pin(custody::CustodyConnection::connect(network.clone(), local.vault.clone()))
                    .await?,
            );
        }
        let native = Arc::new(FreshPairingNative::new(network, local.vault.clone()));
        let participant = Arc::new(LocalPairingParticipant {
            root: local.root.path().into(),
            account_id: id.into(),
            vault: local.vault.clone(),
            provider: credential.clone(),
            db: Mutex::new(None),
            persist: Arc::new(NativePairingPublication {
                native: native.clone(),
                runtime: tokio::runtime::Handle::current(),
            }),
            query: Arc::new(NativePairingQuery {
                config: session,
                runtime: tokio::runtime::Handle::current(),
            }),
        });
        if primary {
            let reference = identity.local_ref.device_id.clone();
            client.initialize_born_v3_branch(&reference, local.vault.clone()).await?;
            seed_history(&client)?;
            participant.take_client(&mut client)?;
            let slot = participant.db.lock().map_err(|_| "test: source history writer")?;
            slot.as_ref().ok_or("test: source history writer missing")?.store_message_content(
                "paired-history-thread",
                "paired-history-before-enrollment",
                super::super::history::BODY,
            )?;
        }
        let mut actor = PairingActor::new(
            identity,
            primary.then_some(native as Arc<dyn PairingNative>),
            Arc::new(HttpRelay::from_config(config)?),
            config.clone(),
        );
        actor.set_participant(participant.clone());
        Ok((actor, Self { client, participant, credential, phrase, local }))
    }
    pub(in super::super) async fn connect_network(
        &mut self,
        profile: &NodeProfile,
        stack: &super::super::process_stack::Stack,
    ) -> TestResult<ramflux_sdk::AccountSessionHarness> {
        let local = self.local.clone();
        let participant = self.participant.clone();
        tokio::task::spawn_blocking(move || -> Result<(), SdkError> {
            let native = custody::load_account(local.root.path(), &local.id, network_now()?)?;
            let authority =
                participant.query.current_authority(&native.record().body.account_anchor)?;
            let slot = participant.db.lock().map_err(|_| SdkError::PairingCode("Busy"))?;
            refresh_authority(
                local.root.path(),
                slot.as_ref().ok_or(SdkError::AccountDbNotUnlocked)?,
                local.vault.as_ref(),
                &local.id,
                &authority,
                network_now()?,
            )?;
            Ok(())
        })
        .await
        .map_err(|_| "test: network authority worker")??;
        self.participant.return_client(&mut self.client)?;
        let native = custody::load_account(self.root.path(), &self.id, wall()?)?;
        let (_, _, reference) = self.vault.local_branch(native.record())?;
        assert!(
            ordinary_session_admitted(&self.client, &self.id)?,
            "test: network pairing admission remained closed"
        );
        self.client.initialize_born_v3_branch(&reference.device_id, self.vault.clone()).await?;
        let config = session_config(&self.local, profile, stack, &reference)?;
        let client = std::mem::take(&mut self.client);
        Box::pin(ramflux_sdk::AccountSessionHarness::connect_pairing(
            ramflux_sdk::NativePairingNetworkFixture { client, config, node: profile.clone() },
        ))
        .await
        .map_err(Into::into)
    }
}
fn session_config(
    local: &Local,
    node: &NodeProfile,
    stack: &super::super::process_stack::Stack,
    reference: &DeviceRef,
) -> TestResult<GatewaySessionConfig> {
    let delivery = if reference.account_anchor.is_empty() {
        "unreserved".into()
    } else {
        let native = custody::load_account(local.root.path(), &local.id, wall()?)?;
        ramflux_crypto::RootQualifiedDeviceRef::from_custody_record(
            native.verified(),
            &reference.device_id,
        )?
        .storage_key()
        .to_owned()
    };
    let mut config = GatewaySessionConfig::quic(GatewayQuicEndpointConfig {
        bind_addr: "0.0.0.0:0".parse()?,
        gateway_addr: stack.gateway_quic.parse()?,
        server_name: "localhost".into(),
        ca_cert: stack.root.join("certs/ca.pem"),
        principal_id: reference.account_anchor.clone(),
        device_id: reference.device_id.clone(),
        target_delivery_id: delivery,
        prekey_http_url: Some(node.prekey_http_url.clone()),
    })
    .with_native_custody(GatewayCustodyConfig {
        account_root: local.root.path().into(),
        account_id: local.id.clone(),
        node_id: node.node_id.clone(),
        node_public_key: node.node_public_key.clone(),
        vault: local.vault.clone(),
    });
    config.device_epoch = reference.device_epoch;
    Ok(config)
}
fn seed_history(client: &RamfluxClient) -> TestResult {
    let mut session =
        client.init_dm_initiator_session(random_32()?, random_32()?, random_32()?, random_32()?)?;
    let encrypted = session.encrypt(super::super::history::BODY, b"paired-history-thread")?;
    client.send_direct_message(
        "paired-history-thread",
        "paired-history-before-enrollment",
        "phone-primary",
        &ramflux_protocol::canonical_json_bytes(&encrypted)?,
    )?;
    Ok(())
}

fn network_now() -> Result<u64, SdkError> {
    wall().map_err(|_| SdkError::CustodySetupInvalid)
}

struct Initial {
    client: RamfluxClient,
    identity: PairingIdentity,
    phrase: Option<Zeroizing<String>>,
}
fn initial(local: &Local, primary: bool) -> TestResult<Initial> {
    let mut client = RamfluxClient::new();
    let mut phrase = None;
    let identity = if primary {
        let (account, recovery) = create_primary(local)?;
        phrase = Some(recovery);
        client.open_account_index(local.root.path())?;
        client.unlock_account(&local.id, PASSWORD)?;
        let reference = account.record().body.master_certificate.body.primary_device_ref.clone();
        PairingIdentity {
            account_id: local.id.clone(),
            local_ref: reference,
            master_public_key: Some(
                account.record().body.master_certificate.body.master_public_key.clone(),
            ),
            base_record_hash: object_hash(account.record())?,
            base_epoch: account.record().body.device_set_epoch,
            is_primary: true,
        }
    } else {
        PairingIdentity {
            account_id: local.id.clone(),
            local_ref: DeviceRef {
                account_anchor: String::new(),
                device_id: "unreserved".into(),
                device_epoch: 1,
            },
            master_public_key: None,
            base_record_hash: encode_base64url([0; 32]),
            base_epoch: 1,
            is_primary: false,
        }
    };

    Ok(Initial { client, identity, phrase })
}

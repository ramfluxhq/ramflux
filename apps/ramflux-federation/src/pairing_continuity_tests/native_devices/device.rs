// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Each endpoint owns its account directory, private provider and credential vault.
use super::*;
const PASSWORD: &[u8] = b"independent TLS pairing data password";
pub(super) struct Local {
    pub(super) root: tempfile::TempDir,
    pub(super) id: String,
    pub(super) vault: Arc<vault::Vault>,
    pub(super) connection: String,
}
pub(super) struct Device {
    pub(super) client: RamfluxClient,
    pub(super) participant: Arc<LocalPairingParticipant>,
    pub(super) credential: Arc<Credential>,
    pub(super) phrase: Option<Zeroizing<String>>,
    local: Arc<Local>,
}
impl std::ops::Deref for Device {
    type Target = Local;
    fn deref(&self) -> &Local {
        &self.local
    }
}
#[derive(Default)]
pub(super) struct Credential(pub(super) Mutex<Option<Zeroizing<String>>>);
impl LocalCredentialProvider for Credential {
    fn provide(
        &self,
        request: &ramflux_protocol::custody::pairing::local_dto::CredentialRequest,
    ) -> Result<CredentialOutcome, SdkError> {
        if request.action == "phrase" {
            let phrase = self.0.lock().map_err(|_| SdkError::PairingCode("Busy"))?;
            return Ok(CredentialOutcome::Provided {
                passphrase: SecretUtf8::from_bytes(
                    phrase.as_ref().ok_or(SdkError::PairingCode("WrongContext"))?.as_bytes(),
                )?,
                confirmation: None,
            });
        }
        Ok(CredentialOutcome::Provided {
            passphrase: SecretUtf8::from_bytes(PASSWORD)?,
            confirmation: (request.action == "setup")
                .then(|| SecretUtf8::from_bytes(PASSWORD))
                .transpose()?,
        })
    }
}
impl Device {
    pub(super) fn create(
        node: Arc<node::Access>,
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
        let mut client = RamfluxClient::new();
        let credential = Arc::new(Credential::default());
        let mut phrase = None;
        let identity = if primary {
            let (account, recovery) = create_primary(&local)?;
            phrase = Some(recovery);
            node.router.publish_custody_record(
                &ramflux_node_core::CustodyPublication {
                    record: account.record().clone(),
                    compacted_ids: None,
                },
                wall()?,
                &node.redb,
            )?;
            client.open_account_index(local.root.path())?;
            client.unlock_account(id, PASSWORD)?;
            PairingIdentity {
                account_id: id.into(),
                local_ref: account.record().body.master_certificate.body.primary_device_ref.clone(),
                master_public_key: Some(
                    account.record().body.master_certificate.body.master_public_key.clone(),
                ),
                base_record_hash: object_hash(account.record())?,
                base_epoch: account.record().body.device_set_epoch,
                is_primary: true,
            }
        } else {
            PairingIdentity {
                account_id: id.into(),
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
        let native = prover(local.clone(), node.clone());
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
            query: node,
        });
        if primary {
            participant.take_client(&mut client)?;
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
    pub(super) fn full_frontend(
        &mut self,
        node: Arc<node::Access>,
        config: &PairingConfig,
        primary: bool,
    ) -> TestResult<(PairingActor, PairingLocalWriterService)> {
        let native = custody::load_account(self.root.path(), &self.id, wall()?)?;
        let authority = node.current_authority(&native.record().body.account_anchor)?;
        {
            let slot = self.participant.db.lock().map_err(|_| "test: full frontend owner")?;
            refresh_authority(
                self.root.path(),
                slot.as_ref().ok_or("test: own writer absent")?,
                self.vault.as_ref(),
                &self.id,
                &authority,
                wall()?,
            )?;
        }
        let native = custody::load_account(self.root.path(), &self.id, wall()?)?;
        let (_, _, reference) = self.vault.local_branch(native.record())?;
        let node_identity = node.identity();
        let mut actor = PairingActor::new(
            PairingIdentity {
                account_id: self.id.clone(),
                local_ref: reference,
                master_public_key: Some(
                    native.record().body.master_certificate.body.master_public_key.clone(),
                ),
                base_record_hash: object_hash(native.record())?,
                base_epoch: native.record().body.device_set_epoch,
                is_primary: primary,
            },
            primary.then(|| prover(self.local.clone(), node) as Arc<dyn PairingNative>),
            Arc::new(HttpRelay::from_config(config)?),
            config.clone(),
        );
        actor.set_participant(self.participant.clone());
        actor.set_full_node(node_identity);
        let service = {
            let slot = self.participant.db.lock().map_err(|_| "test: original full writer")?;
            actor.bind_frontend_writer(slot.as_ref().ok_or("test: original writer absent")?)?
        };
        self.participant.return_client(&mut self.client)?;
        Ok((actor, service))
    }
    pub(super) fn service_data(&mut self, actor: &mut PairingActor) -> TestResult {
        actor.service_full_transfer_client(&self.client)?;
        Ok(())
    }
    pub(super) async fn admit(&mut self, node: &node::Access) -> TestResult {
        let account = custody::load_account(self.root.path(), &self.id, wall()?)?;
        let authority = node.current_authority(&account.record().body.account_anchor)?;
        {
            let slot = self.participant.db.lock().map_err(|_| "test: local SDK writer mutex")?;
            let db = slot.as_ref().ok_or("test: local SDK writer missing")?;
            refresh_authority(
                self.root.path(),
                db,
                self.vault.as_ref(),
                &self.id,
                &authority,
                wall()?,
            )?;
        }
        {
            let slot = self.participant.db.lock().map_err(|_| "test: local SDK writer mutex")?;
            let db = slot.as_ref().ok_or("test: local SDK writer missing")?;
            assert_eq!(
                db.next_pairing_own_sync()?.is_some(),
                self.vault.primary_entries()? == 1,
                "test: own-history attempt is queued only by the approving primary"
            );
        }
        self.participant.return_client(&mut self.client)?;
        let (_, _, reference) = self.vault.local_branch(account.record())?;
        let vault = self.vault.clone();
        self.client.initialize_born_v3_branch(&reference.device_id, vault).await?;
        assert!(
            ordinary_session_admitted(&self.client, &self.id)?,
            "test: real SDK activation gate stayed closed"
        );
        Ok(())
    }
}
fn prover(local: Arc<Local>, node: Arc<node::Access>) -> Arc<ProofPairingNative> {
    Arc::new(ProofPairingNative::new(Arc::new(move |action| {
        let local = local.clone();
        let node = node.clone();
        Box::pin(async move { node.prove(&local, action) })
    })))
}
fn create_primary(local: &Local) -> TestResult<(custody::BornAccount, Zeroizing<String>)> {
    let mut ceremony = custody::CreationCeremony::begin(
        local.root.path(),
        custody::CreateInput {
            local_account_id: local.id.clone(),
            principal_id: "tls-pairing-account".into(),
            device_id: "phone-primary".into(),
            display_name: "Phone primary".into(),
            principal_kind: ramflux_protocol::PrincipalKind::Human,
            custodian_account_id: None,
        },
        wall()?,
    )?;
    let phrase = ceremony.show_once()?;
    let words =
        phrase.split_whitespace().map(|word| Zeroizing::new(word.to_owned())).collect::<Vec<_>>();
    let positions = ceremony.hidden_challenge()?;
    let mut answers = Vec::new();
    for position in positions {
        answers.push(
            words
                .get(usize::from(position.checked_sub(1).ok_or("test: phrase position")?))
                .ok_or("test: phrase word")?
                .clone(),
        );
    }
    let answers: [Zeroizing<String>; 3] = answers.try_into().map_err(|_| "test: phrase answers")?;
    let account =
        ceremony.confirm_with_passphrase(&answers, local.vault.as_ref(), wall()?, PASSWORD)?;
    Ok((account, phrase))
}

#[cfg(unix)]
#[path = "device/network.rs"]
mod network;

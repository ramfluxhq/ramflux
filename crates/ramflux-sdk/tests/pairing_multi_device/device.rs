// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Three independent SDK roots, data writers and attended local vault providers.
use super::{
    ResultOf,
    node::{Endpoint, Node, now},
    relay::Relay,
    vault::Vault,
};
use ramflux_protocol::custody::{DeviceRef, object_hash};
use ramflux_sdk::{
    RamfluxClient, SdkError,
    custody::{self, pairing::*},
};
use std::sync::{Arc, Mutex};
use zeroize::Zeroizing;
const PASSWORD: &[u8] = b"pairing fixture data password";
pub struct Device {
    pub root: tempfile::TempDir,
    pub id: String,
    pub client: RamfluxClient,
    pub vault: Arc<Vault>,
    pub participant: Arc<LocalPairingParticipant>,
    pub actor: PairingActor,
    pub endpoint: Endpoint,
}
struct Credential;
impl LocalCredentialProvider for Credential {
    fn provide(
        &self,
        request: &ramflux_protocol::custody::pairing::local_dto::CredentialRequest,
    ) -> Result<CredentialOutcome, SdkError> {
        Ok(CredentialOutcome::Provided {
            passphrase: SecretUtf8::from_bytes(PASSWORD)?,
            confirmation: (request.action == "setup")
                .then(|| SecretUtf8::from_bytes(PASSWORD))
                .transpose()?,
        })
    }
}
impl Device {
    pub async fn create(node: Arc<Node>, id: &str, primary: bool) -> ResultOf<Self> {
        let root = tempfile::tempdir()?;
        let vault = Arc::new(Vault::default());
        let mut client = RamfluxClient::new();
        let identity = if primary {
            let account = confirm_primary(root.path(), id, vault.as_ref())?;
            node.persist_head(
                &ramflux_protocol::custody::Publication {
                    record: account.record().clone(),
                    compacted_ids: None,
                },
                now()?,
            )?;
            client.open_account_index(root.path())?;
            client.unlock_account(id, PASSWORD)?;
            client.initialize_born_v3_branch("primary", vault.clone()).await?;
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
                base_record_hash: ramflux_protocol::encode_base64url([0; 32]),
                base_epoch: 1,
                is_primary: false,
            }
        };
        let endpoint = Endpoint {
            node: node.clone(),
            root: root.path().into(),
            account: id.into(),
            vault: vault.clone(),
            connection: ramflux_protocol::encode_base64url(ramflux_crypto::random_32()?),
        };
        let native = endpoint.native();
        let participant = Arc::new(LocalPairingParticipant {
            root: root.path().into(),
            account_id: id.into(),
            vault: vault.clone(),
            provider: Arc::new(Credential),
            db: Mutex::new(None),
            persist: Arc::new(NativePairingPublication {
                native: native.clone(),
                runtime: tokio::runtime::Handle::current(),
            }),
            query: node.clone(),
        });
        if primary {
            participant.take_client(&mut client)?;
        }
        let mut actor = PairingActor::new(
            identity,
            primary.then_some(native as Arc<dyn PairingNative>),
            Arc::new(Relay(node)),
            PairingConfig { enabled: true, extra_root_ca_pem: None },
        );
        actor.set_participant(participant.clone());
        Ok(Self { root, id: id.into(), client, vault, participant, actor, endpoint })
    }
    pub async fn admit_client(&mut self, node: &Node) -> ResultOf<()> {
        let native = custody::load_account(self.root.path(), &self.id, now()?)?;
        let authority = node.current_authority(&native.record().body.account_anchor)?;
        {
            let slot = self.participant.db.lock().map_err(|_| "test: staged writer mutex")?;
            let db = slot.as_ref().ok_or("test: staged actual writer")?;
            refresh_authority(
                self.root.path(),
                db,
                self.vault.as_ref(),
                &self.id,
                &authority,
                now()?,
            )?;
        }
        self.participant.return_client(&mut self.client)?;
        let (_, _, reference) = self.endpoint.branch()?;
        self.client.initialize_born_v3_branch(&reference.device_id, self.vault.clone()).await?;
        assert!(
            ordinary_session_admitted(&self.client, &self.id)?,
            "test: installed recipient's actual writer remained unadmitted"
        );
        Ok(())
    }
}

fn confirm_primary(
    root: &std::path::Path,
    id: &str,
    vault: &Vault,
) -> ResultOf<custody::BornAccount> {
    let mut ceremony = custody::CreationCeremony::begin(
        root,
        custody::CreateInput {
            local_account_id: id.into(),
            principal_id: "pairing-fixture".into(),
            device_id: "primary".into(),
            display_name: "Phone".into(),
            principal_kind: ramflux_protocol::PrincipalKind::Human,
            custodian_account_id: None,
        },
        now()?,
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
    let account = ceremony.confirm_with_passphrase(&answers, vault, now()?, PASSWORD)?;
    Ok(account)
}

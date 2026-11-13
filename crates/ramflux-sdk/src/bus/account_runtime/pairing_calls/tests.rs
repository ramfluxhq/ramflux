// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Actual account command owner stays available while source preparation/native begin waits.
use super::*;
use crate::{custody::pairing::*, prelude::*};
use ramflux_protocol::custody::{CustodyAuthority, DeviceRef, Publication, object_hash};
use std::sync::{Arc, Mutex};
use tokio::sync::{mpsc, watch};
type TestResult = Result<(), Box<dyn std::error::Error>>;
struct HoldIssue(Mutex<Option<oneshot::Sender<()>>>);
impl PairingNative for HoldIssue {
    fn issue(
        &self,
        _: ramflux_protocol::custody::pairing::native::CreateSpec,
    ) -> std::pin::Pin<
        Box<
            dyn Future<
                    Output = Result<ramflux_protocol::custody::pairing::native::Issued, SdkError>,
                > + Send,
        >,
    > {
        let entered = self.0.lock().unwrap_or_else(std::sync::PoisonError::into_inner).take();
        Box::pin(async move {
            if let Some(entered) = entered {
                let _ = entered.send(());
            }
            std::future::pending().await
        })
    }
    fn create(
        &self,
        _: ramflux_protocol::custody::pairing::native::Create,
    ) -> std::pin::Pin<
        Box<
            dyn Future<
                    Output = Result<ramflux_protocol::custody::pairing::native::Created, SdkError>,
                > + Send,
        >,
    > {
        Box::pin(async { Err(SdkError::PairingCode("WrongContext")) })
    }
}
struct NoPublication;
impl NodeHeadPersist for NoPublication {
    fn persist_head(&self, _: &Publication, _: u64) -> Result<String, SdkError> {
        Err(SdkError::PairingCode("WrongContext"))
    }
}
impl PairingAuthorityQuery for NoPublication {
    fn current_authority(&self, _: &str) -> Result<CustodyAuthority, SdkError> {
        Err(SdkError::PairingCode("WrongContext"))
    }
}
struct NoCredential;
impl LocalCredentialProvider for NoCredential {
    fn provide(
        &self,
        _: &ramflux_protocol::custody::pairing::local_dto::CredentialRequest,
    ) -> Result<CredentialOutcome, SdkError> {
        Err(SdkError::PairingCode("WrongContext"))
    }
}
fn command(
    id: &str,
    method: &str,
    body: serde_json::Value,
) -> (AccountCommand, oneshot::Receiver<Result<ActorResponse, SdkError>>) {
    let (reply, receive) = oneshot::channel();
    let (outbound, _events) = mpsc::channel(1);
    (
        AccountCommand {
            admission: None,
            private: None,
            request: LocalBusFrame::request("courier", Some(id.into()), "test", method, body),
            connection_id: 1,
            topics: BTreeSet::new(),
            attended: true,
            nodes: None,
            outbound,
            reply: Some(reply),
        },
        receive,
    )
}
#[tokio::test]
async fn pairing_full_source_begin_courier_keeps_account_commands_and_lock_responsive() -> TestResult
{
    crate::bus::credentials::contract_tests::deadline(Box::pin(run())).await
}
async fn run() -> TestResult {
    let root = tempfile::tempdir()?;
    let id = "source-courier";
    let now = crate::custody::network_now()?;
    let SourceFixture { client, participant, mut issue, signal, anchor } =
        prepare_source(root.path(), id, now)?;
    let (mut runtime, _lifetime) = runtime(client, root.path(), id, &anchor)?;
    let (begin, mut result) = command(
        id,
        "device.transfer.begin",
        serde_json::to_value(ramflux_protocol::custody::pairing::local_dto::FullTransferBegin {
            schema: "ramflux.pairing.TransferBegin.v3".into(),
            version: 3,
            recipient_mode: "new".into(),
            destination_ref: None,
            display_name: "Phone".into(),
            capabilities: vec!["message".into(), "register".into(), "sync".into()],
            lease_not_before: now,
            lease_expires_at: now + 86_400,
            data_selection:
                ramflux_protocol::custody::pairing::context_v3::DataSelectionV3::FullAccountDataV1(
                    ramflux_protocol::custody::pairing::context_v3::FullAccountData {},
                ),
            transfer_profile:
                ramflux_protocol::custody::pairing::context_v3::TransferProfile::FullAccountDataV1,
        })?,
    );
    assert!(!runtime.apply(begin).await?, "test: long source begin stopped its account owner");
    loop {
        tokio::select! {
            entered=&mut issue=>{entered?;break;},
            ()=signal.notified()=>runtime.service_pairing_data(),
        }
    }
    assert!(
        matches!(result.try_recv(), Err(oneshot::error::TryRecvError::Empty)),
        "test: source begin returned before its held native operation completed"
    );
    let account = runtime.state.accounts.get(id).ok_or("test: actual frontend")?;
    assert!(
        account.client.account_db()?.pairing_live_rows()?.is_empty(),
        "test: pre-Issue preparation created a live operation"
    );
    account.client.account_db()?.persist_actor_state("test/ordinary-after-pin", &true)?;
    let (second, refused) = command(id, "device.transfer.begin", serde_json::json!({}));
    runtime.apply(second).await?;
    assert!(
        matches!(refused.await?, Err(SdkError::PairingCode("Busy"))),
        "test: a second source begin waited behind the active bulk/native work"
    );
    let (mut ordinary, _unused) = command(id, "account.authorize-backup", serde_json::json!({}));
    let (reply, authorized) = oneshot::channel();
    ordinary.private =
        Some(crate::bus::actor::PrivateCommand::AuthorizeBackup { generation: 0, reply });
    runtime.apply(ordinary).await?;
    authorized.await??;
    let (lock, locked) = command(id, "account.lock", serde_json::json!({}));
    assert!(
        runtime.apply(lock).await?,
        "test: account lock did not complete with an active source begin"
    );
    locked.await??;
    assert!(result.await?.is_err(), "test: lifecycle cancellation returned a source invitation");
    assert!(
        participant.db.lock().map_err(|_| "test: participant mutex")?.is_none(),
        "test: source courier parked or retained the ordinary frontend database"
    );
    assert!(
        crate::custody::pairing::work_signal(root.path(), id).is_none(),
        "test: account lock left a pairing service alive"
    );
    Ok(())
}
struct SourceFixture {
    client: RamfluxClient,
    participant: Arc<LocalPairingParticipant>,
    issue: oneshot::Receiver<()>,
    signal: Arc<tokio::sync::Notify>,
    anchor: String,
}
fn prepare_source(
    root: &std::path::Path,
    id: &str,
    now: u64,
) -> Result<SourceFixture, Box<dyn std::error::Error>> {
    let vault = Arc::new(crate::custody::tests::TestVault::default());
    let native = crate::custody::tests::create_with_device(root, id, "phone", vault.as_ref(), now)?;
    let anchor = native.record().body.account_anchor.clone();
    let identity = PairingIdentity {
        account_id: id.into(),
        local_ref: DeviceRef {
            account_anchor: anchor.clone(),
            device_id: "phone".into(),
            device_epoch: 1,
        },
        master_public_key: Some(
            native.record().body.master_certificate.body.master_public_key.clone(),
        ),
        base_record_hash: object_hash(native.record())?,
        base_epoch: native.record().body.device_set_epoch,
        is_primary: true,
    };
    let mut client = RamfluxClient::new();
    client.open_account_index(root)?;
    client.seal_new_account_data(id, &anchor, b"source-courier-original-password")?;
    client.unlock_account(id, b"source-courier-original-password")?;
    let participant = Arc::new(LocalPairingParticipant {
        root: root.into(),
        account_id: id.into(),
        vault,
        provider: Arc::new(NoCredential),
        db: Mutex::new(None),
        persist: Arc::new(NoPublication),
        query: Arc::new(NoPublication),
    });
    let (entered, issue) = oneshot::channel();
    let config = PairingConfig { enabled: true, extra_root_ca_pem: None };
    let mut pairing = PairingActor::new(
        identity,
        Some(Arc::new(HoldIssue(Mutex::new(Some(entered))))),
        Arc::new(HttpRelay::from_config(&config)?),
        config,
    );
    pairing.set_participant(participant.clone());
    let service = pairing.bind_frontend_writer(client.account_db()?)?;
    crate::custody::pairing::install_actor_with_writer(root, id.into(), pairing, Some(service))?;
    let signal =
        crate::custody::pairing::work_signal(root, id).ok_or("test: pairing service signal")?;
    Ok(SourceFixture { client, participant, issue, signal, anchor })
}
struct RuntimeOwners {
    _preempt: watch::Sender<u64>,
    _shutdown: watch::Sender<bool>,
}

fn runtime(
    client: RamfluxClient,
    root: &std::path::Path,
    id: &str,
    anchor: &str,
) -> Result<(AccountRuntime, RuntimeOwners), SdkError> {
    let gateway = GatewaySessionConfig::auto(GatewayQuicEndpointConfig {
        bind_addr: "127.0.0.1:0".parse().map_err(|_| SdkError::CustodySetupInvalid)?,
        gateway_addr: "127.0.0.1:1".parse().map_err(|_| SdkError::CustodySetupInvalid)?,
        server_name: "unused.example".into(),
        ca_cert: root.join("unused.pem"),
        principal_id: anchor.into(),
        device_id: "phone".into(),
        target_delivery_id: String::new(),
        prekey_http_url: None,
    });
    let account =
        crate::bus::state::LocalBusAccountState::disconnected(client, gateway, anchor.into());
    let (_commands, receiver) = mpsc::channel(1);
    let (_lifecycle, lifecycle) = mpsc::channel(1);
    let (preempt_owner, preempt) = watch::channel(0);
    let (shutdown_owner, shutdown) = watch::channel(false);
    let (events, _batches) = mpsc::channel(1);
    let (connection_sender, connection_work) = mpsc::channel(1);
    Ok((
        AccountRuntime {
            timeouts: crate::bus::runtime_limits::RuntimeTimeouts::default(),
            id: id.into(),
            state: crate::bus::state::LocalBusDaemonState {
                account_index: Some(AccountIndex::open(root)?),
                config: LocalBusConfig::new(root.join("bus.sock"), root),
                nodes: crate::node::NodeStore::default(),
                accounts: BTreeMap::from([(id.into(), account)]),
                active_account_id: None,
                attended_accounts: BTreeSet::new(),
                subscribers: BTreeMap::new(),
            },
            receiver,
            lifecycle,
            preempt,
            readers: Arc::new(Mutex::new(None)),
            events,
            shutdown,
            courier: None,
            networking_expiry_pending: None,
            networking_expiry_warned: false,
            networking_observation_warned: false,
            transfers: crate::bus::account_runtime::uploads::Transfers::start(),
            connection_sender,
            connection_work,
            ledger: None,
            pairing: crate::bus::account_runtime::pairing_calls::Calls::default(),
            receive_gate_hook: None,
            courier_events: None,
        },
        RuntimeOwners { _preempt: preempt_owner, _shutdown: shutdown_owner },
    ))
}

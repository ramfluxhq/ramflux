// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Real encrypted head checks, transferee countersignatures and stale-owner repair.
use super::*;
use crate::client::shared_group::{TRANSFER_SEND_PREFIX, TransferBody, TransferDelivery};

type Capture = Arc<Mutex<Vec<ramflux_protocol::Envelope>>>;

struct Rig {
    captures: [Capture; 3],
    root: PathBuf,
    phone: LocalBusAccountState,
    laptop: LocalBusAccountState,
    next: LocalBusAccountState,
    config: GatewaySessionConfig,
    directory: tokio::task::JoinHandle<()>,
    removed_root: String,
}
impl Rig {
    async fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let root = runtime_tests::root("group-handover");
        let mut phone = runtime_tests::account(
            &root.join("phone"),
            "sender",
            None,
            Arc::new(AtomicBool::new(false)),
        )?;
        let (laptop, mut config, _, old, next) =
            sibling_fixture_with_peer(&root, &mut phone, false).await?;
        old.abort();
        let own_root = phone.client.owned_device_identity()?.root_commitment().to_owned();
        let next_root = next.client.owned_device_identity()?.root_commitment().to_owned();
        let mut own: crate::prekey::SdkDeviceManifestResponse = phone
            .client
            .account_db()?
            .load_actor_state(&format!("identity/manifest-root/{own_root}"))?
            .ok_or("own manifest")?;
        let mut remote: crate::prekey::SdkDeviceManifestResponse = phone
            .client
            .account_db()?
            .load_actor_state(&format!("identity/manifest-root/{next_root}"))?
            .ok_or("next manifest")?;
        crate::client::identity_authority::test_support::sign_manifest(
            phone.client.identity_root.as_ref().ok_or(SdkError::IdentityRootMissing)?,
            &mut own,
            3,
        )?;
        crate::client::identity_authority::test_support::sign_manifest(
            next.client.identity_root.as_ref().ok_or(SdkError::IdentityRootMissing)?,
            &mut remote,
            3,
        )?;
        for client in [&phone.client, &laptop.client, &next.client] {
            client.persist_root_verified_directory(&own)?;
            client.persist_root_verified_directory(&remote)?;
        }
        let (address, directory) = super::super::fixture::directory(
            &root,
            BTreeMap::from([
                (own_root, serde_json::to_value(own)?),
                (next_root, serde_json::to_value(remote)?),
            ]),
        )
        .await?;
        config.gateway_addr = address;
        config.tcp_gateway_addr = Some(address);
        let mut rig = Self {
            captures: std::array::from_fn(|_| Arc::default()),
            root,
            phone,
            laptop,
            next,
            config,
            directory,
            removed_root: String::new(),
        };
        rig.configure()?;
        rig.create_group()?;
        Ok(rig)
    }
    fn configure(&mut self) -> Result<(), SdkError> {
        let states = [&self.phone.client, &self.laptop.client, &self.next.client];
        let gateways = states
            .iter()
            .enumerate()
            .map(|(index, sender)| {
                let mut gateway =
                    super::super::fixture::RecordingGateway::new(self.captures[index].clone());
                for recipient in &states {
                    if sender.owned_device_identity()? != recipient.owned_device_identity()? {
                        gateway.prekeys.extend(fresh_sibling_gateway(sender, recipient)?.prekeys);
                    }
                }
                Ok(gateway)
            })
            .collect::<Result<Vec<_>, SdkError>>()?;
        for (account, gateway) in
            [&mut self.phone, &mut self.laptop, &mut self.next].into_iter().zip(gateways)
        {
            let own = account.client.owned_device_identity()?;
            let row = account.client.trusted_device(&own)?;
            let mut config = self.config.clone();
            config.principal_id = account
                .client
                .device_branch
                .as_ref()
                .ok_or(SdkError::IdentityRootMissing)?
                .principal_id
                .clone();
            config.device_id = own.device_id().into();
            config.target_delivery_id = row["target_delivery_id"]
                .as_str()
                .ok_or(StorageError::GroupPermissionDenied)?
                .into();
            config = config.with_account_identity(&account.client)?;
            account.gateway_config = config.clone();
            account.target_delivery_id = config.target_delivery_id.clone();
            account
                .put_engine(GatewaySessionEngine::with_test_transport(config, Box::new(gateway)));
        }
        Ok(())
    }
    fn create_group(&mut self) -> TestResult {
        self.phone.client.shared_group_create(
            "group",
            "group-thread",
            None,
            &self.phone.target_delivery_id,
        )?;
        self.phone.client.shared_group_change(
            "group",
            &self.phone.target_delivery_id,
            ramflux_protocol::GroupStateChange::Add {
                member: self.next.client.owned_group_actor(&self.next.target_delivery_id)?.identity,
                role: ramflux_protocol::SharedGroupRole::Member,
            },
        )?;
        let outsider = runtime_tests::account(
            &self.root.join("mallory"),
            "mallory",
            None,
            Arc::new(AtomicBool::new(false)),
        )?;
        self.removed_root = outsider.client.owned_device_identity()?.root_commitment().into();
        let base = self.phone.client.shared_group_change(
            "group",
            &self.phone.target_delivery_id,
            ramflux_protocol::GroupStateChange::Add {
                member: outsider.client.owned_group_actor("mallory")?.identity,
                role: ramflux_protocol::SharedGroupRole::Member,
            },
        )?;
        self.laptop.client.accept_shared_group_state(&base, &self.laptop.target_delivery_id)?;
        self.next.client.accept_shared_group_state(&base, &self.next.target_delivery_id)?;
        Ok(())
    }
    async fn authorize(&self) -> Result<ramflux_protocol::GroupTransferAcceptance, SdkError> {
        let state = self
            .laptop
            .client
            .account_db()?
            .shared_group_state("group")?
            .ok_or(StorageError::GroupPermissionDenied)?;
        Box::pin(self.laptop.client.group_transfer_authorization(
            &self.laptop.gateway_config,
            &state,
            &self.next.client.owned_group_actor(&self.next.target_delivery_id)?,
            &self.laptop.target_delivery_id,
        ))
        .await
    }
    async fn deliver_probes(&mut self) -> TestResult {
        for _ in 0..2 {
            assert_eq!(crate::bus::shared_group_sync::flush_requests(&mut self.laptop).await?, 1);
        }
        let packets = take_submitted(&self.captures[1])?;
        assert_eq!(packets.len(), 2);
        for envelope in packets {
            if envelope.target_delivery_id == self.phone.target_delivery_id {
                deliver(&mut self.phone, envelope).await?;
            } else {
                deliver(&mut self.next, envelope).await?;
            }
        }
        Ok(())
    }
    async fn deliver_replies(&mut self) -> TestResult {
        for (account, capture) in
            [(&mut self.phone, &self.captures[0]), (&mut self.next, &self.captures[2])]
        {
            assert_eq!(crate::bus::shared_group_sync::flush_requests(account).await?, 1);
            for envelope in take_submitted(capture)? {
                deliver(&mut self.laptop, envelope).await?;
            }
        }
        Ok(())
    }
}
fn take_submitted(capture: &Capture) -> Result<Vec<ramflux_protocol::Envelope>, SdkError> {
    Ok(std::mem::take(
        &mut *capture.lock().map_err(|_| SdkError::LocalBus("transfer capture lock".into()))?,
    ))
}
async fn deliver(
    account: &mut LocalBusAccountState,
    envelope: ramflux_protocol::Envelope,
) -> TestResult {
    let mut engine = GatewaySessionEngine::with_test_transport(
        account.gateway_config.clone(),
        Box::new(super::super::fixture::RecordingGateway::new(Arc::default())),
    );
    let entry = GatewayInboxEntry {
        forwarded: false,
        inbox_seq: 1,
        target_delivery_id: envelope.target_delivery_id.clone(),
        envelope,
    };
    let pool = ramflux_transport::RelayQuicPool::new(
        ramflux_transport::RelayQuicPoolConfig::functional_default()?,
    );
    account.client.apply_routed_entry(&mut engine, &pool, &entry, false).await?;
    Ok(())
}
#[tokio::test]
async fn r6_shared_group_handover_requires_creator_head_checks_and_transferee_countersign()
-> TestResult {
    Box::pin(check_handover(false)).await
}
#[tokio::test]
async fn r6_shared_group_stale_laptop_gets_signed_refusal_and_reissues_without_undoing_removal()
-> TestResult {
    Box::pin(check_handover(true)).await
}
async fn check_handover(stale: bool) -> TestResult {
    let mut rig = Rig::new().await?;
    if stale {
        rig.phone.client.shared_group_change(
            "group",
            &rig.phone.target_delivery_id,
            ramflux_protocol::GroupStateChange::Remove {
                root_commitment: rig.removed_root.clone(),
                device_id: "device-mallory".into(),
            },
        )?;
        rig.phone.client.shared_group_change(
            "group",
            &rig.phone.target_delivery_id,
            ramflux_protocol::GroupStateChange::SetName { name: "current creator head".into() },
        )?;
    }
    let refusal = rig.authorize().await.err().ok_or("transfer unexpectedly ready")?;
    assert_eq!(crate::bus::io::local_bus_error_code(&refusal), "transfer_requires_sync");
    assert_proposal_survives_issue_expiry(&rig.laptop.client)?;
    Box::pin(rig.deliver_probes()).await?;
    if stale {
        let replies = rig
            .phone
            .client
            .account_db()?
            .list_actor_states::<TransferDelivery>(TRANSFER_SEND_PREFIX)?;
        assert!(replies.iter().any(|row|matches!(&row.control.body,TransferBody::Head{reply} if reply.requires_sync && reply.head.epoch==5)));
    } else {
        let blocked = rig
            .phone
            .client
            .shared_group_change(
                "group",
                &rig.phone.target_delivery_id,
                ramflux_protocol::GroupStateChange::SetName { name: "must wait".into() },
            )
            .err()
            .ok_or("creator changed reserved head")?;
        assert_eq!(crate::bus::io::local_bus_error_code(&blocked), "transfer_requires_sync");
    }
    Box::pin(rig.deliver_replies()).await?;
    if stale {
        assert_eq!(rig.laptop.client.group_state("group")?.group_epoch, 5);
        assert!(
            rig.laptop
                .client
                .account_db()?
                .shared_group_state("group")?
                .ok_or("state")?
                .view()
                .effective_role(&rig.removed_root, "device-mallory")
                .is_none()
        );
        let blocked = rig.authorize().await.err().ok_or("cancellation must finish first")?;
        assert_eq!(
            crate::bus::io::local_bus_error_body(&blocked).reason_code.as_deref(),
            Some("cancellation_delivery_pending")
        );
        // Refusal durably cancels the old reservation on every participant before a new probe.
        for _ in 0..2 {
            assert_eq!(crate::bus::shared_group_sync::flush_requests(&mut rig.laptop).await?, 1);
        }
        for envelope in take_submitted(&rig.captures[1])? {
            if envelope.target_delivery_id == rig.phone.target_delivery_id {
                deliver(&mut rig.phone, envelope).await?;
            } else {
                deliver(&mut rig.next, envelope).await?;
            }
        }
        Box::pin(rig.deliver_replies()).await?; // Authenticated cancellation acknowledgements.
        assert!(rig.authorize().await.is_err());
        Box::pin(rig.deliver_probes()).await?;
        Box::pin(rig.deliver_replies()).await?;
    }
    let acceptance = rig.authorize().await?;
    let old = rig.laptop.client.account_db()?.shared_group_state("group")?.ok_or("old head")?;
    assert_eq!(acceptance.base_hash, old.snapshot().state_hash);
    let handover = rig.laptop.client.shared_group_change(
        "group",
        &rig.laptop.target_delivery_id,
        ramflux_protocol::GroupStateChange::TransferOwnership {
            creator: rig.next.client.owned_group_actor(&rig.next.target_delivery_id)?,
            acceptance: Box::new(acceptance),
        },
    )?;
    assert_eq!(handover.view().epoch, old.view().epoch + 1);
    assert_eq!(
        handover.creator().identity.root_commitment,
        rig.next.client.owned_device_identity()?.root_commitment()
    );
    if stale {
        assert!(handover.view().effective_role(&rig.removed_root, "device-mallory").is_none());
    }
    rig.directory.abort();
    let root = rig.root.clone();
    drop(rig);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[tokio::test]
async fn r6_stale_transfer_snapshot_returns_typed_error_and_persists_signed_refusal() -> TestResult
{
    Box::pin(stale_snapshot()).await
}
async fn stale_snapshot() -> TestResult {
    let mut rig = Rig::new().await?;
    let base = rig.laptop.client.account_db()?.shared_group_state("group")?.ok_or("base")?;
    // Model a stale/malicious issuer bypassing the honest SDK's freshness gate.
    let acceptance = ramflux_crypto::accept_group_transfer(
        rig.next.client.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?,
        &rig.next.client.owned_group_actor(&rig.next.target_delivery_id)?,
        &base,
        &ramflux_protocol::encode_base64url([73; 32]),
        now_unix_timestamp(),
    )?;
    let stale = ramflux_crypto::advance_group_state(
        rig.laptop.client.identity_root.as_ref().ok_or(SdkError::IdentityRootMissing)?,
        rig.laptop.client.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?,
        &rig.laptop.client.owned_group_actor(&rig.laptop.target_delivery_id)?,
        &base,
        ramflux_protocol::GroupStateChange::TransferOwnership {
            creator: rig.next.client.owned_group_actor(&rig.next.target_delivery_id)?,
            acceptance: Box::new(acceptance),
        },
    )?;
    // The issuing device has committed the handover before a lagging peer refuses it.
    rig.laptop.client.accept_shared_group_state(&stale, &rig.laptop.target_delivery_id)?;
    rig.phone.client.shared_group_change(
        "group",
        &rig.phone.target_delivery_id,
        ramflux_protocol::GroupStateChange::Remove {
            root_commitment: rig.removed_root.clone(),
            device_id: "device-mallory".into(),
        },
    )?;
    let head = rig.phone.client.shared_group_change(
        "group",
        &rig.phone.target_delivery_id,
        ramflux_protocol::GroupStateChange::SetName { name: "current head".into() },
    )?;
    let mut engine = rig.laptop.take_live_engine().await?;
    let mut message = GatewayDirectMessage {
        conversation_id: "group-thread".into(),
        message_id: "stale-transfer".into(),
        envelope_id: "stale-transfer".into(),
        source_principal_id: engine.config.principal_id.clone(),
        sender_id: engine.config.device_id.clone(),
        recipient_device_id: Some(rig.phone.gateway_config.device_id.clone()),
        recipient_principal_commitment: Some(
            rig.phone.client.owned_device_identity()?.root_commitment().into(),
        ),
        target_delivery_id: rig.phone.target_delivery_id.clone(),
        encrypted_body: Vec::new(),
        created_at: now_unix_timestamp(),
        ttl: 60,
    };
    message.encrypted_body = serde_json::to_vec(
        &rig.laptop
            .client
            .seal_routed_as(
                &mut engine,
                &message,
                &rig.laptop.client.shared_group_packet(&stale, false)?,
                crate::client::routed::Route::group_control("group"),
            )
            .await?,
    )?;
    let envelope = crate::dm::gateway_direct_message_envelope(&engine.config, &message, None)?;
    rig.laptop.put_engine(engine);
    let error = deliver(&mut rig.phone, envelope).await.err().ok_or("stale transfer accepted")?;
    let sdk = error.downcast_ref::<SdkError>().ok_or("typed SDK error missing")?;
    assert_eq!(crate::bus::io::local_bus_error_code(sdk), "transfer_requires_sync");
    assert_eq!(
        rig.phone
            .client
            .account_db()?
            .shared_group_state("group")?
            .ok_or("head")?
            .snapshot()
            .state_hash,
        head.snapshot().state_hash
    );
    Box::pin(assert_stale_refusal(&mut rig, &base, &head, &stale)).await?;
    rig.directory.abort();
    let root = rig.root.clone();
    drop(rig);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

async fn assert_stale_refusal(
    rig: &mut Rig,
    base: &ramflux_crypto::VerifiedGroupState,
    head: &ramflux_crypto::VerifiedGroupState,
    stale: &ramflux_crypto::VerifiedGroupState,
) -> TestResult {
    let rows = rig
        .phone
        .client
        .account_db()?
        .list_actor_states::<TransferDelivery>(TRANSFER_SEND_PREFIX)?;
    let refusal = rows.iter().find(|row| matches!(&row.control.body, TransferBody::Head {reply} if reply.requires_sync && reply.head.state_hash==head.snapshot().state_hash)).ok_or("durable signed refusal missing")?;
    refusal.control.verify(now_unix_timestamp())?;
    assert_eq!(crate::bus::shared_group_sync::flush_requests(&mut rig.phone).await?, 1);
    let envelope = take_submitted(&rig.captures[0])?.pop().ok_or("refusal not routed")?;
    deliver(&mut rig.laptop, envelope).await?;
    let event = rig
        .laptop
        .client
        .account_db()?
        .latest_journal_event("group.state.conflict")?
        .ok_or("stale refusal event missing")?;
    assert_eq!(event.body["reason"], "transfer_refused_stale");
    assert_eq!(event.body["base_hash"], base.snapshot().state_hash);
    assert_eq!(
        rig.laptop
            .client
            .account_db()?
            .shared_group_state("group")?
            .ok_or("head")?
            .snapshot()
            .state_hash,
        stale.snapshot().state_hash,
        "a post-commit refusal must not silently reverse ownership"
    );
    Ok(())
}

fn assert_proposal_survives_issue_expiry(client: &crate::RamfluxClient) -> TestResult {
    // Pruning issue-expired metadata must not orphan a still-reserved proposal.
    client.account_db()?.retain_expiring_actor_states(
        "group-transfer/pending/",
        now_unix_timestamp() + 3600,
        128,
    )?;
    assert_eq!(client.account_db()?.actor_state_usage("group-transfer/pending/")?.0, 1);
    Ok(())
}

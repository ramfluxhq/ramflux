// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Abandoned transfers release without a user retry, including revoked participants.
use super::*;
use crate::bus::state::LocalBusAccountState;
use crate::client::native_test_support::Fixture as Native;
use crate::client::shared_group::tests::temp_root;
use ramflux_protocol::{GroupStateChange, SharedGroupRole};

fn native_err(error: &dyn std::error::Error) -> SdkError {
    SdkError::LocalBus(error.to_string())
}

/// Device storage key that the raw transfer entry points expect as their target.
fn skey(client: &RamfluxClient) -> Result<String, SdkError> {
    Ok(client.owned_device_identity()?.storage_key().into())
}

struct Fixture {
    /// Holds the phone's primary so that it can sign the revocations in these tests.
    phone: LocalBusAccountState,
    laptop: RamfluxClient,
    next: RamfluxClient,
    base: VerifiedGroupState,
    probe: TransferProbe,
    path: ramflux_test_support::TestPath,
    /// Data root of the laptop sibling, whose custody store must also adopt revocations.
    laptop_root: std::path::PathBuf,
}
impl Fixture {
    fn new(name: &str) -> Result<Self, SdkError> {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?
            .block_on(Box::pin(Self::build(name)))
    }
    async fn build(name: &str) -> Result<Self, SdkError> {
        let path = temp_root(name)?;
        std::fs::create_dir_all(&path)?;
        let mut phone = Native::with_device(&format!("{name}-owner"), "phone")
            .await
            .map_err(|error| native_err(&*error))?;
        let laptop = Box::pin(phone.enroll_sibling(&format!("{name}-laptop"), "laptop"))
            .await
            .map_err(|error| native_err(&*error))?;
        let next = Native::with_device(&format!("{name}-next"), "next")
            .await
            .map_err(|error| native_err(&*error))?;
        phone.accept_peer(&next).map_err(|error| native_err(&*error))?;
        next.accept_peer(&phone).map_err(|error| native_err(&*error))?;
        laptop.client.persist_observed_identity_directory_now(&next.manifest)?;
        next.client.persist_observed_identity_directory_now(&laptop.manifest)?;
        let laptop_bus = laptop.into_bus();
        let laptop_root = laptop_bus
            .native_setup
            .as_ref()
            .ok_or(SdkError::CustodySetupInvalid)?
            .data_root
            .clone();
        let laptop = laptop_bus.client;
        let next = next.into_bus().client;
        let phone = phone.into_bus();
        phone.client.fixture_group_create("group", "thread", None, "phone")?;
        let base = phone.client.fixture_group_change(
            "group",
            "phone",
            GroupStateChange::Add {
                member: next.fixture_group_actor("next")?.identity,
                role: SharedGroupRole::Member,
            },
        )?;
        laptop.fixture_accept_group_state(&base, "laptop")?;
        next.fixture_accept_group_state(&base, "next")?;
        let now = now_unix_timestamp();
        let probe = TransferProbe {
            id: ramflux_protocol::encode_base64url([97; 32]),
            actor: phone.client.fixture_group_actor("phone")?,
            creator: next.fixture_group_actor("next")?,
            base: base.snapshot().clone(),
            required: vec![
                TransferDevice {
                    root: laptop.owned_device_identity()?.root_commitment().into(),
                    device: "laptop".into(),
                },
                TransferDevice {
                    root: next.owned_device_identity()?.root_commitment().into(),
                    device: "next".into(),
                },
            ],
            issued_at: now,
            expires_at: now + 60,
        };
        Ok(Self { phone, laptop, next, base, probe, path, laptop_root })
    }
    fn pending(&self, probe: &TransferProbe) -> Result<(), SdkError> {
        self.phone.client.reserve_group_transfer(probe, &self.base)?;
        self.phone.client.account_db()?.persist_actor_state(
            &key(PENDING, "group"),
            &Pending {
                probe: probe.clone(),
                replies: BTreeMap::new(),
                expires_at: ramflux_protocol::MAX_SAFE_JSON_INTEGER.cast_signed(),
            },
        )?;
        Ok(())
    }
    /// Primary-signed revocation of `name` on the phone, which holds the account primary.
    /// Returns the manifest that receivers must adopt. The revoked device's own branch is not
    /// re-initialised, because the phone may be the device being revoked.
    fn revoke(&mut self, name: &str) -> Result<crate::prekey::SdkDeviceManifestResponse, SdkError> {
        let root = self
            .phone
            .native_setup
            .as_ref()
            .ok_or(SdkError::CustodySetupInvalid)?
            .data_root
            .clone();
        let (mut manifest, vault) = {
            let material = self
                .phone
                .client
                .native_bus_fixture
                .as_ref()
                .ok_or(SdkError::CustodySetupInvalid)?;
            (material.manifest.clone(), material.vault.clone())
        };
        let mut native = manifest.custody.clone().ok_or(SdkError::CustodySetupInvalid)?;
        let now = crate::custody::network_now()?.max(native.publication.record.body.issued_at);
        let current = self
            .phone
            .client
            .current_custody_authority(&manifest.principal_commitment, now)?
            .ok_or(SdkError::CustodySetupInvalid)?;
        let primary = vault.primary_for_public_key(
            &native.publication.record.body.master_certificate.body.self_signing_public_key,
        )?;
        native.publication.record = primary.revoke_device(&current, name, now)?;
        native.devices.retain(|entry| entry.device_ref.device_id != name);
        manifest.devices.retain(|entry| entry.device_id != name);
        manifest.custody = Some(native.clone());
        let id = self.phone.client.account_db()?.local_account_id.clone();
        let authority = ramflux_protocol::custody::CustodyAuthority {
            publication: native.publication,
            custodian_publication: native.custodian_publication,
        };
        crate::custody::accept_publication(&root, &id, &authority, now)?;
        // The revoked device itself does not adopt its own revocation; every other device does.
        if name != "laptop" {
            let laptop_id = self.laptop.account_db()?.local_account_id.clone();
            crate::custody::accept_publication(&self.laptop_root, &laptop_id, &authority, now)?;
        }
        if let Some(material) = self.phone.client.native_bus_fixture.as_mut() {
            material.manifest = manifest.clone();
        }
        self.phone.client.persist_identity_directory(&manifest)?;
        Ok(manifest)
    }
    /// Group changes on the laptop are signed with the account primary held by the phone.
    /// A sibling vault never holds the primary, so the fixture supplies the phone's copy.
    fn laptop_change(&self, change: GroupStateChange) -> Result<VerifiedGroupState, SdkError> {
        let primary = self.phone.client.fixture_primary()?;
        self.laptop.shared_group_change_with_primary(
            "group",
            &skey(&self.laptop)?,
            change,
            primary.as_ref(),
        )
    }
    fn close(self) -> Result<(), SdkError> {
        let path = self.path.clone();
        drop(self);
        std::fs::remove_dir_all(path)?;
        Ok(())
    }
}
#[test]
fn r8_lost_issuer_reservation_releases_after_issue_deadline_and_skew() -> Result<(), SdkError> {
    let f = Fixture::new("lost-transfer-issuer")?;
    f.laptop.reserve_group_transfer(&f.probe, &f.base)?;
    f.laptop.advance_group_transfer_deadlines(f.probe.expires_at + 300)?;
    assert!(f.laptop.check_group_transfer_lease("group", None).is_err());
    f.laptop.advance_group_transfer_deadlines(f.probe.expires_at + 301)?;
    f.laptop.check_group_transfer_lease("group", None)?;
    f.laptop_change(GroupStateChange::SetName { name: "unfrozen without issuer".into() })?;
    assert!(
        f.laptop.reserve_group_transfer(&f.probe, &f.base).is_err(),
        "delayed completed proposal remains fenced"
    );
    f.close()
}
#[test]
fn r8_abandoned_issuer_automatically_signs_cancellation_and_revocation_releases_sibling()
-> Result<(), SdkError> {
    let mut f = Fixture::new("auto-transfer-cancel")?;
    f.pending(&f.probe)?;
    f.laptop.reserve_group_transfer(&f.probe, &f.base)?;
    f.phone.client.advance_group_transfer_deadlines(f.probe.expires_at + 301)?;
    assert!(!f.phone.client.account_db()?.actor_state_exists(&key(PENDING, "group"))?);
    f.phone.client.check_group_transfer_lease("group", None)?;
    let rows = f.phone.client.account_db()?.list_actor_states::<TransferDelivery>(SEND_PREFIX)?;
    let cancel = rows
        .iter()
        .find(|row| matches!(&row.control.body,TransferBody::Head{reply} if reply.cancelled))
        .ok_or(StorageError::AuthorizationRejected)?;
    cancel.control.verify(now_unix_timestamp())?;
    let manifest = f.revoke("phone")?;
    f.laptop.persist_identity_directory(&manifest)?;
    // Before timeout, a verified revoked issuer is already released.
    f.laptop.advance_group_transfer_deadlines(f.probe.expires_at)?;
    f.laptop.check_group_transfer_lease("group", None)?;
    f.laptop_change(GroupStateChange::SetName { name: "revoked issuer released".into() })?;
    f.close()
}
#[test]
fn r8_revoked_cancel_target_does_not_block_a_fresh_completed_transfer() -> Result<(), SdkError> {
    let mut f = Fixture::new("revoked-cancel-target")?;
    f.pending(&f.probe)?;
    f.phone.client.cancel_group_transfer(&f.probe)?;
    f.revoke("laptop")?;
    assert!(f.phone.client.cancellation_delivery_pending("group")?);
    let rows = f.phone.client.account_db()?.list_actor_states::<TransferDelivery>(SEND_PREFIX)?;
    let cancel = rows
        .iter()
        .find(|row| matches!(&row.control.body,TransferBody::Head{reply} if reply.cancelled))
        .ok_or(StorageError::AuthorizationRejected)?;
    f.next.apply_group_transfer_control(&cancel.control, &skey(&f.next)?)?;
    let replies = f.next.account_db()?.list_actor_states::<TransferDelivery>(SEND_PREFIX)?;
    let ack = replies
        .iter()
        .find(|row| matches!(&row.control.body,TransferBody::Head{reply} if reply.cancel_ack))
        .ok_or(StorageError::AuthorizationRejected)?;
    f.phone.client.apply_group_transfer_control(&ack.control, &skey(&f.phone.client)?)?;
    assert!(!f.phone.client.cancellation_delivery_pending("group")?);
    let mut fresh = f.probe.clone();
    fresh.id = ramflux_protocol::encode_base64url([98; 32]);
    fresh.required.retain(|target| target.device != "laptop");
    f.pending(&fresh)?;
    let wire =
        TransferControl::sign(&f.phone.client, TransferBody::Probe { probe: Box::new(fresh) })?;
    f.next.apply_group_transfer_control(&wire, &skey(&f.next)?)?;
    let replies = f.next.account_db()?.list_actor_states::<TransferDelivery>(SEND_PREFIX)?;
    let head = replies
        .iter()
        .find(|row| matches!(&row.control.body,TransferBody::Head{reply} if reply.acceptance.is_some()))
        .ok_or(StorageError::AuthorizationRejected)?;
    f.phone.client.apply_group_transfer_control(&head.control, &skey(&f.phone.client)?)?;
    let pending: Pending = f
        .phone
        .client
        .account_db()?
        .load_actor_state(&key(PENDING, "group"))?
        .ok_or(StorageError::AuthorizationRejected)?;
    let acceptance = f.phone.client.completed_group_transfer(&pending, &f.base)?;
    let transferred = f.phone.client.fixture_group_change(
        "group",
        "phone",
        GroupStateChange::TransferOwnership {
            creator: f.next.fixture_group_actor("next")?,
            acceptance: Box::new(acceptance),
        },
    )?;
    assert_eq!(transferred.creator().identity, f.next.fixture_group_actor("next")?.identity);
    f.close()
}

#[test]
fn r8_restored_or_merged_transfer_backups_never_freeze_group_changes() -> Result<(), SdkError> {
    use ramflux_storage::{AccountDb, AccountDbKey, AccountIndex, BackupDatabase};
    let f = Fixture::new("restore-transfer-state")?;
    f.pending(&f.probe)?;
    f.phone.client.stage_group_transfer_control(TransferControl::sign(
        &f.phone.client,
        TransferBody::Probe { probe: Box::new(f.probe.clone()) },
    )?)?;
    assert!(
        f.phone
            .client
            .fixture_group_change(
                "group",
                "phone",
                GroupStateChange::SetName { name: "must wait".into() }
            )
            .is_err()
    );
    assert_eq!(f.phone.client.account_db()?.actor_state_usage("group-transfer/")?.0, 4);
    let incoming = f.path.join("pending-backup.db");
    let snapshot = f.phone.client.account_db()?.write_backup_snapshot(&incoming)?;
    let primary = f.phone.client.fixture_primary()?;
    let target = skey(&f.phone.client)?;
    for merge in [false, true] {
        let index = AccountIndex::open(f.path.join(if merge { "merge" } else { "restore" }))?;
        index.create_account("acct", f.phone.client.owned_device_identity()?.root_commitment())?;
        let key = AccountDbKey::generate()?;
        let target_path = index.root().join(index.account("acct")?.db_relative_path);
        std::fs::create_dir_all(target_path.parent().ok_or(StorageError::AuthorizationRejected)?)?;
        if merge {
            let live = AccountDb::open(&index, "acct", &key)?;
            live.persist_actor_state(
                "group-transfer/outcome/local",
                &serde_json::json!({"inert_after_install":true}),
            )?;
            drop(live);
            let mut staging = BackupDatabase::open(&target_path, &key)?;
            staging.merge_backup_with_group_actor(
                &incoming,
                &snapshot.key,
                Some(&f.phone.client.fixture_group_actor("phone")?),
                || Ok(()),
            )?;
        } else {
            BackupDatabase::open(&incoming, &snapshot.key)?.copy_to(&target_path, &key)?;
            BackupDatabase::open(&target_path, &key)?.archive_outbound()?;
        }
        let mut restored = RamfluxClient::new();
        restored.born_v3_account.clone_from(&f.phone.client.born_v3_account);
        restored.device_branch.clone_from(&f.phone.client.device_branch);
        restored.active_account_db = Some(AccountDb::open(&index, "acct", &key)?);
        restored.account_index = Some(index);
        assert_eq!(restored.account_db()?.actor_state_usage("group-transfer/")?.0, 0);
        restored.shared_group_change_with_primary(
            "group",
            &target,
            GroupStateChange::SetName { name: "unfrozen after restore".into() },
            primary.as_ref(),
        )?;
    }
    f.close()
}

#[test]
fn a_poisoned_deadline_item_does_not_block_healthy_lease_release() -> Result<(), SdkError> {
    for prefix in [PENDING, LEASE, SEND_PREFIX] {
        let f = Fixture::new("poisoned-transfer-deadline")?;
        f.laptop.reserve_group_transfer(&f.probe, &f.base)?;
        let id = format!("{prefix}!poison");
        let poison = serde_json::json!({"invalid":"retryable deadline item"});
        f.laptop.account_db()?.persist_actor_state(&id, &poison)?;
        for _ in 0..2 {
            f.laptop.advance_group_transfer_deadlines(f.probe.expires_at + 301)?;
            f.laptop.check_group_transfer_lease("group", None)?;
            assert_eq!(
                f.laptop.account_db()?.load_actor_state::<serde_json::Value>(&id)?,
                Some(poison.clone())
            );
        }
        f.laptop_change(GroupStateChange::SetName {
            name: "healthy after poisoned deadline".into(),
        })?;
        f.close()?;
    }
    Ok(())
}

#[path = "transfer_maintenance_tests.rs"]
mod maintenance_tests;

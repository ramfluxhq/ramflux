// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Abandoned transfers release without a user retry, including revoked participants.
use super::*;
use crate::client::identity_authority::test_support::{public_manifest, sign_manifest};
use crate::client::shared_group::tests::{person, temp_root};
use ramflux_protocol::{GroupStateChange, SharedGroupRole};

struct Fixture {
    path: PathBuf,
    phone: RamfluxClient,
    laptop: RamfluxClient,
    next: RamfluxClient,
    base: VerifiedGroupState,
    probe: TransferProbe,
}
impl Fixture {
    fn new(name: &str) -> Result<Self, SdkError> {
        let path = temp_root(name)?;
        let phone = person(&path.join("phone"), "owner", "phone", 11, 12)?;
        let laptop = person(&path.join("laptop"), "owner", "laptop", 11, 32)?;
        let next = person(&path.join("next"), "next", "next", 21, 22)?;
        super::tests::install_transfer_directories(&phone, &laptop, &next)?;
        phone.shared_group_create("group", "thread", None, "target-phone")?;
        let base = phone.shared_group_change(
            "group",
            "target-phone",
            GroupStateChange::Add {
                member: next.owned_group_actor("target-next")?.identity,
                role: SharedGroupRole::Member,
            },
        )?;
        laptop.accept_shared_group_state(&base, "target-laptop")?;
        next.account_db()?.establish_friend_link(
            "owner",
            next.owned_device_identity()?.root_commitment(),
            phone.owned_device_identity()?.root_commitment(),
        )?;
        next.accept_shared_group_state(&base, "target-next")?;
        let now = now_unix_timestamp();
        let probe = TransferProbe {
            id: ramflux_protocol::encode_base64url([97; 32]),
            actor: phone.owned_group_actor("target-phone")?,
            creator: next.owned_group_actor("target-next")?,
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
        Ok(Self { path, phone, laptop, next, base, probe })
    }
    fn pending(&self, probe: &TransferProbe) -> Result<(), SdkError> {
        self.phone.reserve_group_transfer(probe, &self.base)?;
        self.phone.account_db()?.persist_actor_state(
            &key(PENDING, "group"),
            &Pending {
                probe: probe.clone(),
                replies: BTreeMap::new(),
                expires_at: ramflux_protocol::MAX_SAFE_JSON_INTEGER.cast_signed(),
            },
        )?;
        Ok(())
    }
    fn revoke(&self, name: &str, receiver: &RamfluxClient) -> Result<(), SdkError> {
        let root = self.phone.identity_root.as_ref().ok_or(SdkError::IdentityRootMissing)?;
        let mut manifest = public_manifest(&self.phone)?;
        manifest.devices.extend(public_manifest(&self.laptop)?.devices);
        sign_manifest(root, &mut manifest, 2)?;
        let old = manifest.signed_device_set.take().ok_or(StorageError::AuthorizationRejected)?;
        let mut devices = old.devices;
        let removed = devices
            .iter_mut()
            .find(|device| device.device_id == name)
            .ok_or(StorageError::AuthorizationRejected)?;
        removed.status = ramflux_protocol::DeviceSetStatus::Revoked;
        removed.revoked_at = Some(now_unix_timestamp());
        manifest.devices.retain(|device| device.device_id != name);
        manifest.signed_device_set = Some(ramflux_crypto::sign_device_set_with_profile(
            root,
            ramflux_crypto::DeviceSetSigningInput {
                principal_kind: ramflux_protocol::PrincipalKind::Human,
                device_set_epoch: 3,
                devices,
            },
            old.profile.as_deref().cloned(),
        )?);
        receiver.persist_identity_directory(&manifest)
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
    f.laptop.shared_group_change(
        "group",
        "target-laptop",
        GroupStateChange::SetName { name: "unfrozen without issuer".into() },
    )?;
    assert!(
        f.laptop.reserve_group_transfer(&f.probe, &f.base).is_err(),
        "delayed completed proposal remains fenced"
    );
    f.close()
}
#[test]
fn r8_abandoned_issuer_automatically_signs_cancellation_and_revocation_releases_sibling()
-> Result<(), SdkError> {
    let f = Fixture::new("auto-transfer-cancel")?;
    f.pending(&f.probe)?;
    f.laptop.reserve_group_transfer(&f.probe, &f.base)?;
    f.phone.advance_group_transfer_deadlines(f.probe.expires_at + 301)?;
    assert!(!f.phone.account_db()?.actor_state_exists(&key(PENDING, "group"))?);
    f.phone.check_group_transfer_lease("group", None)?;
    let rows = f.phone.account_db()?.list_actor_states::<TransferDelivery>(SEND_PREFIX)?;
    let cancel = rows
        .iter()
        .find(|row| matches!(&row.control.body,TransferBody::Head{reply} if reply.cancelled))
        .ok_or(StorageError::AuthorizationRejected)?;
    cancel.control.verify(now_unix_timestamp())?;
    f.revoke("phone", &f.laptop)?;
    // Before timeout, a verified revoked issuer is already released.
    f.laptop.advance_group_transfer_deadlines(f.probe.expires_at)?;
    f.laptop.check_group_transfer_lease("group", None)?;
    f.laptop.shared_group_change(
        "group",
        "target-laptop",
        GroupStateChange::SetName { name: "revoked issuer released".into() },
    )?;
    f.close()
}
#[test]
fn r8_revoked_cancel_target_does_not_block_a_fresh_completed_transfer() -> Result<(), SdkError> {
    let f = Fixture::new("revoked-cancel-target")?;
    f.pending(&f.probe)?;
    f.phone.cancel_group_transfer(&f.probe)?;
    f.revoke("laptop", &f.phone)?;
    assert!(f.phone.cancellation_delivery_pending("group")?);
    let rows = f.phone.account_db()?.list_actor_states::<TransferDelivery>(SEND_PREFIX)?;
    let cancel = rows
        .iter()
        .find(|row| matches!(&row.control.body,TransferBody::Head{reply} if reply.cancelled))
        .ok_or(StorageError::AuthorizationRejected)?;
    f.next.apply_group_transfer_control(&cancel.control, "target-next")?;
    let replies = f.next.account_db()?.list_actor_states::<TransferDelivery>(SEND_PREFIX)?;
    let ack = replies
        .iter()
        .find(|row| matches!(&row.control.body,TransferBody::Head{reply} if reply.cancel_ack))
        .ok_or(StorageError::AuthorizationRejected)?;
    f.phone.apply_group_transfer_control(&ack.control, "target-phone")?;
    assert!(!f.phone.cancellation_delivery_pending("group")?);
    let mut fresh = f.probe.clone();
    fresh.id = ramflux_protocol::encode_base64url([98; 32]);
    fresh.required.retain(|target| target.device != "laptop");
    f.pending(&fresh)?;
    let wire = TransferControl::sign(&f.phone, TransferBody::Probe { probe: Box::new(fresh) })?;
    f.next.apply_group_transfer_control(&wire, "target-next")?;
    let replies = f.next.account_db()?.list_actor_states::<TransferDelivery>(SEND_PREFIX)?;
    let head = replies.iter().find(|row|matches!(&row.control.body,TransferBody::Head{reply} if reply.acceptance.is_some())).ok_or(StorageError::AuthorizationRejected)?;
    f.phone.apply_group_transfer_control(&head.control, "target-phone")?;
    let pending: Pending = f
        .phone
        .account_db()?
        .load_actor_state(&key(PENDING, "group"))?
        .ok_or(StorageError::AuthorizationRejected)?;
    let acceptance = f.phone.completed_group_transfer(&pending, &f.base)?;
    let transferred = f.phone.shared_group_change(
        "group",
        "target-phone",
        GroupStateChange::TransferOwnership {
            creator: f.next.owned_group_actor("target-next")?,
            acceptance: Box::new(acceptance),
        },
    )?;
    assert_eq!(transferred.creator().identity, f.next.owned_group_actor("target-next")?.identity);
    f.close()
}

#[test]
fn r8_restored_or_merged_transfer_backups_never_freeze_group_changes() -> Result<(), SdkError> {
    use ramflux_storage::{AccountDb, AccountDbKey, AccountIndex, BackupDatabase};
    let f = Fixture::new("restore-transfer-state")?;
    f.pending(&f.probe)?;
    f.phone.stage_group_transfer_control(TransferControl::sign(
        &f.phone,
        TransferBody::Probe { probe: Box::new(f.probe.clone()) },
    )?)?;
    assert!(
        f.phone
            .shared_group_change(
                "group",
                "target-phone",
                GroupStateChange::SetName { name: "must wait".into() }
            )
            .is_err()
    );
    assert_eq!(f.phone.account_db()?.actor_state_usage("group-transfer/")?.0, 4);
    let incoming = f.path.join("pending-backup.db");
    let snapshot = f.phone.account_db()?.write_backup_snapshot(&incoming)?;
    for merge in [false, true] {
        let index = AccountIndex::open(f.path.join(if merge { "merge" } else { "restore" }))?;
        index.create_account("acct", f.phone.owned_device_identity()?.root_commitment())?;
        let key = AccountDbKey::generate()?;
        let target = index.root().join(index.account("acct")?.db_relative_path);
        std::fs::create_dir_all(target.parent().ok_or(StorageError::AuthorizationRejected)?)?;
        if merge {
            let live = AccountDb::open(&index, "acct", &key)?;
            live.persist_actor_state(
                "group-transfer/outcome/local",
                &serde_json::json!({"inert_after_install":true}),
            )?;
            drop(live);
            let mut staging = BackupDatabase::open(&target, &key)?;
            staging.merge_backup_with_group_actor(
                &incoming,
                &snapshot.key,
                Some(&f.phone.owned_group_actor("target-phone")?),
                || Ok(()),
            )?;
        } else {
            BackupDatabase::open(&incoming, &snapshot.key)?.copy_to(&target, &key)?;
            BackupDatabase::open(&target, &key)?.archive_outbound()?;
        }
        let mut restored = RamfluxClient::new();
        restored.create_identity_root("owner", [11; 32]);
        restored.create_device_branch("owner", "phone", 2, [12; 32]);
        restored.active_account_db = Some(AccountDb::open(&index, "acct", &key)?);
        restored.account_index = Some(index);
        assert_eq!(restored.account_db()?.actor_state_usage("group-transfer/")?.0, 0);
        restored.shared_group_change(
            "group",
            "target-phone",
            GroupStateChange::SetName { name: "unfrozen after restore".into() },
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
        f.laptop.shared_group_change(
            "group",
            "target-laptop",
            GroupStateChange::SetName { name: "healthy after poisoned deadline".into() },
        )?;
        f.close()?;
    }
    Ok(())
}

// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Verified retained-head witnesses for receiver-owned removal floors.
use super::{
    AccountDb,
    shared_group_removals::{DeviceFloor, Floors},
};
use crate::StorageError;
use ramflux_crypto::{VerifiedGroupState, verify_group_state_snapshot};
use ramflux_protocol::{GroupStateSnapshot, custody::object_hash};

/// An exact tuple from the removal-floor owner. This is a local capability, not a wire DTO.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GroupRemovalFloor {
    Root { root: String, epoch: u64 },
    Device { root: String, device: String, epoch: u64 },
}

/// A pruned floor and the oldest retained signed head which still attests it.
/// Its reference uses custody's existing `object_hash` over the exact signed snapshot.
#[derive(Clone, Debug)]
pub struct PrunedGroupFloor {
    pub floor: GroupRemovalFloor,
    pub attesting_epoch: u64,
    pub attesting_hash: String,
    pub signed_head: GroupStateSnapshot,
}

impl GroupRemovalFloor {
    fn attested_by(&self, head: &VerifiedGroupState) -> bool {
        let state = head.view();
        let (root, epoch) = match self {
            Self::Root { root, epoch } | Self::Device { root, epoch, .. } => (root, *epoch),
        };
        if epoch == 0 || state.epoch < epoch {
            return false;
        }
        let root_absent =
            !state.members.iter().any(|member| &member.identity.root_commitment == root);
        match self {
            Self::Root { .. } => root_absent,
            Self::Device { device, .. } => {
                root_absent
                    || state.excluded.iter().any(|excluded| {
                        &excluded.root_commitment == root
                            && &excluded.device_id == device
                            && excluded.removed_epoch >= epoch
                    })
            }
        }
    }
    fn into_floors(self) -> Floors {
        let mut floors = Floors::default();
        match self {
            Self::Root { root, epoch } => {
                floors.roots.insert(root, epoch);
            }
            Self::Device { root, device, epoch } => {
                floors.devices.push(DeviceFloor { root, device, epoch });
            }
        }
        floors
    }
}

impl AccountDb {
    /// Reconstruct witnesses without fabricating references to pruned signed snapshots.
    /// # Errors
    /// Missing retained attestation, malformed history or storage failure refuses the export.
    pub fn pruned_group_floor_witnesses(
        &self,
        group: &str,
    ) -> Result<Vec<PrunedGroupFloor>, StorageError> {
        let floors = self.shared_group_removal_floors(group)?;
        let mut heads = self.retained_signed_group_heads(group)?;
        if let Some(current) = self.shared_group_state(group)? {
            let hash = object_hash(current.snapshot())?;
            if !heads.iter().any(|head| object_hash(head).is_ok_and(|value| value == hash)) {
                heads.push(current.snapshot().clone());
            }
        }
        let mut verified = heads
            .into_iter()
            .map(|head| {
                let hash = object_hash(&head)?;
                Ok((verify_group_state_snapshot(head)?, hash))
            })
            .collect::<Result<Vec<_>, StorageError>>()?;
        verified.sort_by(|(a, ah), (b, bh)| (a.view().epoch, ah).cmp(&(b.view().epoch, bh)));
        let tuples = floors
            .roots
            .into_iter()
            .map(|(root, epoch)| GroupRemovalFloor::Root { root, epoch })
            .chain(floors.devices.into_iter().map(|floor| GroupRemovalFloor::Device {
                root: floor.root,
                device: floor.device,
                epoch: floor.epoch,
            }));
        tuples
            .map(|floor| {
                let (head, hash) = verified
                    .iter()
                    .find(|(head, _)| floor.attested_by(head))
                    .ok_or(StorageError::GroupPermissionDenied)?;
                Ok(PrunedGroupFloor {
                    floor,
                    attesting_epoch: head.view().epoch,
                    attesting_hash: hash.clone(),
                    signed_head: head.snapshot().clone(),
                })
            })
            .collect()
    }

    /// Verify an incoming witness against the target's independently bound group genesis,
    /// then union its denial with the target floors. This never grants group membership.
    /// # Errors
    /// Rejects transplanted genesis, altered hash/epoch, invalid signature or unsupported floor.
    pub fn accept_pruned_group_floor(
        &self,
        group: &str,
        expected_genesis: &str,
        proof: &PrunedGroupFloor,
    ) -> Result<(), StorageError> {
        let head = verify_group_state_snapshot(proof.signed_head.clone())?;
        if head.view().group_id != group
            || head.genesis_hash()? != expected_genesis
            || proof.attesting_hash != object_hash(head.snapshot())?
            || proof.attesting_epoch != head.view().epoch
            || !proof.floor.attested_by(&head)
        {
            return Err(StorageError::GroupPermissionDenied);
        }
        self.write_transaction(|| {
            let mut floors = self.shared_group_removal_floors(group)?;
            let prior = floors.clone();
            floors.merge(proof.floor.clone().into_floors());
            floors.check_capacity(prior.len())?;
            let group = group.to_owned();
            self.connection.call(move |db| floors.store_index_delta(db, &group, &prior))?;
            Ok(())
        })
    }
}

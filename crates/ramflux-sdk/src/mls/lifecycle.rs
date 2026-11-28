// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Lifecycle of a DM or self group (spec §3.3 updates, §3.4): when a new device is added and by
//! whom, the local freshness checks on send and receive, the Remove triggers and the 24 h
//! own-leaf Update. Groups never run any of this (no periodic Update in the beta).
//!
//! Rule V: freshness is local knowledge. A leaf the directory rejects is removed by a NEW commit
//! (sender side) or its application messages are refused (receiver side); it never makes a
//! received commit or Welcome invalid. The clock appears only as a scheduling input (`now`).

use ramflux_mls::{GroupKind, Mls, MlsError, MlsKv};

use super::key_packages::FetchedKeyPackage;
use super::order::{CommitOutcome, ConvState, ConvStore, MadeCommit, Scope, commit_and_submit};
use crate::SdkError;
use crate::gateway::access::MlsFrameAccess;

/// The approving device spreads its adds over `U(0, 60 s)` per conversation.
pub(crate) const ADD_JITTER_MAX_SECS: u64 = 60;
/// Another own device adds a missing sibling only after this long (10 min).
pub(crate) const OWN_SIBLING_ADD_DELAY_SECS: u64 = 600;
/// A peer device adds a missing device only after this long (30 min).
pub(crate) const PEER_DEVICE_ADD_DELAY_SECS: u64 = 1_800;
/// Conversations used within this window get the new device at once (30 days); older ones on
/// first use.
pub(crate) const RECENT_CONVERSATION_SECS: u64 = 30 * 86_400;
/// The own leaf is updated when it is at least this old (24 h).
pub(crate) const UPDATE_AFTER_SECS: u64 = 86_400;
/// Backstop: the own leaf is updated after this many own generations in one epoch.
pub(crate) const UPDATE_BACKSTOP_GENERATIONS: u64 = 1_000;

/// Who notices a device missing from a conversation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DeviceAdder {
    /// The own device that approved the new device.
    Approver,
    /// Another own device of the same account.
    #[allow(dead_code)]
    OwnSibling,
    /// A device of the peer.
    #[allow(dead_code)]
    PeerDevice,
}

/// Seconds after the device was first seen missing before `role` adds it. `jitter_draw` is a
/// uniform random `u64` from the caller; only the approver uses it.
pub(crate) fn add_delay_secs(role: DeviceAdder, jitter_draw: u64) -> u64 {
    match role {
        DeviceAdder::Approver => jitter_draw % (ADD_JITTER_MAX_SECS + 1),
        DeviceAdder::OwnSibling => OWN_SIBLING_ADD_DELAY_SECS,
        DeviceAdder::PeerDevice => PEER_DEVICE_ADD_DELAY_SECS,
    }
}

/// Whether `role` should add the missing device now: it was first seen missing at `missing_since`
/// and `role`'s delay has passed.
pub(crate) fn add_due(role: DeviceAdder, missing_since: u64, now: u64, jitter_draw: u64) -> bool {
    now >= missing_since.saturating_add(add_delay_secs(role, jitter_draw))
}

/// Whether a conversation last used at `last_used` gets a new device eagerly (`true`) or on its
/// first use (`false`).
pub(crate) fn add_eagerly(last_used: u64, now: u64) -> bool {
    now.saturating_sub(last_used) < RECENT_CONVERSATION_SECS
}

/// Why an own-leaf Update is due.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum UpdateTrigger {
    /// The leaf is at least 24 h old (unlock, wake or the daily timer, also for receive-only
    /// devices).
    Age,
    /// This device just changed the membership.
    MembershipChange,
    /// The own custody head changed.
    CustodyHeadChanged,
    /// 1 000 own generations in one epoch.
    Generations,
}

/// What happened since the last Update that makes one due.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct UpdateContext {
    /// This device committed an Add or Remove.
    pub(crate) membership_changed_by_us: bool,
    /// The own custody head changed.
    pub(crate) custody_head_changed: bool,
}

/// The first reason an own-leaf Update is due, if any. Only `dm` and `self` update; groups never
/// do in the beta.
pub(crate) fn update_due(
    kind: GroupKind,
    state: &ConvState,
    epoch: u64,
    now: u64,
    context: UpdateContext,
) -> Option<UpdateTrigger> {
    if !kind.is_device_kind() {
        return None;
    }
    if context.membership_changed_by_us {
        Some(UpdateTrigger::MembershipChange)
    } else if context.custody_head_changed {
        Some(UpdateTrigger::CustodyHeadChanged)
    } else if state.generations_epoch == epoch && state.generations >= UPDATE_BACKSTOP_GENERATIONS {
        Some(UpdateTrigger::Generations)
    } else if now.saturating_sub(state.leaf_updated_at) >= UPDATE_AFTER_SECS {
        Some(UpdateTrigger::Age)
    } else {
        None
    }
}

/// Count one own generation sealed in `epoch` (the counter restarts when the epoch changes).
pub(crate) fn record_generation(state: &mut ConvState, epoch: u64) {
    if state.generations_epoch != epoch {
        state.generations_epoch = epoch;
        state.generations = 0;
    }
    state.generations = state.generations.saturating_add(1);
}

/// Persist one own generation sealed in `epoch`.
///
/// # Errors
/// Storage failure, or the conversation has no group.
pub(crate) fn note_sealed<K: MlsKv>(
    store: &ConvStore<'_, K>,
    scope: &Scope,
    epoch: u64,
) -> Result<(), SdkError> {
    let Some(mut state) = store.get(&scope.conversation_id)? else {
        return Ok(());
    };
    record_generation(&mut state, epoch);
    store.put(&scope.conversation_id, &state)
}

/// What the local directory says about one leaf.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[allow(dead_code)]
pub(crate) enum LeafFreshness {
    /// Passes the directory check now.
    Fresh,
    /// The directory has no head (or an older one) for the leaf's account: refresh the head once
    /// and ask again.
    NeedsRefresh,
    /// Revoked, lease expired or key mismatch.
    Stale,
}

/// Directory-path freshness of one leaf (may read the clock; local to this device).
///
/// # Errors
/// An unknown group or leaf, storage or provider failures.
#[allow(dead_code)]
pub(crate) fn check_leaf<K: MlsKv>(
    mls: &Mls<K>,
    group_id: &[u8],
    leaf: u32,
) -> Result<LeafFreshness, SdkError> {
    match mls.check_leaf_directory(group_id, leaf) {
        Ok(_) => Ok(LeafFreshness::Fresh),
        Err(MlsError::AuthorityNeeded(_)) => Ok(LeafFreshness::NeedsRefresh),
        Err(MlsError::CredentialRejected(_)) => Ok(LeafFreshness::Stale),
        Err(error) => Err(error.into()),
    }
}

/// The sender's pre-seal check of every other leaf.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
#[allow(dead_code)]
pub(crate) struct SenderCheck {
    /// Leaves to remove before sealing.
    pub(crate) stale: Vec<u32>,
    /// Leaves whose account needs a head refresh first.
    pub(crate) needs_refresh: Vec<u32>,
}

#[allow(dead_code)]
impl SenderCheck {
    /// Sealing may go ahead: nothing to remove and nothing unverified.
    pub(crate) fn is_clear(&self) -> bool {
        self.stale.is_empty() && self.needs_refresh.is_empty()
    }
}

/// Check every leaf except the own before sealing (spec §3.4, sender side). The caller refreshes
/// the accounts of `needs_refresh` once, asks again and then removes `stale` by commit.
///
/// # Errors
/// An unknown group, storage or provider failures.
#[allow(dead_code)]
pub(crate) fn check_before_seal<K: MlsKv>(
    mls: &Mls<K>,
    group_id: &[u8],
) -> Result<SenderCheck, SdkError> {
    let status = mls.status(group_id)?;
    let mut check = SenderCheck::default();
    for member in status.members.iter().filter(|member| member.leaf != status.own_leaf) {
        match check_leaf(mls, group_id, member.leaf)? {
            LeafFreshness::Fresh => {}
            LeafFreshness::NeedsRefresh => check.needs_refresh.push(member.leaf),
            LeafFreshness::Stale => check.stale.push(member.leaf),
        }
    }
    Ok(check)
}

/// The receiver's verdict on an application message's sender leaf.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[allow(dead_code)]
pub(crate) enum ReceiveVerdict {
    /// Deliver the message.
    Accept,
    /// Refresh the sender's account head once, then ask again.
    NeedsRefresh,
    /// Refuse the message (`credential_rejected`). After a refresh confirms it, the receiver
    /// commits the Remove ([`remove_leaves`]).
    Refuse,
}

/// Check the sender of an application message against the local directory (V6).
///
/// # Errors
/// An unknown group or leaf, storage or provider failures.
#[allow(dead_code)]
pub(crate) fn check_received<K: MlsKv>(
    mls: &Mls<K>,
    group_id: &[u8],
    sender_leaf: u32,
) -> Result<ReceiveVerdict, SdkError> {
    Ok(match check_leaf(mls, group_id, sender_leaf)? {
        LeafFreshness::Fresh => ReceiveVerdict::Accept,
        LeafFreshness::NeedsRefresh => ReceiveVerdict::NeedsRefresh,
        LeafFreshness::Stale => ReceiveVerdict::Refuse,
    })
}

/// Leaves of `group_id` the directory already marks revoked (no clock): an own sibling removes
/// them at once.
///
/// # Errors
/// An unknown group, storage or provider failures.
#[allow(dead_code)]
pub(crate) fn revoked_leaves<K: MlsKv>(
    mls: &Mls<K>,
    group_id: &[u8],
) -> Result<Vec<u32>, SdkError> {
    let status = mls.status(group_id)?;
    Ok(status
        .members
        .iter()
        .filter(|member| member.revoked && member.leaf != status.own_leaf)
        .map(|member| member.leaf)
        .collect())
}

/// What a run of Remove commits did.
#[derive(Debug, Eq, PartialEq)]
#[allow(dead_code)]
pub(crate) struct RemoveReport {
    /// Leaves whose Remove the orderer accepted (or that were already gone).
    pub(crate) removed: Vec<u32>,
    /// The first commit that did not reach `Accepted`; later leaves were not tried.
    pub(crate) stopped: Option<CommitOutcome<()>>,
}

#[allow(dead_code)]
fn not_found(error: &SdkError) -> bool {
    matches!(error, SdkError::Mls { code, .. } if *code == "not_found")
}

/// Commit a Remove for each leaf, one commit each, each after a catch-up (spec §3.4 triggers:
/// sender before sealing, receiver after a refresh confirmed, own sibling for a revoked sibling).
/// A leaf that is already gone counts as removed.
///
/// # Errors
/// Storage and MLS failures, an orderer refusal, gateway failures other than the
/// not-yet-available answer.
#[allow(dead_code)]
pub(crate) async fn remove_leaves<K: MlsKv>(
    access: &mut impl MlsFrameAccess,
    mls: &Mls<K>,
    store: &ConvStore<'_, K>,
    scope: &Scope,
    leaves: &[u32],
    now: u64,
) -> Result<RemoveReport, SdkError> {
    let mut report = RemoveReport { removed: Vec::new(), stopped: None };
    for &leaf in leaves {
        let outcome = commit_and_submit(access, mls, store, scope, now, |mls, group_id| {
            let present = mls.status(group_id)?.members.iter().any(|member| member.leaf == leaf);
            if !present {
                return Err(SdkError::Mls {
                    code: "not_found",
                    detail: "the leaf is already removed".to_owned(),
                });
            }
            let output = mls.remove(group_id, leaf)?.commit_plain().map_err(MlsError::from)?;
            Ok(MadeCommit { epoch: output.epoch, commit: output.message, welcome: None, extra: () })
        })
        .await;
        match outcome {
            // `Lost` stops the run, like every outcome other than `Accepted`.
            Ok(CommitOutcome::Accepted { .. }) => report.removed.push(leaf),
            Err(error) if not_found(&error) => report.removed.push(leaf),
            Ok(other) => {
                report.stopped = Some(other);
                break;
            }
            Err(error) => return Err(error),
        }
    }
    Ok(report)
}

/// Add the devices behind `key_packages` (a new own device, a peer's new device) in one commit.
/// The Welcome in `Accepted { extra }` goes out as an ordinary envelope once the orderer accepted.
///
/// # Errors
/// No `KeyPackages`, storage and MLS failures, an orderer refusal, gateway failures other than
/// the not-yet-available answer.
pub(crate) async fn add_devices<K: MlsKv>(
    access: &mut impl MlsFrameAccess,
    mls: &Mls<K>,
    store: &ConvStore<'_, K>,
    scope: &Scope,
    key_packages: &[FetchedKeyPackage],
    now: u64,
) -> Result<CommitOutcome<Vec<u8>>, SdkError> {
    if key_packages.is_empty() {
        return Err(SdkError::Mls {
            code: "policy_rejected",
            detail: "no device to add".to_owned(),
        });
    }
    let packages: Vec<Vec<u8>> =
        key_packages.iter().map(|entry| entry.key_package.clone()).collect();
    commit_and_submit(access, mls, store, scope, now, |mls, group_id| {
        let output = mls.add(group_id, &packages)?.commit_plain().map_err(MlsError::from)?;
        Ok(MadeCommit {
            epoch: output.epoch,
            commit: output.commit,
            welcome: Some(output.welcome.clone()),
            extra: output.welcome,
        })
    })
    .await
}

/// Rotate the own leaf (24 h Update and its other triggers). The conversation's leaf age and
/// generation counter restart when the orderer accepts.
///
/// # Errors
/// Storage and MLS failures, an orderer refusal, gateway failures other than the
/// not-yet-available answer.
pub(crate) async fn update_own_leaf<K: MlsKv>(
    access: &mut impl MlsFrameAccess,
    mls: &Mls<K>,
    store: &ConvStore<'_, K>,
    scope: &Scope,
    now: u64,
) -> Result<CommitOutcome<()>, SdkError> {
    let outcome = commit_and_submit(access, mls, store, scope, now, |mls, group_id| {
        let output = mls.update(group_id)?.commit_plain().map_err(MlsError::from)?;
        Ok(MadeCommit { epoch: output.epoch, commit: output.message, welcome: None, extra: () })
    })
    .await?;
    if matches!(outcome, CommitOutcome::Accepted { .. })
        && let Some(mut state) = store.get(&scope.conversation_id)?
    {
        state.leaf_updated_at = now;
        state.generations = 0;
        store.put(&scope.conversation_id, &state)?;
    }
    Ok(outcome)
}

/// Run the Update when one is due.
///
/// # Errors
/// As [`update_own_leaf`], plus an unknown group.
pub(crate) async fn update_if_due<K: MlsKv>(
    access: &mut impl MlsFrameAccess,
    mls: &Mls<K>,
    store: &ConvStore<'_, K>,
    scope: &Scope,
    now: u64,
    context: UpdateContext,
) -> Result<Option<CommitOutcome<()>>, SdkError> {
    let Some(state) = store.get(&scope.conversation_id)? else {
        return Ok(None);
    };
    let status = mls.status(&state.group_id)?;
    if update_due(status.kind, &state, status.epoch, now, context).is_none() {
        return Ok(None);
    }
    update_own_leaf(access, mls, store, scope, now).await.map(Some)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn state(updated_at: u64) -> ConvState {
        ConvState::new(vec![1; 32], 0, updated_at)
    }

    #[test]
    fn approver_jitter_stays_inside_sixty_seconds() {
        for draw in [0, 1, 60, 61, u64::MAX] {
            assert!(add_delay_secs(DeviceAdder::Approver, draw) <= 60, "draw {draw}");
        }
        assert_eq!(add_delay_secs(DeviceAdder::OwnSibling, 7), 600, "own sibling waits 10 min");
        assert_eq!(add_delay_secs(DeviceAdder::PeerDevice, 7), 1_800, "peer device waits 30 min");
    }

    #[test]
    fn add_is_due_only_after_the_role_delay() {
        assert!(!add_due(DeviceAdder::OwnSibling, 1_000, 1_599, 0), "10 min not over");
        assert!(add_due(DeviceAdder::OwnSibling, 1_000, 1_600, 0), "10 min over");
        assert!(!add_due(DeviceAdder::PeerDevice, 1_000, 2_799, 0), "30 min not over");
        assert!(add_due(DeviceAdder::PeerDevice, 1_000, 2_800, 0), "30 min over");
    }

    #[test]
    fn recent_conversations_get_the_device_eagerly() {
        assert!(add_eagerly(1_000, 1_000 + RECENT_CONVERSATION_SECS - 1), "inside 30 days");
        assert!(!add_eagerly(1_000, 1_000 + RECENT_CONVERSATION_SECS), "older: on first use");
    }

    #[test]
    fn groups_never_update() {
        let due = update_due(
            GroupKind::Group,
            &state(0),
            1,
            10 * UPDATE_AFTER_SECS,
            UpdateContext::default(),
        );
        assert_eq!(due, None, "no periodic Update in a group");
    }

    #[test]
    fn leaf_age_triggers_at_twenty_four_hours() {
        let context = UpdateContext::default();
        assert_eq!(
            update_due(GroupKind::Dm, &state(100), 1, 100 + UPDATE_AFTER_SECS - 1, context),
            None,
            "fresh leaf"
        );
        assert_eq!(
            update_due(GroupKind::Own, &state(100), 1, 100 + UPDATE_AFTER_SECS, context),
            Some(UpdateTrigger::Age),
            "24 h old"
        );
    }

    #[test]
    fn membership_change_and_custody_head_trigger_at_once() {
        let membership =
            UpdateContext { membership_changed_by_us: true, custody_head_changed: false };
        assert_eq!(
            update_due(GroupKind::Dm, &state(100), 1, 101, membership),
            Some(UpdateTrigger::MembershipChange),
            "own commit"
        );
        let custody = UpdateContext { membership_changed_by_us: false, custody_head_changed: true };
        assert_eq!(
            update_due(GroupKind::Dm, &state(100), 1, 101, custody),
            Some(UpdateTrigger::CustodyHeadChanged),
            "own custody head"
        );
    }

    #[test]
    fn generation_backstop_counts_per_epoch() {
        let mut state = state(100);
        for _ in 0..UPDATE_BACKSTOP_GENERATIONS {
            record_generation(&mut state, 4);
        }
        let context = UpdateContext::default();
        assert_eq!(
            update_due(GroupKind::Dm, &state, 4, 101, context),
            Some(UpdateTrigger::Generations),
            "1 000 in epoch 4"
        );
        assert_eq!(
            update_due(GroupKind::Dm, &state, 5, 101, context),
            None,
            "a new epoch restarts the count"
        );
        record_generation(&mut state, 5);
        assert_eq!(state.generations, 1, "the counter restarted at the epoch change");
    }
}

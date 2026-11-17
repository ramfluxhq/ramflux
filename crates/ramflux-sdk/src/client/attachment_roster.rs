// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Media-target roster for an attachment send. Every device, key and layer comes from a
//! verified custody record (CARD-HEAD-PIN B+: same anchor and master certificate, current
//! epoch and head), never from a raw directory entry, and a layer counts only inside the
//! window of its own signed declaration. The roster is rebuilt at wrapping and again at
//! admission, so a device that stopped being a target is never granted a key it should not have.

use std::collections::BTreeMap;

use crate::RamfluxClient;
use crate::SdkError;
use crate::attachment_send::{
    CODE_AUTHORITY_UNAVAILABLE, MediaDevice, MediaScope, Refusal, choose_targets,
};

/// What the roster is for. Group members are `(root commitment, device id)` pairs taken from
/// the verified group state.
pub(crate) enum RosterScope<'a> {
    Dm { peer_root: &'a str },
    Group { members: &'a [(String, String)] },
}

/// A frozen set of media targets plus the membership generation it was read at.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct MediaRoster {
    pub targets: Vec<MediaDevice>,
    pub epoch: u64,
}

impl MediaRoster {
    /// The identity of the set: the ordered `(anchor, device, epoch)` triples.
    #[must_use]
    pub(crate) fn keys(&self) -> Vec<(String, String, u64)> {
        let mut keys: Vec<_> = self
            .targets
            .iter()
            .map(|device| {
                (device.account_anchor.clone(), device.device_id.clone(), device.device_epoch)
            })
            .collect();
        keys.sort();
        keys
    }
}

impl RamfluxClient {
    /// Plans the media targets from the verified cache. `homes` maps a root commitment to its
    /// home node. The sender's own device is never a target.
    /// # Errors
    /// Returns `authority_unavailable` when a needed verified record or home is missing, and
    /// the `choose_targets` refusals (`peer_upgrade_required`, `recipient_empty`,
    /// `recipient_limit`).
    pub(crate) fn plan_media_roster(
        &self,
        scope: &RosterScope<'_>,
        homes: &BTreeMap<String, String>,
        group_epoch: u64,
    ) -> Result<MediaRoster, SdkError> {
        let now = u64::try_from(crate::time::now_unix_timestamp())
            .map_err(|_| SdkError::LocalBus("clock".into()))?;
        let own_root = self.own_account_anchor()?;
        let sender = self
            .device_branch
            .as_ref()
            .map(|branch| (branch.device_id.clone(), branch.device_epoch))
            .ok_or(SdkError::IdentityRootMissing)?;
        let mut devices = Vec::new();
        let media_scope = match scope {
            RosterScope::Dm { peer_root } => {
                self.collect((peer_root, None, false), homes, now, &mut devices)?;
                self.collect((&own_root, None, true), homes, now, &mut devices)?;
                MediaScope::Dm
            }
            RosterScope::Group { members } => {
                for (root, device) in *members {
                    let own = root == &own_root;
                    self.collect((root, Some(device), own), homes, now, &mut devices)?;
                }
                MediaScope::Group
            }
        };
        devices.retain(|device| {
            !(device.account_anchor == own_root
                && device.device_id == sender.0
                && device.device_epoch == sender.1)
        });
        let targets = choose_targets(media_scope, &devices)?;
        Ok(MediaRoster { targets, epoch: group_epoch })
    }

    fn collect(
        &self,
        (root, only, own): (&str, Option<&String>, bool),
        homes: &BTreeMap<String, String>,
        now: u64,
        out: &mut Vec<MediaDevice>,
    ) -> Result<(), SdkError> {
        let roster = self
            .cached_roster(root)?
            .ok_or_else(|| {
                tracing::warn!(root, "no verified authority record is cached for this root");
                SdkError::from(Refusal::new(CODE_AUTHORITY_UNAVAILABLE))
            })?;
        let home = homes
            .get(root)
            .filter(|home| !home.is_empty())
            .ok_or_else(|| {
                tracing::warn!(root, "no home node is known for this root");
                SdkError::from(Refusal::new(CODE_AUTHORITY_UNAVAILABLE))
            })?;
        for device in roster.media_devices(now) {
            if only.is_some_and(|wanted| wanted != &device.device_id) {
                continue;
            }
            out.push(MediaDevice {
                account_anchor: device.account_anchor,
                device_id: device.device_id,
                device_epoch: device.device_epoch,
                signing_public: device.signing_public,
                home_node_id: home.clone(),
                hpke_public: device.agreement_public,
                layer: device.layer,
                own,
            });
        }
        Ok(())
    }
}

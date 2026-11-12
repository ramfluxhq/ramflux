// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Bounded expiry cleanup; generation fences isolate successive root reservations.
use super::replay_journal::{
    EXPIRY, OWN_EXPIRY, REPLAY, ROOT_EXPIRY, ROOTS, decode_entry, decode_root,
};
use crate::{NodeCoreError, serialize_snapshot_value};
use redb::ReadableTable;

pub(super) fn prune(
    write: &redb::WriteTransaction,
    now: i64,
    limit: usize,
    owner: Option<&str>,
) -> Result<(), NodeCoreError> {
    let root_candidates = {
        let index = write.open_table(ROOT_EXPIRY).map_err(error)?;
        index
            .iter()
            .map_err(error)?
            .take((limit / 2).max(1))
            .map(|row| {
                let (key, generation) = row.map_err(error)?;
                let (at, owner) = key.value();
                Ok((at, owner.to_owned(), generation.value()))
            })
            .collect::<Result<Vec<_>, NodeCoreError>>()?
    };
    let mut examined = 0;
    for (at, owner, generation) in root_candidates {
        if at >= now {
            break;
        }
        examined += 1;
        let mut roots = write.open_table(ROOTS).map_err(error)?;
        let mut index = write.open_table(ROOT_EXPIRY).map_err(error)?;
        let current = roots
            .get(owner.as_str())
            .map_err(error)?
            .map(|raw| decode_root(raw.value()))
            .transpose()?;
        if current.is_some_and(|root| root.generation == generation && root.latest_expiry == at) {
            roots.remove(owner.as_str()).map_err(error)?;
        }
        index.remove((at, owner.as_str())).map_err(error)?;
    }
    // Protect an existing root's own reclaimable share from other roots' expired backlog.
    if let Some(owner) = owner {
        let root = {
            let roots = write.open_table(ROOTS).map_err(error)?;
            roots.get(owner).map_err(error)?.map(|raw| decode_root(raw.value())).transpose()?
        };
        if let Some(root) = root.filter(|root| root.latest_expiry >= now) {
            let candidates = {
                let index = write.open_table(OWN_EXPIRY).map_err(error)?;
                index
                    .range(
                        (owner, root.generation, i64::MIN, "")..(owner, root.generation, now, ""),
                    )
                    .map_err(error)?
                    .take(limit.saturating_sub(examined))
                    .map(|row| {
                        let (key, _) = row.map_err(error)?;
                        let (_, _, at, key) = key.value();
                        Ok((at, key.to_owned()))
                    })
                    .collect::<Result<Vec<_>, NodeCoreError>>()?
            };
            for (at, key) in candidates {
                examined += 1;
                prune_identity(write, at, &key, Some((owner, root.generation)))?;
            }
        }
    }
    let candidates = {
        let index = write.open_table(EXPIRY).map_err(error)?;
        index
            .iter()
            .map_err(error)?
            .take(limit.saturating_sub(examined))
            .map(|row| {
                let (key, _) = row.map_err(error)?;
                let (at, key) = key.value();
                Ok((at, key.to_owned()))
            })
            .collect::<Result<Vec<_>, NodeCoreError>>()?
    };
    for (at, key) in candidates {
        if at >= now {
            break;
        }
        prune_identity(write, at, &key, None)?;
    }
    Ok(())
}
fn prune_identity(
    write: &redb::WriteTransaction,
    at: i64,
    key: &str,
    owner_hint: Option<(&str, u64)>,
) -> Result<(), NodeCoreError> {
    let mut entries = write.open_table(REPLAY).map_err(error)?;
    let mut index = write.open_table(EXPIRY).map_err(error)?;
    let mut own_index = write.open_table(OWN_EXPIRY).map_err(error)?;
    let current =
        entries.get(key).map_err(error)?.map(|raw| decode_entry(raw.value())).transpose()?;
    if let Some(entry) = current.filter(|entry| entry.expiry == at) {
        entries.remove(key).map_err(error)?;
        own_index.remove((entry.owner.as_str(), entry.generation, at, key)).map_err(error)?;
        let mut roots = write.open_table(ROOTS).map_err(error)?;
        let root = roots
            .get(entry.owner.as_str())
            .map_err(error)?
            .map(|raw| decode_root(raw.value()))
            .transpose()?;
        if let Some(mut root) = root.filter(|root| root.generation == entry.generation) {
            root.count = root
                .count
                .checked_sub(1)
                .ok_or_else(|| NodeCoreError::ReplayGuard("corrupt replay root count".into()))?;
            if root.count == 0 {
                roots.remove(entry.owner.as_str()).map_err(error)?;
                write
                    .open_table(ROOT_EXPIRY)
                    .map_err(error)?
                    .remove((root.latest_expiry, entry.owner.as_str()))
                    .map_err(error)?;
            } else {
                roots
                    .insert(entry.owner.as_str(), serialize_snapshot_value(&root)?.as_slice())
                    .map_err(error)?;
            }
        }
    }
    if let Some((owner, generation)) = owner_hint {
        own_index.remove((owner, generation, at, key)).map_err(error)?;
    }
    // Even an obsolete index is removed; it cannot erase a renewed body.
    index.remove((at, key)).map_err(error)?;
    Ok(())
}
fn error(error: impl std::fmt::Display) -> NodeCoreError {
    NodeCoreError::Redb(error.to_string())
}

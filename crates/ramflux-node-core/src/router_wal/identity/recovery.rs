// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Offline association validation, pre-S6 upgrade and resumable incarnation rotation.
use super::{
    Arc, Association, BTreeMap, Chain, File, HEADER_LEN, KEY, MAGIC, Metadata, Mutex,
    NodeCoreError, OpenOptions, Path, ROUTER_WAL_MAGIC, ReadableDatabase, ReadableTable,
    RouterWalPayload, RouterWalRecovery, StoredRouterWalPayload, Write, commit, directory_key,
    durability_io, error, fs, header_bytes, incarnation, io, read_header, read_router_wal_record,
    recover_router_wal_at, router_wal_existing_shard_roots, router_wal_segment_ids,
    router_wal_segment_path, write_router_wal_record_to_file,
};
type CursorInventory = (BTreeMap<String, String>, BTreeMap<String, u64>);

fn inventory(root: &Path) -> Result<BTreeMap<String, Vec<u64>>, NodeCoreError> {
    let roots = std::iter::once(root.to_path_buf())
        .chain(router_wal_existing_shard_roots(root)?.into_iter().map(|(_, path)| path));
    roots
        .map(|directory| {
            let mut ids = router_wal_segment_ids(&directory)?;
            ids.sort_unstable();
            Ok((directory_key(root, &directory)?, ids))
        })
        .collect()
}
fn load_metadata(db: &redb::Database) -> Result<Option<Metadata>, NodeCoreError> {
    let txn = db.begin_read().map_err(error)?;
    let table = txn.open_table(crate::ROUTER_SNAPSHOT_TABLE).map_err(error)?;
    let metadata = table
        .get(KEY)
        .map_err(error)?
        .map(|row| serde_json::from_slice::<Metadata>(row.value()))
        .transpose()
        .map_err(error)?;
    if metadata.as_ref().is_some_and(|metadata| metadata.version != 1) {
        return Err(error("unsupported future WAL association version"));
    }
    Ok(metadata)
}
fn cursors(db: &redb::Database) -> Result<CursorInventory, NodeCoreError> {
    let txn = db.begin_read().map_err(error)?;
    let table = txn.open_table(crate::ROUTER_CURSOR_STATE_TABLE).map_err(error)?;
    let mut ids = BTreeMap::new();
    let mut issued = BTreeMap::new();
    for item in table.iter().map_err(error)? {
        let (target, bytes) = item.map_err(error)?;
        let stored: incarnation::StoredCursor =
            serde_json::from_slice(bytes.value()).map_err(error)?;
        issued.insert(
            target.value().into(),
            stored
                .cursor
                .issued_inbox_seq
                .max(stored.cursor.inbox_seq)
                .max(stored.cursor.settled_inbox_seq),
        );
        if let Some(id) = stored.inbox_incarnation_id {
            incarnation::validate(&id)?;
            ids.insert(target.value().into(), id);
        }
    }
    // Legacy snapshot-only counters must participate even before incremental tables exist.
    let snapshots = txn.open_table(crate::ROUTER_SNAPSHOT_TABLE).map_err(error)?;
    if let Some(bytes) = snapshots.get(crate::ROUTER_INBOX_SLICE_KEY).map_err(error)? {
        let inbox: crate::OpaqueDeviceInbox =
            serde_json::from_slice(bytes.value()).map_err(error)?;
        for cursor in inbox.cursor_states() {
            issued
                .entry(cursor.target_delivery_id.clone())
                .and_modify(|seq| {
                    *seq = (*seq).max(inbox.issued_sequence(&cursor.target_delivery_id));
                })
                .or_insert(inbox.issued_sequence(&cursor.target_delivery_id));
        }
    }
    Ok((ids, issued))
}
fn write_identity(root: &Path, id: &str) -> Result<(), NodeCoreError> {
    let path = root.join("identity");
    let temporary = root.join("identity.pending");
    let mut file = File::create(&temporary).map_err(error)?;
    durability_io::write_header(&mut file, &temporary, id.as_bytes()).map_err(error)?;
    durability_io::sync_file(&file, &temporary).map_err(error)?;
    fs::rename(&temporary, &path).map_err(error)?;
    durability_io::sync_dir(root).map_err(error)
}
/// Only an absent required record is a rotation trigger. Empty residue files are retained.
fn recorded_head_missing(metadata: &Metadata, inventory: &BTreeMap<String, Vec<u64>>) -> bool {
    metadata.chains.iter().any(|(key, chain)| {
        let ids = inventory.get(key);
        ids.is_none_or(|ids| {
            !ids.contains(&chain.head)
                || !ids.contains(&chain.anchor)
                || chain.legacy.iter().any(|id| *id >= chain.anchor && !ids.contains(id))
        })
    })
}
fn inspect(
    root: &Path,
    metadata: Option<&Metadata>,
    inventory: &BTreeMap<String, Vec<u64>>,
) -> Result<bool, NodeCoreError> {
    let mut mismatch = false;
    if let Some(metadata) = metadata {
        mismatch |= fs::read_to_string(root.join("identity")).ok().as_deref()
            != Some(metadata.directory_id.as_str());
        mismatch |= recorded_head_missing(metadata, inventory);
        for (key, chain) in &metadata.chains {
            if let Ok(size) = fs::metadata(router_wal_segment_path(&root.join(key), chain.anchor)) {
                mismatch |= chain.anchor_lsn > size.len();
            }
        }
    }
    for (key, ids) in inventory {
        let directory = root.join(key);
        let chain = metadata.and_then(|metadata| metadata.chains.get(key));
        let mut previous = None;
        for segment in ids {
            if chain.is_some_and(|chain| *segment < chain.anchor) {
                continue;
            }
            let path = router_wal_segment_path(&directory, *segment);
            let mut bytes = fs::read(&path).map_err(error)?;
            let legacy = bytes.starts_with(ROUTER_WAL_MAGIC);
            let newest = ids.last() == Some(segment);
            let expected_len = if chain.is_some_and(|chain| chain.legacy.contains(segment))
                || (metadata.is_none() && legacy)
            {
                ROUTER_WAL_MAGIC.len()
            } else {
                HEADER_LEN
            };
            let empty_residue = newest
                && bytes.len() <= expected_len
                && (bytes.len() <= ROUTER_WAL_MAGIC.len()
                    || bytes.starts_with(MAGIC)
                    || bytes.iter().all(|byte| *byte == 0));
            if empty_residue
                && let Some(metadata) = metadata
                && expected_len == HEADER_LEN
            {
                // Repair in place, never unlink the recorded empty head. A kill at either
                // boundary leaves a header-only image that the next start repairs again.
                let header =
                    header_bytes(&metadata.directory_id, *segment, previous.unwrap_or(u64::MAX));
                durability_io::boundary(&path, "empty_head_repair", || {
                    let mut file = OpenOptions::new().write(true).truncate(true).open(&path)?;
                    file.write_all(&header)?;
                    file.sync_all()
                })
                .map_err(error)?;
                bytes = header;
            }
            if bytes.len() >= MAGIC.len() && bytes.starts_with(MAGIC) {
                let mut file = File::open(&path).map_err(error)?;
                let (_, header) = read_header(&mut file)?;
                if let Some((identity, id, parent)) = header {
                    if let Some(metadata) = metadata {
                        mismatch |= identity != metadata.directory_id;
                    }
                    mismatch |=
                        id != *segment || previous.is_some_and(|previous| parent != previous);
                }
            } else if legacy
                && metadata.is_some()
                && !chain.is_some_and(|chain| chain.legacy.contains(segment))
                && !empty_residue
            {
                mismatch = true;
            }
            previous = Some(*segment);
        }
    }
    Ok(mismatch)
}
fn chains(
    root: &Path,
    inventory: &BTreeMap<String, Vec<u64>>,
    old: Option<&Metadata>,
) -> Result<BTreeMap<String, Chain>, NodeCoreError> {
    let mut chains = BTreeMap::new();
    for (key, ids) in inventory {
        let Some(head) = ids.last() else { continue };
        let anchor = old.and_then(|old| old.chains.get(key)).map_or(ids[0], |chain| chain.anchor);
        let mut legacy = Vec::new();
        for id in ids.iter().filter(|id| **id >= anchor) {
            let bytes = fs::read(router_wal_segment_path(&root.join(key), *id)).map_err(error)?;
            if bytes.starts_with(ROUTER_WAL_MAGIC) {
                legacy.push(*id);
            }
        }
        chains.insert(key.clone(), Chain { anchor, head: *head, legacy, anchor_lsn: 0 });
    }
    Ok(chains)
}
fn rewrite(
    root: &Path,
    metadata: &Metadata,
    ids: &BTreeMap<String, String>,
    inventory: &BTreeMap<String, Vec<u64>>,
) -> Result<(), NodeCoreError> {
    for (key, segments) in inventory {
        let directory = root.join(key);
        let mut previous = u64::MAX;
        for segment in segments {
            let path = router_wal_segment_path(&directory, *segment);
            let mut source = File::open(&path).map_err(error)?;
            read_header(&mut source)?;
            let temporary = path.with_extension("rewrite");
            let mut output = File::create(&temporary).map_err(error)?;
            output
                .write_all(&header_bytes(&metadata.directory_id, *segment, previous))
                .map_err(error)?;
            while let Some((stored, _)) = read_router_wal_record(&mut source)? {
                let payload: RouterWalPayload = stored.try_into()?;
                let RouterWalPayload::Submission { entry, .. } = &payload;
                let stored = StoredRouterWalPayload::try_from(&payload)?;
                let stored = if let Some(entry) = entry {
                    StoredRouterWalPayload::Incarnated {
                        incarnation_id: ids
                            .get(&entry.target_delivery_id)
                            .ok_or_else(|| error("rotation omitted inbox"))?
                            .clone(),
                        payload: Box::new(stored),
                    }
                } else {
                    stored
                };
                let encoded = postcard::to_allocvec(&stored).map_err(error)?;
                write_router_wal_record_to_file(&output, &encoded)?;
            }
            durability_io::sync_file(&output, &temporary).map_err(error)?;
            durability_io::boundary(&path, "rotation_segment", || fs::rename(&temporary, &path))
                .map_err(error)?;
            durability_io::sync_dir(&directory).map_err(error)?;
            previous = *segment;
        }
    }
    write_identity(root, &metadata.directory_id)
}
pub(super) fn prepare(
    root: &Path,
    db: Arc<redb::Database>,
    db_path: &Path,
) -> Result<(Association, RouterWalRecovery), NodeCoreError> {
    durability_io::create_dir_all(root).map_err(error)?;
    let old = load_metadata(&db)?;
    let inventory = inventory(root)?;
    let mut rotate = inspect(root, old.as_ref(), &inventory)?;
    let anchors = old
        .as_ref()
        .map(|metadata| {
            metadata.chains.iter().map(|(key, chain)| (key.clone(), chain.anchor)).collect()
        })
        .unwrap_or_default();
    let mut recovered = recover_router_wal_at(root, &anchors)?;
    let (mut ids, mut issued) = cursors(&db)?;
    let had_metadata = old.is_some() || !ids.is_empty() || !recovered.state.incarnations.is_empty();
    for (target, seq) in &recovered.state.issued_by_target {
        issued.entry(target.clone()).and_modify(|old| *old = (*old).max(*seq)).or_insert(*seq);
    }
    for (target, id) in &recovered.state.incarnations {
        if ids.get(target).is_some_and(|old| old != id) {
            rotate = true;
        }
        ids.entry(target.clone()).or_insert_with(|| id.clone());
    }
    rotate |= recovered.state.incarnation_conflict;
    // S6 cursor metadata paired with a missing association is loss, not a pre-S6 upgrade.
    rotate |= old.is_none() && had_metadata;
    let pending = old.as_ref().is_some_and(|old| old.rotation_pending);
    if rotate && !pending {
        for target in issued.keys() {
            ids.insert(target.clone(), incarnation::new_id()?);
        }
    }
    for target in issued.keys() {
        if !ids.contains_key(target) {
            ids.insert(target.clone(), incarnation::new_id()?);
        }
    }
    let mut metadata = old.clone().unwrap_or(Metadata {
        version: 1,
        directory_id: incarnation::new_id()?,
        rotation_pending: false,
        chains: BTreeMap::new(),
    });
    if rotate && !pending {
        metadata.directory_id = incarnation::new_id()?;
    }
    if rotate || pending {
        metadata.rotation_pending = true;
        durability_io::boundary(db_path, "rotation_pending", || {
            commit(&db, &metadata, &ids, &issued, true).map_err(io::Error::other)
        })
        .map_err(error)?;
        let mut active = inventory.clone();
        for (key, segments) in &mut active {
            if let Some(chain) = metadata.chains.get(key) {
                segments.retain(|segment| *segment >= chain.anchor);
            }
        }
        rewrite(root, &metadata, &ids, &active)?;
        metadata.chains = chains(root, &active, None)?;
        let anchors =
            metadata.chains.iter().map(|(key, chain)| (key.clone(), chain.anchor)).collect();
        recovered = recover_router_wal_at(root, &anchors)?;
        metadata.rotation_pending = false;
    } else {
        metadata.chains = chains(root, &inventory, old.as_ref())?;
        write_identity(root, &metadata.directory_id)?;
    }
    durability_io::boundary(db_path, "association_commit", || {
        commit(&db, &metadata, &ids, &issued, false).map_err(io::Error::other)
    })
    .map_err(error)?;
    Ok((
        Association { root: root.into(), db, metadata: Mutex::new(metadata), ids: Mutex::new(ids) },
        recovered,
    ))
}

// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! WAL association, chained headers and durable head/anchor transitions.
use super::{
    Arc, BTreeMap, Deserialize, File, Mutex, NodeCoreError, OpenOptions, Path, PathBuf,
    ROUTER_WAL_MAGIC, ROUTER_WAL_SEGMENT_BYTES_DEFAULT, ROUTER_WAL_SEGMENT_BYTES_ENV, Read,
    RouterWalPayload, RouterWalRecovery, RouterWalState, RouterWalStore, RouterWalWriter, Seek,
    Serialize, StoredRouterWalPayload, Write, durability_io, fs, io, read_router_wal_record,
    recover_router_wal_at, router_wal_existing_shard_roots, router_wal_pipeline_enabled,
    router_wal_segment_ids, router_wal_segment_path, router_wal_shard_count, router_wal_u64_env,
    write_router_wal_record_to_file,
};
use crate::router_store::incarnation;
use redb::{ReadableDatabase, ReadableTable};
pub(crate) mod maintenance;
mod recovery;
const KEY: &str = "session_push_wal_v1";
const MAGIC: &[u8] = b"ramflux-router-wal-v2\n";
pub(super) const HEADER_LEN: usize = MAGIC.len() + 32 + 16;
#[derive(Clone, Default, Deserialize, Serialize)]
struct Chain {
    anchor: u64,
    head: u64,
    /// Bare-header segments accepted only as the recorded pre-S6 prefix.
    legacy: Vec<u64>,
    anchor_lsn: u64,
}
#[derive(Clone, Deserialize, Serialize)]
struct Metadata {
    version: u32,
    directory_id: String,
    rotation_pending: bool,
    chains: BTreeMap<String, Chain>,
}
pub(super) struct Association {
    root: PathBuf,
    db: Arc<redb::Database>,
    metadata: Mutex<Metadata>,
    ids: Mutex<BTreeMap<String, String>>,
}
pub(super) fn error(value: impl std::fmt::Display) -> NodeCoreError {
    NodeCoreError::Redb(value.to_string())
}
pub(super) fn segment_error(path: &Path, cause: impl std::fmt::Display) -> NodeCoreError {
    NodeCoreError::WalSegmentRequiresQuarantine {
        path: path.to_path_buf(),
        cause: cause.to_string(),
    }
}
fn directory_key(root: &Path, directory: &Path) -> Result<String, NodeCoreError> {
    Ok(directory.strip_prefix(root).map_err(error)?.to_string_lossy().into_owned())
}
impl Association {
    pub(super) fn reserve(&self, target: &str) -> Result<String, NodeCoreError> {
        let mut ids = self.ids.lock().map_err(error)?;
        if let Some(id) = ids.get(target) {
            return Ok(id.clone());
        }
        let id = incarnation::new_id()?;
        ids.insert(target.into(), id.clone());
        Ok(id)
    }
    pub(super) fn record_head(&self, directory: &Path, head: u64) -> Result<(), NodeCoreError> {
        let key = directory_key(&self.root, directory)?;
        let mut metadata = self.metadata.lock().map_err(error)?;
        let mut next = metadata.clone();
        let chain = next.chains.entry(key).or_insert(Chain {
            anchor: head,
            head,
            legacy: Vec::new(),
            anchor_lsn: 0,
        });
        chain.head = head;
        let path = router_wal_segment_path(directory, head);
        // The actual Immediate commit must complete before the first frame append.
        durability_io::boundary(&path, "head_commit", || {
            commit(&self.db, &next, &BTreeMap::new(), &BTreeMap::new(), false, false)
                .map_err(io::Error::other)
        })
        .map_err(error)?;
        *metadata = next;
        Ok(())
    }
    pub(super) fn retire(&self, directory: &Path, segment: u64) -> Result<bool, NodeCoreError> {
        let key = directory_key(&self.root, directory)?;
        let mut metadata = self.metadata.lock().map_err(error)?;
        let mut next = metadata.clone();
        let Some(chain) = next.chains.get_mut(&key) else { return Ok(false) };
        if segment < chain.anchor {
            return Ok(true);
        }
        if segment != chain.anchor || segment >= chain.head {
            return Ok(false);
        }
        let ids = router_wal_segment_ids(directory)?;
        let Some(anchor) = ids.into_iter().filter(|id| *id > segment).min() else {
            return Ok(false);
        };
        chain.anchor = anchor;
        chain.anchor_lsn = 0;
        chain.legacy.retain(|id| *id >= anchor);
        commit(&self.db, &next, &BTreeMap::new(), &BTreeMap::new(), false, false)?;
        *metadata = next;
        Ok(true)
    }
}
fn commit(
    db: &redb::Database,
    metadata: &Metadata,
    ids: &BTreeMap<String, String>,
    issued: &BTreeMap<String, u64>,
    rotate: bool,
    finish_operator: bool,
) -> Result<(), NodeCoreError> {
    crate::fatal_durability::run(|| {
        let mut txn = db.begin_write().map_err(error)?;
        txn.set_durability(redb::Durability::Immediate).map_err(error)?;
        for (target, id) in ids {
            incarnation::set_cursor(
                &txn,
                target,
                issued.get(target).copied().unwrap_or(0),
                id,
                rotate,
            )?;
        }
        {
            let mut table = txn.open_table(crate::ROUTER_SNAPSHOT_TABLE).map_err(error)?;
            if finish_operator {
                table.remove(maintenance::KEY).map_err(error)?;
            }
            table
                .insert(KEY, serde_json::to_vec(metadata).map_err(error)?.as_slice())
                .map_err(error)?;
        }
        txn.commit().map_err(error)
    })
}
pub(super) fn header(
    association: Option<&Association>,
    directory: &Path,
    segment: u64,
) -> Result<Vec<u8>, NodeCoreError> {
    let Some(association) = association else { return Ok(ROUTER_WAL_MAGIC.to_vec()) };
    let metadata = association.metadata.lock().map_err(error)?;
    let key = directory_key(&association.root, directory)?;
    let previous = metadata.chains.get(&key).map_or(u64::MAX, |chain| {
        if chain.head == segment { segment.checked_sub(1).unwrap_or(u64::MAX) } else { chain.head }
    });
    Ok(header_bytes(&metadata.directory_id, segment, previous))
}
fn header_bytes(id: &str, segment: u64, previous: u64) -> Vec<u8> {
    let mut header = MAGIC.to_vec();
    header.extend_from_slice(id.as_bytes());
    header.extend_from_slice(&segment.to_le_bytes());
    header.extend_from_slice(&previous.to_le_bytes());
    header
}
type Header = (u64, Option<(String, u64, u64)>);
pub(super) fn read_header(file: &mut File) -> Result<Header, NodeCoreError> {
    let mut magic = vec![0; MAGIC.len()];
    file.read_exact(&mut magic).map_err(error)?;
    if magic == ROUTER_WAL_MAGIC {
        return Ok((ROUTER_WAL_MAGIC.len() as u64, None));
    }
    if magic != MAGIC {
        return Err(error(
            "invalid router WAL segment magic; stop router and gateways and use --rotate-inbox-incarnations --quarantine-wal-segment",
        ));
    }
    let mut id = [0; 32];
    let mut segment = [0; 8];
    let mut previous = [0; 8];
    file.read_exact(&mut id).map_err(error)?;
    file.read_exact(&mut segment).map_err(error)?;
    file.read_exact(&mut previous).map_err(error)?;
    let id = String::from_utf8(id.to_vec()).map_err(error)?;
    incarnation::validate(&id)?;
    Ok((HEADER_LEN as u64, Some((id, u64::from_le_bytes(segment), u64::from_le_bytes(previous)))))
}
/// A recorded empty v2 head keeps its segment id and receives a complete header.
pub(super) fn repair_empty_header(
    file: &mut File,
    path: &Path,
    newest: bool,
) -> Result<(), NodeCoreError> {
    if !newest {
        return Ok(());
    }
    let size = usize::try_from(file.metadata().map_err(error)?.len()).map_err(error)?;
    if size > HEADER_LEN || size <= ROUTER_WAL_MAGIC.len() {
        return Ok(());
    }
    let mut bytes = vec![0; size];
    file.read_exact(&mut bytes).map_err(error)?;
    file.rewind().map_err(error)?;
    if bytes.starts_with(MAGIC) && size < HEADER_LEN {
        // Recovery::prepare supplies the canonical identity before recovering this residue.
        return Err(error(format!("incomplete chained WAL header: {}", path.display())));
    }
    Ok(())
}
pub(super) fn encode_payload(
    association: Option<&Association>,
    payload: &RouterWalPayload,
) -> Result<StoredRouterWalPayload, NodeCoreError> {
    let stored = StoredRouterWalPayload::try_from(payload)?;
    let RouterWalPayload::Submission { entry, .. } = payload;
    if let (Some(association), Some(entry)) = (association, entry) {
        return Ok(StoredRouterWalPayload::Incarnated {
            incarnation_id: association.reserve(&entry.target_delivery_id)?,
            payload: Box::new(stored),
        });
    }
    Ok(stored)
}
pub(super) fn decode_payload(
    stored: StoredRouterWalPayload,
    state: &mut RouterWalState,
) -> Result<RouterWalPayload, NodeCoreError> {
    match stored {
        StoredRouterWalPayload::Incarnated { incarnation_id, payload } => {
            incarnation::validate(&incarnation_id)?;
            if matches!(*payload, StoredRouterWalPayload::Incarnated { .. }) {
                return Err(error("nested WAL incarnation record"));
            }
            let payload: RouterWalPayload = (*payload).try_into()?;
            let RouterWalPayload::Submission { entry, .. } = &payload;
            let entry = entry
                .as_ref()
                .ok_or_else(|| error("WAL incarnation record without inbox counter"))?;
            if state
                .incarnations
                .insert(entry.target_delivery_id.clone(), incarnation_id.clone())
                .is_some_and(|old| old != incarnation_id)
            {
                state.incarnation_conflict = true;
            }
            Ok(payload)
        }
        stored => stored.try_into(),
    }
}
impl RouterWalStore {
    pub(crate) fn open_associated(
        root: &Path,
        db: Arc<redb::Database>,
        db_path: &Path,
    ) -> Result<Self, NodeCoreError> {
        Self::open_associated_config(
            root,
            db,
            db_path,
            router_wal_pipeline_enabled(),
            router_wal_shard_count(),
            router_wal_u64_env(ROUTER_WAL_SEGMENT_BYTES_ENV, ROUTER_WAL_SEGMENT_BYTES_DEFAULT)
                .max(1024 * 1024),
        )
    }
    pub(crate) fn open_associated_config(
        root: &Path,
        db: Arc<redb::Database>,
        db_path: &Path,
        pipeline: bool,
        shards: usize,
        segment_bytes: u64,
    ) -> Result<Self, NodeCoreError> {
        Self::validate_formats(root)?;
        let (association, recovered) = recovery::prepare(root, db, db_path)?;
        let association = Arc::new(association);
        let state = Arc::new(Mutex::new(recovered.state));
        let writer = RouterWalWriter::start_associated(
            root,
            segment_bytes,
            shards.max(1),
            &recovered.shards,
            &state,
            pipeline,
            Some(&association),
        )?;
        Ok(Self { root: root.into(), state, writer, association: Some(association) })
    }
    pub(crate) fn reserve_incarnation(&self, target: &str) -> Result<String, NodeCoreError> {
        self.association
            .as_ref()
            .ok_or_else(|| error("WAL has no redb association"))?
            .reserve(target)
    }
    pub(crate) fn committed_inbox(
        &self,
        target: &str,
    ) -> Result<Option<(String, u64)>, NodeCoreError> {
        let state = self.state.lock().map_err(error)?;
        let Some(issued) = state.issued_by_target.get(target) else { return Ok(None) };
        Ok(Some((self.reserve_incarnation(target)?, *issued)))
    }
}

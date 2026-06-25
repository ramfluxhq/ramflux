#![allow(clippy::wildcard_imports)]
use crate::*;
use serde::Serialize;

pub(crate) fn history_bundle_hash(
    source_device_id: &str,
    target_device_id: &str,
    events: &[HistoryEventRecord],
    checkpoints: &[ProjectionCheckpointRecord],
) -> Result<String, StorageError> {
    #[derive(Serialize)]
    struct HashBody<'a> {
        source_device_id: &'a str,
        target_device_id: &'a str,
        encrypted_event_batch: &'a [HistoryEventRecord],
        projection_checkpoints: &'a [ProjectionCheckpointRecord],
    }
    let bytes = serde_json::to_vec(&HashBody {
        source_device_id,
        target_device_id,
        encrypted_event_batch: events,
        projection_checkpoints: checkpoints,
    })?;
    Ok(blake3::hash(&bytes).to_hex().to_string())
}

// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Effective policy and authenticated upload recovery on the existing attachment plane.
use super::{
    Arc, AttachmentMeshReply, AttachmentPolicy, AttachmentService, CODE_LAYOUT, CODE_REJECTED,
    CODE_UNAVAILABLE, Duration, LocalAttachmentBackend, OwnerAdmissionError, QualifiedOwner,
    ScopedGrantRegistry, WireBytes, ledger_code, now, ok, refuse,
};
use ramflux_node_core::AttachmentCheckpoint;

pub(super) fn policy() -> anyhow::Result<AttachmentPolicy> {
    let mut policy = AttachmentPolicy::default();
    for (name, value) in [
        ("RAMFLUX_RELAY_ATTACHMENT_QUOTA_BYTES", &mut policy.quota_bytes),
        ("RAMFLUX_RELAY_ATTACHMENT_MAX_PLAINTEXT_BYTES", &mut policy.max_plaintext_bytes),
        ("RAMFLUX_RELAY_ATTACHMENT_RETENTION_SECONDS", &mut policy.retention_seconds),
        ("RAMFLUX_RELAY_ATTACHMENT_PENDING_LEASE_SECONDS", &mut policy.pending_lease_seconds),
        ("RAMFLUX_RELAY_ATTACHMENT_PENDING_MAX_SECONDS", &mut policy.pending_max_seconds),
    ] {
        match ramflux_node_core::environment::var(name) {
            Ok(text) => {
                *value = text.trim().parse().map_err(|_| anyhow::anyhow!("invalid {name}"))?;
            }
            Err(std::env::VarError::NotPresent) => {}
            Err(_) => anyhow::bail!("invalid {name}"),
        }
    }
    if policy.quota_bytes == 0
        || policy.max_plaintext_bytes > AttachmentPolicy::default().max_plaintext_bytes
    {
        anyhow::bail!("attachment quota must be positive and object limit at most 4 GiB");
    }
    Ok(policy)
}

pub(super) fn account(
    registry: &ScopedGrantRegistry,
    requester: &QualifiedOwner,
) -> AttachmentMeshReply {
    match registry.account_status_after_authentication(requester) {
        Ok(status) => encode(&status),
        Err(error) => ledger_code(&error),
    }
}

pub(super) fn checkpoint(
    registry: &ScopedGrantRegistry,
    backend: &LocalAttachmentBackend,
    requester: &QualifiedOwner,
    ids: [WireBytes; 3],
    generation_and_index: (u64, u32),
    now: u64,
) -> AttachmentMeshReply {
    let [upload, object, manifest] = ids;
    let (generation, index) = generation_and_index;
    let (Ok(upload_id), Ok(object_id), Ok(manifest_hash)) =
        (upload.0.try_into(), object.0.try_into(), manifest.0.try_into())
    else {
        return refuse(CODE_LAYOUT);
    };
    let query = AttachmentCheckpoint {
        upload_id,
        object_id,
        manifest_hash,
        payload_generation: generation,
        index,
    };
    match registry.checkpoint_after_authentication(requester, &query, backend, now) {
        Ok(status) => encode(&status),
        Err(OwnerAdmissionError::Ledger(error)) => ledger_code(&error),
        Err(_) => refuse(CODE_REJECTED),
    }
}

fn encode(value: &impl serde::Serialize) -> AttachmentMeshReply {
    match serde_json::to_vec(value) {
        Ok(bytes) => ok(bytes),
        Err(_) => refuse(CODE_UNAVAILABLE),
    }
}

pub(super) fn start_cleanup(service: Arc<AttachmentService>) -> anyhow::Result<()> {
    ramflux_node_core::spawn_service_worker("attachment-cleanup", move |shutdown| {
        let mut cursor = None;
        while !shutdown.is_cancelled() {
            match service.registry.cleanup_turn(&service.backend, now(), cursor.as_deref()) {
                Ok(next) => cursor = next,
                Err(error) => tracing::warn!(%error, "attachment cleanup turn deferred"),
            }
            if !ramflux_node_core::service_shutdown_sleep(Duration::from_secs(1)) {
                break;
            }
        }
    })?;
    Ok(())
}

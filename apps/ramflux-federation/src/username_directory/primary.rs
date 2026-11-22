// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Private primary process: reconciles/fsyncs, then acknowledges exact heads to the witness.
use super::{Result, directory, error, flag, ipc, primary_peer::Peer, refuse, wire};
use std::time::Duration;

pub fn run(config: &directory::DirectoryConfig) -> Result<()> {
    let directory::DirectoryRole::Center { primary, witness } = &config.role else {
        return refuse("primary role");
    };
    ipc::self_uid(witness.center_uid)?;
    ipc::owner(
        primary.parent().ok_or_else(|| error("primary parent"))?,
        witness.center_uid,
        0o700,
        true,
    )?;
    let (peer, welcome) = Peer::connect(witness)?;
    let wire::Response::Welcome { writer, head, recovery } = welcome else {
        return refuse("witness welcome");
    };
    if head.center_id != config.center.id || head.generation != config.center.generation {
        return refuse("witness identity mismatch");
    }
    let mut projection = if primary.exists() {
        ipc::owner(primary, witness.center_uid, 0o600, false)?;
        directory::PrimaryProjection::resume(primary, writer)?
    } else {
        if !flag("--username-rebuild") || !recovery {
            return refuse("missing primary requires explicit controller recovery at both peers");
        }
        let mut projection = directory::PrimaryProjection::create(primary, writer)?;
        projection.begin_rebuild(&head)?;
        let mut cursor = None;
        loop {
            let wire::Response::Image { page } =
                peer.request(wire::Request::Image { head: head.clone(), after: cursor.take() })?
            else {
                return refuse("witness image response");
            };
            let finished = page.rows.is_empty();
            cursor.clone_from(&page.next);
            let batches = projection.copy_image_page(&head, page)?;
            for row in batches {
                let wire::Response::Batch { group } = peer.request(wire::Request::Batch {
                    head: head.clone(),
                    id: row.batch_id.clone(),
                })?
                else {
                    return refuse("witness batch response");
                };
                if group.batch.as_ref() != Some(&row) {
                    return refuse("witness batch mismatch");
                }
                projection.copy_batch_results(&row, &group.records)?;
            }
            if finished {
                break;
            }
        }
        projection.finish_rebuild(&head)?;
        projection
    };
    loop {
        if ramflux_node_core::service_shutdown_token().is_cancelled() {
            return Ok(());
        }
        let head = projection.head()?;
        let wire::Response::Group { group } =
            peer.request(wire::Request::Sync { head: head.clone() })?
        else {
            return refuse("witness replay response");
        };
        if let Some(group) = group {
            projection.apply_records(&group.records, group.batch.as_ref())?;
            continue;
        }
        let wire::Response::Ready = peer.request(wire::Request::Applied { head })? else {
            return refuse("witness applied response");
        };
        if !ramflux_node_core::service_shutdown_sleep(Duration::from_millis(100)) {
            return Ok(());
        }
    }
}

// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Authoring guards execute before parsing or signing a human operation.
use super::*;
use crate::bus::runtime_tests::{account, root};
use std::sync::{Arc, atomic::AtomicBool};
#[tokio::test(flavor = "current_thread")]
async fn every_human_task_method_rejects_headless_mode_and_nonhuman_kind_before_signing()
-> Result<(), SdkError> {
    let root = root("task-authority");
    let local = account(&root, "agent", None, Arc::new(AtomicBool::new(false)))?;
    let mut state = LocalBusDaemonState {
        config: LocalBusConfig::new(root.join("bus.sock"), &root),
        account_index: None,
        nodes: crate::node::NodeStore::default(),
        accounts: BTreeMap::from([("agent".into(), local)]),
        active_account_id: Some("agent".into()),
        attended_accounts: BTreeSet::new(),
        subscribers: BTreeMap::new(),
    };
    for (mode, kind) in [
        (LocalBusClientMode::HeadlessAi, "human"),
        (LocalBusClientMode::AttendedCli, "headless_ai"),
    ] {
        let path = local_bus_account_manifest_path(&root, "agent");
        let mut manifest = read_local_bus_account_manifest(&path)?;
        manifest.client_mode = mode;
        manifest.kind = Some(kind.into());
        write_local_bus_account_manifest(&root, &manifest)?;
        for method in ["task.start", "task.accept", "task.decline", "task.resolve", "task.cancel"] {
            let request = LocalBusFrame::request(
                method,
                Some("agent".into()),
                "task",
                method,
                serde_json::json!({}),
            );
            let result = dispatch_task(&request, &mut state).await;
            assert!(
                matches!(result,Err(SdkError::LocalBus(ref error)) if error=="task human decision requires attended human account"),
                "{method} must fail at authoring guard"
            );
        }
    }
    drop(state);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

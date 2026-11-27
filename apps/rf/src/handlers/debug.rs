// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! `rf debug mls ...`: one bus request per command, the JSON reply printed (MLS-0c).

#![allow(clippy::wildcard_imports)]
use super::*;
use crate::cli::{DebugAction, DebugCommand, MlsAction};
use serde_json::{Value, json};

pub(crate) async fn handle(socket: PathBuf, command: DebugCommand) -> Result<(), RfError> {
    let DebugAction::Mls(mls) = command.action;
    let account = mls
        .account
        .ok_or_else(|| RfError::Message("--account is required for rf debug mls".into()))?;
    let (method, body) = request(mls.action)?;
    let mut bus = LocalBusClient::connect(&socket).await?;
    let response = bus.request(Some(account), "debug", method, body).await?;
    print_json(&response)
}

/// Blob paths travel as absolute paths: the daemon runs in another directory.
fn abs(path: &std::path::Path) -> Result<String, RfError> {
    let path = std::path::absolute(path)?;
    path.into_os_string()
        .into_string()
        .map_err(|_| RfError::Message("path is not valid UTF-8".into()))
}

fn request(action: MlsAction) -> Result<(&'static str, Value), RfError> {
    Ok(match action {
        MlsAction::KeyPackage(a) => {
            let mut body = json!({ "kind": a.kind, "out_path": abs(&a.out)? });
            if let Some(tamper) = a.tamper {
                body["tamper"] = json!(tamper);
            }
            ("debug.mls.key_package", body)
        }
        MlsAction::Create(a) => {
            let mut body = json!({ "kind": a.kind });
            if let Some(tier) = a.tier {
                body["tier"] = json!(tier);
            }
            ("debug.mls.create", body)
        }
        MlsAction::Add(a) => {
            let paths =
                a.key_packages.iter().map(|path| abs(path)).collect::<Result<Vec<_>, _>>()?;
            (
                "debug.mls.add",
                json!({
                    "group_id_hex": a.group_id,
                    "key_package_paths": paths,
                    "commit_path": abs(&a.commit_out)?,
                    "welcome_path": abs(&a.welcome_out)?,
                }),
            )
        }
        MlsAction::BulkAdd(a) => (
            "debug.mls.bulk_add",
            json!({ "group_id_hex": a.group_id, "count": a.count, "batch": a.batch }),
        ),
        MlsAction::Join(a) => ("debug.mls.join", json!({ "welcome_path": abs(&a.welcome)? })),
        MlsAction::Send(a) => {
            let mut body = json!({
                "group_id_hex": a.group_id,
                "text": a.text,
                "out_path": abs(&a.out)?,
            });
            if let Some(aad) = a.aad_hex {
                body["aad_hex"] = json!(aad);
            }
            ("debug.mls.send", body)
        }
        MlsAction::Recv(a) => ("debug.mls.receive", json!({ "message_path": abs(&a.message)? })),
        MlsAction::Update(a) => {
            let mut body = json!({ "group_id_hex": a.group_id, "out_path": abs(&a.out)? });
            if let Some(tamper) = a.tamper {
                body["tamper"] = json!(tamper);
            }
            ("debug.mls.update", body)
        }
        MlsAction::Leave(a) => {
            ("debug.mls.leave", json!({ "group_id_hex": a.group_id, "out_path": abs(&a.out)? }))
        }
        MlsAction::CommitPending(a) => (
            "debug.mls.commit_pending",
            json!({ "group_id_hex": a.group_id, "out_path": abs(&a.out)? }),
        ),
        MlsAction::Remove(a) => (
            "debug.mls.remove",
            json!({ "group_id_hex": a.group_id, "leaf": a.leaf, "out_path": abs(&a.out)? }),
        ),
        MlsAction::Status(a) => match a.group_id {
            Some(group) => ("debug.mls.status", json!({ "group_id_hex": group })),
            None => ("debug.mls.status", json!({})),
        },
        MlsAction::Export(a) => (
            "debug.mls.export",
            json!({
                "group_id_hex": a.group_id,
                "label": a.label,
                "context_hex": a.context_hex,
                "len": a.len,
            }),
        ),
        MlsAction::Kat(a) => ("debug.mls.kat", json!({ "path": abs(&a.path)? })),
        MlsAction::Trust(a) => ("debug.mls.trust_pinned", json!({ "sig_pk_hex": a.sig_pk_hex })),
    })
}

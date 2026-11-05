// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Authenticated mesh point reads share the in-memory published point view.
use super::MeshResponse;
pub(super) fn reply(
    path: &str,
    state: &ramflux_node_core::RouterCore,
) -> anyhow::Result<MeshResponse> {
    let (status, value) = value(path, state)?;
    Ok(MeshResponse::json(status, serde_json::to_vec(&value)?))
}
pub(super) fn value(
    path: &str,
    state: &ramflux_node_core::RouterCore,
) -> anyhow::Result<(&'static str, serde_json::Value)> {
    let invalid = || ("400 Bad Request", serde_json::json!({"reason":"invalid_seq"}));
    let suffix =
        path.strip_prefix("/mvp1/inbox-entry/").unwrap_or("").split('?').next().unwrap_or("");
    let Some((target, seq)) = suffix.rsplit_once('/') else {
        return Ok(invalid());
    };
    let Ok(seq) = seq.parse::<u64>() else {
        return Ok(invalid());
    };
    match state.fetch_entry(target, seq, i64::try_from(ramflux_node_core::now_unix_seconds())?) {
        Ok(reply) => Ok(("200 OK", serde_json::to_value(reply)?)),
        Err(ramflux_node_core::EntryFetchError::InvalidSeq) => Ok(invalid()),
        Err(error) => Err(error.into()),
    }
}
#[cfg(test)]
mod tests {
    #[test]
    fn point_entry_mesh_contract() -> anyhow::Result<()> {
        let (state, store, path) = crate::router_runtime::tests::test_router("point-entry-mesh")?;
        let handle = crate::router_runtime::RouterHandle::tokio(state.clone(), store.clone(), None);
        let response = super::super::handle_mesh_request_value(
            ramflux_transport::MeshHttpRequest {
                method: "POST".into(),
                path: "/mvp0/envelope".into(),
                body: serde_json::to_vec(&crate::router_runtime::tests::current_envelope(
                    "entry-fetch",
                    "point-target",
                )?)?,
            },
            &handle,
            "ramflux-gateway",
        )?;
        let response: ramflux_node_core::EnvelopeSubmitResponse =
            serde_json::from_slice(&response.body)?;
        anyhow::ensure!(response.inbox_seq == Some(1));
        for (suffix, status) in [
            ("point-target/1", "200 OK"),
            ("point-target/0", "400 Bad Request"),
            ("point-target/2", "400 Bad Request"),
            ("unknown/1", "400 Bad Request"),
        ] {
            let response = super::super::handle_mesh_request_value(
                ramflux_transport::MeshHttpRequest {
                    method: "GET".into(),
                    path: format!("/mvp1/inbox-entry/{suffix}"),
                    body: Vec::new(),
                },
                &handle,
                "ramflux-gateway",
            )?;
            assert_eq!(response.status, status);
            let body: serde_json::Value = serde_json::from_slice(&response.body)?;
            if status == "200 OK" {
                assert_eq!(body["frame_type"], "entry");
                assert_eq!(body["record"]["entry"]["inbox_seq"], 1);
            } else {
                assert_eq!(body, serde_json::json!({"reason":"invalid_seq"}));
            }
        }
        assert_eq!(store.inbox_status("unknown")?, (None, 0));
        drop(handle);
        drop(store);
        drop(state);
        std::fs::remove_file(path)?;
        Ok(())
    }
}

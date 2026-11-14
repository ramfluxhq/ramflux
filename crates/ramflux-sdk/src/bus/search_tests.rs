// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Real supervisor ingress must refuse before even looking up the requested account.
use super::{state::LocalBusConnectionState, supervisor::Supervisor};
use crate::{LocalBusConfig, LocalBusFrame, SdkError};
use ramflux_storage::local_search::SearchError;

#[tokio::test(flavor = "current_thread")]
async fn local_search_generation_zero_ingress_is_inert() -> Result<(), Box<dyn std::error::Error>> {
    tokio::task::LocalSet::new()
        .run_until(tokio::time::timeout(std::time::Duration::from_secs(10), async {
            let directory = tempfile::TempDir::new()?;
            let supervisor = Supervisor::new(LocalBusConfig::new(
                directory.path().join("bus.sock"),
                directory.path(),
            ))?;
            let (outbound, _receive) = tokio::sync::mpsc::channel(1);
            let connection = LocalBusConnectionState::new(42, outbound);
            for method in ["search.query", "search.index.rebuild"] {
                let mut request = LocalBusFrame::request(
                    "request",
                    Some("account-that-must-not-be-opened".into()),
                    "ramflux.sdk.v1",
                    method,
                    serde_json::json!({"query":"secretcanary"}),
                );
                request.operation_id = Some("must-not-create-receipt".into());
                assert!(
                    matches!(
                        supervisor.request(request, &connection).await,
                        Err(SdkError::Search(SearchError::NotActivated))
                    ),
                    "disabled search must refuse before account lookup or receipt admission"
                );
            }
            let request = LocalBusFrame::request(
                "status",
                Some("account-that-must-not-be-opened".into()),
                "ramflux.sdk.v1",
                "search.index.status",
                serde_json::json!({}),
            );
            let response = supervisor.request(request, &connection).await?;
            assert_eq!(
                response.body.get("coverage").and_then(serde_json::Value::as_str),
                Some("disabled"),
                "disabled status must come from capability state"
            );
            assert!(
                !directory.path().join("accounts").exists(),
                "disabled ingress must not create an account database tree"
            );
            Ok::<_, Box<dyn std::error::Error>>(())
        }))
        .await??;
    Ok(())
}

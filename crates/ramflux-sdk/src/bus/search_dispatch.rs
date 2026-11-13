// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Shared search dispatch owns account/client scope and final reply publication.
use super::{actor::ActorResponse, state::LocalBusConnectionState, supervisor::Supervisor};
use crate::prelude::*;
use crate::search::{SearchError, SearchQuery};

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Control {
    request_id: Option<String>,
    cursor: Option<crate::search::SearchText>,
    job_id: Option<String>,
}
impl Supervisor {
    pub(super) async fn search_request(
        &self,
        request: LocalBusFrame,
        connection: &LocalBusConnectionState,
    ) -> Result<ActorResponse, SdkError> {
        let request = SecretRequest(request);
        let id = request_account_id(&request)?.to_owned();
        let actor = self.search_actor(&id)?;
        let pool = actor.reader_pool()?;
        let runtime = pool.search_runtime()?;
        let owner = connection.connection_id;
        let body = match request.method.as_str() {
            "search.query" => {
                let query: SearchQuery = serde_json::from_value(request.body.clone())
                    .map_err(|_| SearchError::InvalidQuery)?;
                // Correlation-only identity is preserved, never replaced by an operation receipt.
                query.validate()?;
                pool.search_query(owner, query).await?
            }
            "search.index.status" => pool.search_status().await?,
            "search.cancel" | "search.cursor.close" | "search.index.rebuild.cancel" => {
                let control: Control = serde_json::from_value(request.body.clone())
                    .map_err(|_| SearchError::InvalidQuery)?;
                match request.method.as_str() {
                    "search.cursor.close" => {
                        let token = control.cursor.ok_or(SearchError::InvalidQuery)?;
                        runtime.close_cursor(owner, token.expose());
                    }
                    "search.cancel" => {
                        let id = control.request_id.ok_or(SearchError::InvalidQuery)?;
                        if id.len() > 128 {
                            return Err(SearchError::InvalidQuery.into());
                        }
                        runtime.cancel(owner, &id);
                    }
                    _ => {
                        let id = control.job_id.ok_or(SearchError::InvalidQuery)?;
                        runtime.cancel_rebuild(owner, &id);
                    }
                }
                serde_json::json!({"released":true})
            }
            "search.index.rebuild" => {
                let control: Control = serde_json::from_value(request.body.clone())
                    .map_err(|_| SearchError::InvalidQuery)?;
                let job = control.job_id.ok_or(SearchError::InvalidQuery)?;
                let cancelled = runtime.start_rebuild(owner, &job)?;
                let response = serde_json::json!({"job_id":job,"state":"building"});
                self.spawn_search_rebuild(actor, runtime, owner, job, cancelled);
                response
            }
            _ => return Err(SearchError::InvalidQuery.into()),
        };
        Ok(ActorResponse { body, events: Vec::new(), nodes: None })
    }
    pub(super) fn resolve_search_completion(
        &self,
        frame: &LocalBusFrame,
        owner: u64,
    ) -> Result<crate::search::SearchCompletion, SdkError> {
        let token = frame
            .body
            .get("search_completion")
            .and_then(serde_json::Value::as_str)
            .ok_or(SearchError::CursorStale)?;
        if token.len() != 43 {
            return Err(SearchError::CursorStale.into());
        }
        self.search_actor(request_account_id(frame)?)?
            .reader_pool()?
            .search_runtime()?
            .take_completion(owner, token)
    }
    pub(super) fn search_disconnect(&self, owner: u64) {
        for actor in self.search_actors() {
            if let Ok(pool) = actor.reader_pool()
                && let Ok(runtime) = pool.search_runtime()
            {
                runtime.disconnect(owner);
            }
        }
    }
}

struct SecretRequest(LocalBusFrame);
impl std::ops::Deref for SecretRequest {
    type Target = LocalBusFrame;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
impl Drop for SecretRequest {
    fn drop(&mut self) {
        super::secrets::wipe(&mut self.0.body);
    }
}

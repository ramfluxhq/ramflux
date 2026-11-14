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
    unlock_epoch: Option<String>,
}
impl Supervisor {
    pub(super) async fn search_request(
        &self,
        request: LocalBusFrame,
        connection: &LocalBusConnectionState,
    ) -> Result<ActorResponse, SdkError> {
        let request = SecretRequest(request);
        let id = request_account_id(&request)?.to_owned();
        if id.is_empty()
            || id.len() > 256
            || request.request_id.is_empty()
            || request.request_id.len() > 128
        {
            return Err(SearchError::InvalidQuery.into());
        }
        let actor = self.search_actor(&id)?;
        let pool = actor.reader_pool()?;
        let runtime = pool.search_runtime()?;
        let owner = connection.connection_id;
        let body = match request.method.as_str() {
            "search.query" => {
                validate_query_body(&request.body)?;
                let query: SearchQuery = serde_json::from_value(request.body.clone())
                    .map_err(|_| SearchError::InvalidQuery)?;
                // Correlation-only identity is preserved, never replaced by an operation receipt.
                query.validate()?;
                pool.search_query(owner, query).await?
            }
            "search.index.status" => {
                if request.body.as_object().is_none_or(|body| !body.is_empty()) {
                    return Err(SearchError::InvalidQuery.into());
                }
                pool.search_status().await?
            }
            "search.cancel" | "search.cursor.close" | "search.index.rebuild.cancel" => {
                validate_control_body(&request.body)?;
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
                        let epoch = counter(control.unlock_epoch.as_deref())?;
                        runtime.cancel(owner, epoch, &id)?;
                    }
                    _ => {
                        let id = control.job_id.ok_or(SearchError::InvalidQuery)?;
                        let epoch = counter(control.unlock_epoch.as_deref())?;
                        if epoch != runtime.unlock_epoch() {
                            return Err(SearchError::CursorStale.into());
                        }
                        runtime.cancel_rebuild(owner, epoch, &id)?;
                    }
                }
                serde_json::json!({"released":true})
            }
            "search.index.rebuild" => {
                validate_control_body(&request.body)?;
                let control: Control = serde_json::from_value(request.body.clone())
                    .map_err(|_| SearchError::InvalidQuery)?;
                let job = control.job_id.ok_or(SearchError::InvalidQuery)?;
                let cancelled = runtime.start_rebuild(owner, &job)?;
                let response = serde_json::json!({"job_id":job,"state":"queued","unlock_epoch":runtime.unlock_epoch().to_string()});
                self.spawn_search_rebuild(actor, runtime, owner, cancelled);
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

fn counter(value: Option<&str>) -> Result<u64, SdkError> {
    let value = value.ok_or(SearchError::InvalidQuery)?;
    if value.is_empty()
        || value.len() > 20
        || !value.bytes().all(|byte| byte.is_ascii_digit())
        || value.len() > 1 && value.starts_with('0')
    {
        return Err(SearchError::InvalidQuery.into());
    }
    value.parse().map_err(|_| SearchError::InvalidQuery.into())
}

fn validate_query_body(value: &serde_json::Value) -> Result<(), SdkError> {
    let object = value.as_object().ok_or(SearchError::InvalidQuery)?;
    if object.len() > 7
        || object.keys().any(|key| {
            !matches!(
                key.as_str(),
                "request_id"
                    | "query"
                    | "kinds"
                    | "conversation_id"
                    | "limit"
                    | "cursor"
                    | "include_snippets"
            )
        })
    {
        return Err(SearchError::InvalidQuery.into());
    }
    for (key, max, required) in [
        ("request_id", 128, true),
        ("query", 1024, true),
        ("conversation_id", 256, false),
        ("cursor", 128, false),
    ] {
        match object.get(key) {
            Some(serde_json::Value::String(text)) if !text.is_empty() && text.len() <= max => {}
            None | Some(serde_json::Value::Null) if !required => {}
            _ => return Err(SearchError::InvalidQuery.into()),
        }
    }
    if let Some(kinds) = object.get("kinds") {
        let kinds = kinds.as_array().ok_or(SearchError::InvalidQuery)?;
        if kinds.is_empty()
            || kinds.len() > 3
            || kinds.iter().any(|kind| kind.as_str().is_none_or(|kind| kind.len() > 16))
        {
            return Err(SearchError::InvalidQuery.into());
        }
    }
    Ok(())
}
fn validate_control_body(value: &serde_json::Value) -> Result<(), SdkError> {
    let object = value.as_object().ok_or(SearchError::InvalidQuery)?;
    if object.len() > 4
        || object.iter().any(|(key, value)| {
            !matches!(key.as_str(), "request_id" | "cursor" | "job_id" | "unlock_epoch")
                || !value.is_null()
                    && value.as_str().is_none_or(|value| value.is_empty() || value.len() > 128)
        })
    {
        return Err(SearchError::InvalidQuery.into());
    }
    Ok(())
}

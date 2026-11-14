// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Query admission happens before the existing reader queue; controls never enter that queue.
use super::{AccountReaders, ReadCommand, ReaderIdentity, closed, local};
use crate::search::{LocalSearch, SearchError, SearchQuery};
use crate::{RamfluxClient, SdkError};
use std::sync::{Arc, RwLock};
use tokio::sync::oneshot;

pub(in crate::bus) enum Work {
    Query { owner: u64, request: Box<SearchQuery>, admission: crate::search::admission::Admission },
    Status,
}
struct QueryCancellation {
    runtime: Arc<LocalSearch>,
    owner: u64,
    id: String,
    armed: bool,
}
impl Drop for QueryCancellation {
    fn drop(&mut self) {
        if self.armed {
            let _ = self.runtime.cancel(self.owner, self.runtime.unlock_epoch(), &self.id);
        }
    }
}

impl AccountReaders {
    pub(in crate::bus) fn search_runtime(&self) -> Result<Arc<LocalSearch>, SdkError> {
        self.search.clone().ok_or_else(|| SearchError::IndexUnavailable.into())
    }
    pub(in crate::bus) async fn search_query(
        &self,
        owner: u64,
        request: SearchQuery,
    ) -> Result<serde_json::Value, SdkError> {
        request.validate()?;
        let runtime = self.search_runtime()?;
        let admission = runtime.admit(owner, &request.request_id).await?;
        let mut cancellation =
            QueryCancellation { runtime, owner, id: request.request_id.clone(), armed: true };
        let (reply, result) = oneshot::channel();
        self.enqueue(ReadCommand::Search(
            Work::Query { owner, request: Box::new(request), admission },
            reply,
        ))?;
        let body = result.await.map_err(|_| closed())??;
        cancellation.armed = false;
        Ok(body)
    }
    pub(in crate::bus) async fn search_status(&self) -> Result<serde_json::Value, SdkError> {
        let (reply, result) = oneshot::channel();
        self.enqueue(ReadCommand::Search(Work::Status, reply))?;
        result.await.map_err(|_| closed())?
    }
}

pub(super) fn execute(
    client: &mut RamfluxClient,
    identity: &ReaderIdentity,
    view: &Arc<RwLock<Arc<local::AccountView>>>,
    runtime: Option<&Arc<LocalSearch>>,
    work: Work,
) -> Result<serde_json::Value, SdkError> {
    let runtime = runtime.ok_or(SearchError::IndexUnavailable)?;
    client.reader_device_identity.clone_from(&*identity.read().map_err(|_| closed())?);
    let view = Arc::clone(&*view.read().map_err(|_| closed())?);
    client.born_v3_account.clone_from(&view.native);
    client.reader_account_root.clone_from(&view.account_root);
    match work {
        Work::Query { owner, request, admission } => {
            let completion = runtime.execute_query(client, owner, &request, admission)?;
            runtime.queue_completion(owner, completion)
        }
        Work::Status => Ok(serde_json::to_value(runtime.index_status(client)?)?),
    }
}

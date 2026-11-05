// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Directory work for sibling backfill and requested contact safety refresh.

use crate::bus::connection_manager::{AccountWork, SessionContext};
use crate::{GatewaySessionConfig, SdkDeviceManifestResponse, SdkError};
use std::{sync::Arc, time::Duration};
use tokio::sync::{Mutex, mpsc, oneshot};

#[derive(Clone, Copy, Debug)]
pub(crate) enum BackfillKind {
    Own,
    Peer,
}
pub(crate) struct BackfillPlan {
    pub kind: BackfillKind,
    pub root: String,
    pub config: GatewaySessionConfig,
    pub checkpoint_key: &'static str,
    pub checkpoint: serde_json::Value,
}
pub(crate) struct SafetyPlan {
    pub peer: String,
    pub own: String,
    pub config: GatewaySessionConfig,
    pub link: serde_json::Value,
}
pub(crate) enum DirectoryWork {
    HeadRefresh(super::head_refresh::Work),
    PrepareBackfill {
        generation: u64,
        reply: oneshot::Sender<Result<Option<BackfillPlan>, SdkError>>,
    },
    ApplyBackfill {
        generation: u64,
        plan: Box<BackfillPlan>,
        outcome: Result<SdkDeviceManifestResponse, SdkError>,
        reply: oneshot::Sender<Result<(), SdkError>>,
    },
    PrepareSafety {
        generation: u64,
        root: String,
        reply: oneshot::Sender<Result<Option<SafetyPlan>, SdkError>>,
    },
    ApplySafety {
        generation: u64,
        plan: Box<SafetyPlan>,
        own: Box<SdkDeviceManifestResponse>,
        peer: SdkDeviceManifestResponse,
        reply: oneshot::Sender<Result<(), SdkError>>,
    },
}
const ATTEMPT: Duration = Duration::from_secs(5);

pub(crate) async fn backfill(context: SessionContext, writer: mpsc::Sender<AccountWork>) {
    let mut cancel = context.cancel.clone();
    loop {
        let pass = backfill_pass(context.generation, &writer);
        let result = tokio::select! {biased;_=cancel.changed()=>break,result=pass=>result};
        let failed = result.is_err();
        if let Err(error) = result {
            tracing::debug!(%error,"own-contact backfill deferred");
        }
        tokio::select! {
            biased;
            _=cancel.changed()=>break,
            ()=tokio::time::sleep(ATTEMPT)=>{},
            ()=context.courier_wake("own-contact-backfill"),if !failed=>{},
        }
    }
}
async fn backfill_pass(
    generation: u64,
    writer: &mpsc::Sender<AccountWork>,
) -> Result<(), SdkError> {
    let (reply, response) = oneshot::channel();
    writer
        .send(AccountWork::Directory(Box::new(DirectoryWork::PrepareBackfill {
            generation,
            reply,
        })))
        .await
        .map_err(|_| stopped())?;
    let Some(plan) = response.await.map_err(|_| stopped())?? else {
        return Ok(());
    };
    let outcome = fetch(&plan.config, &plan.root).await;
    let (reply, response) = oneshot::channel();
    writer
        .send(AccountWork::Directory(Box::new(DirectoryWork::ApplyBackfill {
            generation,
            plan: Box::new(plan),
            outcome,
            reply,
        })))
        .await
        .map_err(|_| stopped())?;
    response.await.map_err(|_| stopped())?
}

pub(crate) async fn safety(
    mut context: SessionContext,
    writer: mpsc::Sender<AccountWork>,
    requests: Arc<Mutex<mpsc::Receiver<String>>>,
) {
    loop {
        let root = tokio::select! {biased;_=context.cancel.changed()=>break,root=async {requests.lock().await.recv().await}=>root};
        let Some(root) = root else {
            break;
        };
        let pass = safety_pass(context.generation, &writer, root);
        let result = tokio::select! {biased;_=context.cancel.changed()=>break,result=pass=>result};
        if let Err(error) = result {
            tracing::debug!(%error,"contact safety refresh deferred");
        }
        tokio::select! {biased;_=context.cancel.changed()=>break,()=tokio::time::sleep(ATTEMPT)=>{}}
    }
}
async fn safety_pass(
    generation: u64,
    writer: &mpsc::Sender<AccountWork>,
    root: String,
) -> Result<(), SdkError> {
    let (reply, response) = oneshot::channel();
    writer
        .send(AccountWork::Directory(Box::new(DirectoryWork::PrepareSafety {
            generation,
            root,
            reply,
        })))
        .await
        .map_err(|_| stopped())?;
    let Some(plan) = response.await.map_err(|_| stopped())?? else {
        return Ok(());
    };
    let own = fetch(&plan.config, &plan.own).await?;
    let peer = fetch(&plan.config, &plan.peer).await?;
    let (reply, response) = oneshot::channel();
    writer
        .send(AccountWork::Directory(Box::new(DirectoryWork::ApplySafety {
            generation,
            plan: Box::new(plan),
            own: Box::new(own),
            peer,
            reply,
        })))
        .await
        .map_err(|_| stopped())?;
    response.await.map_err(|_| stopped())?
}
pub(super) async fn fetch(
    config: &GatewaySessionConfig,
    root: &str,
) -> Result<SdkDeviceManifestResponse, SdkError> {
    tokio::time::timeout(ATTEMPT, async {
        crate::prekey::sdk_gateway_get_json::<Option<SdkDeviceManifestResponse>>(
            config,
            &format!("/mvp1/device-manifest/{root}"),
        )
        .await?
        .ok_or_else(|| SdkError::InboundPending("directory response unavailable".into()))
    })
    .await
    .map_err(|_| SdkError::NodeTimeout { retry_after_ms: 5_000 })?
}
fn stopped() -> SdkError {
    ramflux_transport::TransportError::ShutdownDraining.into()
}

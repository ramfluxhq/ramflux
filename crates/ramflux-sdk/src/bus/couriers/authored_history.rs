// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Own-authored sibling attestations use the same actor/network split as received history.
use super::writer::Writer;
use crate::SdkError;
use crate::bus::connection_manager::{CallClass, SessionContext};
use crate::client::routed::{SendMaterial, SendMaterialRequest};

pub(crate) async fn pass(context: SessionContext, writer: Writer) -> Result<bool, SdkError> {
    let prepared = writer
        .apply(|account| {
            let config = account.gateway_config.clone();
            Ok(account.client.prepare_authored_history(&config)?.map(|plan| (config, plan)))
        })
        .await?;
    let Some((config, mut plan)) = prepared else { return Ok(false) };
    let material = if plan.envelope.is_some() {
        SendMaterial { manifest: None, bundle: None }
    } else {
        let request =
            std::mem::replace(&mut plan.request, SendMaterialRequest { root: None, prekey: None });
        super::pair_material::fetch(&context, &config, request, CallClass::Bulk).await?
    };
    let sealed = writer
        .apply(move |account| account.client.seal_authored_history(&config, plan, material))
        .await?;
    let Some((plan, envelope)) = sealed else { return Ok(true) };
    context
        .call(
            move |engine| {
                Box::pin(async move {
                    engine.submit_envelope(envelope).await?;
                    Ok(())
                })
            },
            context.call_deadline(),
        )
        .await?;
    writer.apply(move |account| account.client.complete_authored_history(&plan)).await?;
    Ok(true)
}

#[cfg(test)]
pub(crate) async fn drive_once(
    account: &mut crate::prelude::LocalBusAccountState,
) -> Result<bool, SdkError> {
    account.client.stage_authored_history()?;
    if account.client.account_db()?.actor_state_usage("own-history/pending/")?.0 == 0 {
        return Ok(false);
    }
    let client = account.session_client().await?;
    account.apply_session_metadata(client);
    let context =
        account.connection.as_ref().ok_or(SdkError::GatewaySessionNotEstablished)?.test_context();
    let (sender, mut work) = tokio::sync::mpsc::channel(2);
    let writer = Writer::new(sender, context.generation);
    let future = pass(context, writer);
    tokio::pin!(future);
    loop {
        tokio::select! {
            result = &mut future => return result,
            work = work.recv() => {
                let Some(crate::bus::connection_manager::AccountWork::Courier(checkpoint)) = work else {
                    return Err(SdkError::GatewaySessionNotEstablished);
                };
                checkpoint.apply(account);
            }
        }
    }
}

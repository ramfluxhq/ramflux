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

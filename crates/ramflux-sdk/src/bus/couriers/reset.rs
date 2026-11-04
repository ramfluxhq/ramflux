// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Pair reset retry is independent of receive deadlines and owns no database.

use super::writer::Writer;
use crate::bus::connection_manager::{SessionClient, SessionContext};
use crate::client::routed::{PairControlDraft, SendMaterial, SendMaterialRequest};
use crate::prelude::*;

pub(crate) async fn receive_failure(
    writer: &Writer,
    config: &GatewaySessionConfig,
    entry: &GatewayInboxEntry,
    error: &SdkError,
) -> Result<(), SdkError> {
    if !matches!(
        error,
        SdkError::PairRecoveryRequired
            | SdkError::Crypto(ramflux_crypto::CryptoError::MaxSkipExceeded)
    ) {
        return Ok(());
    }
    let config = config.clone();
    let entry = entry.clone();
    let plan = writer
        .apply(move |account| {
            let draft = account.client.prepare_pair_recovery_draft(&config, &entry)?;
            plan(account, draft)
        })
        .await?;
    if let Some(plan) = plan {
        send(writer, plan).await?;
    }
    Ok(())
}

pub(crate) async fn pass(_: SessionContext, writer: Writer) -> Result<bool, SdkError> {
    let prepared = writer
        .apply(|account| {
            let draft = account
                .client
                .prepare_due_pair_reset(&account.gateway_config, now_unix_timestamp())?;
            plan(account, draft)
        })
        .await?;
    if let Some(prepared) = prepared {
        send(&writer, prepared).await?;
        Ok(true)
    } else {
        Ok(false)
    }
}
struct Plan {
    draft: PairControlDraft,
    request: SendMaterialRequest,
    session: SessionClient,
}
fn plan(
    account: &LocalBusAccountState,
    draft: Option<PairControlDraft>,
) -> Result<Option<Plan>, SdkError> {
    draft
        .map(|draft| {
            let session = account.live_session_client()?;
            let request = account.client.pair_control_material_request(session.config(), &draft)?;
            Ok(Plan { draft, request, session })
        })
        .transpose()
}
async fn send(writer: &Writer, mut plan: Plan) -> Result<(), SdkError> {
    let manifest = if let Some(root) = plan.request.root {
        Some((
            root.clone(),
            crate::client::contact::fetch_verified_device_manifest(plan.session.config(), &root)
                .await?,
        ))
    } else {
        None
    };
    let bundle =
        if let Some(lookup) = plan.request.prekey {
            Some(
                plan.session.fetch_prekey_bundle(&lookup).await?.bundle.ok_or_else(|| {
                    SdkError::InboundPending("recipient prekey unavailable".into())
                })?,
            )
        } else {
            None
        };
    let config = plan.session.config().clone();
    let draft = plan.draft;
    let envelope = writer
        .apply(move |account| {
            account.client.seal_pair_control_prepared(
                &config,
                draft,
                SendMaterial { manifest, bundle },
            )
        })
        .await?;
    if let Some(envelope) = envelope {
        plan.session.submit_envelope(envelope).await?;
    }
    Ok(())
}

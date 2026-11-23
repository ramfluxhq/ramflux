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
            let config = account.sealing_config()?;
            let draft = account.client.prepare_due_pair_reset(&config, now_unix_timestamp())?;
            plan(account, draft)
        })
        .await;
    // A cold head is not a courier failure. An error skips the wake for the
    // whole network wait, so the directory refresh could not restart this pass.
    let prepared = match prepared {
        Ok(prepared) => prepared,
        Err(SdkError::FreshHeadRequired { .. }) => return Ok(false),
        Err(error) => return Err(error),
    };
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
    /// The reset the draft belongs to; a refusal applies only while it is still current.
    submitted: Option<serde_json::Value>,
}
fn plan(
    account: &LocalBusAccountState,
    draft: Option<PairControlDraft>,
) -> Result<Option<Plan>, SdkError> {
    draft
        .map(|draft| {
            let session = account.live_session_client()?;
            let request = account.client.pair_control_material_request(session.config(), &draft)?;
            let local = account.client.local_device_identity(&session.config().device_id)?;
            let submitted = account.client.pair_reset_fingerprint(&local, draft.remote())?;
            Ok(Plan { draft, request, session, submitted })
        })
        .transpose()
}
async fn send(writer: &Writer, mut plan: Plan) -> Result<(), SdkError> {
    let root = plan.request.root.clone();
    let origin = match root.as_deref() {
        Some(root) => {
            let owned = root.to_owned();
            Some(writer.apply(move |account| account.client.pinned_manifest_origin(&owned)).await?)
        }
        None => None,
    };
    let manifest = match (root.as_deref(), origin.clone()) {
        (Some(root), Some(origin)) => Some((
            root.to_owned(),
            crate::client::foreign_manifest::fetch_sender_manifest(
                plan.session.config(),
                origin,
                root,
            )
            .await?,
        )),
        _ => None,
    };
    let bundle = match plan.request.prekey.clone() {
        Some(lookup) => Some(reset_prekey(&mut plan, origin.as_ref(), &lookup).await?),
        None => None,
    };
    let sealing = plan.session.sealing_config()?;
    let (remote, kind) = (plan.draft.remote().clone(), plan.draft.kind());
    let submitted = plan.submitted.clone();
    let draft = plan.draft;
    let envelope = writer
        .apply(move |account| {
            account.client.seal_pair_control_prepared(
                &sealing,
                draft,
                SendMaterial { manifest, bundle },
            )
        })
        .await?;
    if let Some(envelope) = envelope {
        // A certain gateway refusal is applied by the actor; anything else stays uncertain.
        if let Err(refusal) = plan.session.submit_envelope_classified(envelope).await? {
            let config = plan.session.config().clone();
            return Err(writer
                .apply(move |account| {
                    let local = account.client.local_device_identity(&config.device_id)?;
                    account.client.pair_control_refused(
                        &local,
                        &remote,
                        kind,
                        refusal,
                        submitted.as_ref(),
                    )
                })
                .await?);
        }
    }
    Ok(())
}

async fn reset_prekey(
    plan: &mut Plan,
    origin: Option<&crate::client::foreign_manifest::SenderManifestOrigin>,
    lookup: &str,
) -> Result<ramflux_crypto::PrekeyBundle, SdkError> {
    if let Some(crate::client::foreign_manifest::SenderManifestOrigin::Remote {
        home,
        fingerprint,
    }) = origin
    {
        let base = crate::client::recipient_home::public_prekey_base(home, fingerprint).await?;
        return crate::prekey::http_async::get::<crate::prekey::SdkPrekeyResponse>(
            &base,
            &format!("/mvp1/prekey/{lookup}"),
            plan.session.config().timeout,
        )
        .await?
        .bundle
        .ok_or_else(|| SdkError::InboundPending("recipient prekey unavailable".into()));
    }
    plan.session
        .fetch_prekey_bundle(lookup)
        .await?
        .bundle
        .ok_or_else(|| SdkError::InboundPending("recipient prekey unavailable".into()))
}

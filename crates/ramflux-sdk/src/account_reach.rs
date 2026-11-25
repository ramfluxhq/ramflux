// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Live reach reads and primary-authorized changes; cached floors grant no admission.
use crate::{
    SdkError,
    gateway::GatewaySessionConfig,
    username_directory::{self as directory, UsernameConnection},
};
use ramflux_protocol::{
    account_reach::{ReachChange, ReachMode, ReachPolicyBody, ReachRecord, ReachState},
    custody::object_hash,
    username_directory as w,
};
use ramflux_storage::AccountDb;

/// Local marker written by a restore import: the archived floor must not be exported or signed
/// from until a live home read has been observed (see `apply`).
fn sync_key(anchor: &str) -> String {
    format!("reach/sync/{anchor}")
}

pub(crate) fn sync_pending(db: &AccountDb, anchor: &str) -> Result<bool, SdkError> {
    Ok(db.load_actor_state::<bool>(&sync_key(anchor))?.unwrap_or(false))
}

/// Typed transient refusal: the client retries after the hint, and the home read clears it.
pub(crate) fn sync_refusal() -> SdkError {
    SdkError::NetworkingPendingContext {
        retry_after_ms: Some(2_000),
        networking: Box::new(serde_json::json!({"phase":"pending","reason":"reach_sync"})),
    }
}

pub(crate) fn observe(db: &AccountDb, record: &ReachRecord, root: &str) -> Result<(), SdkError> {
    ramflux_crypto::account_reach::verify_reach_policy(&record.policy, &record.authority)?;
    if record.policy.body.account_anchor != root {
        return Err(w::DirectoryCode::OwnershipMismatch.into());
    }
    db.observe_account_reach(record)?;
    Ok(())
}

fn state(result: &directory::UsernameNetworkReply) -> Result<&ReachState, SdkError> {
    let w::NativeUsernameReply::Reach { state } = &result.reply else {
        return Err(w::DirectoryCode::DirectoryUnavailable.into());
    };
    let first = state.history.predecessors.first().unwrap_or(&state.history.home);
    if !matches!(first.record, ramflux_protocol::home_migration::HomeRecord::Genesis { .. }) {
        return Err(w::DirectoryCode::MigrationRequired.into());
    }
    let home = ramflux_crypto::home_migration::verify_home_chain(
        &state.history,
        first,
        crate::custody::network_now()?,
    )?;
    if home.home().0 != result.own_home
        || home.evidence().record.account_anchor() != result.own_record.body.account_anchor
    {
        return Err(w::DirectoryCode::OwnershipMismatch.into());
    }
    if let Some(policy) = &state.policy {
        ramflux_crypto::account_reach::verify_reach_policy(policy, &state.authority)?;
        if policy.body.account_anchor != result.own_record.body.account_anchor {
            return Err(w::DirectoryCode::OwnershipMismatch.into());
        }
    }
    Ok(state)
}

pub(crate) async fn exchange(
    config: &GatewaySessionConfig,
    transport: &UsernameConnection,
    pin: w::NativeDirectoryPin,
    change: Option<ReachChange>,
    deadline: tokio::time::Instant,
) -> Result<directory::UsernameNetworkReply, SdkError> {
    let mut current = directory::exchange_username(
        config,
        transport,
        pin.clone(),
        w::NativeUsernameAction::ReachGet,
        deadline,
    )
    .await?;
    if state(&current)?.policy.is_none() {
        require_primary_device(config)?;
        current = submit(
            config,
            transport,
            &pin,
            &current,
            ReachChange {
                mode: ReachMode::ContactsOnly,
                expected_revision: 0,
                operation_id: ramflux_crypto::blake3_256_base64url(
                    "ramflux.account.reach.initialize.v1",
                    current.own_record.body.account_anchor.as_bytes(),
                ),
            },
            deadline,
        )
        .await?;
    }
    match change {
        Some(change) => submit(config, transport, &pin, &current, change, deadline).await,
        None => Ok(current),
    }
}

/// Reach initialisation is a primary-only write. A secondary device waits with a typed retry
/// hint until the primary has initialised the policy, instead of submitting a refused change.
fn require_primary_device(config: &GatewaySessionConfig) -> Result<(), SdkError> {
    let custody = config.custody.as_ref().ok_or(SdkError::NetworkingPending)?;
    let account = crate::custody::load_account(
        &custody.account_root,
        &custody.account_id,
        crate::custody::network_now()?,
    )?;
    let primary = &account.record().body.master_certificate.body.primary_device_ref;
    if account.local_device_id()? == primary.device_id.as_str() {
        return Ok(());
    }
    Err(SdkError::NetworkingPendingContext {
        retry_after_ms: Some(2_000),
        networking: Box::new(
            serde_json::json!({"phase":"pending","reason":"reach_requires_primary"}),
        ),
    })
}

/// Resend a journaled reach intent only after a live home read decides what it still means:
/// - the home already holds a policy with the intent's operation id: the operation committed
///   (possibly as bytes re-signed on newer heads), so the read is the result and `settle`
///   drops the intent;
/// - the intent was signed on the current authority and home heads: resend its exact bytes;
/// - a head moved (device added or removed, home migrated): sign the same mode,
///   expected revision and operation id on the current heads and send that. The journal keeps
///   the original intent; a later retry repeats this decision, and Ed25519 signing of the same
///   body yields the same bytes, so the home's operation dedupe still applies.
///
/// A stale expected revision is answered by the home as a conflict, which also drops the
/// intent, so no stored change is resubmitted forever.
pub(crate) async fn resubmit(
    config: &GatewaySessionConfig,
    transport: &UsernameConnection,
    pin: &w::NativeDirectoryPin,
    intent: &ramflux_protocol::account_reach::ReachPolicy,
    deadline: tokio::time::Instant,
) -> Result<directory::UsernameNetworkReply, SdkError> {
    let current = directory::exchange_username(
        config,
        transport,
        pin.clone(),
        w::NativeUsernameAction::ReachGet,
        deadline,
    )
    .await?;
    let view = state(&current)?;
    if view
        .policy
        .as_ref()
        .is_some_and(|policy| policy.body.operation_id == intent.body.operation_id)
    {
        return Ok(current);
    }
    let first = view.history.predecessors.first().unwrap_or(&view.history.home);
    let home = ramflux_crypto::home_migration::verify_home_chain(
        &view.history,
        first,
        crate::custody::network_now()?,
    )?;
    if intent.body.home_head_hash == home.hash()
        && intent.body.authority_head_hash == object_hash(&current.own_record)?
    {
        return directory::exchange_username(
            config,
            transport,
            pin.clone(),
            w::NativeUsernameAction::ReachSet { policy: Box::new(intent.clone()) },
            deadline,
        )
        .await;
    }
    let change = ReachChange {
        mode: intent.body.mode,
        expected_revision: intent.body.expected_revision,
        operation_id: intent.body.operation_id.clone(),
    };
    submit(config, transport, pin, &current, change, deadline).await
}

async fn submit(
    config: &GatewaySessionConfig,
    transport: &UsernameConnection,
    pin: &w::NativeDirectoryPin,
    current: &directory::UsernameNetworkReply,
    change: ReachChange,
    deadline: tokio::time::Instant,
) -> Result<directory::UsernameNetworkReply, SdkError> {
    let view = state(current)?;
    let first = view.history.predecessors.first().unwrap_or(&view.history.home);
    let home = ramflux_crypto::home_migration::verify_home_chain(
        &view.history,
        first,
        crate::custody::network_now()?,
    )?;
    let body = ReachPolicyBody {
        version: 1,
        account_anchor: current.own_record.body.account_anchor.clone(),
        home_head_hash: home.hash().into(),
        authority_head_hash: object_hash(&current.own_record)?,
        revision: change.expected_revision.checked_add(1).ok_or(w::DirectoryCode::Capacity)?,
        expected_revision: change.expected_revision,
        operation_id: change.operation_id,
        mode: change.mode,
    };
    let custody = config.custody.as_ref().ok_or(SdkError::NetworkingPending)?;
    let root = custody.account_root.clone();
    let account_id = custody.account_id.clone();
    let vault = std::sync::Arc::clone(&custody.vault);
    let policy = tokio::task::spawn_blocking(move || {
        let account =
            crate::custody::load_account(&root, &account_id, crate::custody::network_now()?)?;
        if object_hash(account.record())? != body.authority_head_hash {
            return Err(SdkError::NetworkingPending);
        }
        Ok(account.group_primary(vault.as_ref())?.sign_reach_policy(account.verified(), body)?)
    })
    .await
    .map_err(|_| SdkError::NetworkingPending)??;
    directory::exchange_username(
        config,
        transport,
        pin.clone(),
        w::NativeUsernameAction::ReachSet { policy: Box::new(policy) },
        deadline,
    )
    .await
}

pub(crate) fn apply(
    db: &AccountDb,
    result: &directory::UsernameNetworkReply,
) -> Result<serde_json::Value, SdkError> {
    let view = state(result)?;
    let policy = view.policy.as_ref().ok_or(w::DirectoryCode::DirectoryUnavailable)?;
    observe(
        db,
        &ReachRecord { policy: policy.clone(), authority: *view.authority.clone() },
        &result.own_record.body.account_anchor,
    )?;
    db.remove_actor_state(&sync_key(&policy.body.account_anchor))?;
    let body = serde_json::json!({"mode":policy.body.mode,"revision":policy.body.revision,"policy":policy});
    if view.conflict {
        let error = crate::bindings::AdapterError {
            details: crate::bindings::ErrorDetails::ReachRevisionConflict {
                reason: "reach_revision_conflict".into(),
                mode: policy.body.mode,
                revision: policy.body.revision,
                policy: Box::new(policy.clone()),
            },
            ..crate::bindings::AdapterError::new(
                crate::bindings::GeneratedErrorCode::InvalidArgument,
                "Reach revision changed",
            )
        };
        return Err(SdkError::LocalBusRefused {
            code: "reach_revision_conflict".into(),
            message: "Reach revision changed".into(),
            body: Box::new(serde_json::to_value(error)?),
        });
    }
    Ok(body)
}

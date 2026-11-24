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
    let body = serde_json::json!({"mode":policy.body.mode,"revision":policy.body.revision,"policy":policy});
    if view.conflict {
        return Err(SdkError::LocalBusRefused {
            code: "reach_revision_conflict".into(),
            message: "Reach revision changed".into(),
            body: Box::new(body),
        });
    }
    Ok(body)
}

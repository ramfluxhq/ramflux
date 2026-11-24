// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Journal exact signed reach changes in the writer before handing transport any bytes.
use crate::{SdkError, prelude::LocalBusAccountState};
use ramflux_protocol::{
    account_reach::{ReachChange, ReachPolicy, ReachPolicyBody, ReachRecord},
    username_directory as w,
};

pub(super) fn prepare_set(
    account: &LocalBusAccountState,
    body: &serde_json::Value,
) -> Result<w::NativeUsernameAction, SdkError> {
    let change: ReachChange = serde_json::from_value(body.clone())?;
    let db = account.client.account_db()?;
    let key = format!("reach/change/{}", account.principal_commitment);
    if let Some(old) = db.load_actor_state::<ReachPolicy>(&key)? {
        if old.body.mode != change.mode
            || old.body.expected_revision != change.expected_revision
            || old.body.operation_id != change.operation_id
        {
            return Err(w::DirectoryCode::OperationPending.into());
        }
        return Ok(w::NativeUsernameAction::ReachSet { policy: Box::new(old) });
    }
    let floor: ReachRecord = db
        .load_actor_state(&format!("reach/floor/{}", account.principal_commitment))?
        .ok_or(SdkError::NetworkingPending)?;
    let config = account.sealing_config()?;
    let custody = config.custody.as_ref().ok_or(SdkError::NetworkingPending)?;
    let native = crate::custody::load_account(
        &custody.account_root,
        &custody.account_id,
        crate::custody::network_now()?,
    )?;
    let policy = native.group_primary(custody.vault.as_ref())?.sign_reach_policy(
        native.verified(),
        ReachPolicyBody {
            version: 1,
            account_anchor: account.principal_commitment.clone(),
            home_head_hash: floor.policy.body.home_head_hash,
            authority_head_hash: ramflux_protocol::custody::object_hash(native.record())?,
            operation_id: change.operation_id,
            mode: change.mode,
            expected_revision: change.expected_revision,
            revision: change.expected_revision.checked_add(1).ok_or(w::DirectoryCode::Capacity)?,
        },
    )?;
    db.persist_actor_state(&key, &policy)?;
    Ok(w::NativeUsernameAction::ReachSet { policy: Box::new(policy) })
}

pub(super) fn settle(
    account: &LocalBusAccountState,
    result: &crate::username_directory::UsernameNetworkReply,
) -> Result<(), SdkError> {
    let w::NativeUsernameReply::Reach { state } = &result.reply else {
        return Ok(());
    };
    let db = account.client.account_db()?;
    let key = format!("reach/change/{}", account.principal_commitment);
    if let Some(intent) = db.load_actor_state::<ReachPolicy>(&key)?
        && (state.conflict
            || state.policy.as_ref().is_some_and(|policy| {
                policy == &intent || policy.body.revision > intent.body.revision
            }))
    {
        db.remove_actor_state(&key)?;
    }
    Ok(())
}

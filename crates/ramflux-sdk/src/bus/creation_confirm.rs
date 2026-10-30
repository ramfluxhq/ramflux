// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Secret confirmation persists off the bus thread, then opens the ordinary account actor.
use super::{custody_response, supervisor::Supervisor};
use crate::{
    LocalBusFrame, SdkError,
    custody::{CommitGate, CreationCeremony},
};
use std::sync::Arc;
use tokio::sync::watch;
use zeroize::Zeroizing;

struct CancelOnDrop(Arc<CommitGate>);
impl Drop for CancelOnDrop {
    fn drop(&mut self) {
        self.0.cancel();
    }
}

pub(super) async fn respond(
    request: &mut LocalBusFrame,
    supervisor: &Supervisor,
    ceremony: &mut Option<CreationCeremony>,
    disconnected: &mut watch::Receiver<bool>,
) -> Result<Zeroizing<Vec<u8>>, SdkError> {
    super::custody_setup::validate_headers(request, ceremony)?;
    let result = confirm(request, supervisor, ceremony, disconnected).await;
    *ceremony = None;
    match result {
        Ok(account) => custody_response::success(request, account),
        Err(error) => custody_response::error(request, &error),
    }
}

async fn confirm(
    request: &mut LocalBusFrame,
    supervisor: &Supervisor,
    ceremony: &mut Option<CreationCeremony>,
    disconnected: &mut watch::Receiver<bool>,
) -> Result<crate::LocalBusCreatedAccount, SdkError> {
    super::requests::deadline(request)?;
    if request.kind != crate::LocalBusFrameKind::Request || request.operation_id.is_some() {
        return Err(SdkError::CustodySetupInvalid);
    }
    let mut pending = ceremony.take().ok_or(SdkError::CustodySetupInvalid)?;
    let home_node_id = pending.home_node_id().map(str::to_owned);
    let (words, passphrase) = take_secrets(request)?;
    let gate = Arc::new(CommitGate::new(pending.deadline()));
    let _cancel = CancelOnDrop(Arc::clone(&gate));
    pending.guard_commit(gate);
    let vault = super::custody_setup::primary_provider(&supervisor.config);
    let worker = tokio::task::spawn_blocking(move || {
        let account = pending.confirm_with_passphrase(
            &words,
            vault.as_ref(),
            super::custody_setup::now()?,
            passphrase.as_bytes(),
        )?;
        Ok::<_, SdkError>((account.local_account_id().to_owned(), passphrase, home_node_id))
    });
    let (id, passphrase, home_node_id) = tokio::select! {
        biased;
        _ = disconnected.changed() => return Err(SdkError::CustodySetupInvalid),
        result = worker => result.map_err(|_| SdkError::CustodySetupInvalid)??,
    };
    if *disconnected.borrow() {
        return Err(SdkError::CustodySetupInvalid);
    }
    tokio::select! {
        biased;
        _ = disconnected.changed() => Err(SdkError::CustodySetupInvalid),
        result = supervisor.activate_native(&id, passphrase, home_node_id) => result,
    }
}

fn take_secrets(
    request: &mut LocalBusFrame,
) -> Result<([Zeroizing<String>; 3], Zeroizing<String>), SdkError> {
    let map = request
        .body
        .as_object_mut()
        .filter(|map| map.len() == 2)
        .ok_or(SdkError::CustodySetupInvalid)?;
    let Some(serde_json::Value::String(passphrase)) = map.remove("passphrase") else {
        return Err(SdkError::CustodySetupInvalid);
    };
    let passphrase = Zeroizing::new(passphrase);
    let values = map
        .get_mut("words")
        .and_then(serde_json::Value::as_array_mut)
        .filter(|words| words.len() == 3)
        .ok_or(SdkError::CustodySetupInvalid)?;
    let mut words = std::array::from_fn(|_| Zeroizing::new(String::new()));
    for (target, value) in words.iter_mut().zip(values) {
        let serde_json::Value::String(word) = std::mem::take(value) else {
            return Err(SdkError::CustodySetupInvalid);
        };
        *target = Zeroizing::new(word);
    }
    Ok((words, passphrase))
}

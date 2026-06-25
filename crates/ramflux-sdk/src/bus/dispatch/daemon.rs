#![allow(clippy::missing_errors_doc)]
#![allow(clippy::wildcard_imports)]
use crate::prelude::*;

pub(crate) fn dispatch_daemon_bus_request(
    request: &LocalBusFrame,
    state: &LocalBusDaemonState,
) -> Result<LocalBusDispatchResult, SdkError> {
    match request.method.as_str() {
        "daemon.status" => Ok(local_bus_ok(serde_json::json!({
            "accounts": state.accounts.len(),
            "socket_path": state.config.socket_path,
        }))),
        "daemon.stop" => Ok(local_bus_ok(serde_json::json!({
            "stopping": false,
            "reason": "external shutdown handle required by embedded serve_local_bus_until"
        }))),
        other => Err(SdkError::LocalBus(format!("unsupported local bus method: {other}"))),
    }
}

pub(crate) fn local_bus_ok(response_body: serde_json::Value) -> LocalBusDispatchResult {
    LocalBusDispatchResult { response_body, event: None }
}

pub(crate) fn local_bus_account<'a>(
    state: &'a LocalBusDaemonState,
    account_id: &str,
) -> Result<&'a LocalBusAccountState, SdkError> {
    state
        .accounts
        .get(account_id)
        .ok_or_else(|| SdkError::LocalBus(format!("account not open: {account_id}")))
}

pub(crate) fn local_bus_account_mut<'a>(
    state: &'a mut LocalBusDaemonState,
    account_id: &str,
) -> Result<&'a mut LocalBusAccountState, SdkError> {
    state
        .accounts
        .get_mut(account_id)
        .ok_or_else(|| SdkError::LocalBus(format!("account not open: {account_id}")))
}

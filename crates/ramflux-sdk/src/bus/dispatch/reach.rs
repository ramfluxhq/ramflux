// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Exact account-authenticated reach adapters. Signing credentials never cross the bus.
use crate::prelude::{
    GatewaySessionAccess, LocalBusDaemonState, LocalBusDispatchResult, LocalBusFrame, SdkError,
    local_bus_account_mut, local_bus_ok, request_account_id,
};
use ramflux_protocol::contact_reach::{self as wire, Operation, Reason};

fn operation(method: &str, body: &serde_json::Value) -> Result<Operation, SdkError> {
    let kind = match method {
        "reach.set" => "policy",
        "reach.state" => "reach_state",
        "strangers.list" => "strangers",
        "strangers.decide" => "admission",
        "conversation.start" => "start",
        "strangers.reply" => "reply",
        _ => return Err(SdkError::ReachRefused(Reason::ForeignInvalidFrame)),
    };
    let mut value = body.clone();
    let object =
        value.as_object_mut().ok_or(SdkError::ReachRefused(Reason::ForeignInvalidFrame))?;
    if object.insert("kind".into(), serde_json::json!(kind)).is_some() {
        return Err(SdkError::ReachRefused(Reason::ForeignInvalidFrame));
    }
    if method == "strangers.list"
        && object.insert("ack_seqs".into(), serde_json::json!([])).is_some()
    {
        return Err(SdkError::ReachRefused(Reason::ForeignInvalidFrame));
    }
    Ok(wire::decode(&ramflux_protocol::canonical_json_bytes(&value)?, wire::MAX_FRAME_BYTES)?)
}
pub(crate) async fn dispatch(
    request: &LocalBusFrame,
    state: &mut LocalBusDaemonState,
) -> Result<LocalBusDispatchResult, SdkError> {
    if request.method == "strangers.report" || !wire::enabled() {
        return Ok(local_bus_ok(serde_json::to_value(wire::unavailable())?));
    }
    let operation = operation(&request.method, &request.body)?;
    let account_id = request_account_id(request)?;
    let account = local_bus_account_mut(state, account_id)?;
    let mut engine = account.session_client().await?;
    let result = engine.reach_operation(operation).await;
    account.apply_session_metadata(engine);
    Ok(local_bus_ok(serde_json::to_value(result?)?))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn cr_bus_adapter_preserves_closed_strangers_and_state_bodies() -> Result<(), SdkError> {
        let list = operation("strangers.list", &serde_json::json!({"after_seq":0,"limit":16}))?;
        assert!(
            matches!(list,Operation::Strangers {after_seq:0,limit:16,ack_seqs} if ack_seqs.is_empty()),
            "list must not smuggle an ACK or consent action"
        );
        assert!(
            operation(
                "strangers.list",
                &serde_json::json!({"after_seq":0,"limit":16,"ack_seqs":[1]})
            )
            .is_err(),
            "the list-only bus grammar has no hidden ACK side effect"
        );
        assert!(
            operation("reach.state", &serde_json::json!({"known_revision":0,"page":0})).is_err(),
            "nullable snapshot id must remain explicit"
        );
        assert!(
            operation("reach.set", &serde_json::json!({"mode":"open"})).is_err(),
            "unsigned mode cannot become primary approval"
        );
        Ok(())
    }
}

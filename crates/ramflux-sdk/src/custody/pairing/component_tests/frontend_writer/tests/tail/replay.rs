// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Foreign signed parents and replayed data-only discovery cannot reopen terminal endpoints.
use super::*;

pub(super) fn original(
    rig: &Rig,
    request: &StatusRequest,
) -> Result<
    (ramflux_protocol::custody::pairing::full_transfer::relay::HelloFull, String),
    Box<dyn std::error::Error>,
> {
    let hello = rig
        .full_hellos
        .lock()
        .map_err(|_| "test: recorded original A3 hello")?
        .iter()
        .find(|hello| hello.role == "initiator")
        .cloned()
        .ok_or("test: no actual original-source hello to replay")?;
    let live = rig
        .source
        .client
        .account_db()?
        .pairing_live_rows()?
        .into_iter()
        .find(|row| row.operation_id == request.operation_id)
        .ok_or("test: original invitation missing")?;
    let invitation: ramflux_protocol::custody::Envelope<
        ramflux_protocol::custody::pairing::native::Invitation,
    > = ramflux_protocol::parse_i_json(&live.descriptor)?;
    Ok((hello, invitation.body.public_origin))
}

#[tokio::test(start_paused = true)]
async fn pairing_full_tail_requires_retained_chain_and_refuses_completed_replay() -> TestResult {
    let hold = ClockHold::new();
    crate::bus::credentials::contract_tests::deadline(Box::pin(hostile_context::run(
        hostile_context::Fault::Parent,
    )))
    .await?;
    crate::bus::credentials::contract_tests::deadline(Box::pin(cold_cleanup(true))).await?;
    hold.finish().await?;
    Ok(())
}

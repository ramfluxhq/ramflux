// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Explicit attended source approval, never an alias for SAS Confirm or B's phrase input.
use super::{PairingBusClient, TerminalProvider, invalid, invoke, output};
use crate::{
    RfError,
    cli::{TransferAction, TransferCommand},
};
use ramflux_protocol::custody::pairing::{
    PairingWire,
    local_dto::{Outcome, StatusRequest, TransferAffirm},
};
use std::{path::PathBuf, sync::Arc};
pub(super) async fn handle(socket: PathBuf, command: TransferCommand) -> Result<(), RfError> {
    dispatch(socket, command).await.map_err(output::failure)
}
async fn dispatch(socket: PathBuf, command: TransferCommand) -> Result<(), RfError> {
    if matches!(command.action, TransferAction::Affirm { .. }) {
        return execute(socket, command).await;
    }
    let prepared = preflight(&command.action, command.sas_out.as_deref())?;
    let display = super::sas::Display {
        socket: &socket,
        account: &command.account,
        sas_out: command.sas_out.as_deref(),
        prepared: std::cell::RefCell::new(prepared),
    };
    let mut client = PairingBusClient::connect(&socket, Arc::new(TerminalProvider)).await?;
    match command.action {
        action @ TransferAction::Begin { .. } => {
            let (request, path) = begin_request(action)?;
            super::begin_request(
                &mut client,
                &command.account,
                ("transfer.begin", request),
                path,
                &display,
            )
            .await
        }
        TransferAction::Join { display_name, invitation_file } => {
            super::join_request(
                &mut client,
                &command.account,
                ("transfer.join", display_name),
                &invitation_file,
                &display,
            )
            .await
        }
        TransferAction::Confirm {
            operation,
            transcript_hash,
            matches,
            peer_sas_file,
            peer_sas_attended,
        } => {
            super::sas::confirm(
                &mut client,
                &command.account,
                &display,
                ramflux_protocol::custody::pairing::local_dto::Confirm {
                    schema: "ramflux.pairing.Confirm.v2".into(),
                    version: 2,
                    operation_id: operation.operation_id,
                    generation: operation.generation,
                    transcript_hash,
                    r#match: matches,
                },
                peer_sas_file,
                peer_sas_attended,
            )
            .await
        }
        TransferAction::Prepare { operation, transcript_hash } => {
            let result = invoke(
                &mut client,
                &command.account,
                "transfer.prepare",
                &ramflux_protocol::custody::pairing::local_dto::Prepare {
                    schema: "ramflux.pairing.Prepare.v2".into(),
                    version: 2,
                    operation_id: operation.operation_id,
                    generation: operation.generation,
                    transcript_hash,
                },
            )
            .await?;
            super::finish(&display, result)
        }
        TransferAction::Status(operation) => {
            super::status(&mut client, &command.account, &display, operation, true).await
        }
        TransferAction::Cancel(operation) => {
            super::cancel(&mut client, &command.account, &display, operation).await
        }
        TransferAction::Affirm { .. } => Err(invalid()),
    }
}
fn begin_request(
    action: TransferAction,
) -> Result<(ramflux_protocol::custody::pairing::local_dto::FullTransferBegin, PathBuf), RfError> {
    use ramflux_protocol::custody::pairing::{
        context_v3::{DataSelectionV3, FullAccountData, TransferProfile},
        local_dto::FullTransferBegin,
    };
    let TransferAction::Begin {
        display_name,
        capabilities,
        lease_not_before,
        lease_expires_at,
        invitation_out,
        destination_device,
        destination_epoch,
        account_anchor,
    } = action
    else {
        return Err(invalid());
    };
    let destination_ref = match (destination_device, destination_epoch, account_anchor) {
        (None, None, None) => None,
        (Some(device_id), Some(device_epoch), Some(account_anchor)) => {
            Some(ramflux_protocol::custody::DeviceRef { account_anchor, device_id, device_epoch })
        }
        _ => return Err(invalid()),
    };
    let mut request = FullTransferBegin {
        schema: "ramflux.pairing.TransferBegin.v3".into(),
        version: 3,
        recipient_mode: if destination_ref.is_some() { "existing" } else { "new" }.into(),
        destination_ref,
        capabilities,
        lease_not_before,
        lease_expires_at,
        data_selection: DataSelectionV3::FullAccountDataV1(FullAccountData {}),
        transfer_profile: TransferProfile::FullAccountDataV1,
        display_name,
    };
    request.normalize();
    request.validate().map_err(|_| invalid())?;
    Ok((request, invitation_out))
}
fn preflight(
    action: &TransferAction,
    output: Option<&std::path::Path>,
) -> Result<Option<super::InvitationOutput>, RfError> {
    if matches!(
        action,
        TransferAction::Confirm {
            matches: true,
            peer_sas_file: Some(_),
            peer_sas_attended: false,
            ..
        }
    ) {
        return Err(invalid());
    }
    let needs_output = matches!(action, TransferAction::Join { .. });
    let needs_input =
        matches!(action, TransferAction::Confirm { matches: true, peer_sas_file: None, .. });
    super::sas::preflight_requirements(needs_output, needs_input, output)
}
async fn execute(socket: PathBuf, command: TransferCommand) -> Result<(), RfError> {
    let TransferAction::Affirm { operation, transcript_hash, new_record_hash, approved } =
        command.action
    else {
        return Err(invalid());
    };
    let mut request = TransferAffirm {
        schema: "ramflux.pairing.TransferAffirm.v2".into(),
        version: 2,
        operation_id: operation.operation_id,
        generation: operation.generation,
        transcript_hash,
        new_record_hash,
        approved,
    };
    request.validate().map_err(|_| invalid())?;
    // Refuse an unattended positive action before opening a bus connection.
    let mut terminal =
        if approved { Some(super::super::account_ceremony::Terminal::open()?) } else { None };
    let mut client = PairingBusClient::connect(socket, Arc::new(TerminalProvider)).await?;
    if let Some(terminal) = &mut terminal {
        let current = invoke(
            &mut client,
            &command.account,
            "status",
            &StatusRequest {
                schema: "ramflux.pairing.StatusRequest.v2".into(),
                version: 2,
                operation_id: request.operation_id.clone(),
                generation: request.generation,
            },
        )
        .await?;
        let Outcome::Update { value } = current.outcome else {
            return Err(invalid());
        };
        if value.operation_id != request.operation_id
            || value.generation != request.generation
            || value.transcript_hash.as_deref() != Some(request.transcript_hash.as_str())
            || value.proposal_hash.as_deref() != Some(request.new_record_hash.as_str())
            || value.phase != "proposal_pending"
            || value.emoji_indices.is_some()
        {
            return Err(invalid());
        }
        let destination = value.peer_ref.ok_or_else(invalid)?;
        let answer=terminal.line(&format!("Move primary to device {} at epoch {}.\nExact candidate: {}\nType affirm to approve; anything else rejects: ",
            destination.device_id,destination.device_epoch,request.new_record_hash),false)?;
        request.approved = answer.as_str() == "affirm";
    }
    let result = invoke(&mut client, &command.account, "transfer.affirm", &request).await?;
    let exit = output::outcome(&result);
    output::print(&serde_json::to_value(result)?)?;
    if exit == 0 { Ok(()) } else { Err(RfError::PairingExit { code: exit }) }
}

#[cfg(test)]
mod tests;

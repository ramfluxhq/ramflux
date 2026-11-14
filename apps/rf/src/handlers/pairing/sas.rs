// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Attended seven-name comparison. A CLI flag alone never restores SAS approval.
use super::{
    Confirm, InvitationOutput, LocalResult, OpenOptions, Outcome, PairingAction, PairingBusClient,
    Path, PathBuf, Read, RfError, StatusRequest, Write, finish, invalid, invoke, registry,
};
use ramflux_protocol::custody::pairing::PairingWire;
mod comparison;
pub(super) struct Display<'a> {
    pub socket: &'a Path,
    pub sas_out: Option<&'a Path>,
    pub account: &'a str,
    pub prepared: std::cell::RefCell<Option<InvitationOutput>>,
}
pub(super) fn preflight(
    action: &PairingAction,
    output: Option<&Path>,
) -> Result<Option<InvitationOutput>, RfError> {
    let needs_output = matches!(
        action,
        PairingAction::Join { .. } | PairingAction::Status(_) | PairingAction::TransferStatus(_)
    );
    if matches!(
        action,
        PairingAction::Confirm {
            matches: true,
            peer_sas_file: Some(_),
            peer_sas_attended: false,
            ..
        }
    ) {
        return Err(invalid());
    }
    let needs_input =
        matches!(action, PairingAction::Confirm { matches: true, peer_sas_file: None, .. });
    preflight_requirements(needs_output, needs_input, output)
}
pub(super) fn preflight_requirements(
    needs_output: bool,
    needs_input: bool,
    output: Option<&Path>,
) -> Result<Option<InvitationOutput>, RfError> {
    if ((needs_output && output.is_none()) || needs_input)
        && super::super::account_ceremony::Terminal::open().is_err()
    {
        return Err(invalid());
    }
    output.map(|path| InvitationOutput::create(path.into())).transpose()
}
fn names(indices: &[u64]) -> Result<String, RfError> {
    if indices.len() != 7 {
        return Err(invalid());
    }
    let names = indices
        .iter()
        .map(|index| {
            usize::try_from(*index)
                .ok()
                .and_then(|index| ramflux_crypto::custody::pairing::SAS_EMOJI.get(index))
                .map(|(_, name)| *name)
                .ok_or_else(invalid)
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(names.join("\n") + "\n")
}
pub(super) fn display(display: &Display<'_>, result: &mut LocalResult) -> Result<(), RfError> {
    let Outcome::Update { value } = &mut result.outcome else {
        return Ok(());
    };
    let Some(indices) = &value.emoji_indices else {
        return Ok(());
    };
    let names = names(indices)?;
    if display.sas_out.is_some() {
        let role =
            registry::Registry::open(display.socket)?.role(&value.operation_id, display.account)?;
        let bytes = comparison::encode(value, &role)?;
        let mut output = display.prepared.borrow_mut().take().ok_or_else(invalid)?;
        output.commit(&bytes)?;
        if let Err(error) = registry::Registry::open(display.socket)
            .and_then(|registry| registry.register_sas(&value.operation_id, &output))
        {
            output.keep = false;
            return Err(error);
        }
    } else {
        let mut terminal = OpenOptions::new().write(true).open("/dev/tty")?;
        writeln!(terminal, "Compare all seven SAS names:\n{names}")?;
    }
    value.emoji_indices = None;
    Ok(())
}
pub(super) async fn confirm(
    bus: &mut PairingBusClient,
    account: &str,
    display: &Display<'_>,
    mut request: Confirm,
    peer: Option<PathBuf>,
    attended: bool,
) -> Result<(), RfError> {
    request.validate().map_err(|_| invalid())?;
    if request.r#match && peer.is_some() && !attended {
        return Err(invalid());
    }
    let positive = request.r#match;
    let mut affirmed = positive;
    let mut owned_peer = None;
    if positive {
        let current = invoke(
            bus,
            account,
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
        {
            return Err(invalid());
        }
        let names = names(value.emoji_indices.as_deref().ok_or_else(invalid)?)?;
        if let Some(path) = peer {
            let owned = registry::JoinedFile::open(&path)?;
            let mut bytes = Vec::new();
            registry::private_file(&path)?.take(4097).read_to_end(&mut bytes)?;
            if bytes.len() > 4096 {
                return Err(invalid());
            }
            let role =
                registry::Registry::open(display.socket)?.role(&request.operation_id, account)?;
            affirmed = comparison::peer_matches(&value, &role, &bytes)?;
            owned_peer = Some(owned);
        } else {
            let mut terminal = super::super::account_ceremony::Terminal::open()?;
            let answer = terminal.line(
                &format!("Compare all seven SAS names:\n{names}Type match or mismatch: "),
                false,
            )?;
            affirmed = match answer.as_str() {
                "match" => true,
                "mismatch" => false,
                _ => return Err(invalid()),
            };
        }
    }
    request.r#match = affirmed;
    let mut result = invoke(bus, account, "confirm", &request).await?;
    if let Some(owned) = owned_peer {
        owned.remove()?;
    }
    registry::Registry::open(display.socket)?.cleanup(&request.operation_id)?;
    // Confirmation consumes the managed SAS files; never re-create them from its reply.
    if let Outcome::Update { value } = &mut result.outcome {
        value.emoji_indices = None;
    }
    let printed = finish(display, result);
    if positive && !affirmed {
        match printed {
            Ok(()) | Err(RfError::PairingExit { .. }) => Err(RfError::PairingExit { code: 4 }),
            other => other,
        }
    } else {
        printed
    }
}

#[cfg(test)]
mod tests;

// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Public pairing actions share the SDK coordinator; invitation bearers use private files.
use crate::{
    RfError,
    cli::{PairingAction, PairingCommand, PairingOperation},
};
use ramflux_protocol::custody::pairing::{
    PairingWire,
    local_dto::{Approve, Begin, Cancel, Confirm, Join, LocalResult, Outcome, StatusRequest},
    native::InviteToken,
};
use ramflux_sdk::custody::pairing::private_credential::PairingBusClient;
use std::{
    fs::{File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
};
use zeroize::Zeroizing;
mod output;
mod registry;
mod sas;

pub(crate) async fn handle(socket: PathBuf, command: PairingCommand) -> Result<(), RfError> {
    handle_attended(socket, command).await.map_err(output::failure)
}
async fn handle_attended(socket: PathBuf, command: PairingCommand) -> Result<(), RfError> {
    let prepared = sas::preflight(&command.action, command.sas_out.as_deref())?;
    let display = sas::Display {
        socket: &socket,
        sas_out: command.sas_out.as_deref(),
        account: &command.account,
        prepared: std::cell::RefCell::new(prepared),
    };
    let mut bus = PairingBusClient::connect(&socket, std::sync::Arc::new(TerminalProvider)).await?;
    let full_status = matches!(&command.action, PairingAction::TransferStatus(_));
    match command.action {
        PairingAction::Begin {
            display_name,
            capabilities,
            lease_not_before,
            lease_expires_at,
            invitation_out,
        } => {
            begin(
                &mut bus,
                &command.account,
                Begin {
                    schema: "ramflux.pairing.Begin.v2".into(),
                    version: 2,
                    display_name,
                    capabilities,
                    lease_not_before,
                    lease_expires_at,
                },
                invitation_out,
                &display,
            )
            .await
        }

        PairingAction::Join { display_name, invitation_file } => {
            join(&mut bus, &command.account, display_name, &invitation_file, &display).await
        }
        PairingAction::Confirm {
            operation,
            transcript_hash,
            matches,
            peer_sas_file,
            peer_sas_attended,
        } => {
            sas::confirm(
                &mut bus,
                &command.account,
                &display,
                Confirm {
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
        PairingAction::Approve { operation, transcript_hash, proposal_hash, approved } => finish(
            &display,
            invoke(
                &mut bus,
                &command.account,
                "approve",
                &Approve {
                    schema: "ramflux.pairing.Approve.v2".into(),
                    version: 2,
                    operation_id: operation.operation_id,
                    generation: operation.generation,
                    transcript_hash,
                    proposal_hash,
                    approved,
                },
            )
            .await?,
        ),
        PairingAction::Status(operation) | PairingAction::TransferStatus(operation) => {
            status(&mut bus, &command.account, &display, operation, full_status).await
        }
        PairingAction::Cancel(operation) => {
            cancel(&mut bus, &command.account, &display, operation).await
        }
    }
}
async fn status(
    bus: &mut PairingBusClient,
    account: &str,
    display: &sas::Display<'_>,
    operation: PairingOperation,
    full: bool,
) -> Result<(), RfError> {
    let result = invoke(
        bus,
        account,
        if full { "transfer.status" } else { "status" },
        &StatusRequest {
            schema: "ramflux.pairing.StatusRequest.v2".into(),
            version: 2,
            operation_id: operation.operation_id,
            generation: operation.generation,
        },
    )
    .await?;
    finish(display, result)
}
async fn cancel(
    bus: &mut PairingBusClient,
    account: &str,
    display: &sas::Display<'_>,
    operation: PairingOperation,
) -> Result<(), RfError> {
    let result = invoke(
        bus,
        account,
        "cancel",
        &Cancel {
            schema: "ramflux.pairing.Cancel.v2".into(),
            version: 2,
            operation_id: operation.operation_id,
            generation: operation.generation,
        },
    )
    .await?;
    finish(display, result)
}

async fn join(
    bus: &mut PairingBusClient,
    account: &str,
    display_name: String,
    path: &Path,
    display: &sas::Display<'_>,
) -> Result<(), RfError> {
    let owned = registry::JoinedFile::open(path)?;
    let token = read_invitation(path)?;
    registry::Registry::open(display.socket)?.record_role(
        &token.invitation.body.request_id,
        account,
        "responder",
    )?;
    let result = invoke(
        bus,
        account,
        "join",
        &Join { schema: "ramflux.pairing.Join.v2".into(), version: 2, token, display_name },
    )
    .await?;
    if matches!(&result.outcome, Outcome::Update { value } if value.result.is_none()) {
        owned.remove()?;
    }
    show(display, result)
}

struct InvitationOutput {
    path: PathBuf,
    file: File,
    keep: bool,
}
impl InvitationOutput {
    fn create(path: PathBuf) -> Result<Self, RfError> {
        let file = OpenOptions::new().write(true).create_new(true).mode(0o600).open(&path)?;
        Ok(Self { path, file, keep: false })
    }
    fn commit(&mut self, bytes: &[u8]) -> Result<(), RfError> {
        self.file.write_all(bytes)?;
        self.file.sync_all()?;
        File::open(
            self.path.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or(Path::new(".")),
        )?
        .sync_all()?;
        self.keep = true;
        Ok(())
    }
}
impl Drop for InvitationOutput {
    fn drop(&mut self) {
        if !self.keep
            && let (Ok(owned), Ok(named)) =
                (self.file.metadata(), std::fs::symlink_metadata(&self.path))
            && owned.dev() == named.dev()
            && owned.ino() == named.ino()
        {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}
async fn begin(
    bus: &mut PairingBusClient,
    account: &str,
    mut request: Begin,
    path: PathBuf,
    display: &sas::Display<'_>,
) -> Result<(), RfError> {
    let mut output = InvitationOutput::create(path)?;
    request.normalize();
    let result = invoke(bus, account, "begin", &request).await?;
    let LocalResult { outcome: Outcome::Begin { value }, .. } = result else {
        return show(display, result);
    };
    let bytes = Zeroizing::new(value.invite_token.to_wire_bytes().map_err(|_| invalid())?);
    if let Err(error) = output.commit(&bytes).and_then(|()| {
        registry::Registry::open(display.socket)?.register(&value.operation_id, &output, account)
    }) {
        output.keep = false;
        let _ = invoke(
            bus,
            account,
            "cancel",
            &Cancel {
                schema: "ramflux.pairing.Cancel.v2".into(),
                version: 2,
                operation_id: value.operation_id.clone(),
                generation: value.generation,
            },
        )
        .await;
        return Err(error);
    }
    output::print(
        &serde_json::json!({"operation_id":value.operation_id,"generation":value.generation,"expires_at":value.expires_at,"invitation_file":output.path}),
    )
}

fn invalid() -> RfError {
    RfError::Message("Invalid pairing response or invitation.".into())
}
async fn invoke<T: PairingWire + serde::Serialize>(
    bus: &mut PairingBusClient,
    account: &str,
    action: &str,
    request: &T,
) -> Result<LocalResult, RfError> {
    request.validate().map_err(|_| invalid())?;
    let method = if action == "transfer.status" {
        "device.transfer.status".into()
    } else {
        format!("device.pair.{action}")
    };
    let value = bus
        .request(Some(account.into()), "device", &method, serde_json::to_value(request)?)
        .await?;
    let result: LocalResult = serde_json::from_value(value).map_err(|_| invalid())?;
    result
        .validate_method(method.strip_prefix("device.").ok_or_else(invalid)?)
        .map_err(|_| invalid())?;
    Ok(result)
}
fn finish(display: &sas::Display<'_>, result: LocalResult) -> Result<(), RfError> {
    let terminal = match &result.outcome {
        Outcome::Update { value }
            if matches!(
                value.phase.as_str(),
                "completed" | "cancelled" | "expired" | "rejected"
            ) =>
        {
            Some((&value.operation_id, value.phase == "expired"))
        }
        Outcome::FullStatus { value }
            if matches!(
                value.stage,
                ramflux_protocol::custody::pairing::local_dto::FullStatusStage::Installed
                    | ramflux_protocol::custody::pairing::local_dto::FullStatusStage::Cancelled
                    | ramflux_protocol::custody::pairing::local_dto::FullStatusStage::Expired
            ) =>
        {
            Some((
                &value.operation_id,
                value.stage
                    == ramflux_protocol::custody::pairing::local_dto::FullStatusStage::Expired,
            ))
        }
        _ => None,
    };
    if let Some((operation, expired)) = terminal {
        registry::Registry::open(display.socket)?.cleanup(operation)?;
        if expired {
            eprintln!(
                "Expired invitation files contain dead tokens; remove any unmanaged copies. Cleanup does not run while rf is absent."
            );
        }
    }
    show(display, result)
}

fn show(display: &sas::Display<'_>, mut result: LocalResult) -> Result<(), RfError> {
    if matches!(result.outcome, Outcome::Begin { .. }) {
        return Err(invalid());
    }
    sas::display(display, &mut result)?;
    let exit = output::outcome(&result);
    output::print(&serde_json::to_value(result)?)?;
    if exit == 0 { Ok(()) } else { Err(RfError::PairingExit { code: exit }) }
}
fn read_invitation(path: &Path) -> Result<InviteToken, RfError> {
    let fd = rustix::fs::open(
        path,
        rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::NOFOLLOW,
        rustix::fs::Mode::empty(),
    )
    .map_err(std::io::Error::from)?;
    let file = File::from(fd);
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.permissions().mode() & 0o077 != 0
        || metadata.uid() != rustix::process::geteuid().as_raw()
    {
        return Err(RfError::Message(
            "Invitation must be a same-user private regular file.".into(),
        ));
    }
    let mut bytes = Zeroizing::new(Vec::with_capacity(InviteToken::LIMIT + 1));
    file.take(u64::try_from(InviteToken::LIMIT + 1).map_err(|_| invalid())?)
        .read_to_end(&mut bytes)?;
    InviteToken::from_wire_bytes(&bytes).map_err(|_| invalid())
}

#[cfg(test)]
mod tests;

/// Secrets come exclusively from the controlling terminal, including phone-primary phrase input.
struct TerminalProvider;
impl ramflux_sdk::custody::pairing::LocalCredentialProvider for TerminalProvider {
    fn provide(
        &self,
        request: &ramflux_protocol::custody::pairing::local_dto::CredentialRequest,
    ) -> Result<ramflux_sdk::custody::pairing::CredentialOutcome, ramflux_sdk::SdkError> {
        use ramflux_sdk::custody::pairing::{CredentialOutcome, SecretUtf8};
        let read = || -> Result<CredentialOutcome, RfError> {
            let mut terminal = super::account_ceremony::Terminal::open()?;
            let prompt = match request.action.as_str() {
                "setup" => "New local data passphrase (hidden): ",
                "unlock" => "Local data passphrase (hidden): ",
                "phrase" => "Recovery phrase for this primary transfer (hidden): ",
                _ => return Ok(CredentialOutcome::Refused),
            };
            let pass = terminal.line(prompt, true)?;
            let confirmation = if request.action == "setup" {
                let repeated = terminal.line("Repeat local data passphrase (hidden): ", true)?;
                Some(SecretUtf8::from_bytes(repeated.as_bytes())?)
            } else {
                None
            };
            Ok(CredentialOutcome::Provided {
                passphrase: SecretUtf8::from_bytes(pass.as_bytes())?,
                confirmation,
            })
        };
        // UI refusal/EOF/unavailable controlling terminal never falls back to stdin or env.
        Ok(read().unwrap_or(CredentialOutcome::Refused))
    }
}

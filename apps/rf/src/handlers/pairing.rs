// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Public pairing actions share the SDK coordinator; invitation bearers use private files.
use crate::{
    RfError,
    cli::{PairingAction, PairingCommand},
};
use ramflux_protocol::custody::pairing::{
    PairingWire,
    local_dto::{Approve, Begin, Cancel, Confirm, Join, LocalResult, Outcome, StatusRequest},
    native::InviteToken,
};
use ramflux_sdk::LocalBusClient;
use std::{
    fs::{File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
};
use zeroize::Zeroizing;

pub(crate) async fn handle(socket: PathBuf, command: PairingCommand) -> Result<(), RfError> {
    let mut bus = LocalBusClient::connect(socket).await?;
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
            )
            .await
        }

        PairingAction::Join { display_name, invitation_file } => {
            join(&mut bus, &command.account, display_name, &invitation_file).await
        }
        PairingAction::Confirm { operation, transcript_hash, matches } => show(
            invoke(
                &mut bus,
                &command.account,
                "confirm",
                &Confirm {
                    schema: "ramflux.pairing.Confirm.v2".into(),
                    version: 2,
                    operation_id: operation.operation_id,
                    generation: operation.generation,
                    transcript_hash,
                    r#match: matches,
                },
            )
            .await?,
        ),
        PairingAction::Approve { operation, transcript_hash, proposal_hash, approved } => show(
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
        PairingAction::Status(operation) => show(
            invoke(
                &mut bus,
                &command.account,
                "status",
                &StatusRequest {
                    schema: "ramflux.pairing.StatusRequest.v2".into(),
                    version: 2,
                    operation_id: operation.operation_id,
                    generation: operation.generation,
                },
            )
            .await?,
        ),
        PairingAction::Cancel(operation) => show(
            invoke(
                &mut bus,
                &command.account,
                "cancel",
                &Cancel {
                    schema: "ramflux.pairing.Cancel.v2".into(),
                    version: 2,
                    operation_id: operation.operation_id,
                    generation: operation.generation,
                },
            )
            .await?,
        ),
    }
}
async fn join(
    bus: &mut LocalBusClient,
    account: &str,
    display_name: String,
    path: &Path,
) -> Result<(), RfError> {
    let token = read_invitation(path)?;
    show(
        invoke(
            bus,
            account,
            "join",
            &Join { schema: "ramflux.pairing.Join.v2".into(), version: 2, token, display_name },
        )
        .await?,
    )
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
    bus: &mut LocalBusClient,
    account: &str,
    mut request: Begin,
    path: PathBuf,
) -> Result<(), RfError> {
    let mut output = InvitationOutput::create(path)?;
    request.normalize();
    let result = invoke(bus, account, "begin", &request).await?;
    let LocalResult { outcome: Outcome::Begin { value }, .. } = result else { return show(result) };
    let bytes = Zeroizing::new(value.invite_token.to_wire_bytes().map_err(|_| invalid())?);
    if let Err(error) = output.commit(&bytes) {
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
    super::print_json(
        &serde_json::json!({"operation_id":value.operation_id,"generation":value.generation,"expires_at":value.expires_at,"invitation_file":output.path}),
    )
}

fn invalid() -> RfError {
    RfError::Message("Invalid pairing response or invitation.".into())
}
async fn invoke<T: PairingWire + serde::Serialize>(
    bus: &mut LocalBusClient,
    account: &str,
    action: &str,
    request: &T,
) -> Result<LocalResult, RfError> {
    request.validate().map_err(|_| invalid())?;
    let value = bus
        .request(
            Some(account.into()),
            "device",
            &format!("device.pair.{action}"),
            serde_json::to_value(request)?,
        )
        .await?;
    let result: LocalResult = serde_json::from_value(value).map_err(|_| invalid())?;
    result.validate().map_err(|_| invalid())?;
    Ok(result)
}
fn show(result: LocalResult) -> Result<(), RfError> {
    if matches!(result.outcome, Outcome::Begin { .. }) {
        return Err(invalid());
    }
    if let Outcome::Update { value } = &result.outcome
        && let Some(indices) = &value.emoji_indices
        && let Ok(mut terminal) = OpenOptions::new().write(true).open("/dev/tty")
    {
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
        writeln!(terminal, "Compare all seven SAS names: {}", names.join(" · "))?;
    }
    super::print_json(&serde_json::to_value(result)?)
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

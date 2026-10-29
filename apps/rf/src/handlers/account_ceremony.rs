// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Explicit local ceremonies read secret input only from the controlling terminal.
use crate::RfError;
use std::{
    fs::{File, OpenOptions},
    io::{IsTerminal, Read, Write},
    path::Path,
    process::{Command, Stdio},
};
use zeroize::Zeroizing;

struct Terminal {
    input: File,
    output: File,
    echo_disabled: bool,
}
impl Terminal {
    fn open() -> Result<Self, RfError> {
        let terminal =
            OpenOptions::new().read(true).write(true).open("/dev/tty").map_err(|_| {
                RfError::Message("This ceremony requires a local interactive terminal.".into())
            })?;
        if !terminal.is_terminal() {
            return Err(RfError::Message("A local interactive terminal is required.".into()));
        }
        Ok(Self { input: terminal.try_clone()?, output: terminal, echo_disabled: false })
    }
    fn echo(&mut self, enabled: bool) -> Result<(), RfError> {
        let status = Command::new("stty")
            .arg(if enabled { "echo" } else { "-echo" })
            .stdin(Stdio::from(self.input.try_clone()?))
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()?;
        if !status.success() {
            return Err(RfError::Message("Could not protect terminal input.".into()));
        }
        self.echo_disabled = !enabled;
        Ok(())
    }
    fn line(&mut self, prompt: &str, hidden: bool) -> Result<Zeroizing<String>, RfError> {
        self.output.write_all(prompt.as_bytes())?;
        self.output.flush()?;
        if hidden {
            self.echo(false)?;
        }
        let mut bytes = Zeroizing::new(Vec::with_capacity(4096));
        let mut byte = Zeroizing::new([0]);
        let mut overflow = false;
        loop {
            self.input.read_exact(&mut *byte)?;
            if byte[0] == b'\n' {
                break;
            }
            if bytes.len() < 4096 {
                bytes.push(byte[0]);
            } else {
                overflow = true;
            }
        }
        if hidden {
            self.echo(true)?;
            writeln!(self.output)?;
        }
        if overflow {
            return Err(RfError::Message("Terminal input exceeds the ceremony limit.".into()));
        }
        if bytes.last() == Some(&b'\r') {
            bytes.pop();
        }
        match String::from_utf8(std::mem::take(&mut *bytes)) {
            Ok(value) => Ok(Zeroizing::new(value)),
            Err(error) => {
                drop(Zeroizing::new(error.into_bytes()));
                Err(RfError::Message("Terminal input must be valid UTF-8.".into()))
            }
        }
    }
}
impl Drop for Terminal {
    fn drop(&mut self) {
        if self.echo_disabled {
            let _ = self.echo(true);
        }
    }
}

pub(crate) async fn recover(socket: &Path, account: &str) -> Result<(), RfError> {
    let mut terminal = Terminal::open()?;
    let mut client = ramflux_sdk::LocalBusRecoveryClient::connect(socket).await?;
    let pending = client.begin(account).await?;
    writeln!(
        terminal.output,
        "Account fingerprint: {}\n{}",
        pending.account_anchor, pending.warning
    )?;
    let confirmed = terminal.line("Type the displayed account fingerprint to confirm: ", false)?;
    if *confirmed != pending.account_anchor {
        return Err(RfError::Message("Account fingerprint confirmation did not match.".into()));
    }
    let phrase = terminal.line("Recovery phrase (hidden): ", true)?;
    let passphrase = terminal.line("Local data passphrase (hidden): ", true)?;
    let result = client.confirm(&phrase, &passphrase, &pending.account_anchor).await?;
    crate::utils::print_json(&serde_json::to_value(result)?)
}

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
        if hidden {
            self.echo(false)?;
        }
        self.output.write_all(prompt.as_bytes())?;
        self.output.flush()?;
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

/// Show recovery material only on the controlling terminal, then erase before challenging.
pub(crate) async fn create(socket: &Path, display_name: &str) -> Result<(), RfError> {
    let mut terminal = Terminal::open()?;
    let mut client = ramflux_sdk::LocalBusCreationClient::connect(socket).await?;
    client.begin(display_name, ramflux_protocol::PrincipalKind::Human).await?;
    let result = create_confirm(&mut terminal, &mut client).await;
    if result.is_err() {
        let _ = client.cancel().await;
    }
    crate::utils::print_json(&serde_json::to_value(result?)?)
}

async fn create_confirm(
    terminal: &mut Terminal,
    client: &mut ramflux_sdk::LocalBusCreationClient,
) -> Result<ramflux_sdk::LocalBusCreatedAccount, RfError> {
    // An alternate screen keeps the once-only phrase out of the normal terminal scrollback.
    terminal.output.write_all(b"\x1b[?1049h\x1b[2J\x1b[H")?;
    let shown = show_phrase(terminal, client).await;
    let cleared = terminal.output.write_all(b"\x1b[2J\x1b[H\x1b[?1049l");
    terminal.output.flush()?;
    cleared?;
    shown?;
    let positions = client.hidden_challenge().await?;
    let mut words = std::array::from_fn(|_| Zeroizing::new(String::new()));
    for (word, position) in words.iter_mut().zip(positions) {
        *word = terminal.line(&format!("Recovery word {position} (hidden): "), true)?;
    }
    let passphrase = terminal.line("New local data passphrase (hidden): ", true)?;
    let repeated = terminal.line("Repeat local data passphrase (hidden): ", true)?;
    if *passphrase != *repeated {
        return Err(RfError::Message("Local data passphrases did not match.".into()));
    }
    drop(repeated);
    Ok(client.confirm(&words, &passphrase).await?)
}

async fn show_phrase(
    terminal: &mut Terminal,
    client: &mut ramflux_sdk::LocalBusCreationClient,
) -> Result<(), RfError> {
    let phrase = client.show_once().await?;
    writeln!(
        terminal.output,
        "Write down these 24 recovery words and keep them private.\n{}",
        phrase.as_str()
    )?;
    terminal.output.flush()?;
    drop(terminal.line("Press Enter after saving the words to hide them: ", true)?);
    drop(phrase);
    Ok(())
}

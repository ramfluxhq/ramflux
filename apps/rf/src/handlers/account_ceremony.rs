// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Explicit local ceremonies read secret input only from the controlling terminal.
use crate::RfError;
use std::{
    fs::File,
    io::{IsTerminal, Read, Write},
    path::Path,
};
#[cfg(not(windows))]
use std::{
    fs::OpenOptions,
    process::{Command, Stdio},
};
use zeroize::Zeroizing;

struct Terminal {
    input: File,
    output: File,
    echo_disabled: bool,
    /// A carriage return ended the previous line. A following line feed belongs to that Enter.
    #[cfg(windows)]
    skip_lf: bool,
    /// Modes from before the ceremony. Restored on the way out, including virtual-terminal state.
    #[cfg(windows)]
    saved_input_mode: u32,
    #[cfg(windows)]
    saved_output_mode: u32,
    /// Escape sequences hide the words only when the output console accepted this mode.
    #[cfg(windows)]
    virtual_terminal: bool,
    #[cfg(windows)]
    modes_restored: bool,
}
impl Terminal {
    fn open() -> Result<Self, RfError> {
        #[cfg(windows)]
        {
            let input = super::windows_console::open_input().map_err(|error| {
                RfError::Message(format!(
                    "This ceremony requires a local interactive terminal: {error}"
                ))
            })?;
            let output = super::windows_console::open_output().map_err(|error| {
                RfError::Message(format!(
                    "This ceremony requires a local interactive terminal: {error}"
                ))
            })?;
            if !input.is_terminal() {
                return Err(RfError::Message("A local interactive terminal is required.".into()));
            }
            let saved_input_mode =
                super::windows_console::console_mode(&input).map_err(|error| {
                    RfError::Message(format!("Could not protect terminal input: {error}"))
                })?;
            let saved_output_mode =
                super::windows_console::console_mode(&output).map_err(|error| {
                    RfError::Message(format!("Could not protect the recovery words: {error}"))
                })?;
            super::windows_console::prepare_input(&input).map_err(|error| {
                RfError::Message(format!("Could not protect terminal input: {error}"))
            })?;
            let virtual_terminal = match super::windows_console::enable_virtual_terminal(
                &output,
                saved_output_mode,
            ) {
                Ok(()) => true,
                Err(vt_error) => {
                    // No escape sequence is written unless this flag sticks. A console that
                    // rejects it must still be able to erase the buffer, or the words would
                    // stay on screen.
                    if let Err(clear_error) = super::windows_console::screen_buffer_usable(&output)
                    {
                        return Err(RfError::Message(format!(
                            "Could not protect the recovery words: virtual terminal {vt_error}; console clear {clear_error}"
                        )));
                    }
                    false
                }
            };
            return Ok(Self {
                input,
                output,
                echo_disabled: false,
                skip_lf: false,
                saved_input_mode,
                saved_output_mode,
                virtual_terminal,
                modes_restored: false,
            });
        }
        #[cfg(not(windows))]
        {
            let terminal =
                OpenOptions::new().read(true).write(true).open("/dev/tty").map_err(|_| {
                    RfError::Message("This ceremony requires a local interactive terminal.".into())
                })?;
            if !terminal.is_terminal() {
                return Err(RfError::Message("A local interactive terminal is required.".into()));
            }
            Ok(Self { input: terminal.try_clone()?, output: terminal, echo_disabled: false })
        }
    }
    fn echo(&mut self, enabled: bool) -> Result<(), RfError> {
        #[cfg(windows)]
        {
            super::windows_console::set_echo(&self.input, enabled).map_err(|error| {
                RfError::Message(format!("Could not protect terminal input: {error}"))
            })?;
            self.echo_disabled = !enabled;
            return Ok(());
        }
        #[cfg(not(windows))]
        {
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
            #[cfg(windows)]
            if self.skip_lf {
                self.skip_lf = false;
                if byte[0] == b'\n' {
                    continue;
                }
            }
            if byte[0] == b'\n' {
                break;
            }
            #[cfg(windows)]
            if byte[0] == b'\r' {
                self.skip_lf = true;
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

    fn restore_modes(&mut self) -> Result<(), RfError> {
        #[cfg(windows)]
        {
            if self.modes_restored {
                return Ok(());
            }
            super::windows_console::restore_modes(
                &self.input,
                self.saved_input_mode,
                &self.output,
                self.saved_output_mode,
            )
            .map_err(|error| {
                RfError::Message(format!("Could not restore the terminal: {error}"))
            })?;
            self.modes_restored = true;
            self.echo_disabled = false;
            return Ok(());
        }
        #[cfg(not(windows))]
        {
            if self.echo_disabled {
                self.echo(true)?;
            }
            Ok(())
        }
    }
}

fn finish<T>(terminal: &mut Terminal, outcome: Result<T, RfError>) -> Result<T, RfError> {
    let restored = terminal.restore_modes();
    match outcome {
        Ok(value) => restored.map(|()| value),
        Err(error) => Err(error),
    }
}

impl Drop for Terminal {
    fn drop(&mut self) {
        #[cfg(windows)]
        if !self.modes_restored {
            let _ = self.restore_modes();
        }
        #[cfg(not(windows))]
        if self.echo_disabled {
            let _ = self.echo(true);
        }
    }
}

pub(crate) async fn recover(socket: &Path, account: &str) -> Result<(), RfError> {
    let mut terminal = Terminal::open()?;
    let outcome = recover_with(&mut terminal, socket, account).await;
    finish(&mut terminal, outcome)
}

async fn recover_with(
    terminal: &mut Terminal,
    socket: &Path,
    account: &str,
) -> Result<(), RfError> {
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
pub(crate) async fn create(
    socket: &Path,
    display_name: &str,
    kind: crate::cli::AccountKind,
    custodian: Option<&str>,
) -> Result<(), RfError> {
    let mut terminal = Terminal::open()?;
    let outcome = create_with(&mut terminal, socket, display_name, kind, custodian).await;
    finish(&mut terminal, outcome)
}

async fn create_with(
    terminal: &mut Terminal,
    socket: &Path,
    display_name: &str,
    kind: crate::cli::AccountKind,
    custodian: Option<&str>,
) -> Result<(), RfError> {
    let mut client = ramflux_sdk::LocalBusCreationClient::connect(socket).await?;
    let result = match (kind, custodian) {
        (crate::cli::AccountKind::Human, None) => {
            client.begin(display_name, ramflux_protocol::PrincipalKind::Human).await?;
            create_human_confirm(terminal, &mut client).await
        }
        (crate::cli::AccountKind::HeadlessAi, Some(custodian)) => {
            client.begin_headless(display_name, custodian).await?;
            create_headless_confirm(terminal, &mut client).await
        }
        (crate::cli::AccountKind::HeadlessAi, None) => {
            Err(RfError::Message("Headless AI account creation requires --custodian.".into()))
        }
        (crate::cli::AccountKind::Human, Some(_)) => {
            Err(RfError::Message("Human account creation does not accept --custodian.".into()))
        }
    };
    if result.is_err() {
        let _ = client.cancel().await;
    }
    crate::utils::print_json(&serde_json::to_value(result?)?)
}

async fn create_human_confirm(
    terminal: &mut Terminal,
    client: &mut ramflux_sdk::LocalBusCreationClient,
) -> Result<ramflux_sdk::LocalBusCreatedAccount, RfError> {
    let words = recovery_challenge(terminal, client).await?;
    let passphrase = terminal.line("New local data passphrase (hidden): ", true)?;
    let repeated = terminal.line("Repeat local data passphrase (hidden): ", true)?;
    if *passphrase != *repeated {
        return Err(RfError::Message("Local data passphrases did not match.".into()));
    }
    drop(repeated);
    Ok(client.confirm(&words, &passphrase).await?)
}

async fn create_headless_confirm(
    terminal: &mut Terminal,
    client: &mut ramflux_sdk::LocalBusCreationClient,
) -> Result<ramflux_sdk::LocalBusCreatedAccount, RfError> {
    let words = recovery_challenge(terminal, client).await?;
    Ok(client.confirm_headless(&words).await?)
}

async fn recovery_challenge(
    terminal: &mut Terminal,
    client: &mut ramflux_sdk::LocalBusCreationClient,
) -> Result<[Zeroizing<String>; 3], RfError> {
    // An alternate screen keeps the once-only phrase out of the normal terminal scrollback.
    // On a Windows console that rejects virtual-terminal mode, the same hide is a buffer erase.
    enter_private_screen(terminal)?;
    let shown = show_phrase(terminal, client).await;
    let cleared = leave_private_screen(terminal);
    cleared?;
    shown?;
    let positions = client.hidden_challenge().await?;
    let mut words = std::array::from_fn(|_| Zeroizing::new(String::new()));
    for (word, position) in words.iter_mut().zip(positions) {
        *word = terminal.line(&format!("Recovery word {position} (hidden): "), true)?;
    }
    Ok(words)
}

fn enter_private_screen(terminal: &mut Terminal) -> Result<(), RfError> {
    #[cfg(windows)]
    if !terminal.virtual_terminal {
        return Ok(());
    }
    terminal.output.write_all(b"\x1b[?1049h\x1b[2J\x1b[H")?;
    terminal.output.flush()?;
    Ok(())
}

fn leave_private_screen(terminal: &mut Terminal) -> Result<(), RfError> {
    #[cfg(windows)]
    if !terminal.virtual_terminal {
        let cleared = super::windows_console::clear_screen_and_scrollback(&terminal.output);
        let flushed = terminal.output.flush();
        cleared.map_err(|error| {
            RfError::Message(format!("Could not hide the recovery words: {error}"))
        })?;
        flushed?;
        return Ok(());
    }
    let cleared = terminal.output.write_all(b"\x1b[2J\x1b[H\x1b[?1049l");
    terminal.output.flush()?;
    cleared?;
    Ok(())
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

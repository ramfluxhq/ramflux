// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Bounded direct child pipes. No shell, environment KEK, secret output or stderr.
use super::{LinuxVaultMode, cleanup::Secret, init::LinuxVaultInitError as Error};
use std::{process::Stdio, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    process::Command,
    sync::watch,
    time::Instant,
};

pub(super) const NAMES: [&str; 3] = ["rf-primary-kek", "rf-device-kek", "rf-data-kek"];
pub(super) const CAP: usize = 16384;

pub(super) async fn pipe<const N: usize>(
    mode: LinuxVaultMode,
    realm: usize,
    encrypt: bool,
    input: &[u8],
    cancel: &mut watch::Receiver<bool>,
    deadline: Instant,
) -> Result<(Secret<N>, usize), Error> {
    let name = NAMES.get(realm).ok_or(Error::Realm)?;
    let key = match mode {
        LinuxVaultMode::SystemdHost => "host",
        LinuxVaultMode::SystemdTpm2 => "host+tpm2",
        LinuxVaultMode::DesktopSecretService => return Err(Error::Mode),
    };
    if *cancel.borrow() {
        return Err(Error::Cancelled);
    }
    let mut cmd = Command::new("/usr/bin/systemd-creds");
    cmd.arg(if encrypt { "encrypt" } else { "decrypt" });
    if encrypt {
        cmd.arg(format!("--with-key={key}"));
    }
    cmd.arg(format!("--name={name}"))
        .args(["-", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true);
    transfer(cmd, input, cancel, deadline).await
}

async fn transfer<const N: usize>(
    mut cmd: Command,
    input: &[u8],
    cancel: &mut watch::Receiver<bool>,
    deadline: Instant,
) -> Result<(Secret<N>, usize), Error> {
    let mut child = cmd.spawn().map_err(|_| Error::Provider)?;
    let mut stdin = child.stdin.take().ok_or(Error::Provider)?;
    let mut stdout = child.stdout.take().ok_or(Error::Provider)?;
    let mut output = Secret::<N>::new("p04-child-output");
    let mut guarded = Secret::<{ CAP + 1 }>::new("p04-child-stdin");
    if input.len() > CAP {
        child.kill().await.map_err(|_| Error::Provider)?;
        return Err(Error::Length);
    }
    guarded.bytes_mut()[..input.len()].copy_from_slice(input);
    #[cfg(test)]
    test_hook::run();
    let end = deadline.min(Instant::now() + Duration::from_secs(30));
    let result = {
        let transfer = async {
            let send = async {
                stdin
                    .write_all(&guarded.bytes()[..input.len()])
                    .await
                    .map_err(|_| Error::Provider)?;
                stdin.shutdown().await.map_err(|_| Error::Provider)?;
                drop(stdin);
                Ok::<_, Error>(())
            };
            let receive = async {
                let mut n = 0;
                loop {
                    if n == N {
                        return Err(Error::Length);
                    }
                    let got = stdout
                        .read(&mut output.bytes_mut()[n..])
                        .await
                        .map_err(|_| Error::Provider)?;
                    if got == 0 {
                        return Ok(n);
                    }
                    n += got;
                }
            };
            let ((), size) = tokio::try_join!(send, receive)?;
            let status = child.wait().await.map_err(|_| Error::Provider)?;
            if !status.success() {
                return Err(Error::Provider);
            }
            Ok(size)
        };
        tokio::select! {
            biased;
            _ = cancel.changed() => Err(Error::Cancelled),
            () = tokio::time::sleep_until(end) => Err(Error::Timeout),
            value = transfer => value,
        }
    };
    if result.is_err() {
        // Reap before returning: installation lock and worker slot remain owned.
        let _ = child.kill().await;
        let _ = child.wait().await;
    }
    Ok((output, result?))
}

pub(super) async fn decrypt(
    mode: LinuxVaultMode,
    realm: usize,
    blob: &[u8],
    cancel: &mut watch::Receiver<bool>,
    deadline: Instant,
) -> Result<Secret<33>, Error> {
    let (key, len) = pipe::<33>(mode, realm, false, blob, cancel, deadline).await?;
    if len != 32 {
        return Err(Error::Length);
    }
    Ok(key)
}

pub(super) async fn probe(
    cancel: &mut watch::Receiver<bool>,
    deadline: Instant,
) -> Result<(), Error> {
    let mut command = Command::new("/usr/bin/systemd-creds");
    command
        .arg("--version")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true);
    let (version, len) = transfer::<1025>(command, &[], cancel, deadline).await?;
    let text = std::str::from_utf8(&version.bytes()[..len]).map_err(|_| Error::Provider)?;
    let n = text
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse::<u32>().ok())
        .ok_or(Error::Provider)?;
    if n < 252 {
        return Err(Error::Provider);
    }
    Ok(())
}

#[cfg(test)]
pub(super) mod test_hook {
    use std::cell::RefCell;
    type Hook = Box<dyn FnOnce()>;
    thread_local! { static HOOK: RefCell<Option<Hook>> = const { RefCell::new(None) }; }
    pub(crate) fn set(hook: Hook) {
        HOOK.with(|h| *h.borrow_mut() = Some(hook));
    }
    pub(super) fn run() {
        HOOK.with(|h| {
            if let Some(hook) = h.borrow_mut().take() {
                hook();
            }
        });
    }
}

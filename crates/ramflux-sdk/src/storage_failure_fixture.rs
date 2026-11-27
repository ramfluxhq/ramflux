// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Real account faults shared by boundary regression tests.
use crate::prelude::*;
use std::process::{Child, Command, Stdio};

pub(crate) type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
#[derive(Clone, Copy, Debug)]
pub(crate) enum Fault {
    Busy,
    Io,
    Integrity,
}

pub(crate) struct Holder(Child);
impl Drop for Holder {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

pub(crate) struct Fixture {
    pub(crate) index: AccountIndex,
    pub(crate) anchor: String,
    holder: Option<Holder>,
    directory: crate::custody::tests::Root,
}

impl Fixture {
    /// A native custody account `acct` sealed under `account-secret`, then faulted.
    pub(crate) fn new(fault: Fault) -> TestResult<Self> {
        let directory = crate::custody::tests::Root::new()?;
        let vault = crate::custody::tests::TestVault::default();
        let account = crate::custody::tests::create(
            &directory.0,
            "acct",
            &vault,
            crate::custody::network_now()?,
        )?;
        let anchor = account.record().body.account_anchor.clone();
        let mut client = RamfluxClient::new();
        client.open_account_index(&directory.0)?;
        client.seal_new_account_data("acct", &anchor, b"account-secret")?;
        let index = client.account_index()?.clone();
        drop(client);
        let mut fixture = Self { index, anchor, holder: None, directory };
        fixture.holder = apply_fault(&fixture.index, fault)?;
        Ok(fixture)
    }

    pub(crate) fn root(&self) -> &Path {
        &self.directory.0
    }

    pub(crate) fn client(&self) -> Result<RamfluxClient, SdkError> {
        let mut client = RamfluxClient::new();
        client.open_account_index(self.root())?;
        Ok(client)
    }

    #[cfg(feature = "c-abi")]
    pub(crate) fn error(&self) -> TestResult<StorageError> {
        match self.client()?.unlock_account("acct", b"account-secret") {
            Err(SdkError::Storage(error)) => Ok(error),
            other => Err(format!("expected a real storage failure, got {other:?}").into()),
        }
    }
}

/// Injects real storage faults into a native account.
pub(crate) fn apply_fault(index: &AccountIndex, fault: Fault) -> TestResult<Option<Holder>> {
    match fault {
        Fault::Busy => {
            let mut holder = Holder(
                Command::new(std::env::current_exe()?)
                    .args([
                        "--exact",
                        "client::account::tests::account_writer_sdk_process_fixture",
                        "--nocapture",
                    ])
                    .env("RAMFLUX_SDK_WRITER_TEST_ROOT", index.root())
                    .stdin(Stdio::null())
                    .spawn()?,
            );
            let deadline = std::time::Instant::now() + Duration::from_secs(30);
            while !index.root().join("sdk-writer-ready").exists() {
                assert!(holder.0.try_wait()?.is_none(), "writer child exited before readiness");
                assert!(std::time::Instant::now() < deadline, "writer child startup timed out");
                std::thread::sleep(Duration::from_millis(10));
            }
            return Ok(Some(holder));
        }
        Fault::Io => {
            let lock = index.root().join("accounts/acct/.writer.lock");
            std::fs::remove_file(&lock)?;
            std::fs::create_dir(&lock)?;
        }
        Fault::Integrity => {
            let mut wrapped = index.load_wrapped_db_key("acct")?.ok_or("wrapped key")?;
            wrapped.wrapped_key[0] ^= 1;
            index.store_wrapped_db_key("acct", &wrapped)?;
        }
    }
    Ok(None)
}

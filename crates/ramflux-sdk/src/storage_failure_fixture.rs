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

struct Holder(Child);
impl Drop for Holder {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

pub(crate) struct Fixture {
    pub(crate) index: AccountIndex,
    pub(crate) manifest: LocalBusPersistedAccount,
    holder: Option<Holder>,
    directory: tempfile::TempDir,
}

impl Fixture {
    pub(crate) fn new(fault: Fault) -> TestResult<Self> {
        let directory = tempfile::tempdir()?;
        let root = directory.path();
        let mut client = RamfluxClient::new();
        client.open_account_index(root)?;
        let identity = client.create_identity_root("principal", [41; 32]);
        let commitment =
            ramflux_crypto::identity_root_commitment(&identity.signing_key.verifying_key());
        client.create_device_branch("principal", "device", 1, [42; 32]);
        client.create_account("acct", &commitment)?;
        client.unlock_account("acct", b"account-secret")?;
        drop(client);
        let index = AccountIndex::open(root)?;
        let manifest = LocalBusPersistedAccount {
            schema: "ramflux.local_bus.account_manifest.v1".into(),
            local_account_id: "acct".into(),
            principal_id: "principal".into(),
            principal_commitment: commitment,
            device_id: "device".into(),
            target_delivery_id: "target".into(),
            account_secret: "account-secret".into(),
            root_seed: [41; 32],
            device_seed: [42; 32],
            label: None,
            kind: None,
            activation_pending: false,
            node_id: None,
            node_tcp_addr: None,
            node_relay: None,
            client_mode: LocalBusClientMode::AttendedCli,
            devices: Vec::new(),
            gateway: GatewayQuicEndpointConfig {
                bind_addr: "127.0.0.1:0".parse()?,
                gateway_addr: "127.0.0.1:1".parse()?,
                server_name: "unconnected-test-gateway".into(),
                ca_cert: root.join("unused-ca.pem"),
                principal_id: "principal".into(),
                device_id: "device".into(),
                target_delivery_id: "target".into(),
                prekey_http_url: None,
            },
        };
        write_local_bus_account_manifest(root, &manifest)?;
        let mut fixture = Self { index, manifest, holder: None, directory };
        match fault {
            Fault::Busy => {
                let mut holder = Holder(
                    Command::new(std::env::current_exe()?)
                        .args([
                            "--exact",
                            "client::account::tests::account_writer_sdk_process_fixture",
                            "--nocapture",
                        ])
                        .env("RAMFLUX_SDK_WRITER_TEST_ROOT", fixture.root())
                        .stdin(Stdio::null())
                        .spawn()?,
                );
                let deadline = std::time::Instant::now() + Duration::from_secs(30);
                while !fixture.root().join("sdk-writer-ready").exists() {
                    assert!(holder.0.try_wait()?.is_none(), "writer child exited before readiness");
                    assert!(std::time::Instant::now() < deadline, "writer child startup timed out");
                    std::thread::sleep(Duration::from_millis(10));
                }
                fixture.holder = Some(holder);
            }
            Fault::Io => {
                let lock = fixture.root().join("accounts/acct/.writer.lock");
                std::fs::remove_file(&lock)?;
                std::fs::create_dir(&lock)?;
            }
            Fault::Integrity => {
                let mut wrapped =
                    fixture.index.load_wrapped_db_key("acct")?.ok_or("wrapped key")?;
                wrapped.wrapped_key[0] ^= 1;
                fixture.index.store_wrapped_db_key("acct", &wrapped)?;
            }
        }
        Ok(fixture)
    }

    pub(crate) fn root(&self) -> &Path {
        self.directory.path()
    }

    pub(crate) fn client(&self) -> Result<RamfluxClient, SdkError> {
        let mut client = RamfluxClient::new();
        client.open_account_index(self.root())?;
        Ok(client)
    }

    pub(crate) fn error(&self) -> TestResult<StorageError> {
        match self.client()?.unlock_account("acct", b"account-secret") {
            Err(SdkError::Storage(error)) => Ok(error),
            other => Err(format!("expected a real storage failure, got {other:?}").into()),
        }
    }
}

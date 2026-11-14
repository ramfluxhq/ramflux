// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Kill the real chunk writer at file/receipt boundaries and reopen its encrypted stage.
use super::{CHUNK_BYTES, PairingRole, TestResult, fixture};
use crate::{AccountDb, AccountDbKey, AccountIndex, FullStageReference};
use ramflux_protocol::custody::pairing::PairingWire;
use std::{
    cell::Cell,
    io::{Read as _, Write as _},
    path::Path,
    process::Stdio,
    time::Duration,
};
use tokio::io::{AsyncBufReadExt as _, AsyncReadExt as _};
const ROOT: &str = "RAMFLUX_TEST_PAIRING_CHUNK_CUT_ROOT";
const CUT: &str = "RAMFLUX_TEST_PAIRING_CHUNK_CUT";
mod application;
const CHILD: &str = "account_db::full_transfer::stage_tests::process_cuts::chunk_writer_child";
const PASSWORD: &[u8] = b"original-process-cut-password";
thread_local! { static ARMED: Cell<Option<u8>> = const { Cell::new(None) }; }

pub(in crate::account_db::full_transfer) fn checkpoint(cut: u8) -> std::io::Result<()> {
    if !ARMED.with(|armed| armed.get() == Some(cut)) {
        return Ok(());
    }
    let mut output = std::io::stdout().lock();
    output.write_all(b"PAIRING_CHUNK_CUT\n")?;
    output.flush()?;
    drop(output);
    let (_sender, receiver) = std::sync::mpsc::sync_channel::<()>(0);
    receiver.recv_timeout(Duration::from_secs(30)).map_err(std::io::Error::other)
}
fn open(root: &Path) -> TestResult<AccountDb> {
    Ok(AccountDb::open(
        &AccountIndex::open(root)?,
        "acct",
        &AccountDbKey::derive("acct", PASSWORD),
    )?)
}
fn reference(root: &Path) -> TestResult<FullStageReference> {
    let bytes = super::super::stage::read_bounded(&root.join("reference"), 1024)?;
    Ok(FullStageReference::from_wire_bytes(&bytes)?)
}
#[test]
fn chunk_writer_child() -> TestResult {
    let Some(root) = std::env::var_os(ROOT) else { return Ok(()) };
    let cut: u8 = std::env::var(CUT)?.parse()?;
    if cut > 13 {
        return Err("test: unknown stage durability cut".into());
    }
    let root = std::path::PathBuf::from(root);
    if cut >= 5 {
        return application::write(&root, cut);
    }
    let db = open(&root)?;
    let (_, manifest, bytes) = fixture()?;
    let stage = db.open_full_stage_reference(reference(&root)?, PairingRole::Responder, 604_801)?;
    ARMED.with(|armed| armed.set(Some(cut)));
    stage.retain_forward_chunk(
        &ramflux_protocol::encode_base64url(
            ramflux_protocol::custody::pairing::full_transfer::manifest_hash(&manifest)?,
        ),
        0,
        bytes.get(..CHUNK_BYTES as usize).ok_or("test: bounded first chunk")?,
    )?;
    Err("test: armed real writer did not reach its durability boundary".into())
}
#[tokio::test]
async fn pairing_full_chunk_process_death_preserves_only_durable_receipts() -> TestResult {
    tokio::time::timeout(Duration::from_secs(60), async {
        for cut in 0..=4 {
            run(cut).await?;
        }
        Ok(())
    })
    .await?
}
async fn run(cut: u8) -> TestResult {
    let owner = tempfile::tempdir()?;
    let root = owner.path();
    let (record, manifest, bytes) = fixture()?;
    let index = AccountIndex::open(root)?;
    index.create_account("acct", &record.grant.destination_ref.account_anchor)?;
    let hash = record.base_manifest_hash.clone();
    let db = open(root)?;
    let mut stage = db.create_full_stage_for_test(record, 604_900)?;
    stage.retain_forward_manifest(&manifest, &manifest.manifest.families)?;
    std::fs::write(root.join("reference"), stage.reference().to_wire_bytes()?.as_slice())?;
    drop(stage);
    drop(db);
    kill_writer(root, cut).await?;
    let db = open(root)?;
    let stage = db.open_full_stage_reference(reference(root)?, PairingRole::Responder, 604_801)?;
    assert_eq!(
        stage.revalidate_forward_prefix(&hash)?,
        (cut == 4).then_some(0),
        "test: cut {cut} fabricated or lost a committed durable receipt"
    );
    assert!(
        stage.verify_forward_root(&hash).is_err(),
        "test: cut {cut} fabricated a complete root"
    );
    assert!(
        !stage.connection.query_row(
            "SELECT verified FROM manifest WHERE manifest_hash=?1",
            rusqlite::params![hash],
            |row| row.get::<_, bool>(0)
        )?,
        "test: cut {cut} fabricated semantic DV"
    );
    for (index, chunk) in bytes.chunks(CHUNK_BYTES as usize).enumerate() {
        stage.retain_forward_chunk(&hash, index as u64, chunk)?;
    }
    stage.verify_forward_root(&hash)?;
    let mut restored = zeroize::Zeroizing::new(Vec::new());
    stage.forward_reader(&hash)?.take(bytes.len() as u64 + 1).read_to_end(&mut restored)?;
    assert_eq!(restored.as_slice(), bytes.as_slice(), "test: cut {cut} changed resumed plaintext");
    Ok(())
}
async fn kill_writer(root: &Path, cut: u8) -> TestResult {
    let mut child = tokio::process::Command::new(std::env::current_exe()?)
        .args(["--exact", CHILD, "--nocapture"])
        .env(ROOT, root)
        .env(CUT, cut.to_string())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .kill_on_drop(true)
        .spawn()?;
    let output = child.stdout.take().ok_or("test: child stdout missing")?;
    let mut lines = tokio::io::BufReader::new(output.take(4096));
    let reached = tokio::time::timeout(Duration::from_secs(10), async {
        let mut line = String::new();
        for _ in 0..16 {
            line.clear();
            if lines.read_line(&mut line).await? == 0 {
                break;
            }
            if line.contains("PAIRING_CHUNK_CUT") {
                return Ok::<_, std::io::Error>(true);
            }
        }
        Ok(false)
    })
    .await;
    child.kill().await?;
    let _status = child.wait().await?;
    assert!(reached??, "test: real child never reached chunk cut {cut}");
    Ok(())
}

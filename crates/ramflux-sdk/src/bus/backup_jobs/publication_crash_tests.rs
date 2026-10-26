// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! A killed fallback copy is reclaimed without claiming somebody else's output.
use super::*;
use std::{
    collections::BTreeSet,
    os::unix::fs::OpenOptionsExt,
    process::{Command, Stdio},
    time::{Duration, Instant},
};
type TestResult = Result<(), Box<dyn std::error::Error>>;
const CHILD_ROOT: &str = "RAMFLUX_TEST_BACKUP_COPY_CRASH_ROOT";
#[test]
fn r4_copy_crash_child() -> TestResult {
    let Some(root) = std::env::var_os(CHILD_ROOT) else { return Ok(()) };
    let root = std::path::PathBuf::from(root);
    let unsupported = |_: &Path, _: &Path| Err(io::ErrorKind::Unsupported.into());
    publish_with_operations(
        &root.join(".ramflux-backup-copy-crash.partial"),
        &root.join("backup.rfb"),
        unsupported,
        unsupported,
        &AtomicBool::new(false),
        Some(&root.join("jobs/job_copy-crash")),
    )?;
    Err("the source must stay open until the parent kills this child".into())
}
#[test]
fn r4_restart_removes_an_owned_final_archive_after_a_process_dies_mid_copy() -> TestResult {
    let root = crate::bus::runtime_tests::root("backup-copy-crash");
    let jobs = root.join("jobs");
    let stage = jobs.join("job_copy-crash");
    std::fs::create_dir_all(&stage)?;
    let source = root.join(".ramflux-backup-copy-crash.partial");
    assert!(Command::new("mkfifo").args(["-m", "600"]).arg(&source).status()?.success());
    super::super::recovery::remember_partial_output(&stage, &source)?;
    let mut child = Command::new(std::env::current_exe()?)
        .args([
            "--exact",
            "bus::backup_jobs::publication::crash_tests::r4_copy_crash_child",
            "--nocapture",
        ])
        .env(CHILD_ROOT, &root)
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .spawn()?;
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut writer = loop {
        match std::fs::OpenOptions::new()
            .write(true)
            .custom_flags(i32::try_from(rustix::fs::OFlags::NONBLOCK.bits())?)
            .open(&source)
        {
            Ok(file) => break file,
            Err(_) if Instant::now() < deadline && child.try_wait()?.is_none() => {
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(error.into());
            }
        }
    };
    writer.write_all(b"incomplete authenticated archive")?;
    let output = root.join("backup.rfb");
    while !std::fs::metadata(&output).is_ok_and(|m| m.len() > 0) {
        if Instant::now() >= deadline || child.try_wait()?.is_some() {
            let _ = child.kill();
            let _ = child.wait();
            return Err("copy did not reach its incomplete final file".into());
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    child.kill()?;
    child.wait()?;
    drop(writer);
    super::super::recovery::recover_jobs_excluding(&jobs, &BTreeSet::new())?;
    assert!(!output.exists(), "restart must remove the final file owned by an interrupted copy");
    assert!(!source.exists());
    std::fs::remove_dir_all(root)?;
    Ok(())
}
#[test]
fn r4_recovery_preserves_completed_outputs_and_never_claims_preexisting_destinations() -> TestResult
{
    for exists in [false, true] {
        let root = crate::bus::runtime_tests::root(if exists {
            "backup-existing-output"
        } else {
            "backup-complete-output"
        });
        let jobs = root.join("jobs");
        let stage = jobs.join("job_copy");
        std::fs::create_dir_all(&stage)?;
        let source = root.join("source");
        let output = root.join("final");
        std::fs::write(&source, b"valid complete archive")?;
        if exists {
            std::fs::write(&output, b"previous user file")?;
        }
        let result = copy_exclusive(&source, &output, &AtomicBool::new(false), Some(&stage));
        assert_eq!(result.is_err(), exists);
        super::super::recovery::recover_jobs_excluding(&jobs, &BTreeSet::new())?;
        assert_eq!(
            std::fs::read(&output)?,
            if exists {
                b"previous user file".as_slice()
            } else {
                b"valid complete archive".as_slice()
            }
        );
        std::fs::remove_dir_all(root)?;
    }
    Ok(())
}

// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Readers observe absent or complete authority, and existing authority is never replaced.
use super::{
    checkpoints::{self, Stage},
    *,
};
use crate::custody::tests::Root;
use std::{os::unix::fs::PermissionsExt, sync::mpsc, time::Duration};
type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;

#[tokio::test]
async fn custody_authority_concurrent_reader_never_observes_partial_publication() -> Result {
    let root = Root::new()?;
    let path = root.0.join("authority.json");
    let bytes = serde_json::to_vec(&serde_json::json!({"record": "a".repeat(512 * 1024)}))?;
    let output = path.clone();
    let expected = bytes.clone();
    let (stages, mut observed) = tokio::sync::mpsc::unbounded_channel();
    let (resume, released) = mpsc::channel();
    let writer = tokio::task::spawn_blocking(move || {
        let _checkpoints = checkpoints::install(move |stage| {
            stages.send(stage).map_err(|_| crate::custody::invalid())?;
            released
                .recv_timeout(Duration::from_secs(10))
                .map_err(|_| crate::custody::invalid())?;
            Ok(())
        });
        write_public(&output, &bytes)
    });
    tokio::time::timeout(Duration::from_secs(10), async {
        let stages = [Stage::TemporaryCreated, Stage::TemporarySynced, Stage::Linked];
        let mut next_stage = 0;
        let mut held = None;
        // Read continuously, including while the worker fills and syncs the temporary file.
        while next_stage < stages.len() || !writer.is_finished() {
            if held.is_none() && next_stage < stages.len() {
                match observed.try_recv() {
                    Ok(stage) => {
                        assert_eq!(stage, stages[next_stage]);
                        held = Some((stage, 0));
                    }
                    Err(tokio::sync::mpsc::error::TryRecvError::Empty) => {}
                    Err(tokio::sync::mpsc::error::TryRecvError::Disconnected) => {
                        return Err("publication worker stopped".into());
                    }
                }
            }
            match fs::read(&path) {
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    if let Some((stage, _)) = held {
                        assert_ne!(stage, Stage::Linked);
                    }
                }
                Ok(bytes) => {
                    assert!(
                        bytes == expected,
                        "reader observed partial authority bytes: {} bytes",
                        bytes.len()
                    );
                    if let Some((stage, _)) = held {
                        assert_eq!(stage, Stage::Linked, "authority became visible before linking");
                    }
                }
                Err(error) => return Err(error.into()),
            }
            if let Some((_, reads)) = &mut held {
                *reads += 1;
                if *reads == 128 {
                    resume.send(())?;
                    next_stage += 1;
                    held = None;
                }
            }
            tokio::task::yield_now().await;
        }
        writer.await??;
        assert_eq!(fs::read(&path)?, expected);
        assert_eq!(fs::metadata(&path)?.permissions().mode() & 0o777, 0o600);
        assert_eq!(fs::read_dir(&root.0)?.count(), 1, "temporary publication was not removed");
        Ok::<_, Box<dyn std::error::Error>>(())
    })
    .await??;
    Ok(())
}

#[test]
fn custody_authority_publication_never_replaces_existing_or_incomplete_authority() -> Result {
    for existing in [b"existing authority".as_slice(), b""] {
        let root = Root::new()?;
        let path = root.0.join("authority.json");
        fs::write(&path, existing)?;
        let mode = fs::metadata(&path)?.permissions().mode();
        assert!(matches!(
            write_public(&path, b"replacement authority"),
            Err(SdkError::Io(error)) if error.kind() == std::io::ErrorKind::AlreadyExists
        ));
        assert_eq!(fs::read(&path)?, existing);
        assert_eq!(fs::metadata(&path)?.permissions().mode(), mode);
        assert_eq!(fs::read_dir(&root.0)?.count(), 1, "failed publication leaked its temporary");
    }
    Ok(())
}

#[test]
fn custody_authority_failed_prepublication_removes_only_the_temporary_file() -> Result {
    let root = Root::new()?;
    let path = root.0.join("authority.json");
    let _checkpoint = checkpoints::install(|stage| {
        if stage == Stage::TemporarySynced {
            return Err(crate::custody::invalid());
        }
        Ok(())
    });
    assert!(matches!(write_public(&path, b"authority"), Err(SdkError::CustodySetupInvalid)));
    assert!(!path.exists());
    assert_eq!(fs::read_dir(&root.0)?.count(), 0);
    Ok(())
}

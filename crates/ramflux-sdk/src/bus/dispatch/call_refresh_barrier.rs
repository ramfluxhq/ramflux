// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Integration-build-only barrier for a renewed offer racing terminal signaling.
use crate::SdkError;
use std::{path::PathBuf, time::Duration};

fn path() -> Option<PathBuf> {
    std::env::var_os("RAMFLUX_ITEST_VOICE_REFRESH_BARRIER").map(PathBuf::from)
}

pub(super) async fn wait() -> Result<(), SdkError> {
    let Some(path) = path() else { return Ok(()) };
    tokio::fs::write(path.with_extension("ready"), b"refresh pending").await?;
    tokio::time::timeout(Duration::from_secs(30), async {
        while !tokio::fs::try_exists(path.with_extension("release")).await? {
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        Ok::<_, SdkError>(())
    })
    .await
    .map_err(|_| SdkError::LocalBus("voice refresh test barrier timed out".into()))?
}

pub(super) async fn refused() -> Result<(), SdkError> {
    if let Some(path) = path() {
        tokio::fs::write(path.with_extension("refused"), b"refresh refused").await?;
    }
    Ok(())
}

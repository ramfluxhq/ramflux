// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Ephemeral, bounded subscribers to one in-flight coordinator outcome. No result is cached.
use super::{CheckpointError, Code, Result};
use std::{
    sync::{Arc, Mutex, Weak, mpsc},
    time::Duration,
};

/// One native mutation may await its already durable H1 attempt; this grants no serving right.
pub struct HomeAttempt {
    _alive: Arc<()>,
    receive: mpsc::Receiver<Option<Code>>,
}

pub enum HomeAttemptOutcome {
    Complete,
    Refused(Code),
    Pending,
}
impl HomeAttempt {
    #[must_use]
    pub fn wait(self, timeout: Duration) -> HomeAttemptOutcome {
        match self.receive.recv_timeout(timeout.min(Duration::from_secs(8))) {
            Ok(Some(code)) => HomeAttemptOutcome::Refused(code),
            Ok(None) => HomeAttemptOutcome::Complete,
            Err(_) => HomeAttemptOutcome::Pending,
        }
    }
}
struct Listener {
    root: String,
    operation_id: String,
    alive: Weak<()>,
    send: mpsc::SyncSender<Option<Code>>,
}
#[derive(Default)]
pub(super) struct Attempts {
    listeners: Mutex<Vec<Listener>>,
}
impl Attempts {
    pub(super) fn watch(&self, root: &str, operation_id: &str) -> Result<HomeAttempt> {
        super::super::fixed(root)?;
        super::super::fixed(operation_id)?;
        let mut listeners = self
            .listeners
            .lock()
            .map_err(|_| CheckpointError::Directory(Code::DirectoryUnavailable))?;
        listeners.retain(|listener| listener.alive.strong_count() != 0);
        if listeners.len() >= 64
            || listeners.iter().filter(|listener| listener.root == root).count() >= 4
        {
            return Err(CheckpointError::Directory(Code::Capacity));
        }
        let alive = Arc::new(());
        let (send, receive) = mpsc::sync_channel(1);
        listeners.push(Listener {
            root: root.into(),
            operation_id: operation_id.into(),
            alive: Arc::downgrade(&alive),
            send,
        });
        Ok(HomeAttempt { _alive: alive, receive })
    }
    pub(super) fn complete(
        &self,
        root: &str,
        operation_id: &str,
        code: Option<Code>,
    ) -> Result<()> {
        let mut listeners = self
            .listeners
            .lock()
            .map_err(|_| CheckpointError::Directory(Code::DirectoryUnavailable))?;
        listeners.retain(|listener| {
            if listener.alive.strong_count() == 0 {
                return false;
            }
            if listener.root == root && listener.operation_id == operation_id {
                let _ = listener.send.try_send(code);
                return false;
            }
            true
        });
        Ok(())
    }
}

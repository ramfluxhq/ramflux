// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Deterministically pause a durable append before recovery-index application and ACK.
use super::{Arc, Mutex, RouterWalState, RouterWalStore, mpsc};
use tokio::sync::oneshot;
#[derive(Debug)]
pub(super) struct Pause {
    entered: oneshot::Sender<()>,
    release: mpsc::Receiver<()>,
    done: oneshot::Sender<()>,
}
pub(crate) struct Control {
    pub entered: oneshot::Receiver<()>,
    pub release: mpsc::SyncSender<()>,
    pub done: oneshot::Receiver<()>,
}
pub(super) struct AfterAck(Option<oneshot::Sender<()>>);
impl Drop for AfterAck {
    fn drop(&mut self) {
        if let Some(done) = self.0.take() {
            let _sent = done.send(());
        }
    }
}
impl RouterWalStore {
    pub(crate) fn pause_next_ack(&self) -> Control {
        let (entered, waiting) = oneshot::channel();
        let (release, blocked) = mpsc::sync_channel(1);
        let (done, finished) = oneshot::channel();
        let state = self.state.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        *state.ack_pause.lock().unwrap_or_else(std::sync::PoisonError::into_inner) =
            Some(Pause { entered, release: blocked, done });
        Control { entered: waiting, release, done: finished }
    }
}
pub(super) fn before_apply(state: &Arc<Mutex<RouterWalState>>) -> AfterAck {
    let gate =
        Arc::clone(&state.lock().unwrap_or_else(std::sync::PoisonError::into_inner).ack_pause);
    let pause = gate.lock().unwrap_or_else(std::sync::PoisonError::into_inner).take();
    if let Some(pause) = pause {
        let _sent = pause.entered.send(());
        let _released = pause.release.recv();
        AfterAck(Some(pause.done))
    } else {
        AfterAck(None)
    }
}

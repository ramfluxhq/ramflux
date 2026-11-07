// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Bounded nonblocking session subscriptions with one lag marker per overflow episode.

use super::super::runtime_limits::SUBSCRIBER_QUEUE;
use super::model::DisconnectReason;
use crate::GatewayServerFrame;
use crate::gateway::frame_dispatch::FrameKind;
use std::{
    collections::BTreeSet,
    sync::{Arc, Mutex},
};
use tokio::sync::{Notify, mpsc};

#[derive(Clone, Debug)]
pub(crate) enum SessionEvent {
    Frame {
        frame: Arc<GatewayServerFrame>,
        generation: u64,
    },
    /// A negotiated-session event; the legacy `Frame` shape is unchanged. The first consumer
    /// arrives with the receive adapters of a later part.
    #[allow(dead_code)]
    Capable {
        event: Arc<crate::gateway::session_push::CapableEvent>,
        generation: u64,
    },
    Lagged {
        dropped: u64,
        generation: u64,
    },
    Disconnected {
        reason: DisconnectReason,
        generation: u64,
    },
}

#[derive(Default)]
struct Lag {
    dropping: bool,
    reported: bool,
    dropped: u64,
    terminal: Option<DisconnectReason>,
}

struct Subscriber {
    kinds: BTreeSet<FrameKind>,
    queue: mpsc::Sender<SessionEvent>,
    state: Mutex<Lag>,
    wake: Notify,
}

pub(crate) struct SessionSubscription {
    queue: mpsc::Receiver<SessionEvent>,
    subscriber: Arc<Subscriber>,
    generation: u64,
    ended: bool,
}

impl SessionSubscription {
    pub(crate) async fn recv(&mut self) -> Option<SessionEvent> {
        loop {
            if self.ended {
                return None;
            }
            // notify_one retains a permit if notification precedes the first poll.
            let changed = self.subscriber.wake.notified();
            {
                let mut state =
                    self.subscriber.state.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
                if let Some(reason) = state.terminal {
                    self.ended = true;
                    return Some(SessionEvent::Disconnected {
                        reason,
                        generation: self.generation,
                    });
                }
                if state.dropping && !state.reported {
                    state.reported = true;
                    return Some(SessionEvent::Lagged {
                        dropped: state.dropped,
                        generation: self.generation,
                    });
                }
                if self.queue.is_empty() {
                    *state = Lag::default();
                }
            }
            tokio::select! {
                event=self.queue.recv()=>return event,
                ()=changed=>{},
            }
        }
    }
}

pub(crate) struct SessionHub {
    generation: u64,
    subscribers: Mutex<Vec<Arc<Subscriber>>>,
}

impl SessionHub {
    pub(crate) fn new(generation: u64) -> Self {
        Self { generation, subscribers: Mutex::new(Vec::new()) }
    }
    pub(crate) fn subscribe(
        &self,
        kinds: impl IntoIterator<Item = FrameKind>,
    ) -> SessionSubscription {
        let (queue, receive) = mpsc::channel(SUBSCRIBER_QUEUE);
        let subscriber = Arc::new(Subscriber {
            kinds: kinds.into_iter().collect(),
            queue,
            state: Mutex::new(Lag::default()),
            wake: Notify::new(),
        });
        self.subscribers
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(Arc::clone(&subscriber));
        SessionSubscription {
            queue: receive,
            subscriber,
            generation: self.generation,
            ended: false,
        }
    }
    pub(crate) fn publish(&self, frame: GatewayServerFrame) {
        let kind = FrameKind::of(&frame);
        let frame = Arc::new(frame);
        self.fan_out(kind, |generation| SessionEvent::Frame {
            frame: Arc::clone(&frame),
            generation,
        });
    }

    pub(crate) fn publish_capable(&self, event: crate::gateway::session_push::CapableEvent) {
        let kind = FrameKind::of_capable(&event);
        let event = Arc::new(event);
        self.fan_out(kind, |generation| SessionEvent::Capable {
            event: Arc::clone(&event),
            generation,
        });
    }

    /// One nonblocking delivery per matching subscriber, with the shared lag accounting.
    fn fan_out(&self, kind: FrameKind, event: impl Fn(u64) -> SessionEvent) {
        let mut subscribers =
            self.subscribers.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        subscribers.retain(|subscriber| !subscriber.queue.is_closed());
        for subscriber in subscribers.iter().filter(|subscriber| subscriber.kinds.contains(&kind)) {
            let mut state =
                subscriber.state.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            if state.terminal.is_some() {
                continue;
            }
            if state.dropping {
                state.dropped = state.dropped.saturating_add(1);
                continue;
            }
            if subscriber.queue.try_send(event(self.generation)).is_err() {
                state.dropping = true;
                state.dropped = 1;
                subscriber.wake.notify_one();
            }
        }
    }
    pub(crate) fn lag(&self) {
        for subscriber in
            self.subscribers.lock().unwrap_or_else(std::sync::PoisonError::into_inner).iter()
        {
            let mut state =
                subscriber.state.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            state.dropping = true;
            state.dropped = state.dropped.saturating_add(1);
            subscriber.wake.notify_one();
        }
    }
    pub(crate) fn disconnect(&self, reason: DisconnectReason) {
        for subscriber in
            self.subscribers.lock().unwrap_or_else(std::sync::PoisonError::into_inner).iter()
        {
            subscriber.state.lock().unwrap_or_else(std::sync::PoisonError::into_inner).terminal =
                Some(reason);
            subscriber.wake.notify_one();
        }
    }
}

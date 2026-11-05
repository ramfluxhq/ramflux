// SPDX-License-Identifier: MIT OR Apache-2.0
//! Independent raw/control receivers and fixed coalesced local-control slots.
use crate::{AsyncUdpSocket, ConnectionEvent};
use std::{
    sync::{Arc, Mutex},
    task::{Context, Poll, Waker},
};
use tokio::sync::mpsc;

#[derive(Debug, Default)]
struct Slots {
    close: Option<ConnectionEvent>,
    close_seen: bool,
    rebind: Option<Arc<dyn AsyncUdpSocket>>,
    wake: Option<Waker>,
}
#[derive(Clone, Debug)]
pub(crate) struct Sender {
    raw: mpsc::UnboundedSender<ConnectionEvent>,
    control: mpsc::UnboundedSender<ConnectionEvent>,
    slots: Arc<Mutex<Slots>>,
    bounded: bool,
}
#[derive(Debug)]
pub(crate) struct Receiver {
    raw: mpsc::UnboundedReceiver<ConnectionEvent>,
    control: mpsc::UnboundedReceiver<ConnectionEvent>,
    slots: Arc<Mutex<Slots>>,
}

pub(crate) fn channel(bounded: bool) -> (Sender, Receiver) {
    let (raw, raw_recv) = mpsc::unbounded_channel();
    let (control, control_recv) = mpsc::unbounded_channel();
    let slots = Arc::new(Mutex::new(Slots::default()));
    (
        Sender {
            raw,
            control,
            slots: slots.clone(),
            bounded,
        },
        Receiver {
            raw: raw_recv,
            control: control_recv,
            slots,
        },
    )
}

impl Sender {
    pub(crate) fn send(&self, event: ConnectionEvent) -> Result<(), ()> {
        match event {
            ConnectionEvent::RawProto { .. } => self.raw.send(event).map_err(|_| ()),
            ConnectionEvent::Proto(ref proto) if proto.datagram_size().is_some() => {
                self.raw.send(event).map_err(|_| ())
            }
            ConnectionEvent::Close { error_code, reason } => {
                if self.control.is_closed() {
                    return Err(());
                }
                let mut slots = self.slots.lock().unwrap();
                if !slots.close_seen {
                    slots.close_seen = true;
                    let reason = if self.bounded && reason.len() > 256 {
                        bytes::Bytes::copy_from_slice(&reason[..256])
                    } else {
                        reason
                    };
                    slots.close = Some(ConnectionEvent::Close { error_code, reason });
                }
                let wake = slots.wake.take();
                drop(slots);
                if let Some(wake) = wake {
                    wake.wake();
                }
                Ok(())
            }
            ConnectionEvent::Rebind(socket) => {
                // Exactly one latest socket, never a queue of superseded socket owners.
                let mut slots = self.slots.lock().unwrap();
                slots.rebind = Some(socket);
                let wake = slots.wake.take();
                drop(slots);
                if let Some(wake) = wake {
                    wake.wake();
                }
                Ok(())
            }
            _ => self.control.send(event).map_err(|_| ()),
        }
    }
}
impl Receiver {
    pub(crate) fn poll_recv(
        &mut self,
        cx: &mut Context<'_>,
        raw_enabled: bool,
    ) -> Poll<Option<ConnectionEvent>> {
        // Committed ordinary controls precede terminal visibility and never wait for raw credit.
        if let Poll::Ready(event) = self.control.poll_recv(cx) {
            return Poll::Ready(event);
        }
        {
            let mut slots = self.slots.lock().unwrap();
            if let Some(close) = slots.close.take() {
                return Poll::Ready(Some(close));
            }
            if let Some(socket) = slots.rebind.take() {
                return Poll::Ready(Some(ConnectionEvent::Rebind(socket)));
            }
            if slots.wake.as_ref().is_none_or(|w| !w.will_wake(cx.waker())) {
                slots.wake = Some(cx.waker().clone());
            }
        }
        if raw_enabled {
            self.raw.poll_recv(cx)
        } else {
            Poll::Pending
        }
    }
}

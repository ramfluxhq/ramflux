// SPDX-License-Identifier: MIT OR Apache-2.0
//! Aggregate bidirectional credits retained through endpoint response consumption.
use super::*;
use std::{
    sync::Mutex,
    task::{Context, Waker},
};

/// Ordinary control credit available in each independent direction.
#[derive(Clone, Copy, Debug)]
pub struct ControlLimits {
    /// Payload and backing bytes per direction.
    pub bytes: usize,
    /// Event items per direction.
    pub items: usize,
}

#[derive(Clone, Copy, Debug, Default)]
pub(super) struct Demand {
    forward: usize,
    reverse: usize,
}

#[derive(Debug)]
pub(crate) struct CreditState {
    limits: ControlLimits,
    used: Demand,
    generation: u64,
    wake: Option<Waker>,
}

#[derive(Debug)]
pub(crate) struct Reservation {
    state: Arc<Mutex<CreditState>>,
    demand: Demand,
}

impl Drop for Reservation {
    fn drop(&mut self) {
        let wake = {
            let mut state = self.state.lock().unwrap();
            state.used.forward -= self.demand.forward;
            state.used.reverse -= self.demand.reverse;
            state.generation = state.generation.wrapping_add(1);
            state.wake.take()
        };
        if let Some(wake) = wake {
            wake.wake();
        }
    }
}

pub(super) enum Admission {
    Reserved(Arc<Reservation>),
    Pending,
    Oversize,
}

impl CreditState {
    pub(super) fn new(limits: ControlLimits) -> Arc<Mutex<Self>> {
        Arc::new(Mutex::new(Self {
            limits,
            used: Demand::default(),
            generation: 0,
            wake: None,
        }))
    }
    pub(super) fn reserve(state: &Arc<Mutex<Self>>, demand: Demand) -> Admission {
        let mut locked = state.lock().unwrap();
        // 512-byte forward event and 1024-byte reverse vector/backing reservations.
        let forward_limit = locked.limits.items.min(locked.limits.bytes / 512);
        let reverse_limit = locked.limits.items.min(locked.limits.bytes / 1024);
        if demand.forward > forward_limit || demand.reverse > reverse_limit {
            return Admission::Oversize;
        }
        if demand.forward > forward_limit - locked.used.forward
            || demand.reverse > reverse_limit - locked.used.reverse
        {
            return Admission::Pending;
        }
        locked.used.forward += demand.forward;
        locked.used.reverse += demand.reverse;
        Admission::Reserved(Arc::new(Reservation {
            state: state.clone(),
            demand,
        }))
    }
    pub(super) fn register(state: &Arc<Mutex<Self>>, cx: &Context<'_>) {
        let mut locked = state.lock().unwrap();
        if locked
            .wake
            .as_ref()
            .is_none_or(|w| !w.will_wake(cx.waker()))
        {
            locked.wake = Some(cx.waker().clone());
        }
    }
}

pub(super) struct PendingPacket {
    pub now: Instant,
    pub remote: SocketAddr,
    pub ecn: Option<EcnCodepoint>,
    pub packet: Packet,
    pub number: Option<u64>,
    pub key_update: Option<packet_crypto::DecryptPacketResult>,
    pub remaining: Option<BytesMut>,
    pub owner: Option<Arc<dyn std::any::Any + Send + Sync>>,
}

impl Connection {
    /// Enable dormant control-credit enforcement before processing peer packets.
    ///
    /// # Errors
    /// Returns an error if either ordinary direction cannot contain a response.
    #[cfg(test)]
    fn set_control_credit_limits(&mut self, limits: ControlLimits) -> Result<(), &'static str> {
        if limits.bytes < 1024 || limits.items < 2 || self.control.is_some() {
            return Err("invalid or already frozen control credit");
        }
        self.control = Some(CreditState::new(limits));
        Ok(())
    }

    pub(super) fn queue_endpoint_event(&mut self, event: EndpointEventInner) {
        let terminal = matches!(event, EndpointEventInner::Drained);
        if terminal && self.endpoint_events.iter().any(|e| e.is_drained()) {
            return;
        }
        let credit = if terminal {
            None
        } else {
            self.active_control.clone()
        };
        self.endpoint_events.push_back(EndpointEvent(event, credit));
    }

    fn control_demand(
        &self,
        packet: &Packet,
        remote: SocketAddr,
    ) -> Result<Demand, TransportError> {
        let mut demand = Demand::default();
        if !packet.header.has_frames() {
            return Ok(demand);
        }
        if remote != self.path.remote {
            demand.forward = 1;
        }
        for result in frame::Iter::new(packet.plaintext.as_ref().unwrap().clone())? {
            match result? {
                // Every attempt counts, including repeats; actual retired CIDs are idempotent.
                Frame::RetireConnectionId { .. } => {
                    demand.forward += 1;
                    demand.reverse += 1;
                }
                Frame::NewConnectionId(_) | Frame::PathResponse(_) => demand.forward += 1,
                Frame::Crypto(_) if self.is_handshaking() => {
                    // A handshake transition can issue the initial CID vector and reset binding.
                    demand.forward = demand.forward.max(2);
                    demand.reverse = demand.reverse.max(1);
                }
                _ => {}
            }
        }
        Ok(demand)
    }

    pub(super) fn admit_control_packet(&mut self, mut pending: PendingPacket) -> Option<Packet> {
        if (self.control.is_some() || self.raw_owner.is_some())
            && pending.packet.header.has_frames()
            && pending.packet.plaintext.is_none()
        {
            let bytes = mem::take(&mut pending.packet.payload).freeze();
            pending.packet.plaintext = Some(if let Some(owner) = self.raw_owner.clone() {
                Bytes::from_owner(RawBacking {
                    bytes,
                    _owner: owner,
                })
            } else {
                bytes
            });
        }
        if self.control.is_some() {
            let demand = match self.control_demand(&pending.packet, pending.remote) {
                Ok(demand) => demand,
                // Let the normal parser report the original framing error without committing effects.
                Err(error) => {
                    self.control_close(pending.now, error);
                    return None;
                }
            };
            match CreditState::reserve(self.control.as_ref().unwrap(), demand) {
                Admission::Reserved(reservation) => self.active_control = Some(reservation),
                Admission::Pending => {
                    self.pending_control = Some(pending);
                    return None;
                }
                Admission::Oversize => {
                    self.control_close(
                        pending.now,
                        TransportError::INTERNAL_ERROR("control_packet_oversize"),
                    );
                    return None;
                }
            }
        }
        if let Some(result) = pending.key_update {
            if result.outgoing_key_update_acked {
                if let Some(prev) = self.prev_crypto.as_mut() {
                    prev.end_packet = Some((result.number, pending.now));
                    self.set_key_discard_timer(pending.now, pending.packet.header.space());
                }
            }
            if result.incoming_key_update {
                self.update_keys(Some((result.number, pending.now)), true);
                self.set_key_discard_timer(pending.now, pending.packet.header.space());
            }
        }
        Some(pending.packet)
    }

    /// Terminal adapter for a fallible metadata allocation hook.
    /// Data sends RESOURCE_LIMIT; Initial/Handshake use the existing APPLICATION_ERROR conversion.
    pub fn resource_exhausted(&mut self, now: Instant) {
        if self.control_resource_closed || self.state.is_closed() {
            return;
        }
        self.control_resource_closed = true;
        self.pending_control = None;
        self.control_timer_pending = None;
        self.active_control = None;
        self.error = Some(ConnectionError::LocallyClosed);
        self.close(
            now,
            VarInt::from_u32(0x524c),
            Bytes::from_static(b"RESOURCE_LIMIT"),
        );
    }

    fn control_close(&mut self, now: Instant, error: TransportError) {
        if self.control_resource_closed {
            return;
        }
        self.control_resource_closed = true;
        self.pending_control = None;
        self.control_timer_pending = None;
        self.active_control = None;
        self.error = Some(ConnectionError::TransportError(error.clone()));
        self.close_inner(now, Close::Connection(error.into()));
    }

    pub(super) fn reserve_control_timer(&mut self, now: Instant) -> bool {
        let Some(control) = self.control.as_ref() else {
            return true;
        };
        match CreditState::reserve(
            control,
            Demand {
                forward: 1,
                reverse: 1,
            },
        ) {
            Admission::Reserved(reservation) => {
                self.active_control = Some(reservation);
                self.control_timer_pending = None;
                true
            }
            Admission::Pending => {
                self.timers.stop(Timer::PushNewCid);
                self.control_timer_pending = Some(now);
                false
            }
            Admission::Oversize => {
                self.control_close(
                    now,
                    TransportError::INTERNAL_ERROR("control_timer_oversize"),
                );
                false
            }
        }
    }

    /// Retry the single pending remainder after control consumers return credit.
    /// Returns whether packet input remains paused. Existing committed heads are not replayed.
    pub fn poll_control_resume(&mut self, cx: &mut Context<'_>) -> bool {
        if self.pending_control.is_none() && self.control_timer_pending.is_none() {
            return false;
        }
        CreditState::register(self.control.as_ref().unwrap(), cx);
        if let Some(now) = self.control_timer_pending {
            self.timers.set(Timer::PushNewCid, now);
            self.handle_timeout(now);
        }
        if self.pending_control.is_none() {
            return false;
        }
        // Register before retry so a concurrent final consumer cannot lose the wakeup.
        CreditState::register(self.control.as_ref().unwrap(), cx);
        let pending = self.pending_control.take().unwrap();
        let PendingPacket {
            now,
            remote,
            ecn,
            packet,
            number,
            key_update,
            remaining,
            owner,
        } = pending;
        self.raw_owner = owner;
        self.handle_authenticated_packet(now, remote, ecn, Ok((packet, number, key_update)), false);
        if let Some(pending) = self.pending_control.as_mut() {
            pending.remaining = remaining;
        } else if !self.control_resource_closed {
            if let Some(remaining) = remaining {
                self.handle_coalesced(now, remote, ecn, remaining);
            }
        }
        self.raw_owner = None;
        self.pending_control.is_some()
    }

    pub(crate) fn handle_first_packet_owned(
        &mut self,
        now: Instant,
        remote: SocketAddr,
        ecn: Option<EcnCodepoint>,
        packet_number: u64,
        packet: crate::packet::InitialPacket,
        remaining: Option<BytesMut>,
        owner: Option<Arc<dyn std::any::Any + Send + Sync>>,
    ) -> Result<(), ConnectionError> {
        self.raw_owner = owner;
        let result = self.handle_first_packet(now, remote, ecn, packet_number, packet, remaining);
        self.raw_owner = None;
        result
    }

    /// Whether this connection uses bounded control admission.
    pub fn control_credit_enabled(&self) -> bool {
        self.control.is_some()
    }

    /// Process an event while its allocation owner remains charged through retained backing.
    pub fn handle_event_with_owner(
        &mut self,
        event: ConnectionEvent,
        owner: Arc<dyn std::any::Any + Send + Sync>,
    ) {
        self.raw_owner = Some(owner);
        self.handle_event(event);
        self.raw_owner = None;
    }
}

pub(crate) fn own_bytes(bytes: Bytes, owner: Arc<dyn std::any::Any + Send + Sync>) -> Bytes {
    Bytes::from_owner(RawBacking {
        bytes,
        _owner: owner,
    })
}

struct RawBacking {
    bytes: Bytes,
    _owner: Arc<dyn std::any::Any + Send + Sync>,
}
impl AsRef<[u8]> for RawBacking {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

#[cfg(test)]
mod tests;

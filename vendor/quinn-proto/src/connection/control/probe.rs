// SPDX-License-Identifier: MIT OR Apache-2.0
//! Non-default dependency-test packet construction and state observation.
use super::*;
impl Connection {
    /// Test observation: used directions, generation, retries, authenticated packets,
    /// pending packet, frame effects, ACK membership, closed state and timer waiter.
    #[doc(hidden)]
    pub fn control_test_probe(&self, number: u64) -> [u64; 15] {
        let state = self.control.as_ref().unwrap().lock().unwrap();
        [
            state.used.forward as u64,
            state.used.reverse as u64,
            state.generation,
            state.revalidations,
            self.total_authed_packets,
            self.pending_control
                .as_ref()
                .and_then(|p| p.number)
                .unwrap_or(u64::MAX),
            self.stats.frame_rx.retire_connection_id,
            self.spaces[SpaceId::Data]
                .pending_acks
                .ranges()
                .contains(number) as u64,
            self.state.is_closed() as u64,
            self.control_timer_pending.is_some() as u64,
            self.stats.frame_rx.new_connection_id,
            self.path.total_recvd,
            self.spaces[SpaceId::Handshake]
                .pending_acks
                .ranges()
                .contains(number) as u64,
            self.spaces[SpaceId::Data].dedup.control_test_seen(number) as u64,
            self.spaces[SpaceId::Handshake]
                .dedup
                .control_test_seen(number) as u64,
        ]
    }
    /// Construct an encrypted wire packet using the actual peer's negotiated keys.
    #[doc(hidden)]
    pub fn control_test_packet(&self, number: u64, handshake: bool, frames: &[u8]) -> Vec<u8> {
        let space = if handshake {
            SpaceId::Handshake
        } else {
            SpaceId::Data
        };
        let keys = self.spaces[space].crypto.as_ref().unwrap();
        let number_header = PacketNumber::new(number, 0);
        let header = if handshake {
            Header::Long {
                ty: LongType::Handshake,
                src_cid: self.handshake_cid,
                dst_cid: self.rem_cids.active(),
                number: number_header,
                version: self.version,
            }
        } else {
            Header::Short {
                spin: false,
                key_phase: self.key_phase,
                dst_cid: self.rem_cids.active(),
                number: number_header,
            }
        };
        let mut bytes = Vec::new();
        let partial = header.encode(&mut bytes);
        bytes.extend_from_slice(frames);
        bytes.resize(bytes.len().max(64) + keys.packet.local.tag_len(), 0);
        partial.finish(
            &mut bytes,
            &*keys.header.local,
            Some((number, &*keys.packet.local)),
        );
        bytes
    }
    /// Arm the normal CID timer; the real Tokio driver must execute it.
    #[doc(hidden)]
    pub fn control_test_timer(&mut self, now: Instant) {
        self.timers.set(Timer::PushNewCid, now);
    }
    /// Current local CID sequence interval for valid retirement frames.
    #[doc(hidden)]
    pub fn control_test_cids(&self) -> (u64, u64) {
        self.local_cid_state.active_seq()
    }
}

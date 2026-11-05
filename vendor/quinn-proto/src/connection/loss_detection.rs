// SPDX-License-Identifier: MIT OR Apache-2.0
//! Loss selection and retirement with fallible scratch ownership.
use super::*;
impl Connection {
    pub(super) fn detect_lost_packets(&mut self, now: Instant, pn_space: SpaceId, due_to_ack: bool) -> Result<(),metadata_credit::ResourceExhausted> {
        let mut lost_packets = metadata_scratch::ScratchVec::new(self.metadata.clone(),metadata_credit::MetadataClass::LossScratch);
        let mut lost_mtu_probe = None;
        let in_flight_mtu_probe = self.path.mtud.in_flight_mtu_probe();
        let rtt = self.path.rtt.conservative();
        let loss_delay = cmp::max(rtt.mul_f32(self.config.time_threshold), TIMER_GRANULARITY);

        let largest_acked_packet = self.spaces[pn_space].largest_acked_packet.unwrap();
        let packet_threshold = self.config.packet_threshold as u64;
        let mut size_of_lost_packets = 0u64;

        // InPersistentCongestion: Determine if all packets in the time period before the newest
        // lost packet, including the edges, are marked lost. PTO computation must always
        // include max ACK delay, i.e. operate as if in Data space (see RFC9001 §7.6.1).
        let congestion_period =
            self.pto(SpaceId::Data) * self.config.persistent_congestion_threshold;
        let mut persistent_congestion_start: Option<Instant> = None;
        let mut prev_packet = None;
        let mut in_persistent_congestion = false;

        let space = &mut self.spaces[pn_space];
        space.loss_time = None;

        for (&packet, info) in space.sent_packets.range(0..largest_acked_packet) {
            if prev_packet != Some(packet.wrapping_sub(1)) {
                // An intervening packet was acknowledged
                persistent_congestion_start = None;
            }

            // Packets sent before now - loss_delay are deemed lost.
            // However, we avoid this subtraction as it can panic and there's no
            // saturating equivalent of this substraction operation with a Duration.
            let packet_too_old = now.saturating_duration_since(info.time_sent) >= loss_delay;
            if packet_too_old || largest_acked_packet >= packet + packet_threshold {
                if Some(packet) == in_flight_mtu_probe {
                    // Lost MTU probes are not included in `lost_packets`, because they should not
                    // trigger a congestion control response
                    lost_mtu_probe = in_flight_mtu_probe;
                } else {
                    lost_packets.try_push(packet)?;
                    size_of_lost_packets += info.size as u64;
                    if info.ack_eliciting && due_to_ack {
                        match persistent_congestion_start {
                            // Two ACK-eliciting packets lost more than congestion_period apart, with no
                            // ACKed packets in between
                            Some(start) if info.time_sent - start > congestion_period => {
                                in_persistent_congestion = true;
                            }
                            // Persistent congestion must start after the first RTT sample
                            None if self
                                .path
                                .first_packet_after_rtt_sample
                                .is_some_and(|x| x < (pn_space, packet)) =>
                            {
                                persistent_congestion_start = Some(info.time_sent);
                            }
                            _ => {}
                        }
                    }
                }
            } else {
                let next_loss_time = info.time_sent + loss_delay;
                space.loss_time = Some(
                    space
                        .loss_time
                        .map_or(next_loss_time, |x| cmp::min(x, next_loss_time)),
                );
                persistent_congestion_start = None;
            }

            prev_packet = Some(packet);
        }

        // OnPacketsLost
        if let Some(largest_lost) = lost_packets.last().cloned() {
            let old_bytes_in_flight = self.path.in_flight.bytes;
            let largest_lost_sent = self.spaces[pn_space].sent_packets[&largest_lost].time_sent;
            self.stats.path.lost_packets += lost_packets.len() as u64;
            self.stats.path.lost_bytes += size_of_lost_packets;
            trace!(
                "packets lost: {:?}, bytes lost: {}",
                lost_packets, size_of_lost_packets
            );

            for &packet in lost_packets.iter() {
                let info = self.spaces[pn_space].take(packet).unwrap(); // safe: lost_packets is populated just above
                self.config.qlog_sink.emit_packet_lost(
                    packet,
                    &info,
                    loss_delay,
                    pn_space,
                    now,
                    self.orig_rem_cid,
                );
                self.remove_in_flight(&info);
                for frame in info.stream_frames {
                    self.streams.retransmit(frame);
                    if self.metadata_exhausted(){return Err(metadata_credit::ResourceExhausted{class:metadata_credit::MetadataClass::SendRanges});}
                }
                self.spaces[pn_space].pending.try_merge_thin(info.retransmits)?;
                self.path.mtud.on_non_probe_lost(packet, info.size);
            }

            if self.path.mtud.black_hole_detected(now) {
                self.stats.path.black_holes_detected += 1;
                self.path
                    .congestion
                    .on_mtu_update(self.path.mtud.current_mtu());
                self.datagrams().drop_oversized();
            }

            // Don't apply congestion penalty for lost ack-only packets
            let lost_ack_eliciting = old_bytes_in_flight != self.path.in_flight.bytes;

            if lost_ack_eliciting {
                self.stats.path.congestion_events += 1;
                self.path.congestion.on_congestion_event(
                    now,
                    largest_lost_sent,
                    in_persistent_congestion,
                    size_of_lost_packets,
                );
            }
        }

        // Handle a lost MTU probe
        if let Some(packet) = lost_mtu_probe {
            let info = self.spaces[SpaceId::Data].take(packet).unwrap(); // safe: lost_mtu_probe is omitted from lost_packets, and therefore must not have been removed yet
            self.remove_in_flight(&info);
            self.path.mtud.on_probe_lost();
            self.stats.path.lost_plpmtud_probes += 1;
        }
        Ok(())
    }

}

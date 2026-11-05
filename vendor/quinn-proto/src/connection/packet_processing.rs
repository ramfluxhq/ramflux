// SPDX-License-Identifier: MIT OR Apache-2.0
//! Packet authentication, coalesced traversal and effect boundary.
use super::*;

impl Connection {
    pub(super) fn handle_coalesced(
        &mut self,
        now: Instant,
        remote: SocketAddr,
        ecn: Option<EcnCodepoint>,
        data: BytesMut,
    ) {
        self.path.total_recvd = self.path.total_recvd.saturating_add(data.len() as u64);
        let mut remaining = Some(data);
        while let Some(data) = remaining {
            match PartialDecode::new(
                data,
                &FixedLengthConnectionIdParser::new(self.local_cid_state.cid_len()),
                &[self.version],
                self.endpoint_config.grease_quic_bit,
            ) {
                Ok((partial_decode, rest)) => {
                    remaining = rest;
                    self.handle_decode(now, remote, ecn, partial_decode);
                    if let Some(pending) = self.pending_control.as_mut() { pending.remaining = remaining; return; }
                    if self.control_resource_closed { return; }
                }
                Err(e) => {
                    trace!("malformed header: {}", e);
                    return;
                }
            }
        }
    }

    fn handle_decode(
        &mut self,
        now: Instant,
        remote: SocketAddr,
        ecn: Option<EcnCodepoint>,
        partial_decode: PartialDecode,
    ) {
        if let Some(decoded) = packet_crypto::unprotect_header(
            partial_decode,
            &self.spaces,
            self.zero_rtt_crypto.as_ref(),
            self.peer_params.stateless_reset_token,
        ) {
            self.handle_packet(now, remote, ecn, decoded.packet, decoded.stateless_reset);
        }
    }

    fn handle_packet(
        &mut self,
        now: Instant,
        remote: SocketAddr,
        ecn: Option<EcnCodepoint>,
        packet: Option<Packet>,
        stateless_reset: bool,
    ) {
        self.stats.udp_rx.ios += 1;
        if let Some(ref packet) = packet {
            trace!(
                "got {:?} packet ({} bytes) from {} using id {}",
                packet.header.space(),
                packet.payload_len() + packet.header_data.len(),
                remote,
                packet.header.dst_cid(),
            );
        }

        if self.is_handshaking() && remote != self.path.remote {
            debug!("discarding packet with unexpected remote during handshake");
            return;
        }

        let decrypted = match packet {
            None => Err(None),
            Some(mut packet) => packet_crypto::decrypt_packet_body(&mut packet, &self.spaces,
                self.zero_rtt_crypto.as_ref(), self.key_phase, self.prev_crypto.as_ref(), self.next_crypto.as_ref())
                .map(|key_update| { let number = key_update.as_ref().map(|r| r.number); (packet, number, key_update) }),
        };
        self.handle_authenticated_packet(now, remote, ecn, decrypted, stateless_reset);
    }

    pub(super) fn handle_authenticated_packet(&mut self, now: Instant, remote: SocketAddr, ecn: Option<EcnCodepoint>,
        decrypted: Result<(Packet, Option<u64>, Option<packet_crypto::DecryptPacketResult>), Option<TransportError>>,
        stateless_reset: bool) {
        let was_closed = self.state.is_closed();
        let was_drained = self.state.is_drained();
        let result = match decrypted {
            _ if stateless_reset => {
                debug!("got stateless reset");
                Err(ConnectionError::Reset)
            }
            Err(Some(e)) => {
                warn!("illegal packet: {}", e);
                Err(e.into())
            }
            Err(None) => {
                debug!("failed to authenticate packet");
                self.authentication_failures += 1;
                let integrity_limit = self.spaces[self.highest_space]
                    .crypto
                    .as_ref()
                    .unwrap()
                    .packet
                    .local
                    .integrity_limit();
                if self.authentication_failures > integrity_limit {
                    Err(TransportError::AEAD_LIMIT_REACHED("integrity limit violated").into())
                } else {
                    return;
                }
            }
            Ok((packet, number, key_update)) => {
                let pending = control::PendingPacket { now, remote, ecn, packet, number, key_update, remaining: None };
                let Some(packet) = self.admit_control_packet(pending) else { return; };
                let span = match number {
                    Some(pn) => trace_span!("recv", space = ?packet.header.space(), pn),
                    None => trace_span!("recv", space = ?packet.header.space()),
                };
                let _guard = span.enter();

                let is_duplicate = |n| self.spaces[packet.header.space()].dedup.insert(n);
                if number.is_some_and(is_duplicate) {
                    debug!("discarding possible duplicate packet");
                    return;
                } else if self.state.is_handshake() && packet.header.is_short() {
                    // TODO: SHOULD buffer these to improve reordering tolerance.
                    trace!("dropping short packet during handshake");
                    return;
                } else {
                    if let Header::Initial(InitialHeader { ref token, .. }) = packet.header {
                        if let State::Handshake(ref hs) = self.state {
                            if self.side.is_server() && token != &hs.expected_token {
                                // Clients must send the same retry token in every Initial. Initial
                                // packets can be spoofed, so we discard rather than killing the
                                // connection.
                                warn!("discarding Initial with invalid retry token");
                                return;
                            }
                        }
                    }

                    if !self.state.is_closed() {
                        let spin = match packet.header {
                            Header::Short { spin, .. } => spin,
                            _ => false,
                        };
                        self.on_packet_authenticated(
                            now,
                            packet.header.space(),
                            ecn,
                            number,
                            spin,
                            packet.header.is_1rtt(),
                        );
                    }

                    self.process_decrypted_packet(now, remote, number, packet)
                }
            }
        };

        self.active_control = None;

        // State transitions for error cases
        if let Err(conn_err) = result {
            self.error = Some(conn_err.clone());
            self.state = match conn_err {
                ConnectionError::ApplicationClosed(reason) => State::closed(reason),
                ConnectionError::ConnectionClosed(reason) => State::closed(reason),
                ConnectionError::Reset
                | ConnectionError::TransportError(TransportError {
                    code: TransportErrorCode::AEAD_LIMIT_REACHED,
                    ..
                }) => State::Drained,
                ConnectionError::TimedOut => {
                    unreachable!("timeouts aren't generated by packet processing");
                }
                ConnectionError::TransportError(err) => {
                    debug!("closing connection due to transport error: {}", err);
                    State::closed(err)
                }
                ConnectionError::VersionMismatch => State::Draining,
                ConnectionError::LocallyClosed => {
                    unreachable!("LocallyClosed isn't generated by packet processing");
                }
                ConnectionError::CidsExhausted => {
                    unreachable!("CidsExhausted isn't generated by packet processing");
                }
            };
        }

        if !was_closed && self.state.is_closed() {
            self.close_common();
            if !self.state.is_drained() {
                self.set_close_timer(now);
            }
        }
        if !was_drained && self.state.is_drained() {
            self.queue_endpoint_event(EndpointEventInner::Drained);
            // Close timer may have been started previously, e.g. if we sent a close and got a
            // stateless reset in response
            self.timers.stop(Timer::Close);
        }

        // Transmit CONNECTION_CLOSE if necessary
        if let State::Closed(_) = self.state {
            self.close = remote == self.path.remote;
        }
    }

}

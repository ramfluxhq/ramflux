// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Complete-body scope checks after an atomic mesh claim; replies retain charged queue owners.
use super::{
    FullArm, FullControlFrame, FullDataAccepted, FullDataFrame, FullNativeAdmission,
    FullResumeServer, FullRoute, FullSendPermit, PairingRelayError, wire,
};
use ramflux_protocol::custody::pairing::{
    PairingWire,
    full_transfer::{
        SecretBase64,
        relay::{CloseFull, PollFull, PollFullControl, SendFullControl},
    },
};
use zeroize::Zeroizing;

pub enum FullAdmittedReply {
    Sent(u64),
    ControlSent,
    Packet(Option<FullDataFrame>),
    Control(Option<FullControlFrame>),
    Closed,
}
impl FullSendPermit {
    fn verify_scope(
        &self,
        lease: &str,
        epoch: &str,
        role: &str,
        token: &SecretBase64,
    ) -> Result<(), PairingRelayError> {
        let token = token.decode(32).map_err(|_| PairingRelayError::WrongContext)?;
        let matches = super::constant_time_eq(self.token.as_ref(), token.as_slice());
        if self.lease_id != lease || self.epoch != epoch || self.role != role || !matches {
            return Err(PairingRelayError::WrongContext);
        }
        Ok(())
    }
    pub(in crate::pairing_relay) fn route(&self) -> FullRoute<'_> {
        FullRoute {
            lease_id: &self.lease_id,
            epoch: &self.epoch,
            role: &self.role,
            token: &self.token,
        }
    }
}
impl FullResumeServer {
    pub(in crate::pairing_relay) fn accept_forward(
        &mut self,
        permit: FullSendPermit,
        body: Vec<u8>,
        admission: &FullNativeAdmission<'_>,
    ) -> Result<FullAdmittedReply, PairingRelayError> {
        let mut body = Zeroizing::new(body);
        let arm = permit.arm.ok_or(PairingRelayError::WrongContext)?;
        if body.len() != permit.body.reserved_bytes() || body.capacity() > body.len() {
            return Err(PairingRelayError::WrongContext);
        }
        match arm {
            FullArm::Send => {
                let accepted = self.accept_send(permit, std::mem::take(&mut *body), admission)?;
                let (FullDataAccepted::Accepted(counter) | FullDataAccepted::Duplicate(counter)) =
                    accepted;
                Ok(FullAdmittedReply::Sent(counter))
            }
            FullArm::SendControl => {
                let request =
                    SendFullControl::from_wire_bytes(&body).map_err(|error| wire(&error))?;
                permit.verify_scope(
                    &request.control.lease_id,
                    &request.control.epoch,
                    &request.control.role,
                    &request.token,
                )?;
                self.send_control(&request, admission)?;
                Ok(FullAdmittedReply::ControlSent)
            }
            FullArm::PollControl => {
                let request =
                    PollFullControl::from_wire_bytes(&body).map_err(|error| wire(&error))?;
                permit.verify_scope(
                    &request.lease_id,
                    &request.epoch,
                    &request.role,
                    &request.token,
                )?;
                self.poll_control(&request, admission).map(FullAdmittedReply::Control)
            }
            FullArm::Poll => {
                let request = PollFull::from_wire_bytes(&body).map_err(|error| wire(&error))?;
                permit.verify_scope(
                    &request.lease_id,
                    &request.epoch,
                    &request.role,
                    &request.token,
                )?;
                self.poll_data(
                    &permit.route(),
                    request.acknowledged.map(|value| value.0),
                    admission,
                )
                .map(FullAdmittedReply::Packet)
            }
            FullArm::Close => {
                let request = CloseFull::from_wire_bytes(&body).map_err(|error| wire(&error))?;
                permit.verify_scope(
                    &request.lease_id,
                    &request.epoch,
                    &request.role,
                    &request.token,
                )?;
                let (index, _) = self.authenticate(&permit.route(), admission)?;
                self.ready.swap_remove(index);
                for ticket in &mut self.forward {
                    if ticket
                        .as_ref()
                        .is_some_and(|entry| entry.matches_epoch(&permit.lease_id, &permit.epoch))
                    {
                        ticket.take();
                    }
                }
                // The grant/lease and each endpoint's durable stage remain untouched.
                Ok(FullAdmittedReply::Closed)
            }
        }
    }
}

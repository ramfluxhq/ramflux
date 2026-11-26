// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Device policy, activity and in-band clear sent over the authenticated session (CENTRAL
//! K9-K12). Each send is fire-and-forget at the wire; the node replies nothing.

use super::GatewaySessionEngine;
use super::protocol::{GatewayClientFrame, GatewayDeviceClass};
use crate::SdkError;

impl GatewaySessionEngine {
    /// Record this device's class and mute at the home node. The value is kept and re-sent on
    /// every reconnect (`register_push_route` replays it).
    /// # Errors
    /// Returns a transport error when the frame cannot be written.
    pub async fn send_device_policy(
        &mut self,
        device_class: GatewayDeviceClass,
        muted: bool,
    ) -> Result<(), SdkError> {
        self.config.device_policy = Some((device_class, muted));
        self.write_frame(&GatewayClientFrame::DevicePolicy { device_class, muted }).await
    }

    /// "User active now". The caller rate-limits (at most one per 60 s).
    /// # Errors
    /// Returns a transport error when the frame cannot be written.
    pub async fn send_activity(&mut self) -> Result<(), SdkError> {
        self.write_frame(&GatewayClientFrame::Activity {}).await
    }

    /// Notification state is empty on this device.
    /// # Errors
    /// Returns a transport error when the frame cannot be written.
    pub async fn send_notifications_cleared(&mut self) -> Result<(), SdkError> {
        self.write_frame(&GatewayClientFrame::NotificationsCleared {}).await
    }
}

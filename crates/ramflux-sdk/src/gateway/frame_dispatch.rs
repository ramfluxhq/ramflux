// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! One exhaustive session-frame classification and per-helper reply registry.

use super::GatewayServerFrame;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum FrameKind {
    PushRouteRegistered,
    PushRouteRefused,
    PushRouteDeregistered,
    VoiceLease,
    SessionEstablished,
    Deliver,
    ForwardAck,
    OwnDeviceFanout,
    IdentityRegistered,
    IdentityRegistrationRejected,
    PrincipalManifest,
    PrekeyPublished,
    Prekey,
    RelayTokenIssued,
    RelayTokenV3Issued,
    Ack,
    Cursor,
    Resume,
    Nack,
    Heartbeat,
    Drain,
    InBandWake,
    Ephemeral,
    EphemeralResult,
    Close,
    /// A capable `resync` event (negotiated sessions only).
    Resync,
    CallResolved,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum FrameClass {
    PushRoute,
    Reply,
    Event,
    Terminal,
    Unexpected,
}

impl FrameKind {
    pub(crate) const fn of(frame: &GatewayServerFrame) -> Self {
        match frame {
            GatewayServerFrame::PushRouteRegistered { .. } => Self::PushRouteRegistered,
            GatewayServerFrame::PushRouteRefused { .. } => Self::PushRouteRefused,
            GatewayServerFrame::PushRouteDeregistered { .. } => Self::PushRouteDeregistered,
            GatewayServerFrame::VoiceLease { .. } => Self::VoiceLease,
            GatewayServerFrame::SessionEstablished { .. } => Self::SessionEstablished,
            GatewayServerFrame::Deliver { .. } => Self::Deliver,
            GatewayServerFrame::ForwardAck { .. } => Self::ForwardAck,
            GatewayServerFrame::OwnDeviceFanout { .. } => Self::OwnDeviceFanout,
            GatewayServerFrame::IdentityRegistered { .. } => Self::IdentityRegistered,
            GatewayServerFrame::IdentityRegistrationRejected { .. } => {
                Self::IdentityRegistrationRejected
            }
            GatewayServerFrame::PrincipalManifest { .. } => Self::PrincipalManifest,
            GatewayServerFrame::PrekeyPublished { .. } => Self::PrekeyPublished,
            GatewayServerFrame::Prekey { .. } => Self::Prekey,
            GatewayServerFrame::RelayTokenIssued { .. } => Self::RelayTokenIssued,
            GatewayServerFrame::RelayTokenV3Issued { .. } => Self::RelayTokenV3Issued,
            GatewayServerFrame::Ack { .. } => Self::Ack,
            GatewayServerFrame::Cursor { .. } => Self::Cursor,
            GatewayServerFrame::Resume { .. } => Self::Resume,
            GatewayServerFrame::Nack { .. } => Self::Nack,
            GatewayServerFrame::Heartbeat { .. } => Self::Heartbeat,
            GatewayServerFrame::Drain { .. } => Self::Drain,
            GatewayServerFrame::InBandWake { .. } => Self::InBandWake,
            GatewayServerFrame::Ephemeral { .. } => Self::Ephemeral,
            GatewayServerFrame::EphemeralResult { .. } => Self::EphemeralResult,
            GatewayServerFrame::Close { .. } => Self::Close,
            GatewayServerFrame::CallResolved { .. } => Self::CallResolved,
        }
    }

    /// The kind a subscriber filters on; a capable deliver shares `Deliver` with legacy.
    pub(crate) const fn of_capable(event: &super::session_push::CapableEvent) -> Self {
        match event {
            super::session_push::CapableEvent::Deliver { .. } => Self::Deliver,
            super::session_push::CapableEvent::Resync { .. } => Self::Resync,
        }
    }

    pub(crate) const fn class(self) -> FrameClass {
        match self {
            Self::PushRouteRegistered | Self::PushRouteRefused | Self::PushRouteDeregistered => {
                FrameClass::PushRoute
            }
            Self::Deliver
            | Self::InBandWake
            | Self::Resync
            | Self::Ephemeral
            | Self::CallResolved => FrameClass::Event,
            Self::Drain | Self::Close => FrameClass::Terminal,
            Self::SessionEstablished => FrameClass::Unexpected,
            Self::VoiceLease
            | Self::ForwardAck
            | Self::OwnDeviceFanout
            | Self::IdentityRegistered
            | Self::IdentityRegistrationRejected
            | Self::PrincipalManifest
            | Self::PrekeyPublished
            | Self::Prekey
            | Self::RelayTokenIssued
            | Self::RelayTokenV3Issued
            | Self::Ack
            | Self::Cursor
            | Self::Resume
            | Self::Nack
            | Self::Heartbeat
            | Self::EphemeralResult => FrameClass::Reply,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ExpectedReply {
    Heartbeat,
    Submit,
    EphemeralSubmit,
    Fanout,
    Ack,
    Cursor,
    Resume,
    Identity,
    PublishPrekey,
    Manifest,
    Prekey,

    RelayTokenV3,
    VoiceLease,
    PushRoute,
}

impl ExpectedReply {
    pub(crate) const fn accepts(self, kind: FrameKind) -> bool {
        if matches!(kind, FrameKind::Nack) {
            return true;
        }
        match self {
            Self::Heartbeat => matches!(kind, FrameKind::Heartbeat),
            Self::Submit => matches!(kind, FrameKind::ForwardAck),
            Self::EphemeralSubmit => matches!(kind, FrameKind::EphemeralResult),
            Self::Fanout => matches!(kind, FrameKind::OwnDeviceFanout),
            Self::Ack => matches!(kind, FrameKind::Ack),
            Self::Cursor => matches!(kind, FrameKind::Cursor),
            Self::Resume => matches!(kind, FrameKind::Resume),
            Self::Identity => matches!(
                kind,
                FrameKind::IdentityRegistered | FrameKind::IdentityRegistrationRejected
            ),
            Self::PublishPrekey => matches!(kind, FrameKind::PrekeyPublished),
            Self::Manifest => matches!(kind, FrameKind::PrincipalManifest),
            Self::Prekey => matches!(kind, FrameKind::Prekey),

            Self::RelayTokenV3 => matches!(kind, FrameKind::RelayTokenV3Issued),
            Self::VoiceLease => matches!(kind, FrameKind::VoiceLease),
            Self::PushRoute => matches!(
                kind,
                FrameKind::PushRouteRegistered
                    | FrameKind::PushRouteRefused
                    | FrameKind::PushRouteDeregistered
            ),
        }
    }
}

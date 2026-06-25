use serde::Serialize;

use crate::{
    A2iControlEvent, A2uiSurfaceEvent, Ack, BotEvent, BotInstallGrant, BotManifest, BranchProof,
    ConversationEvent, Cursor, DeviceProof, Envelope, EventId, FederationHandshake,
    FriendLinkEvent, GroupEvent, HomeNodeMigrationProof, IdentityDeletionProof, IdentityEvent,
    McpGrant, MessageEvent, Nack, NotificationWake, ObjectChunkRequest, ObjectManifest,
    SignedRequest, domain,
};

pub trait ProtocolObject: Serialize {
    fn domain(&self) -> &'static str;
    fn replay_key(&self) -> Option<String>;
}

macro_rules! impl_protocol_object {
    ($ty:ty, $domain:expr, $key:expr) => {
        impl ProtocolObject for $ty {
            fn domain(&self) -> &'static str {
                $domain
            }

            fn replay_key(&self) -> Option<String> {
                ($key)(self)
            }
        }
    };
}

impl_protocol_object!(Envelope, domain::ENVELOPE, |v: &Envelope| Some(format!(
    "{}:{}",
    v.domain, v.envelope_id
)));
impl_protocol_object!(SignedRequest, domain::SIGNED_REQUEST, |v: &SignedRequest| Some(format!(
    "{}:{}:{}",
    v.source_device_id, v.nonce, v.request_id
)));
impl_protocol_object!(DeviceProof, domain::DEVICE_PROOF, |v: &DeviceProof| Some(format!(
    "{}:{}:{}",
    v.domain, v.device_id, v.nonce
)));
impl_protocol_object!(BranchProof, domain::BRANCH_PROOF, |v: &BranchProof| Some(format!(
    "{}:{}",
    v.domain, v.proof_id
)));
impl_protocol_object!(
    HomeNodeMigrationProof,
    domain::HOME_NODE_MIGRATION_PROOF,
    |v: &HomeNodeMigrationProof| {
        Some(format!("{}:{}:{}", v.identity_commitment, v.nonce, v.proof_id))
    }
);
impl_protocol_object!(
    IdentityDeletionProof,
    domain::IDENTITY_DELETION_PROOF,
    |v: &IdentityDeletionProof| {
        Some(format!("{}:{}:{}", v.identity_commitment, v.nonce, v.proof_id))
    }
);
impl_protocol_object!(Ack, domain::ACK, |v: &Ack| Some(format!("{}:{}", v.domain, v.ack_id)));
impl_protocol_object!(Nack, domain::NACK, |v: &Nack| Some(format!("{}:{}", v.domain, v.nack_id)));
impl_protocol_object!(Cursor, domain::CURSOR, |v: &Cursor| Some(format!(
    "{}:{}",
    v.domain, v.cursor_id
)));
impl_protocol_object!(EventId, domain::EVENT, |v: &EventId| Some(format!(
    "{}:{}",
    v.domain, v.event_id
)));
impl_protocol_object!(IdentityEvent, domain::IDENTITY_EVENT, |v: &IdentityEvent| {
    Some(format!("{}:{}", v.domain, v.event_id))
});
impl_protocol_object!(FriendLinkEvent, domain::FRIEND_EVENT, |v: &FriendLinkEvent| {
    Some(format!("{}:{}", v.domain, v.event_id))
});
impl_protocol_object!(GroupEvent, domain::GROUP_EVENT, |v: &GroupEvent| Some(format!(
    "{}:{}",
    v.domain, v.event_id
)));
impl_protocol_object!(ConversationEvent, domain::CONVERSATION_EVENT, |v: &ConversationEvent| {
    Some(format!("{}:{}", v.domain, v.event_id))
});
impl_protocol_object!(MessageEvent, domain::MESSAGE_EVENT, |v: &MessageEvent| {
    Some(format!("{}:{}", v.domain, v.event_id))
});
impl_protocol_object!(ObjectManifest, domain::OBJECT_MANIFEST, |v: &ObjectManifest| {
    Some(format!("{}:{}", v.domain, v.object_id))
});
impl_protocol_object!(
    ObjectChunkRequest,
    domain::OBJECT_CHUNK_REQUEST,
    |v: &ObjectChunkRequest| {
        Some(format!("{}:{}:{}", v.domain, v.request_id, v.resume_token.as_deref().unwrap_or("")))
    }
);
impl_protocol_object!(A2iControlEvent, domain::A2I_CONTROL, |v: &A2iControlEvent| {
    Some(format!("{}:{}", v.domain, v.correlation_id))
});
impl_protocol_object!(A2uiSurfaceEvent, domain::A2UI_SURFACE, |v: &A2uiSurfaceEvent| {
    Some(format!("{}:{}", v.domain, v.correlation_id))
});
impl_protocol_object!(McpGrant, domain::MCP_GRANT, |v: &McpGrant| Some(format!(
    "{}:{}",
    v.domain, v.grant_id
)));
impl_protocol_object!(BotManifest, domain::BOT_MANIFEST, |v: &BotManifest| {
    Some(format!("{}:{}", v.domain, v.bot_identity_commitment))
});
impl_protocol_object!(BotEvent, domain::BOT_EVENT, |v: &BotEvent| Some(format!(
    "{}:{}",
    v.domain, v.event_id
)));
impl_protocol_object!(BotInstallGrant, domain::BOT_INSTALL_GRANT, |v: &BotInstallGrant| {
    Some(format!("{}:{}", v.domain, v.grant_id))
});
impl_protocol_object!(NotificationWake, domain::NOTIFICATION_WAKE, |v: &NotificationWake| {
    Some(format!("{}:{}", v.domain, v.wake_id))
});
impl_protocol_object!(
    FederationHandshake,
    domain::FEDERATION_HANDSHAKE,
    |v: &FederationHandshake| { Some(format!("{}:{}", v.domain, v.handshake_id)) }
);

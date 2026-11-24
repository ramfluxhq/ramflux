// SPDX-License-Identifier: BSD-3-Clause
//! Host requests are inert: the SDK rechecks authority and consumes replies once.
use crate::EventToken;
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostSlot {
    pub id: String,
    pub key: String,
    pub token: EventToken,
    #[serde(flatten)]
    pub request: SlotRequest,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum SlotRequest {
    Approval {
        request_id: String,
        request_ref: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        task_binding: Option<ramflux_protocol::a2ui::TaskBinding>,
        /// Verified row only. Absent when the SDK has no matching approval.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        facts: Option<crate::ApprovalFacts>,
    },
    Modal {
        trigger_key: String,
        content_key: String,
    },
    LinkOpen {
        request_id: String,
        url: String,
    },
    Image {
        request_id: String,
        attachment: Value,
        description: String,
        fit: String,
        variant: String,
    },
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SlotOutcome {
    Confirm,
    Deny,
    Cancel,
    Unavailable,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostSlotReply {
    pub token: EventToken,
    pub slot_id: String,
    pub request_id: String,
    pub outcome: SlotOutcome,
}
/// Trusted SDK-to-native image callback. Bytes never enter the VM or JSON tree.
pub struct ImageResult<'a> {
    pub token: EventToken,
    pub slot_id: &'a str,
    pub request_id: &'a str,
    pub result: Result<(&'a str, &'a [u8]), &'a str>,
}

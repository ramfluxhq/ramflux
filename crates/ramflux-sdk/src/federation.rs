#![allow(clippy::missing_errors_doc)]
#![allow(clippy::wildcard_imports)]
#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct SdkFederatedEnvelopeForwardRequest {
    #[serde(flatten)]
    pub signed: ramflux_protocol::SignedFields,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub admin_token: Option<String>,
    pub source_node_id: String,
    pub target_node_id: String,
    pub delivery_class: String,
    pub required_capability: String,
    pub envelope: ramflux_protocol::Envelope,
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct SdkFederatedEnvelopeForwardResponse {
    pub accepted: bool,
    pub source_node_id: String,
    pub target_node_id: String,
    pub delivery: SdkFederatedSubmitResponse,
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct SdkFederatedSubmitResponse {
    pub outcome: String,
    pub target_delivery_id: String,
    pub inbox_seq: Option<u64>,
    pub cursor: Option<serde_json::Value>,
}

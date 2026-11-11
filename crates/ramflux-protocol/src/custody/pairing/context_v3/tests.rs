// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain
use super::*;
use crate::custody::pairing::WireError;
use crate::{canonical_json_bytes, domain};
use serde_json::{Value, json};
type TestResult<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;

pub(crate) fn fixture() -> TestResult<Value> {
    let fixture: Value =
        serde_json::from_str(include_str!("../../../../fixtures/pairing_v2/vectors.json"))?;
    let mut value = fixture["transcript"].clone();
    value["schema"] = json!("ramflux.pairing.Transcript.v3");
    value["version"] = json!(3);
    for name in ["initiator", "responder"] {
        let role = &mut value[name];
        role["schema"] = json!("ramflux.pairing.RoleContext.v3");
        role["version"] = json!(3);
        role["transfer_profile"] = json!("full_account_data_v1");
        role["hpke_key"] =
            json!(crate::encode_base64url([if name == "initiator" { 91 } else { 92 }; 32]));
        let common = &mut role["common"];
        common["schema"] = json!("ramflux.pairing.Common.v3");
        common["version"] = json!(3);
        common["purpose"] = json!("primary_transfer");
        common["requested_role"] = json!("primary");
        common["transfer_id"] = common["invitation_id"].clone();
        common["hpke_suite"] = json!(domain::CUSTODY_TRANSFER_HPKE_SUITE);
        common["data_selection"] = json!({"full_account_data_v1":{}});
    }
    Ok(value)
}
#[test]
fn pairing_v3_round_trip_and_v2_decoders_remain_closed() -> TestResult {
    let value = fixture()?;
    let bytes = canonical_json_bytes(&value)?;
    let transcript = TranscriptV3::from_wire_bytes(&bytes)?;
    assert_eq!(transcript.to_wire_bytes()?, bytes);
    assert!(super::super::Transcript::from_wire_bytes(&bytes).is_err());
    let role = transcript.initiator.to_wire_bytes()?;
    assert!(RoleContext::from_wire_bytes(&role).is_err());
    let common = transcript.initiator.common.to_wire_bytes()?;
    assert!(Common::from_wire_bytes(&common).is_err());
    Ok(())
}
#[test]
fn pairing_v3_rejects_partial_selection_missing_profile_and_unknown_arms() -> TestResult {
    for selection in [
        json!({"selected_keys":[]}),
        json!({"full_account_data_v1":{"extra":true}}),
        json!({"full_account_data_v1":{},"selected_keys":[]}),
        json!({"full_account_data_v2":{}}),
    ] {
        let mut value = fixture()?;
        value["initiator"]["common"]["data_selection"] = selection;
        assert!(TranscriptV3::from_wire_bytes(&canonical_json_bytes(&value)?).is_err());
    }
    for profile in [Value::Null, json!("selected_keys"), json!("full_account_data_v2")] {
        let mut value = fixture()?;
        value["initiator"]["transfer_profile"] = profile;
        assert!(TranscriptV3::from_wire_bytes(&canonical_json_bytes(&value)?).is_err());
    }
    let mut value = fixture()?;
    value["initiator"].as_object_mut().ok_or("role")?.remove("transfer_profile");
    assert!(TranscriptV3::from_wire_bytes(&canonical_json_bytes(&value)?).is_err());
    Ok(())
}
#[test]
fn pairing_v3_refuses_v2_reply_and_duplicate_context_fields() -> TestResult {
    let bytes = canonical_json_bytes(&fixture()?["initiator"])?;
    super::super::require_context_version(&bytes, 3)?;
    assert_eq!(
        super::super::require_context_version(&bytes, 2),
        Err(super::super::WireError::Field("UpdateRequired"))
    );
    let duplicate =
        String::from_utf8(bytes)?.replace("\"version\":3", "\"version\":3,\"version\":3");
    assert!(RoleContextV3::from_wire_bytes(duplicate.as_bytes()).is_err());
    Ok(())
}

#[test]
fn pairing_v3_common_preserves_selected_keys_arm_but_full_roles_refuse_it() -> TestResult {
    let value = fixture()?;
    let mut common =
        CommonV3::from_wire_bytes(&canonical_json_bytes(&value["initiator"]["common"])?)?;
    common.data_selection = DataSelectionV3::SelectedKeys(vec![DataSelection {
        key_id: "history".into(),
        purpose: "history".into(),
    }]);
    let encoded = common.to_wire_bytes()?;
    assert_eq!(CommonV3::from_wire_bytes(&encoded)?.data_selection, common.data_selection);
    let mut role = RoleContextV3::from_wire_bytes(&canonical_json_bytes(&value["initiator"])?)?;
    role.common = common;
    assert_eq!(role.validate(), Err(super::super::WireError::Field("UpdateRequired")));
    Ok(())
}

#[test]
fn pairing_v3_full_invitation_projection_preserves_bindings_and_refuses_selected_key_upgrade()
-> TestResult {
    let transcript = TranscriptV3::from_wire_bytes(&canonical_json_bytes(&fixture()?)?)?;
    let common = &transcript.initiator.common;
    let mut invitation = super::super::native::Invitation {
        schema: "ramflux.pairing.Invitation.v2".into(),
        version: 2,
        invitation_id: common.invitation_id.clone(),
        issuer_seq: common.issuer_seq,
        request_id: crate::encode_base64url([31; 32]),
        node_key: crate::encode_base64url([32; 32]),
        public_origin: "https://relay.example:443".into(),
        account_anchor: common.account_anchor.clone(),
        primary_ref: transcript.initiator.device_ref.clone(),
        base_record_hash: common.record_hash.clone(),
        base_epoch: common.device_set_epoch,
        purpose: common.purpose.clone(),
        recipient_mode: common.recipient_mode.clone(),
        destination_ref: common.destination_ref.clone(),
        capabilities: common.capabilities.clone(),
        lease_not_before: common.lease_not_before,
        lease_expires_at: common.lease_expires_at,
        data_selection: Vec::new(),
        transfer_id: common.transfer_id.clone(),
        created_at: common.expires_at - 300,
        expires_at: common.expires_at,
    };
    assert_eq!(
        CommonV3::from_full_invitation(&invitation, common.master_public_key.clone())?,
        *common
    );
    invitation
        .data_selection
        .push(DataSelection { key_id: "history".into(), purpose: "history".into() });
    assert_eq!(
        CommonV3::from_full_invitation(&invitation, common.master_public_key.clone()),
        Err(WireError::Field("UpdateRequired"))
    );
    Ok(())
}

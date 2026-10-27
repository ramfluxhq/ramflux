// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Bounded registration reconciliation and refresh scheduling for short-lived session proofs.
use super::invalid;
use crate::prelude::*;
use ramflux_protocol::SignedDeviceSetRecord;
const REFRESH_AT: &str = "identity/owned_proof_refresh_at";
pub(crate) const DEFAULT_PROOF_LIFETIME_SECONDS: i64 = 3600;
pub(crate) fn proof_lifetime_seconds() -> Result<i64, SdkError> {
    #[cfg(feature = "itest-identity-proof")]
    match std::env::var("RAMFLUX_TEST_BRANCH_PROOF_TTL_SECS") {
        Ok(value) => return parse_test_proof_lifetime(&value),
        Err(std::env::VarError::NotUnicode(_)) => return Err(invalid("invalid test proof TTL")),
        Err(std::env::VarError::NotPresent) => {}
    }
    Ok(DEFAULT_PROOF_LIFETIME_SECONDS)
}
#[cfg(any(test, feature = "itest-identity-proof"))]
fn parse_test_proof_lifetime(value: &str) -> Result<i64, SdkError> {
    value
        .parse::<i64>()
        .ok()
        .filter(|ttl| (4..=DEFAULT_PROOF_LIFETIME_SECONDS).contains(ttl))
        .ok_or_else(|| invalid("test proof TTL must be 4..3600 seconds"))
}
#[derive(Clone, Copy)]
pub(crate) struct RegistrationTarget<'a> {
    pub commitment: &'a str,
    pub device: &'a str,
    pub delivery: &'a str,
}
impl RamfluxClient {
    pub(crate) fn own_proof_refresh_due(&self, now: i64) -> Result<bool, SdkError> {
        let db = self.account_db()?;
        let own = self.owned_device_identity()?;
        if let Some(manifest) = db.load_actor_state::<SdkDeviceManifestResponse>(&format!(
            "identity/manifest-root/{}",
            own.root_commitment()
        ))? && let Some(device) =
            manifest.devices.iter().find(|device| device.device_id == own.device_id())
            && let Some(proof) = &device.branch_proof
            && now
                >= proof
                    .issued_at
                    .saturating_add((proof.expires_at.saturating_sub(proof.issued_at)) / 2)
        {
            return Ok(true);
        }
        if let Some(at) = db.load_actor_state::<i64>(REFRESH_AT)? {
            return Ok(now >= at);
        }
        let root = self.identity_root.as_ref().ok_or(SdkError::IdentityRootMissing)?;
        Ok(self
            .observed_device_set(&ramflux_crypto::identity_root_commitment(
                &root.signing_key.verifying_key(),
            ))?
            .is_some())
    }
    pub(crate) fn record_owned_proof_published(&self, now: i64) -> Result<(), SdkError> {
        self.account_db()?
            .persist_actor_state(REFRESH_AT, &now.saturating_add(proof_lifetime_seconds()? / 2))?;
        Ok(())
    }
    pub(crate) fn validate_registration_ack(
        &self,
        target: &RegistrationTarget<'_>,
        response: &SdkIdentityRegistrationResponse,
    ) -> Result<(), SdkError> {
        let branch = self.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?;
        if !response.session_bound
            || response.device_id != target.device
            || response.principal_id != branch.principal_id
            || response.device_epoch != branch.device_epoch
            || response.target_delivery_id != target.delivery
        {
            return Err(invalid("identity registration ACK mismatch"));
        }
        Ok(())
    }
    pub(crate) fn register_owned_via_http(
        &self,
        gateway_url: &str,
        target: RegistrationTarget<'_>,
        session_id: &str,
    ) -> Result<(), SdkError> {
        let mut last = None;
        for _ in 0..3 {
            let remote: Option<SdkDeviceManifestResponse> = sdk_http_get_json(
                gateway_url,
                &format!("/mvp1/device-manifest/{}", target.commitment),
            )?;
            let record = self.prepare_owned_authority(remote.as_ref())?;
            self.account_db()?.persist_actor_state("identity/registration_set", &record)?;
            let request = self.mvp1_identity_registration_request(
                target.device,
                target.delivery,
                session_id,
                target.commitment,
            )?;
            match sdk_http_post_json::<_, SdkIdentityRegistrationResponse>(
                gateway_url,
                "/mvp1/identity/register",
                &request,
            ) {
                Ok(response) => {
                    self.validate_registration_ack(&target, &response)?;
                    return self.accept_owned_record(&record);
                }
                Err(error) => last = Some(error),
            }
        }
        Err(last.unwrap_or_else(|| invalid("registration reconciliation retry limit reached")))
    }
    pub(crate) async fn register_owned_via_request(
        &self,
        gateway: &GatewaySessionConfig,
        target: RegistrationTarget<'_>,
    ) -> Result<(), SdkError> {
        let mut last = None;
        for _ in 0..3 {
            let record = self.prepare_owned_authority_via_gateway(gateway).await?;
            self.account_db()?.persist_actor_state("identity/registration_set", &record)?;
            let request = self.mvp1_identity_registration_request(
                target.device,
                target.delivery,
                &format!("pre_session_for_{}", target.device),
                target.commitment,
            )?;
            match sdk_gateway_post_json::<_, SdkIdentityRegistrationResponse>(
                gateway,
                "/mvp1/identity/register",
                &request,
            )
            .await
            {
                Ok(response) => {
                    self.validate_registration_ack(&target, &response)?;
                    return self.accept_owned_record(&record);
                }
                Err(error) => last = Some(error),
            }
        }
        Err(last.unwrap_or_else(|| invalid("registration reconciliation retry limit reached")))
    }
    pub(crate) async fn register_owned_via_session(
        &self,
        engine: &mut GatewaySessionEngine,
        target: RegistrationTarget<'_>,
    ) -> Result<(), SdkError> {
        let mut last = None;
        for _ in 0..3 {
            let record: SignedDeviceSetRecord =
                self.prepare_owned_authority_via_gateway(&engine.config).await?;
            self.account_db()?.persist_actor_state("identity/registration_set", &record)?;
            let request = self.mvp1_identity_registration_request(
                target.device,
                target.delivery,
                &engine.session().session_id,
                target.commitment,
            )?;
            match engine.register_identity(request).await {
                Ok(response) => {
                    self.validate_registration_ack(&target, &response)?;
                    return self.accept_owned_record(&record);
                }
                Err(error) => last = Some(error),
            }
        }
        Err(last.unwrap_or_else(|| invalid("registration reconciliation retry limit reached")))
    }
}

#[cfg(test)]
mod lifetime_tests {
    use super::*;
    #[test]
    fn test_only_ttl_is_short_bounded_and_fails_closed_on_invalid_settings() {
        for value in ["4", "60", "3600"] {
            assert!(parse_test_proof_lifetime(value).is_ok());
        }
        for value in ["0", "3", "3601", "-1", "bad", ""] {
            assert!(parse_test_proof_lifetime(value).is_err());
        }
    }
}

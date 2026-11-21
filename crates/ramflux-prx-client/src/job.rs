// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! `GET /api/jobs/{job_id}`: the status of a turn admitted by `post_turn` (`run_id` is set for
//! an rf-shaped turn). A job is kept in memory for one hour after it ends, so a missing job is
//! not proof that a run never happened; the durable `run_id` is the reference rf keeps.

use crate::capabilities::{Capabilities, MESSAGE_TARGET_V1, require};
use crate::client::PrxClient;
use crate::error::{ApiCode, PrxError, decode_ok, local_refusal, present, protocol};
use reqwest::Method;
use serde::Deserialize;
use serde_json::Value;

/// The status of a job. `running` until the job ends.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JobState {
    Running,
    Succeeded,
    Failed,
    Cancelled,
}

impl JobState {
    fn from_wire(status: &str) -> Result<Self, PrxError> {
        match status {
            "running" => Ok(Self::Running),
            "succeeded" => Ok(Self::Succeeded),
            "failed" => Ok(Self::Failed),
            "cancelled" => Ok(Self::Cancelled),
            _ => Err(protocol("job status is not one of running, succeeded, failed, cancelled")),
        }
    }

    /// True for `succeeded`, `failed` and `cancelled`.
    #[must_use]
    pub fn is_terminal(self) -> bool {
        !matches!(self, Self::Running)
    }
}

/// One job, as PRX reports it. Every field of the daemon's job view is typed.
#[derive(Debug, Clone, PartialEq)]
pub struct JobStatus {
    pub job_id: String,
    pub kind: String,
    pub label: String,
    pub work_id: String,
    pub status: JobState,
    pub submitted_at_unix_ms: u64,
    pub elapsed_ms: u64,
    /// HTTP status the job produced, once it has one.
    pub http_status: Option<u16>,
    /// The job result, when the job succeeded; PRX's own JSON, not interpreted here.
    pub result: Option<Value>,
    /// The job error text, when it failed.
    pub error: Option<String>,
    /// The durable run id of an rf-shaped turn; absent for other jobs.
    pub run_id: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireJob {
    job_id: String,
    kind: String,
    label: String,
    work_id: String,
    status: String,
    submitted_at_unix_ms: u64,
    elapsed_ms: u64,
    http_status: Option<u16>,
    result: Option<Value>,
    error: Option<String>,
    /// Skipped by PRX when absent, so an explicit `null` is refused.
    #[serde(default, deserialize_with = "present")]
    run_id: Option<String>,
}

fn job_path(job_id: &str) -> Result<String, PrxError> {
    // A UUID as PRX mints it: hex digits and dashes only, so no value can change the route.
    let safe = !job_id.is_empty() && job_id.bytes().all(|b| b.is_ascii_hexdigit() || b == b'-');
    if safe { Ok(format!("/api/jobs/{job_id}")) } else { Err(local_refusal(ApiCode::FieldInvalid)) }
}

impl PrxClient {
    /// Reads a job. Needs `message_target_v1` (the job exists for the rf message routes).
    ///
    /// # Errors
    /// Returns `Unsupported`, the transport error, or a contract error. An unknown job is
    /// answered by PRX with an uncoded `404` (documented as such), which this client reports as a
    /// `Protocol` error; it is not read as "no run happened".
    pub async fn job_status(
        &self,
        caps: &Capabilities,
        job_id: &str,
    ) -> Result<JobStatus, PrxError> {
        require(caps, MESSAGE_TARGET_V1)?;
        let path = job_path(job_id)?;
        let raw = self.transport.call(Method::GET, &path, None, None).await?;
        let wire: WireJob = decode_ok(&raw.body)?;
        Ok(JobStatus {
            job_id: wire.job_id,
            kind: wire.kind,
            label: wire.label,
            work_id: wire.work_id,
            status: JobState::from_wire(&wire.status)?,
            submitted_at_unix_ms: wire.submitted_at_unix_ms,
            elapsed_ms: wire.elapsed_ms,
            http_status: wire.http_status,
            result: wire.result,
            error: wire.error,
            run_id: wire.run_id,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const BODY: &str = r#"{"job_id":"0f3c2a1e-0000-4000-8000-000000000001","kind":"turn","label":"turn","work_id":"w-1","status":"failed","submitted_at_unix_ms":1700000000000,"elapsed_ms":42,"http_status":null,"result":null,"error":"provider error","run_id":"r-1"}"#;

    fn decode(text: &str) -> Result<WireJob, PrxError> {
        decode_ok(text.as_bytes())
    }

    #[test]
    fn documented_job_view_decodes() {
        let wire = decode(BODY).expect("test: documented job view decodes");
        assert_eq!(JobState::from_wire(&wire.status), Ok(JobState::Failed));
        assert_eq!(wire.run_id.as_deref(), Some("r-1"));
        assert!(JobState::Failed.is_terminal() && !JobState::Running.is_terminal());
    }

    #[test]
    fn run_id_may_be_absent_but_not_null() {
        let absent = BODY.replace(r#","run_id":"r-1""#, "");
        assert!(decode(&absent).expect("test: absent run_id decodes").run_id.is_none());
        let null = BODY.replace(r#""run_id":"r-1""#, r#""run_id":null"#);
        assert!(decode(&null).is_err(), "an explicit null run_id is refused");
    }

    #[test]
    fn unknown_status_and_unknown_field_fail_closed() {
        assert!(JobState::from_wire("cancelling").is_err(), "not in the token document");
        let extra = BODY.replace(r#""run_id":"r-1""#, r#""run_id":"r-1","extra":1"#);
        assert!(decode(&extra).is_err());
    }

    #[test]
    fn job_path_admits_hex_and_dashes_only() {
        assert!(job_path("0f3c2a1e-0000-4000-8000-000000000001").is_ok());
        assert!(job_path("../owner").is_err());
        assert!(job_path("").is_err());
    }
}

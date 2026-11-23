// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Run states and cancellation of an rf turn (`message_idempotency_v1`).
//!
//! `POST /api/sessions/{session_id}/runs/{run_id}/cancel` is the durable cancel: `run_id` is the
//! reference rf keeps. `POST /api/jobs/{job_id}/cancel` is a hint path; PRX answers an evicted,
//! foreign or never-issued job with an uncoded or `job_unknown` 404, which this client reports
//! as `ApiCode::JobUnknown`. That outcome is unknown, never "not run".

use crate::capabilities::{Capabilities, MESSAGE_IDEMPOTENCY_V1, require};
use crate::client::PrxClient;
use crate::error::{ApiCode, PrxError, decode_ok, local_refusal, present, protocol};
use crate::transport::Transport;
use reqwest::Method;
use serde::Deserialize;

/// The state of a turn as PRX reports it on a replay or a cancel answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RunState {
    Running,
    Cancelling,
    Cancelled,
    Succeeded,
    Failed,
}

impl RunState {
    pub(crate) fn from_wire(status: &str) -> Result<Self, PrxError> {
        match status {
            "running" => Ok(Self::Running),
            "cancelling" => Ok(Self::Cancelling),
            "cancelled" => Ok(Self::Cancelled),
            "succeeded" => Ok(Self::Succeeded),
            "failed" => Ok(Self::Failed),
            _ => Err(protocol("run status is not one of the documented states")),
        }
    }

    /// True for `succeeded`, `failed` and `cancelled`: the run will not run again.
    #[must_use]
    pub fn is_terminal(self) -> bool {
        matches!(self, Self::Succeeded | Self::Failed | Self::Cancelled)
    }
}

/// The closed code of a terminal state. Only `interrupted` exists: the run's attempt was cut off
/// when PRX stopped, so it may have executed tools, and a later attempt was admitted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RunCode {
    Interrupted,
}

/// Validates a run state with its optional code: `code` is present only for an interrupted
/// `failed` run, and no other combination is a documented answer.
pub(crate) fn run_state(
    status: &str,
    code: Option<&str>,
) -> Result<(RunState, Option<RunCode>), PrxError> {
    let state = RunState::from_wire(status)?;
    match (state, code) {
        (_, None) => Ok((state, None)),
        (RunState::Failed, Some("interrupted")) => Ok((state, Some(RunCode::Interrupted))),
        _ => Err(protocol("run code is present for a state that does not carry it")),
    }
}

/// The answer of a cancel by run id.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunCancel {
    pub run_id: String,
    pub status: RunState,
    pub code: Option<RunCode>,
}

/// The answer of a cancel by job id (an rf turn's job).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JobCancel {
    pub job_id: String,
    pub run_id: String,
    pub status: RunState,
    pub code: Option<RunCode>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireRunCancel {
    run_id: String,
    status: String,
    #[serde(default, deserialize_with = "present")]
    code: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireJobCancel {
    job_id: String,
    run_id: String,
    status: String,
    #[serde(default, deserialize_with = "present")]
    code: Option<String>,
}

/// A run id is the UUID PRX mints: hex digits and dashes only, so no value changes the route.
fn id_is_safe(id: &str) -> bool {
    !id.is_empty() && id.bytes().all(|b| b.is_ascii_hexdigit() || b == b'-')
}

fn run_path(session_id: &str, run_id: &str) -> Result<String, PrxError> {
    let session_safe = !session_id.is_empty()
        && session_id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-');
    if session_safe && id_is_safe(run_id) {
        Ok(format!("/api/sessions/{session_id}/runs/{run_id}/cancel"))
    } else {
        Err(local_refusal(ApiCode::FieldInvalid))
    }
}

fn job_path(job_id: &str) -> Result<String, PrxError> {
    if id_is_safe(job_id) {
        Ok(format!("/api/jobs/{job_id}/cancel"))
    } else {
        Err(local_refusal(ApiCode::FieldInvalid))
    }
}

impl PrxClient {
    /// Cancels a run by its durable id. A running turn answers `cancelling` or `cancelled`; an
    /// ended run answers its terminal state (`interrupted` for a crashed attempt). Needs
    /// `message_idempotency_v1`.
    ///
    /// # Errors
    /// Returns `Unsupported`, the API error (`run_unknown` 404: this owner never had such a run
    /// in this session, which is not proof that nothing ran), or a transport or contract error.
    pub async fn cancel_run(
        &self,
        caps: &Capabilities,
        session_id: &str,
        run_id: &str,
    ) -> Result<RunCancel, PrxError> {
        require(caps, MESSAGE_IDEMPOTENCY_V1)?;
        let path = run_path(session_id, run_id)?;
        let raw = self.transport.call(Method::POST, &path, None, None).await?;
        let wire: WireRunCancel = decode_ok(&raw.body)?;
        if wire.run_id != run_id {
            return Err(protocol("cancel answer names another run"));
        }
        let (status, code) = run_state(&wire.status, wire.code.as_deref())?;
        Ok(RunCancel { run_id: wire.run_id, status, code })
    }

    /// Cancels the job of an rf turn. Any 404 is `Api { code: JobUnknown }` whatever its body:
    /// the job may be evicted, foreign or never issued, so the outcome is unknown. Use
    /// `cancel_run` with the durable run id.
    ///
    /// # Errors
    /// Returns `Unsupported`, `JobUnknown` for any 404, the API error, or a contract error.
    pub async fn cancel_job(
        &self,
        caps: &Capabilities,
        job_id: &str,
    ) -> Result<JobCancel, PrxError> {
        require(caps, MESSAGE_IDEMPOTENCY_V1)?;
        let path = job_path(job_id)?;
        let raw = self.transport.call_raw(Method::POST, &path, None).await?;
        if raw.status == 404 {
            return Err(PrxError::Api {
                status: 404,
                code: ApiCode::JobUnknown,
                current_revision: None,
                revision: None,
                current_incarnation: None,
            });
        }
        let raw = Transport::check_status(raw)?;
        let wire: WireJobCancel = decode_ok(&raw.body)?;
        if wire.job_id != job_id {
            return Err(protocol("job cancel answer names another job"));
        }
        let (status, code) = run_state(&wire.status, wire.code.as_deref())?;
        Ok(JobCancel { job_id: wire.job_id, run_id: wire.run_id, status, code })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{caps_with, offline_client};

    #[test]
    fn run_states_are_the_documented_closed_set() {
        for (wire, state) in [
            ("running", RunState::Running),
            ("cancelling", RunState::Cancelling),
            ("cancelled", RunState::Cancelled),
            ("succeeded", RunState::Succeeded),
            ("failed", RunState::Failed),
        ] {
            assert_eq!(RunState::from_wire(wire), Ok(state));
        }
        assert!(RunState::from_wire("queued").is_err(), "not a documented state");
        assert!(RunState::Failed.is_terminal() && !RunState::Cancelling.is_terminal());
    }

    #[test]
    fn interrupted_code_only_on_failed() {
        assert_eq!(
            run_state("failed", Some("interrupted")),
            Ok((RunState::Failed, Some(RunCode::Interrupted)))
        );
        assert_eq!(run_state("failed", None), Ok((RunState::Failed, None)));
        assert!(run_state("cancelled", Some("interrupted")).is_err());
        assert!(run_state("failed", Some("other")).is_err(), "closed code set");
    }

    #[test]
    fn paths_admit_only_documented_id_shapes() {
        assert_eq!(
            run_path("rf-session_1", "0f3c2a1e-0000-4000-8000-000000000001").expect("path"),
            "/api/sessions/rf-session_1/runs/0f3c2a1e-0000-4000-8000-000000000001/cancel"
        );
        assert!(run_path("s", "../x").is_err());
        assert!(run_path("", "0f3c").is_err());
        assert!(job_path("0f3c-1").is_ok() && job_path("a/b").is_err());
    }

    #[test]
    fn cancel_without_the_token_is_refused_before_any_request() {
        let (_dir, client) = offline_client();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("test: runtime");
        let caps = caps_with(&[]);
        assert!(matches!(
            runtime.block_on(client.cancel_run(&caps, "rf-s-1", "0f3c-1")),
            Err(PrxError::Unsupported { .. })
        ));
        assert!(matches!(
            runtime.block_on(client.cancel_job(&caps, "0f3c-1")),
            Err(PrxError::Unsupported { .. })
        ));
    }
}

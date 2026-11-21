// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! The apply helper: rf's 409 rule ("rf reply 4", item 4) on top of `list` and `put`.
//! It never sets `confirm_high_risk`; that is the caller's decision after the user agrees.

use crate::agent::{AgentConfig, AgentReadback, AgentStatus, PutOutcome};
use crate::capabilities::Capabilities;
use crate::client::PrxClient;
use crate::error::{ApiCode, PrxError};
use crate::name::AgentName;
use crate::revision::ConfigRevision;

/// Most PUTs one `apply_agent` sends.
const MAX_ATTEMPTS: u32 = 3;

/// What `apply_agent` did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApplyOutcome {
    /// PRX accepted the PUT, possibly after an automatic retry.
    Applied(PutOutcome),
    /// The stored config already equals the intended one (for example a lost reply, or the
    /// same change made elsewhere). Decided by the config, never by the revision.
    AlreadyApplied(AgentReadback),
    /// The agent changed under the user, or retries ran out. Show `current`; do not overwrite.
    NeedsReview { current: Option<AgentReadback> },
    /// PRX asks for a high-risk confirmation. Resend with `confirm_high_risk = true` after consent.
    NeedsConfirmation { revision: ConfigRevision },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ConflictDecision {
    AlreadyApplied,
    Retry,
    NeedsReview,
}

/// Decides what to do after `revision_conflict`. `current` is the agent read back now
/// (`None` when it does not exist); `reviewed` is the config the user last reviewed
/// (`None` when the user was creating it).
pub(crate) fn decide_conflict(
    current: Option<&AgentReadback>,
    intended: &AgentConfig,
    reviewed: Option<&AgentConfig>,
) -> ConflictDecision {
    let Some(current) = current else {
        return if reviewed.is_none() {
            ConflictDecision::Retry
        } else {
            ConflictDecision::NeedsReview
        };
    };
    if current.status == AgentStatus::Retired {
        return ConflictDecision::NeedsReview;
    }
    if current.config == *intended {
        return ConflictDecision::AlreadyApplied;
    }
    if reviewed.is_some_and(|r| current.config == *r) {
        ConflictDecision::Retry
    } else {
        ConflictDecision::NeedsReview
    }
}

impl PrxClient {
    /// Applies `config` to `name`. Reads the revision from `list`, PUTs, and on
    /// `revision_conflict` reads the agent back and decides with [`decide_conflict`]. At most
    /// three PUTs are sent. Needs `agent_crud_v1` (checked by the calls it makes).
    ///
    /// # Errors
    /// Returns any error of `list`, `get` or `put` that the rule does not handle.
    pub async fn apply_agent(
        &self,
        caps: &Capabilities,
        name: &AgentName,
        config: &AgentConfig,
        reviewed: Option<&AgentConfig>,
    ) -> Result<ApplyOutcome, PrxError> {
        let mut revision = self.list(caps).await?.revision;
        let mut puts: u32 = 0;
        loop {
            puts += 1;
            match self.put(caps, name, config, &revision, false).await {
                Ok(outcome) => return Ok(ApplyOutcome::Applied(outcome)),
                Err(PrxError::Api {
                    code: ApiCode::ConfirmationRequired,
                    revision: Some(revision),
                    ..
                }) => return Ok(ApplyOutcome::NeedsConfirmation { revision }),
                Err(PrxError::Api {
                    code: ApiCode::RevisionConflict,
                    current_revision: Some(current_revision),
                    ..
                }) => {
                    let current = self.read_if_present(caps, name).await?;
                    match (decide_conflict(current.as_ref(), config, reviewed), current) {
                        (ConflictDecision::AlreadyApplied, Some(readback)) => {
                            return Ok(ApplyOutcome::AlreadyApplied(readback));
                        }
                        (ConflictDecision::Retry, _) if puts < MAX_ATTEMPTS => {
                            revision = current_revision;
                        }
                        (_, current) => return Ok(ApplyOutcome::NeedsReview { current }),
                    }
                }
                Err(error) => return Err(error),
            }
        }
    }

    async fn read_if_present(
        &self,
        caps: &Capabilities,
        name: &AgentName,
    ) -> Result<Option<AgentReadback>, PrxError> {
        match self.get(caps, name).await {
            Ok(readback) => Ok(Some(readback)),
            Err(PrxError::Api {
                code: ApiCode::AgentUnknown,
                ..
            }) => Ok(None),
            Err(error) => Err(error),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::autonomy::Autonomy;
    use crate::agent::Tools;

    const HEX: &str = "f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6";
    const UUID: &str = "5f1c2a3e-8b4d-4c6a-9e7f-0a1b2c3d4e5f";
    const NAME: &str = "a_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    fn readback(model: &str, status: &str) -> AgentReadback {
        let body = format!(
            r#"{{"name":"{NAME}","config":{{"provider":"ollama","model":"{model}","autonomy":"full","tools":["*"],"enabled":true}},"revision":"{HEX}","incarnation":"{UUID}","status":"{status}"}}"#
        );
        let name = AgentName::parse(NAME).expect("test: literal name");
        AgentReadback::from_body(body.as_bytes(), &name).expect("test: literal readback decodes")
    }

    fn config(model: &str) -> AgentConfig {
        AgentConfig {
            provider: "ollama".to_owned(),
            model: model.to_owned(),
            prompt: None,
            autonomy: Autonomy::Full,
            tools: Tools::All,
            enabled: true,
        }
    }

    #[test]
    fn intended_config_already_stored_is_already_applied() {
        let current = readback("codellama", "active");
        let decision = decide_conflict(Some(&current), &config("codellama"), Some(&config("llama3")));
        assert_eq!(decision, ConflictDecision::AlreadyApplied, "config equality wins over the review");
    }

    #[test]
    fn unchanged_since_review_retries() {
        let current = readback("llama3", "active");
        let decision = decide_conflict(Some(&current), &config("codellama"), Some(&config("llama3")));
        assert_eq!(decision, ConflictDecision::Retry, "another agent changed; this one did not");
    }

    #[test]
    fn same_agent_changed_needs_review() {
        let current = readback("mistral", "active");
        let decision = decide_conflict(Some(&current), &config("codellama"), Some(&config("llama3")));
        assert_eq!(decision, ConflictDecision::NeedsReview);
    }

    #[test]
    fn create_retries_while_still_absent_and_reviews_otherwise() {
        assert_eq!(decide_conflict(None, &config("codellama"), None), ConflictDecision::Retry);
        assert_eq!(
            decide_conflict(None, &config("codellama"), Some(&config("codellama"))),
            ConflictDecision::NeedsReview,
            "an agent that was reviewed but is now gone needs the user"
        );
        let created_elsewhere = readback("codellama", "active");
        assert_eq!(
            decide_conflict(Some(&created_elsewhere), &config("codellama"), None),
            ConflictDecision::AlreadyApplied,
            "same config found after a lost create reply is applied"
        );
        assert_eq!(
            decide_conflict(Some(&readback("llama3", "active")), &config("codellama"), None),
            ConflictDecision::NeedsReview,
            "a different agent created by someone else needs the user"
        );
    }

    #[test]
    fn retired_agent_always_needs_review() {
        let retired = readback("codellama", "retired");
        assert_eq!(
            decide_conflict(Some(&retired), &config("codellama"), Some(&config("codellama"))),
            ConflictDecision::NeedsReview
        );
    }
}

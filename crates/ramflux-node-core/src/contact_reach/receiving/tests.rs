// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Result-boundary controls only; these do not prove ordinary publication or live transport.
use super::*;
type TestResult = std::result::Result<(), Box<dyn std::error::Error>>;
#[test]
fn cr_staging_and_duplicate_staging_cannot_acknowledge_ordinary_publication() -> TestResult {
    for class in [ReachClass::Accepted, ReachClass::Replied] {
        for duplicate in [false, true] {
            let admitted = super::super::ReachIngress {
                seq: 1,
                class,
                duplicate,
                placement: wire::Placement::Direct,
            };
            let result = staged_result("sealed", &admitted);
            wire::validate_receiving_result(&result)?;
            assert!(
                matches!(
                    result,
                    OperationResult::Submit {
                        outcome: wire::SubmitOutcome::Unknown,
                        reason: None,
                        ..
                    }
                ),
                "a staging receipt cannot claim ordinary durability, including a retry"
            );
        }
    }
    Ok(())
}
#[test]
fn cr_receiving_error_preserves_storage_uncertainty_and_hides_home_authority_details() -> TestResult
{
    for error in [
        super::super::ReachError::Storage(crate::NodeCoreError::Redb("fault".into())),
        super::super::ReachError::Refused(Reason::HomeFork),
        super::super::ReachError::Refused(Reason::CustodyRefused),
        super::super::ReachError::Refused(Reason::FeatureDisabled),
        super::super::ReachError::Refused(Reason::CostRequired),
    ] {
        let result = receiving_error("sealed", &error);
        wire::validate_receiving_result(&result)?;
        match error {
            super::super::ReachError::Storage(_) => assert!(
                matches!(
                    result,
                    OperationResult::Submit {
                        outcome: wire::SubmitOutcome::Unknown,
                        reason: None,
                        ..
                    }
                ),
                "storage cannot become a definite policy refusal"
            ),
            super::super::ReachError::Refused(Reason::HomeFork | Reason::CustodyRefused) => {
                assert!(
                    matches!(
                        result,
                        OperationResult::Submit {
                            outcome: wire::SubmitOutcome::Refused,
                            reason: Some(Reason::ForeignReadRefused),
                            ..
                        }
                    ),
                    "private authority details must not escape the receiving result"
                );
            }
            super::super::ReachError::Refused(Reason::CostRequired) => assert!(
                matches!(
                    result,
                    OperationResult::Submit {
                        outcome: wire::SubmitOutcome::Refused,
                        reason: Some(Reason::CostRequired),
                        ..
                    }
                ),
                "cost_required remains a refusal, never an invented challenge arm"
            ),
            _ => assert!(
                matches!(result, OperationResult::Error { reason: Reason::FeatureDisabled, .. }),
                "the disabled boundary must remain closed"
            ),
        }
    }
    Ok(())
}

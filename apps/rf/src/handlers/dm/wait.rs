// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! A caller-owned wait budget retries only the daemon's specific deferred attachment result.
use crate::RfError;
use serde_json::Value;
use std::{ops::AsyncFnMut, time::Duration};

const DEFERRED: &str = "attachment fetch deferred; retry object.fetch";

pub(super) async fn receive<F>(budget: Duration, mut fetch: F) -> Result<Value, RfError>
where
    F: AsyncFnMut() -> Result<Value, RfError>,
{
    if budget.is_zero() {
        return fetch().await;
    }
    let deadline = tokio::time::Instant::now()
        .checked_add(budget)
        .ok_or_else(|| RfError::Message("dm read --wait budget is too large".into()))?;
    let polling = async {
        loop {
            match fetch().await {
                Ok(value) => return Ok(value),
                Err(error) if error.to_string().ends_with(DEFERRED) => {
                    tokio::time::sleep(Duration::from_millis(250)).await;
                }
                Err(error) => return Err(error),
            }
        }
    };
    tokio::time::timeout_at(deadline, polling)
        .await
        .unwrap_or_else(|_| Err(RfError::Message(DEFERRED.into())))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[tokio::test(start_paused = true)]
    async fn attachment_wait_completes_on_the_third_poll() -> Result<(), RfError> {
        let mut polls = 0;
        let value = receive(Duration::from_secs(2), async || {
            polls += 1;
            if polls < 3 {
                Err(RfError::Message(DEFERRED.into()))
            } else {
                Ok(json!({"plaintext_base64":"cmVjZWl2ZWQ"}))
            }
        })
        .await?;
        assert_eq!(polls, 3);
        assert_eq!(value["plaintext_base64"], "cmVjZWl2ZWQ");
        Ok(())
    }

    #[tokio::test(start_paused = true)]
    async fn attachment_wait_reports_deferred_only_at_its_budget() {
        let started = tokio::time::Instant::now();
        let result =
            receive(Duration::from_secs(1), async || Err(RfError::Message(DEFERRED.into()))).await;
        assert!(matches!(result, Err(RfError::Message(text)) if text == DEFERRED));
        assert_eq!(started.elapsed(), Duration::from_secs(1));
    }

    #[tokio::test(start_paused = true)]
    async fn attachment_wait_does_not_retry_generic_errors_or_default_zero() {
        for (budget, message) in [(0, DEFERRED), (2, "attachment fetch failed; retry object.fetch")]
        {
            let mut polls = 0;
            let started = tokio::time::Instant::now();
            let result = receive(Duration::from_secs(budget), async || {
                polls += 1;
                Err(RfError::Message(message.into()))
            })
            .await;
            assert!(result.is_err());
            assert_eq!(polls, 1);
            assert_eq!(started.elapsed(), Duration::ZERO);
        }
    }
}

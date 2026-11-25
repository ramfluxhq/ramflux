// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Wake notification decision over the candidates recorded at first projection.

use crate::{RamfluxClient, SdkError};

/// Decision for one fetched page. `clears` is true when no eligible unread message remains.
pub(crate) struct Decision {
    pub(crate) show: bool,
    pub(crate) unread_total: u64,
    pub(crate) clears: bool,
}

/// Revalidates and consumes this page's candidates in one transaction (at most once per
/// candidate). Called only after the page is durably applied.
pub(super) fn decide(client: &RamfluxClient) -> Result<Decision, SdkError> {
    let reader = client.read_device_identity()?;
    let outcome = client.account_db()?.consume_notification_decision(reader.as_ref())?;
    Ok(Decision {
        show: outcome.show,
        unread_total: outcome.unread_total,
        clears: !outcome.eligible_unread_remains,
    })
}

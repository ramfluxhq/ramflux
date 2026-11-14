// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

pub(crate) enum ReceiveGroupDirectory {
    Shared(Box<crate::client::shared_group::GroupDirectoryEvidence>),
}

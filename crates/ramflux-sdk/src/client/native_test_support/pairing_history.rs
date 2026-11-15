// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Enrollment-history proof fixture. P13 TODO (MU-ACTIVATION-01): rebuild `seed` and `verify` on
//! the generation-1 own-device sync carrier; the retired group codec and own-sync importer used
//! by the generation-0 version are deleted and must not return.
use super::TestResult;
use crate::{RamfluxClient, custody::PrimaryVault};

pub(crate) fn seed(source: &RamfluxClient, vault: &dyn PrimaryVault) -> TestResult {
    let _ = (source, vault);
    Err("P13 todo: seed enrollment history through generation-1 DM and group producers".into())
}

pub(crate) fn verify(source: &RamfluxClient, target: &RamfluxClient) -> TestResult {
    let _ = (source, target);
    Err("P13 todo: assert target-side history presence through the generation-1 carrier".into())
}

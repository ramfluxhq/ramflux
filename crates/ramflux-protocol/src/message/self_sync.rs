// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Closed `SelfSync` operations (controller OV-P19, 2026-11-11).
use super::{
    SelfSync,
    validation::{self, ValidationError},
};

/// Permanent operation numbers. Values from eight onward are reserved.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum Operation {
    ReadThrough = 1,
    DraftSet = 2,
    DraftClear = 3,
    PinSet = 4,
    PinClear = 5,
    MuteSet = 6,
    MuteClear = 7,
}

impl Operation {
    /// Shared revision family; pin additionally scopes its counter by target.
    #[must_use]
    pub const fn family(self) -> &'static str {
        match self {
            Self::ReadThrough => "read",
            Self::DraftSet | Self::DraftClear => "draft",
            Self::PinSet | Self::PinClear => "pin",
            Self::MuteSet | Self::MuteClear => "mute",
        }
    }
}

/// Checks the exact payload selected by the operation. Absence never means clear.
/// # Errors
/// Refuses unknown operations, zero revisions and mismatched payload fields.
pub fn validate(value: &SelfSync) -> Result<Operation, ValidationError> {
    let operation = match value.operation {
        1 => Operation::ReadThrough,
        2 => Operation::DraftSet,
        3 => Operation::DraftClear,
        4 => Operation::PinSet,
        5 => Operation::PinClear,
        6 => Operation::MuteSet,
        7 => Operation::MuteClear,
        _ => return Err(ValidationError::Content),
    };
    if value.revision == 0
        || value.revision == u64::MAX
        || value.read_through.is_some() != (operation == Operation::ReadThrough)
        || value.draft.is_some() != (operation == Operation::DraftSet)
        || value.pin.is_some() != matches!(operation, Operation::PinSet | Operation::PinClear)
        || value.mute != (operation == Operation::MuteSet)
    {
        return Err(ValidationError::Content);
    }
    for reference in [value.read_through.as_ref(), value.pin.as_ref()].into_iter().flatten() {
        if reference.id.len() != 32
            || reference.conversation_id.is_empty()
            || reference.author_anchor.is_empty()
        {
            return Err(ValidationError::Content);
        }
    }
    if let Some(draft) = &value.draft {
        if draft.sealed_group.is_some()
            || !draft.media.is_empty()
            || draft.forward.is_some()
            || draft.text.len() > 65_536
        {
            return Err(ValidationError::Content);
        }
        validation::validate_message(draft)?;
    }
    Ok(operation)
}

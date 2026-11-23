// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use crate::SdkError;
use ramflux_protocol::username_directory::DirectoryCode;

impl From<DirectoryCode> for SdkError {
    fn from(code: DirectoryCode) -> Self {
        Self::UsernameDirectoryRefused(code)
    }
}
impl From<ramflux_storage::UsernameStorageError> for SdkError {
    fn from(error: ramflux_storage::UsernameStorageError) -> Self {
        match error {
            ramflux_storage::UsernameStorageError::Refused(code) => code.into(),
            ramflux_storage::UsernameStorageError::Storage(error) => Self::Storage(error),
        }
    }
}

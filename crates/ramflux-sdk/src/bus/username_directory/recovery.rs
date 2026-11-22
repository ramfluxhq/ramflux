// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Archive hints can repair only an already committed fresh tuple at the current native home.
use super::{Prepared, directory, w};
use crate::SdkError;
use directory::SignedUsernameChange;
use ramflux_storage::AccountDb;

pub(super) fn candidates(
    db: &AccountDb,
    root: &str,
    pin: &w::NativeDirectoryPin,
) -> Result<Vec<SignedUsernameChange>, SdkError> {
    let mut hints = db.username_recovery_candidates(root)?;
    hints.retain(|hint| hint.center == *pin);
    hints.reverse();
    if let Some(floor) = db.username_floor(root)? {
        if floor.quarantined {
            return Err(w::DirectoryCode::ProfileEquivocation.into());
        }
        hints.insert(
            0,
            SignedUsernameChange {
                center: pin.clone(),
                operation: floor.operation,
                profile: floor.profile,
            },
        );
    }
    Ok(hints)
}

impl Prepared {
    pub(super) async fn exchange_with_recovery(
        &self,
    ) -> Result<directory::UsernameNetworkReply, SdkError> {
        let original =
            directory::exchange_username(&self.gateway, self.pin.clone(), self.action.clone())
                .await;
        if !matches!(
            &original,
            Err(SdkError::UsernameDirectoryRefused(w::DirectoryCode::DirectoryUnavailable))
        ) {
            return original;
        }
        for candidate in &self.repairs {
            let action = w::NativeUsernameAction::Recover {
                operation: Box::new(candidate.operation.clone()),
                profile: Box::new(candidate.profile.clone()),
            };
            match directory::exchange_username(&self.gateway, self.pin.clone(), action).await {
                Ok(_) => {
                    return directory::exchange_username(
                        &self.gateway,
                        self.pin.clone(),
                        self.action.clone(),
                    )
                    .await;
                }
                Err(SdkError::UsernameDirectoryRefused(
                    w::DirectoryCode::StaleEpoch
                    | w::DirectoryCode::Replay
                    | w::DirectoryCode::NotFound
                    | w::DirectoryCode::ProfileRollback,
                )) => {}
                Err(error) => return Err(error),
            }
        }
        original
    }
}

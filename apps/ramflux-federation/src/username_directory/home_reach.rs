// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Home-committed reach and scoped reply permissions on authenticated owner sessions.
use super::{Result, directory, home::HomeService, refuse};
use ramflux_protocol::{
    custody::{DeviceSet, Envelope},
    home_migration::ResolveResult,
    username_directory as w,
};

impl HomeService {
    pub(super) fn execute_reach(
        &self,
        root: &str,
        authority: &Envelope<DeviceSet>,
        history: &ResolveResult,
        action: w::NativeUsernameAction,
    ) -> Result<w::NativeUsernameReply> {
        match action {
            w::NativeUsernameAction::ReplyAuthorize {
                peer_root,
                conversation_id,
                operation_id,
            } => {
                let now = crate::helpers::now_unix_seconds()
                    .map_err(|_| std::io::Error::other("reply clock"))?;
                let permission = self.directory.authorize_reply(
                    root,
                    &peer_root,
                    &conversation_id,
                    &operation_id,
                    now,
                )?;
                Ok(w::NativeUsernameReply::ReplyAuthorized { permission })
            }
            w::NativeUsernameAction::ReachGet => {
                self.report_reach(root)?;
                Ok(w::NativeUsernameReply::Reach {
                    state: Box::new(self.reach_state(root, authority, history)?),
                })
            }
            w::NativeUsernameAction::ReachSet { policy } => {
                self.report_reach(root)?;
                let state = self.directory.commit_reach(
                    *policy,
                    authority,
                    history,
                    crate::now_unix_seconds()?,
                )?;
                self.report_reach(root)?;
                Ok(w::NativeUsernameReply::Reach { state: Box::new(state) })
            }
            _ => refuse("unsupported reach action"),
        }
    }

    fn report_reach(&self, root: &str) -> Result<()> {
        match self
            .client
            .exchange_blocking(root, &directory::DirectoryRequest::Status { operation_id: None })?
        {
            directory::AuthorityResponse::Receipt { .. } => Ok(()),
            directory::AuthorityResponse::Refused { failure }
                if failure.code == w::DirectoryCode::NotFound =>
            {
                Ok(())
            }
            directory::AuthorityResponse::Refused { failure } => {
                Err(directory::CheckpointError::Directory(failure.code).into())
            }
            _ => refuse("reach reporting response mismatch"),
        }
    }

    fn reach_state(
        &self,
        root: &str,
        current: &ramflux_protocol::custody::Envelope<ramflux_protocol::custody::DeviceSet>,
        history: &ramflux_protocol::home_migration::ResolveResult,
    ) -> Result<ramflux_protocol::account_reach::ReachState> {
        let commit = self.directory.reach_commit(root)?;
        let (policy, authority) =
            commit.map_or((None, current.clone()), |row| (Some(row.policy), row.authority));
        Ok(ramflux_protocol::account_reach::ReachState {
            policy,
            authority: Box::new(authority),
            history: Box::new(history.clone()),
            conflict: false,
        })
    }
}

// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Context suppression follows confirmed fanout to one exact active sibling set.
use super::control::{CONTROL_PREFIX, ControlKind, SurfaceControl};
use crate::{RamfluxClient, SdkError};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct OwnContextDelivery {
    conversation: String,
    epoch: Option<u64>,
    targets: String,
    included: bool,
}

impl OwnContextDelivery {
    fn key(&self, db: &ramflux_storage::AccountDb) -> Result<String, SdkError> {
        let binding = ramflux_protocol::canonical_json_bytes(&(
            "ramflux.own_surface.context_delivery.v1",
            &self.conversation,
            self.epoch,
            &self.targets,
        ))?;
        let key = db.routed_seen_key(&binding)?;
        let digest = key
            .strip_prefix("routed/seen/")
            .ok_or_else(|| SdkError::LocalBus("context marker key".into()))?;
        Ok(format!("own-device/context-delivered/{digest}"))
    }
}

impl RamfluxClient {
    pub(crate) fn prepare_own_surface_context(
        &self,
        body: &[u8],
        targets: &[String],
    ) -> Result<(Zeroizing<Vec<u8>>, Option<OwnContextDelivery>), SdkError> {
        let Some(raw) = body.strip_prefix(CONTROL_PREFIX) else {
            return Ok((Zeroizing::new(body.to_vec()), None));
        };
        let mut control: SurfaceControl = ramflux_protocol::parse_i_json(raw)?;
        if control.kind != ControlKind::Own {
            return Ok((Zeroizing::new(body.to_vec()), None));
        }
        let Some(context) = &control.context else {
            return Ok((Zeroizing::new(body.to_vec()), None));
        };
        let mut targets = targets.to_vec();
        targets.sort();
        let mut delivery = OwnContextDelivery {
            conversation: context.conversation_id.clone(),
            epoch: control.group_epoch,
            targets: ramflux_protocol::hash_base64url(
                "ramflux.own_surface.targets.v1",
                &ramflux_protocol::canonical_json_bytes(&targets)?,
            ),
            included: true,
        };
        let now = crate::prelude::now_unix_timestamp();
        if self
            .account_db()?
            .load_actor_state::<serde_json::Value>(&delivery.key(self.account_db()?)?)?
            .and_then(|row| row["expires_at"].as_i64())
            .is_some_and(|expires| expires > now)
        {
            control.context = None;
            delivery.included = false;
        }
        Ok((Zeroizing::new(control.bytes()?), Some(delivery)))
    }

    pub(crate) fn finish_own_surface_context(
        &self,
        delivery: &OwnContextDelivery,
        confirmed: bool,
    ) -> Result<(), SdkError> {
        let db = self.account_db()?;
        let key = delivery.key(db)?;
        if !confirmed {
            db.remove_actor_state(&key)?;
        } else if delivery.included {
            let now = crate::prelude::now_unix_timestamp();
            db.persist_actor_state(
                &key,
                &serde_json::json!({"expires_at":now.saturating_add(600)}),
            )?;
        }
        Ok(())
    }
}

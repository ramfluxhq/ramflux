// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Exclusive ordinary-envelope creation ceremony with typed, zeroizing secret buffers.
use crate::{
    LocalBusCreatedAccount, LocalBusCreatedAccountState, SdkError, custody::CreationState,
};
use ramflux_protocol::PrincipalKind;
use serde::{Deserialize, Serialize};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::UnixStream,
};
use zeroize::Zeroizing;

/// Creation remains bound to this dedicated same-user connection until confirm or cancel.
/// Dropping the client cancels pending setup; secret bodies never enter `LocalBusFrame`.
pub struct LocalBusCreationClient {
    stream: UnixStream,
    sequence: u64,
}

/// Public pending ceremony metadata, safe for UI state and expiry timers.
#[derive(Debug, Deserialize)]
pub struct LocalBusPendingCreation {
    pub ceremony_id: String,
    pub expires_in_ms: u64,
}

#[derive(Serialize)]
struct SetupFrame<'a, T> {
    bus_protocol: &'static str,
    frame_id: &'a str,
    kind: &'static str,
    request_id: &'a str,
    sdk_api: &'static str,
    method: &'a str,
    body: T,
}
#[derive(Deserialize)]
struct Reply {
    bus_protocol: String,
    request_id: String,
    kind: String,
    method: String,
    ok: Option<bool>,
    body: Option<Body>,
    error: Option<Error>,
}
// Optional typed fields allow ordinary error envelopes' empty bodies without buffering
// the secret phrase in an untyped JSON value or an untagged-deserializer scratch tree.
#[derive(Deserialize)]
struct Body {
    ceremony: Option<String>,
    ceremony_id: Option<String>,
    expires_in_ms: Option<u64>,
    phrase: Option<Zeroizing<String>>,
    positions: Option<[u8; 3]>,
    account_id: Option<String>,
    display_name: Option<String>,
    state: Option<LocalBusCreatedAccountState>,
    networking: Option<CreationState>,
    cancelled: Option<bool>,
    account_anchor: Option<String>,
    warning: Option<String>,
}
#[derive(Deserialize)]
struct Error {
    code: String,
}

impl LocalBusCreationClient {
    /// # Errors
    /// Returns socket or peer-policy failures.
    pub async fn connect(socket: impl AsRef<std::path::Path>) -> Result<Self, SdkError> {
        Ok(Self { stream: UnixStream::connect(socket).await?, sequence: 0 })
    }

    /// Begin without caller seeds or identifiers; the daemon allocates all account identifiers.
    /// # Errors
    /// Rejects unavailable custody providers, invalid names and unsupported principal kinds.
    pub async fn begin(
        &mut self,
        display_name: &str,
        principal_kind: PrincipalKind,
    ) -> Result<LocalBusPendingCreation, SdkError> {
        #[derive(Serialize)]
        struct Input<'a> {
            display_name: &'a str,
            principal_kind: PrincipalKind,
        }
        let body = self.exchange("account.create", Input { display_name, principal_kind }).await?;
        if body.ceremony.as_deref() != Some("pending") {
            return Err(SdkError::CustodySetupInvalid);
        }
        Ok(LocalBusPendingCreation {
            ceremony_id: body.ceremony_id.ok_or(SdkError::CustodySetupInvalid)?,
            expires_in_ms: body.expires_in_ms.ok_or(SdkError::CustodySetupInvalid)?,
        })
    }

    /// Moves the phrase directly into an erasing buffer. Display once, then drop it before hide.
    /// # Errors
    /// Rejects missing, expired or previously displayed ceremonies.
    pub async fn show_once(&mut self) -> Result<Zeroizing<String>, SdkError> {
        self.exchange("account.create.show_once", Empty {})
            .await?
            .phrase
            .ok_or(SdkError::CustodySetupInvalid)
    }

    /// Select three one-based word positions after the displayed phrase has been hidden.
    /// # Errors
    /// Rejects wrong ordering, replay or expiry.
    pub async fn hidden_challenge(&mut self) -> Result<[u8; 3], SdkError> {
        self.exchange("account.create.hidden_challenge", Empty {})
            .await?
            .positions
            .ok_or(SdkError::CustodySetupInvalid)
    }

    /// Consume the sole confirmation attempt and open the ordinary unlocked account actor.
    /// Passphrase and words serialize directly from erasing buffers, without a JSON value.
    /// # Errors
    /// Rejects wrong words, expiry, persistence or account-opening failures.
    pub async fn confirm(
        &mut self,
        words: &[Zeroizing<String>; 3],
        passphrase: &Zeroizing<String>,
    ) -> Result<LocalBusCreatedAccount, SdkError> {
        #[derive(Serialize)]
        struct Confirmation<'a> {
            words: &'a [Zeroizing<String>; 3],
            passphrase: &'a Zeroizing<String>,
        }
        let body =
            self.exchange("account.create.confirm", Confirmation { words, passphrase }).await?;
        Ok(LocalBusCreatedAccount {
            account_id: body.account_id.ok_or(SdkError::CustodySetupInvalid)?,
            display_name: body.display_name.ok_or(SdkError::CustodySetupInvalid)?,
            state: body.state.ok_or(SdkError::CustodySetupInvalid)?,
            networking: body.networking.ok_or(SdkError::CustodySetupInvalid)?,
        })
    }

    /// Cancel pending setup; succeeds after a consumed or failed confirmation as well.
    /// # Errors
    /// Returns transport or protocol errors.
    pub async fn cancel(&mut self) -> Result<(), SdkError> {
        if self.exchange("account.create.cancel", Empty {}).await?.cancelled == Some(true) {
            Ok(())
        } else {
            Err(SdkError::CustodySetupInvalid)
        }
    }

    async fn exchange<T: Serialize>(&mut self, method: &str, body: T) -> Result<Body, SdkError> {
        self.sequence = self.sequence.checked_add(1).ok_or(SdkError::CustodySetupInvalid)?;
        let id = format!("creation-{}", self.sequence);
        let bytes = crate::custody::serialize_secret(
            &SetupFrame {
                bus_protocol: "ramflux.local_bus.v1",
                frame_id: &id,
                kind: "request",
                request_id: &id,
                sdk_api: "account",
                method,
                body,
            },
            8192,
        )?;
        let len = u32::try_from(bytes.len()).map_err(|_| SdkError::CustodySetupInvalid)?;
        self.stream.write_all(&len.to_be_bytes()).await?;
        self.stream.write_all(&bytes).await?;
        self.stream.flush().await?;
        drop(bytes);
        let len = self.stream.read_u32().await?;
        if len > 8192 {
            return Err(SdkError::CustodySetupInvalid);
        }
        let mut bytes = Zeroizing::new(vec![0; len as usize]);
        self.stream.read_exact(&mut bytes).await?;
        let reply: Reply =
            serde_json::from_slice(&bytes).map_err(|_| SdkError::CustodySetupInvalid)?;
        if reply.bus_protocol != "ramflux.local_bus.v1"
            || reply.request_id != id
            || reply.method != method
        {
            return Err(SdkError::CustodySetupInvalid);
        }
        if reply.kind == "error" {
            return Err(match reply.error.as_ref().map(|error| error.code.as_str()) {
                Some("CustodyConfirmationFailed") => SdkError::CustodyConfirmationFailed,
                Some("CustodyVaultUnavailable") => SdkError::CustodyVaultUnavailable,
                Some("CustodyExpired") => SdkError::CustodyExpired,
                _ => SdkError::CustodySetupInvalid,
            });
        }
        if reply.kind != "response" || reply.ok != Some(true) || reply.error.is_some() {
            return Err(SdkError::CustodySetupInvalid);
        }
        reply.body.ok_or(SdkError::CustodySetupInvalid)
    }
}

#[derive(Serialize)]
struct Empty {}

/// Exclusive local-only recovery transport. No ordinary/network request can prompt phrase input.
pub struct LocalBusRecoveryClient(LocalBusCreationClient);
/// Display the anchor and warning before requesting explicit phrase confirmation.
#[derive(Debug)]
pub struct LocalBusPendingRecovery {
    pub ceremony_id: String,
    pub account_anchor: String,
    pub expires_in_ms: u64,
    pub warning: String,
}
impl LocalBusRecoveryClient {
    /// # Errors
    /// Returns socket/peer-policy failures.
    pub async fn connect(socket: impl AsRef<std::path::Path>) -> Result<Self, SdkError> {
        Ok(Self(LocalBusCreationClient::connect(socket).await?))
    }
    /// Begin only at the user's explicit request. This sends no recovery secret.
    /// # Errors
    /// Refuses unknown identity, unresolved recovery and unavailable primary vaults.
    pub async fn begin(&mut self, account_id: &str) -> Result<LocalBusPendingRecovery, SdkError> {
        #[derive(Serialize)]
        struct Input<'a> {
            account_id: &'a str,
        }
        let body = self.0.exchange("account.recover.begin", Input { account_id }).await?;
        Ok(LocalBusPendingRecovery {
            ceremony_id: body.ceremony_id.ok_or(SdkError::CustodySetupInvalid)?,
            account_anchor: body.account_anchor.ok_or(SdkError::CustodySetupInvalid)?,
            expires_in_ms: body.expires_in_ms.ok_or(SdkError::CustodySetupInvalid)?,
            warning: body.warning.ok_or(SdkError::CustodySetupInvalid)?,
        })
    }
    /// Confirm the fingerprint displayed by begin; phrase and passphrase erase on drop.
    /// # Errors
    /// Refuses wrong phrase/secret, stale authority, expiry and failed durable persistence.
    pub async fn confirm(
        &mut self,
        phrase: &Zeroizing<String>,
        passphrase: &Zeroizing<String>,
        confirmed_anchor: &str,
    ) -> Result<LocalBusCreatedAccount, SdkError> {
        #[derive(Serialize)]
        struct Input<'a> {
            phrase: &'a Zeroizing<String>,
            passphrase: &'a Zeroizing<String>,
            confirmed_anchor: &'a str,
        }
        let body = self
            .0
            .exchange("account.recover.confirm", Input { phrase, passphrase, confirmed_anchor })
            .await?;
        Ok(LocalBusCreatedAccount {
            account_id: body.account_id.ok_or(SdkError::CustodySetupInvalid)?,
            display_name: body.display_name.ok_or(SdkError::CustodySetupInvalid)?,
            state: body.state.ok_or(SdkError::CustodySetupInvalid)?,
            networking: body.networking.ok_or(SdkError::CustodySetupInvalid)?,
        })
    }
    /// # Errors
    /// Returns transport/protocol errors. Cancellation is idempotent after consumption.
    pub async fn cancel(&mut self) -> Result<(), SdkError> {
        if self.0.exchange("account.recover.cancel", Empty {}).await?.cancelled == Some(true) {
            Ok(())
        } else {
            Err(SdkError::CustodySetupInvalid)
        }
    }
}

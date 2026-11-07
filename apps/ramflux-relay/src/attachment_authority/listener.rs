// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain
//! Dormant relay authority request router (P25 N5b). A source router, and only a
//! source router, may reach `/s9/attachment-authority/{challenge,renew}`. The peer is
//! authorized from the transport SPIFFE identity before the body is read; the
//! service matrix alone is not enough because it also admits the retention service.
//! Nothing binds a socket unless [`AuthorityListenerConfig::bind_addr`] is set, and no
//! production caller constructs a listener.
use super::{
    IssueError, IssueHooks, Outcome, RenewAdmitRequest, RenewAdmitResponse, SourceIssuer, TokenSink,
};
use ramflux_node_core::attachment::{ChallengeMint, HomeVerdict, RenewalRefusal};
use ramflux_protocol::large_attachment::QualifiedOwner;
use serde::{Deserialize, Serialize};
use std::{collections::BTreeSet, time::Duration};

pub const CHALLENGE_PATH: &str = "/s9/attachment-authority/challenge";
pub const RENEW_PATH: &str = "/s9/attachment-authority/renew";
/// The only peer service the relay authority accepts.
pub const ROUTER_SERVICE_ID: &str = "ramflux-router";
const RELAY_SERVICE_ID: &str = "ramflux-relay";
/// Design section 1: bodies are at most 16 KiB on the wire.
pub const MAX_WIRE_BODY: usize = 16 * 1024;
const WRITE_DEADLINE: Duration = Duration::from_secs(5);

/// Off by default: no bind address, no listener.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AuthorityListenerConfig {
    pub bind_addr: Option<String>,
}
impl AuthorityListenerConfig {
    #[must_use]
    pub fn enabled(&self) -> bool {
        self.bind_addr.is_some()
    }
}

/// Requester identity on the wire (`QualifiedOwner` itself is not a wire type).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RequesterWire {
    pub account_anchor: String,
    pub device_id: String,
    pub device_epoch: u64,
    pub signing_public_key: [u8; 32],
    pub home_node_id: String,
}
impl From<&RequesterWire> for QualifiedOwner {
    fn from(w: &RequesterWire) -> Self {
        Self {
            account_anchor: w.account_anchor.clone(),
            device_id: w.device_id.clone(),
            device_epoch: w.device_epoch,
            signing_public_key: w.signing_public_key,
            home_node_id: w.home_node_id.clone(),
        }
    }
}

/// `ChallengeMint` on the wire. `home_verdict` is `Option` only so that a missing one
/// is a typed refusal rather than a parse failure.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChallengeMintRequest {
    pub capability: Vec<u8>,
    pub target_operation: Vec<u8>,
    pub requester: RequesterWire,
    pub home_node: String,
    pub peer_node: String,
    #[serde(default)]
    pub home_verdict: Option<HomeVerdict>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ChallengeReply {
    Minted { challenge: [u8; 32], authority_generation: u64, expires_at: u64 },
    Refused { code: RenewalRefusal },
}

/// What the transport must do with the request.
#[derive(Debug, PartialEq, Eq)]
pub enum Handled {
    /// Refused before the body was read or parsed.
    Rejected { status: &'static str, reason: &'static str },
    /// A challenge reply frame, to be written as JSON.
    Challenge(ChallengeReply),
    /// The renew frame was written to the sink; see the outcome.
    Renew(Outcome),
}

/// One received request. `peer_spiffe_uri` is the verified TLS SAN, never a header.
#[derive(Debug, Clone, Copy)]
pub struct Incoming<'a> {
    pub peer_spiffe_uri: Option<&'a str>,
    pub method: &'a str,
    pub path: &'a str,
    pub body: &'a [u8],
    /// The original request deadline; handling never waits on the ledger past it.
    pub deadline: Option<std::time::Instant>,
}

pub struct AuthorityListener<'a> {
    issuer: &'a SourceIssuer,
    router_only: BTreeSet<String>,
}

impl<'a> AuthorityListener<'a> {
    #[must_use]
    pub fn new(issuer: &'a SourceIssuer) -> Self {
        Self { issuer, router_only: BTreeSet::from([ROUTER_SERVICE_ID.to_owned()]) }
    }

    /// Whether `peer_spiffe_uri` is the router. Transports call this before reading a
    /// single byte of the request; [`Self::handle`] repeats it.
    #[must_use]
    pub fn authorize(&self, peer_spiffe_uri: Option<&str>) -> bool {
        ramflux_node_core::authorize_mesh_peer(RELAY_SERVICE_ID, &self.router_only, peer_spiffe_uri)
            .is_ok()
    }

    /// Routes one request. `peer_spiffe_uri` is the verified TLS SAN, never a header.
    /// # Errors
    /// Only the renew path can fail after authorization: see [`SourceIssuer::respond`].
    pub fn handle(
        &self,
        incoming: &Incoming<'_>,
        clock: &dyn Fn() -> u64,
        sink: &mut dyn TokenSink,
        hooks: &IssueHooks<'_>,
    ) -> Result<Handled, IssueError> {
        let Incoming { peer_spiffe_uri, method, path, body, deadline } = *incoming;
        if !self.authorize(peer_spiffe_uri) {
            return Ok(Handled::Rejected {
                status: "403 Forbidden",
                reason: "attachment authority requires the router identity",
            });
        }
        if method != "POST" || (path != CHALLENGE_PATH && path != RENEW_PATH) {
            return Ok(Handled::Rejected { status: "404 Not Found", reason: "unknown route" });
        }
        if body.len() > MAX_WIRE_BODY {
            return Ok(Handled::Rejected { status: "413 Payload Too Large", reason: "body" });
        }
        if path == CHALLENGE_PATH {
            return Ok(Handled::Challenge(self.challenge(body, clock(), deadline)));
        }
        let bounded = IssueHooks {
            before_admission: hooks.before_admission,
            after_commit: hooks.after_commit,
            before_final_token_check: hooks.before_final_token_check,
            deadline: deadline.or(hooks.deadline),
        };
        self.renew(body, clock, sink, &bounded)
    }

    fn challenge(
        &self,
        body: &[u8],
        now: u64,
        deadline: Option<std::time::Instant>,
    ) -> ChallengeReply {
        let refused = |code| ChallengeReply::Refused { code };
        let Ok(request) = serde_json::from_slice::<ChallengeMintRequest>(body) else {
            return refused(RenewalRefusal::Invalid);
        };
        let Some(verdict) = request.home_verdict.as_ref() else {
            return refused(RenewalRefusal::HomeTrustUnavailable);
        };
        let requester = QualifiedOwner::from(&request.requester);
        match self.issuer.challenge_until(
            &ChallengeMint {
                capability: &request.capability,
                target_operation: &request.target_operation,
                requester: &requester,
                home_node: &request.home_node,
                peer_node: &request.peer_node,
                verdict,
            },
            now,
            deadline,
        ) {
            Ok(c) => ChallengeReply::Minted {
                challenge: c.challenge,
                authority_generation: c.authority_generation,
                expires_at: c.expires_at,
            },
            Err(code) => refused(code),
        }
    }

    fn renew(
        &self,
        body: &[u8],
        clock: &dyn Fn() -> u64,
        sink: &mut dyn TokenSink,
        hooks: &IssueHooks<'_>,
    ) -> Result<Handled, IssueError> {
        let missing_verdict = serde_json::from_slice::<serde_json::Value>(body)
            .is_ok_and(|v| v.get("home_verdict").is_none_or(serde_json::Value::is_null));
        let parsed = if missing_verdict {
            Err(RenewalRefusal::HomeTrustUnavailable)
        } else {
            serde_json::from_slice::<RenewAdmitRequest>(body).map_err(|_| RenewalRefusal::Invalid)
        };
        match parsed {
            Ok(request) => self.issuer.respond(&request, clock, sink, hooks).map(Handled::Renew),
            Err(code) => {
                let frame = serde_json::to_vec(&RenewAdmitResponse::Refused { code })
                    .map_err(|_| IssueError::Write(std::io::ErrorKind::InvalidData))?;
                sink.write_token(&frame, WRITE_DEADLINE).map_err(|e| {
                    sink.reset();
                    IssueError::Write(e.kind())
                })?;
                Ok(Handled::Renew(Outcome::Refused(code)))
            }
        }
    }
}

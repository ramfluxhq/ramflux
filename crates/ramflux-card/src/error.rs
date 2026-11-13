// SPDX-License-Identifier: BSD-3-Clause
/// Failures are terminal for an evaluation, never a partially mounted tree.
#[derive(Debug, thiserror::Error)]
pub enum CardError {
    #[error("card limit exceeded: {0}")]
    Limit(&'static str),
    #[error("invalid card: {0}")]
    Invalid(&'static str),
    #[error("invalid JSON")]
    Json(#[from] serde_json::Error),
    #[error("package signature or engine mismatch")]
    Signature,
    #[error("package admission rejected: {0}")]
    Admission(&'static str),
    #[error("script exception")]
    Script,
    #[error("interpreter memory exhausted")]
    Memory,
    #[error("interpreter stack exhausted")]
    Stack,
    #[error("intrinsic hardening failed")]
    Hardening,
    #[error("interpreter failure")]
    Engine,
    #[error("evaluation budget exhausted")]
    Budget,
    #[error("session is suspended or failed")]
    Inactive,
}
impl From<rquickjs::Error> for CardError {
    fn from(error: rquickjs::Error) -> Self {
        if matches!(error, rquickjs::Error::Allocation) {
            return Self::Memory;
        }
        Self::Engine
    }
}

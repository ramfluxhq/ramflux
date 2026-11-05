// SPDX-License-Identifier: MIT OR Apache-2.0
use super::*;

/// Compute the negotiated idle timeout based on local and remote max_idle_timeout transport parameters.
///
/// According to the definition of max_idle_timeout, a value of `0` means the timeout is disabled; see <https://www.rfc-editor.org/rfc/rfc9000#section-18.2-4.4.1.>
///
/// According to the negotiation procedure, either the minimum of the timeouts or one specified is used as the negotiated value; see <https://www.rfc-editor.org/rfc/rfc9000#section-10.1-2.>
///
/// Returns the negotiated idle timeout as a `Duration`, or `None` when both endpoints have opted out of idle timeout.
pub(super) fn negotiate_max_idle_timeout(x: Option<VarInt>, y: Option<VarInt>) -> Option<Duration> {
    match (x, y) {
        (Some(VarInt(0)) | None, Some(VarInt(0)) | None) => None,
        (Some(VarInt(0)) | None, Some(y)) => Some(Duration::from_millis(y.0)),
        (Some(x), Some(VarInt(0)) | None) => Some(Duration::from_millis(x.0)),
        (Some(x), Some(y)) => Some(Duration::from_millis(cmp::min(x, y).0)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn negotiate_max_idle_timeout_commutative() {
        let test_params = [
            (None, None, None),
            (None, Some(VarInt(0)), None),
            (None, Some(VarInt(2)), Some(Duration::from_millis(2))),
            (Some(VarInt(0)), Some(VarInt(0)), None),
            (
                Some(VarInt(2)),
                Some(VarInt(0)),
                Some(Duration::from_millis(2)),
            ),
            (
                Some(VarInt(1)),
                Some(VarInt(4)),
                Some(Duration::from_millis(1)),
            ),
        ];

        for (left, right, result) in test_params {
            assert_eq!(negotiate_max_idle_timeout(left, right), result);
            assert_eq!(negotiate_max_idle_timeout(right, left), result);
        }
    }
}

// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

import Foundation

// Swift Task cancellation mapped onto the binding's explicit cancel handle.
//
// UniFFI does not cancel a Rust future when the Swift Task is cancelled, so the handle is
// the only cancellation path. Cancelling the Task makes the call return early with an
// `ExecuteOutcome` that says whether the core had already claimed the request:
//
//   .endedBeforeClaim  nothing was executed and nothing will be
//   .endedAfterClaim   the core keeps executing; the effect is unknown to this caller
//
// Neither is thrown as `CancellationError`, because "cancelled" alone would hide the
// difference. Discarding a Task handle without cancelling it does not cancel the request.

extension RamfluxCore {
    /// Run one request. Cancelling the surrounding Task cancels the wait, not an execution
    /// the core already claimed.
    public func run(_ request: CoreRequest) async throws -> ExecuteOutcome {
        let handle = CancelHandle()
        return try await withTaskCancellationHandler {
            try await self.execute(request: request, cancel: handle)
        } onCancel: {
            handle.cancel()
        }
    }

    /// Run one request and return the reply, or throw `RamfluxWaitEnded` when the wait ended
    /// first. Use `run(_:)` when the caller wants to switch over the outcome itself.
    public func reply(to request: CoreRequest) async throws -> CoreResponse {
        switch try await run(request) {
        case .completed(let response):
            return response
        case .endedBeforeClaim(let end):
            throw RamfluxWaitEnded(end: end, claimed: false, lifecycle: false, operationId: nil)
        case .endedAfterClaim(let end, let operationId, let lifecycle):
            throw RamfluxWaitEnded(
                end: end, claimed: true, lifecycle: lifecycle, operationId: operationId)
        }
    }
}

/// The wait for a reply ended before the reply. `claimed == false` proves the request had no
/// effect. `claimed == true` proves nothing: a send may have happened. Reconcile by reading
/// the operation under `operationId`; never retry with a new operation id.
public struct RamfluxWaitEnded: Error, Sendable {
    public let end: WaiterEnd
    public let claimed: Bool
    public let lifecycle: Bool
    public let operationId: String?

    /// True only when the request is proven to have had no effect.
    public var provenNoEffect: Bool { !claimed }
}

extension CoreRequest {
    /// Build a request from a JSON object. The body is encoded with sorted keys so that the
    /// same input always yields the same bytes.
    public static func json(
        _ method: String,
        account: String? = nil,
        body: [String: Any] = [:],
        deadlineMs: UInt64 = 30_000,
        operationId: String? = nil
    ) throws -> CoreRequest {
        let data = try JSONSerialization.data(withJSONObject: body, options: [.sortedKeys])
        guard let text = String(data: data, encoding: .utf8) else {
            throw CocoaError(.fileReadInapplicableStringEncoding)
        }
        return CoreRequest(
            method: method,
            accountId: account,
            bodyJson: text,
            deadlineMs: deadlineMs,
            operationId: operationId)
    }
}

extension CoreResponse {
    /// The reply body as a JSON object. 64-bit integers arrive as decimal strings.
    public func object() throws -> [String: Any] {
        let value = try JSONSerialization.jsonObject(with: Data(bodyJson.utf8))
        return value as? [String: Any] ?? [:]
    }
}

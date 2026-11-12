// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

import Foundation

/// A listener that applies rows with a closure and grants credit back after each batch.
///
/// A stream is a listener plus an explicit cancel; it is deliberately not an `AsyncSequence`
/// with an unbounded buffer. The core delivers at most the granted number of rows, so a slow
/// `apply` slows delivery instead of growing memory. When the host falls too far behind,
/// `onLag` gives the journal sequence to re-read from; no row is lost.
public final class UpdateStream: UpdateListener, @unchecked Sendable {
    public typealias Apply = @Sendable ([UpdateRow]) throws -> Void
    public typealias Lag = @Sendable (_ resumeAfter: UInt64, _ skipped: UInt64) throws -> Void
    public typealias End = @Sendable (SubscriptionEnd) -> Void

    private let apply: Apply
    private let lag: Lag
    private let end: End
    private let lock = NSLock()
    private var subscription: Subscription?

    private init(apply: @escaping Apply, lag: @escaping Lag, end: @escaping End) {
        self.apply = apply
        self.lag = lag
        self.end = end
    }

    /// Open a stream. `window` is the number of rows the core may deliver before the host
    /// has applied any; each applied batch grants the same number of rows back.
    public static func open(
        on core: RamfluxCore,
        account: String?,
        topics: [String],
        after journalSequence: UInt64? = nil,
        window: UInt32 = 64,
        apply: @escaping Apply,
        lag: @escaping Lag = { _, _ in },
        end: @escaping End = { _ in }
    ) throws -> UpdateStream {
        let stream = UpdateStream(apply: apply, lag: lag, end: end)
        let subscription = try core.subscribe(
            filter: SubscribeFilter(
                accountId: account,
                topics: topics,
                afterJournalSequence: journalSequence,
                initialCredit: window),
            listener: stream)
        stream.lock.lock()
        stream.subscription = subscription
        stream.lock.unlock()
        return stream
    }

    /// Stop the stream. Idempotent.
    public func cancel() {
        current()?.cancel()
    }

    private func current() -> Subscription? {
        lock.lock()
        defer { lock.unlock() }
        return subscription
    }

    // MARK: UpdateListener

    public func onUpdates(rows: [UpdateRow]) throws {
        // A throw ends the stream as failed; the rows stay in the journal.
        try apply(rows)
        // Credit is returned only after the rows were applied.
        current()?.grant(rows: UInt32(clamping: rows.count))
    }

    public func onLag(resumeAfterJournalSequence: UInt64, skippedRows: UInt64) throws {
        try lag(resumeAfterJournalSequence, skippedRows)
    }

    public func onEnd(end: SubscriptionEnd) throws {
        self.end(end)
        lock.lock()
        subscription = nil
        lock.unlock()
    }
}

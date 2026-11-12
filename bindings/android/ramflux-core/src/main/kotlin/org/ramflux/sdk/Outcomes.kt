// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

package org.ramflux.sdk

import kotlinx.coroutines.CancellationException
import org.ramflux.sdk.ffi.SubscriptionEnd
import org.ramflux.sdk.ffi.UpdateRow
import org.ramflux.sdk.ffi.WaiterEnd

/**
 * What the core knows about a request whose caller stopped waiting.
 *
 * The typed refusals of the core are the generated `CoreException` cases (one per stable
 * numeric code) and are thrown unchanged. The types below cover the other way a call can
 * end without a reply: the waiter went away.
 */
sealed interface WaiterOutcome {
    /** The core never claimed the request. Proven: nothing ran and nothing will. */
    data class NoEffect(val end: WaiterEnd) : WaiterOutcome

    /**
     * The core claimed the request before the waiter ended and keeps executing it. The
     * effect is unknown to this caller: a send may have happened. Reconcile by reading
     * the operation under [operationId]. Never retry with a new key.
     */
    data class Unknown(
        val end: WaiterEnd,
        val operationId: String?,
        /** True for a keyed lifecycle operation, which the supervisor retains with its receipt. */
        val lifecycle: Boolean,
    ) : WaiterOutcome

    /** The reply arrived, but the caller was already cancelled and never saw it. */
    data class CompletedUnobserved(val operationId: String?) : WaiterOutcome

    /**
     * The core answered with an error the cancelled caller never saw. A typed error can be
     * the reply of a request that ran, so this says nothing about the effect.
     */
    data class FailedUnobserved(val error: Throwable, val operationId: String?) : WaiterOutcome
}

/** The request deadline passed, or the reply channel was lost, before the core claimed it. */
class RequestNotExecutedException(val outcome: WaiterOutcome.NoEffect) :
    Exception("request ended before the core claimed it (${outcome.end}); nothing was executed")

/**
 * The waiter ended after the core claimed the request. This is not a failure of the
 * request and not proof that it had no effect.
 */
class OutcomeUnknownException(val outcome: WaiterOutcome.Unknown) :
    Exception(
        "request was claimed by the core before the waiter ended (${outcome.end}); " +
            "its effect is unknown, reconcile by operation id",
    )

/**
 * Thrown from `execute` when the calling coroutine was cancelled. It is a
 * [CancellationException], so structured concurrency treats it as ordinary cancellation;
 * code that needs to reconcile can read [outcome].
 */
class ExecuteCancelledException(val outcome: WaiterOutcome) :
    CancellationException("execute was cancelled; core outcome: $outcome")

/** One element of an update stream. */
sealed interface UpdateEvent {
    /** A row in journal order. Unknown content is a row, never an exception. */
    data class Row(val row: UpdateRow) : UpdateEvent

    /**
     * Rows were not delivered because the collector fell behind. Nothing is lost: re-read
     * from [resumeAfterJournalSequence]; the stream continues at the live edge.
     */
    data class Lagged(val resumeAfterJournalSequence: ULong, val skippedRows: ULong) : UpdateEvent

    /** Terminal. The flow completes after this element. */
    data class Ended(val end: SubscriptionEnd) : UpdateEvent
}

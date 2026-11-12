// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

package org.ramflux.sdk

import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.async
import kotlinx.coroutines.cancel
import kotlinx.coroutines.channels.BufferOverflow
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.SharedFlow
import kotlinx.coroutines.flow.asSharedFlow
import kotlinx.coroutines.flow.flow
import kotlinx.coroutines.withContext
import org.ramflux.sdk.ffi.CoreConfig
import org.ramflux.sdk.ffi.CoreRequest
import org.ramflux.sdk.ffi.CoreResponse
import org.ramflux.sdk.ffi.CoreState
import org.ramflux.sdk.ffi.ExecuteOutcome
import org.ramflux.sdk.ffi.Negotiated
import org.ramflux.sdk.ffi.NetworkChange
import org.ramflux.sdk.ffi.SubscribeFilter
import org.ramflux.sdk.ffi.SubscriptionEnd
import org.ramflux.sdk.ffi.SuspendEvidence
import org.ramflux.sdk.ffi.UpdateListener
import org.ramflux.sdk.ffi.UpdateRow
import org.ramflux.sdk.ffi.WaiterEnd

/**
 * The coroutine face of the in-process ramflux core.
 *
 * There is one client per data root per process, and the application process is the
 * supervisor. The client opens no socket and holds no database handle of its own: every
 * call is a request to the core, and every stream is a subscription of the core.
 *
 * Cancellation. Cancelling the [kotlinx.coroutines.Job] that runs [execute] tells the core
 * to stop waiting; it does not undo anything. If the core had not claimed the request,
 * nothing ran. If it had, the request keeps running and the effect is unknown to the
 * caller: a cancelled send is not a send that did not happen. The client never retries
 * and never invents an operation id. Every such request is also published on
 * [unobservedOutcomes] so the application can reconcile it by operation id.
 */
class RamfluxClient internal constructor(
    private val bridge: CoreBridge,
    private val blocking: CoroutineDispatcher = Dispatchers.IO,
    callDispatcher: CoroutineDispatcher = Dispatchers.Default,
) : AutoCloseable {
    /**
     * Owns the foreign calls. A caller's cancellation must not tear the foreign future
     * down before the core has said whether it claimed the request, so the call runs here
     * and the caller only awaits it.
     */
    private val calls = CoroutineScope(SupervisorJob() + callDispatcher)

    private val unobserved = MutableSharedFlow<WaiterOutcome>(
        replay = 0,
        extraBufferCapacity = UNOBSERVED_BUFFER,
        onBufferOverflow = BufferOverflow.DROP_OLDEST,
    )

    /**
     * Outcomes of requests whose caller was cancelled before it could see them, other than
     * proven no-effect ones. This is a hint for prompt reconciliation, bounded and lossy
     * under overflow; the authority is the operation receipt in the core.
     */
    val unobservedOutcomes: SharedFlow<WaiterOutcome> = unobserved.asSharedFlow()

    /** Versions, descriptor fingerprint and capabilities agreed when the core was created. */
    val negotiated: Negotiated get() = bridge.negotiated()

    val state: CoreState get() = bridge.state()

    /** Acquire the data-root lock and start the supervisor. */
    suspend fun start(): Unit = withContext(blocking) { bridge.start() }

    /**
     * Leave the foreground: end every stream, close every store, release every file lock.
     * Returns only after the release was observed. Not cancellable once begun, because a
     * half-finished suspension is exactly the state the platform must never freeze.
     */
    suspend fun suspend(): SuspendEvidence =
        withContext(blocking + NonCancellable) { bridge.suspend() }

    /** Return to the foreground. Collect [updates] again afterwards. */
    suspend fun resume(): Unit = withContext(blocking) { bridge.resume() }

    /** Report a default-network change. Never blocks. */
    fun networkChanged(change: NetworkChange) = bridge.networkChanged(change)

    /**
     * Begin creating an account on [nodeId] (or the default node). The returned ceremony
     * shows the recovery phrase once and asks three words back; close it when done.
     *
     * @throws org.ramflux.sdk.ffi.CoreException `CapabilityRejected` when the core cannot
     *   carry the ceremony, `CryptoFailed` when no hardware-backed vault is available.
     */
    suspend fun beginAccountCreation(displayName: String, nodeId: String? = null): AccountCreation =
        bridge.beginAccountCreation(displayName, nodeId)

    /**
     * Run one request and return its reply.
     *
     * @throws org.ramflux.sdk.ffi.CoreException the core's typed refusal or failure.
     * @throws RequestNotExecutedException the deadline passed, or the reply channel was
     *   lost, before the core claimed the request. Nothing was executed.
     * @throws OutcomeUnknownException the waiter ended after the core claimed the request.
     * @throws ExecuteCancelledException the calling coroutine was cancelled.
     */
    suspend fun execute(request: CoreRequest): CoreResponse {
        currentCoroutineContext().ensureActive()
        val token = bridge.newCancelToken()
        // UNDISPATCHED: the request is handed to the core before this function can observe
        // a cancellation, so "cancelled" always has a definite answer from the core.
        val call = calls.async(start = CoroutineStart.UNDISPATCHED) {
            try {
                bridge.execute(request, token)
            } finally {
                token.close()
            }
        }
        val outcome = try {
            call.await()
        } catch (cancelled: CancellationException) {
            if (currentCoroutineContext()[Job]?.isActive != false) {
                // The caller is not cancelled: the client was closed under it. The request
                // was already handed to the core, so nothing can be said about its effect.
                throw OutcomeUnknownException(
                    WaiterOutcome.Unknown(WaiterEnd.REPLY_LOST, request.operationId, false),
                )
            }
            token.cancel()
            // The core answers a cancelled waiter at once, with what it knows about the claim.
            val settled = withContext(NonCancellable) { runCatching { call.await() } }
            val known = settled.fold(
                onSuccess = { it.asWaiterOutcome() },
                // A typed error may be the reply of an executed request, so it proves
                // nothing about the effect and is reported as it is.
                onFailure = { WaiterOutcome.FailedUnobserved(it, request.operationId) },
            )
            if (known !is WaiterOutcome.NoEffect) {
                unobserved.tryEmit(known)
            }
            throw ExecuteCancelledException(known)
        }
        return when (outcome) {
            is ExecuteOutcome.Completed -> outcome.response
            is ExecuteOutcome.EndedBeforeClaim ->
                throw RequestNotExecutedException(WaiterOutcome.NoEffect(outcome.end))
            is ExecuteOutcome.EndedAfterClaim ->
                throw OutcomeUnknownException(
                    WaiterOutcome.Unknown(outcome.end, outcome.operationId, outcome.lifecycle),
                )
        }
    }

    /**
     * Updates as a cold [Flow] with credit back-pressure.
     *
     * The core delivers at most [window] rows ahead of the collector. A row's credit is
     * returned only after the collector's block has finished with it, so a slow collector
     * slows delivery instead of growing a queue. If the collector is so slow that the core
     * must skip rows, the flow emits [UpdateEvent.Lagged] and continues at the live edge;
     * nothing is lost, because the rows are in the journal. The flow ends with
     * [UpdateEvent.Ended]; after [SubscriptionEnd.SUSPENDED] collect again once resumed.
     * Cancelling the collector cancels the subscription.
     */
    fun updates(filter: SubscribeFilter, window: Int = DEFAULT_WINDOW): Flow<UpdateEvent> {
        require(window in 1..MAX_WINDOW) { "window must be in 1..$MAX_WINDOW" }
        return flow {
            // Bounded by construction: rows never exceed the granted credit, and the core
            // sends at most one lag notice per gap and one end.
            val events = Channel<UpdateEvent>(Channel.UNLIMITED)
            val listener = object : UpdateListener {
                override fun onUpdates(rows: List<UpdateRow>) {
                    rows.forEach { events.trySend(UpdateEvent.Row(it)) }
                }

                override fun onLag(resumeAfterJournalSequence: ULong, skippedRows: ULong) {
                    events.trySend(UpdateEvent.Lagged(resumeAfterJournalSequence, skippedRows))
                }

                override fun onEnd(end: SubscriptionEnd) {
                    events.trySend(UpdateEvent.Ended(end))
                    events.close()
                }
            }
            val subscription = withContext(blocking) {
                bridge.subscribe(filter.copy(initialCredit = window.toUInt()), listener)
            }
            try {
                val refill = maxOf(1, window / 2)
                var applied = 0
                for (event in events) {
                    // Returns when the collector has finished with the element.
                    emit(event)
                    if (event is UpdateEvent.Row) {
                        applied += 1
                        if (applied >= refill) {
                            subscription.grant(applied.toUInt())
                            applied = 0
                        }
                    }
                }
            } finally {
                subscription.cancel()
                subscription.close()
            }
        }
    }

    /** Stop the supervisor for good and release the native core. Idempotent. */
    override fun close() {
        calls.cancel()
        bridge.shutdown()
    }

    private fun ExecuteOutcome.asWaiterOutcome(): WaiterOutcome = when (this) {
        is ExecuteOutcome.Completed -> WaiterOutcome.CompletedUnobserved(response.operationId)
        is ExecuteOutcome.EndedBeforeClaim -> WaiterOutcome.NoEffect(end)
        is ExecuteOutcome.EndedAfterClaim -> WaiterOutcome.Unknown(end, operationId, lifecycle)
    }

    companion object {
        const val DEFAULT_WINDOW: Int = 64
        const val MAX_WINDOW: Int = 1024
        private const val UNOBSERVED_BUFFER: Int = 256

        /**
         * Create the client for [config]. Nothing is opened until [start].
         *
         * @throws org.ramflux.sdk.ffi.CoreException `UnsupportedVersion` when these bindings
         *   and the native library are not compatible.
         */
        fun open(config: CoreConfig): RamfluxClient = RamfluxClient(UniffiCoreBridge.open(config))
    }
}

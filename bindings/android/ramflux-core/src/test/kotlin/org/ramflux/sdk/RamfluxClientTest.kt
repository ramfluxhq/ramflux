// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

package org.ramflux.sdk

import java.util.concurrent.atomic.AtomicBoolean
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.async
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.toList
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.StandardTestDispatcher
import kotlinx.coroutines.test.TestScope
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import org.ramflux.sdk.ffi.ApiVersion
import org.ramflux.sdk.ffi.CoreException
import org.ramflux.sdk.ffi.CoreRequest
import org.ramflux.sdk.ffi.CoreResponse
import org.ramflux.sdk.ffi.CoreState
import org.ramflux.sdk.ffi.ErrorDetail
import org.ramflux.sdk.ffi.ExecuteOutcome
import org.ramflux.sdk.ffi.Negotiated
import org.ramflux.sdk.ffi.NetworkChange
import org.ramflux.sdk.ffi.SubscribeFilter
import org.ramflux.sdk.ffi.SubscriptionEnd
import org.ramflux.sdk.ffi.SuspendEvidence
import org.ramflux.sdk.ffi.UpdateListener
import org.ramflux.sdk.ffi.UpdateRow
import org.ramflux.sdk.ffi.UpdateState
import org.ramflux.sdk.ffi.WaiterEnd

/**
 * The coroutine mapping against a bridge that behaves like the core's claim gate. No
 * native library is loaded: the generated records are plain Kotlin.
 */
@OptIn(ExperimentalCoroutinesApi::class)
class RamfluxClientTest {
    /** One pending request of the fake core. */
    private class Pending(val request: CoreRequest) {
        val reply = CompletableDeferred<ExecuteOutcome>()
        val claimed = AtomicBoolean(false)
        var lifecycle = false

        /** The core reaches the first effect of the request. */
        fun claim(lifecycle: Boolean = false) {
            this.lifecycle = lifecycle
            claimed.set(true)
        }
    }

    private class FakeBridge : CoreBridge {
        val pending = mutableListOf<Pending>()
        val grants = mutableListOf<UInt>()
        var listener: UpdateListener? = null
        var filter: SubscribeFilter? = null
        var subscriptionCancelled = false
        var failWith: CoreException? = null

        /** Requests the fake core ran to an effect. Must never exceed one per operation. */
        val effects get() = pending.count { it.claimed.get() }

        override fun negotiated() = Negotiated(ApiVersion(1u, 0u), "00", true, emptyList())

        override fun start() = Unit

        override fun suspend() = SuspendEvidence(true, true, 1u)

        override fun resume() = Unit

        override fun shutdown() = Unit

        override fun state() = CoreState.RUNNING

        override fun networkChanged(change: NetworkChange) = Unit

        override fun newCancelToken(): CancelToken = object : CancelToken {
            override fun cancel() {
                // The claim gate: a cancelled waiter learns whether the core got there first.
                val call = pending.last()
                call.reply.complete(
                    if (call.claimed.get()) {
                        ExecuteOutcome.EndedAfterClaim(
                            WaiterEnd.CANCELLED,
                            call.request.operationId,
                            call.lifecycle,
                        )
                    } else {
                        ExecuteOutcome.EndedBeforeClaim(WaiterEnd.CANCELLED)
                    },
                )
            }

            override fun close() = Unit
        }

        override suspend fun execute(request: CoreRequest, cancel: CancelToken): ExecuteOutcome {
            failWith?.let { throw it }
            val call = Pending(request)
            pending += call
            return call.reply.await()
        }

        override suspend fun beginAccountCreation(displayName: String, nodeId: String?): AccountCreation =
            throw UnsupportedOperationException("not part of these tests")

        override fun subscribe(filter: SubscribeFilter, listener: UpdateListener): SubscriptionHandle {
            this.filter = filter
            this.listener = listener
            return object : SubscriptionHandle {
                override fun grant(rows: UInt) {
                    grants += rows
                }

                override fun cancel() {
                    subscriptionCancelled = true
                }

                override fun close() = Unit
            }
        }
    }

    private fun send(operationId: String? = "op-1") = CoreRequest(
        method = "message.submit",
        accountId = "acct",
        bodyJson = "{}",
        deadlineMs = 30_000u,
        operationId = operationId,
    )

    private fun row(sequence: ULong, state: UpdateState = UpdateState.Content("{}")) =
        UpdateRow("message.received", "acct", sequence, null, state)

    private fun filter() = SubscribeFilter("acct", emptyList(), null, 0u)

    /** A client whose blocking calls and foreign calls both run on the test scheduler. */
    private fun TestScope.client(bridge: CoreBridge): RamfluxClient {
        val dispatcher = StandardTestDispatcher(testScheduler)
        return RamfluxClient(bridge, dispatcher, dispatcher)
    }

    @Test
    fun completed_request_returns_the_reply() = runTest {
        val bridge = FakeBridge()
        val client = client(bridge)
        val reply = async { client.execute(send()) }
        advanceUntilIdle()
        val response = CoreResponse("message.submit", "acct", "{\"ok\":true}", "op-1")
        bridge.pending.single().reply.complete(ExecuteOutcome.Completed(response))
        assertSame(response, reply.await())
    }

    @Test
    fun cancel_before_claim_has_no_effect_and_publishes_nothing() = runTest {
        val bridge = FakeBridge()
        val client = client(bridge)
        var seen: WaiterOutcome? = null
        val job = launch {
            try {
                client.execute(send())
            } catch (cancelled: ExecuteCancelledException) {
                seen = cancelled.outcome
                throw cancelled
            }
        }
        advanceUntilIdle()
        job.cancelAndJoin()
        assertEquals(WaiterOutcome.NoEffect(WaiterEnd.CANCELLED), seen)
        assertEquals("no request may run after a pre-claim cancel", 0, bridge.effects)
        assertEquals(1, bridge.pending.size)
    }

    @Test
    fun cancel_after_a_lifecycle_claim_is_unknown_and_the_core_keeps_the_operation() = runTest {
        val bridge = FakeBridge()
        val client = client(bridge)
        val published = async { client.unobservedOutcomes.first() }
        var seen: WaiterOutcome? = null
        val job = launch {
            try {
                client.execute(send("unlock-1"))
            } catch (cancelled: ExecuteCancelledException) {
                seen = cancelled.outcome
                throw cancelled
            }
        }
        advanceUntilIdle()
        bridge.pending.single().claim(lifecycle = true)
        job.cancelAndJoin()
        val expected = WaiterOutcome.Unknown(WaiterEnd.CANCELLED, "unlock-1", true)
        assertEquals(expected, seen)
        assertEquals("the application is told to reconcile", expected, published.await())
        assertEquals("the claimed operation still belongs to the core", 1, bridge.effects)
        assertEquals("a cancelled call is never sent again", 1, bridge.pending.size)
    }

    @Test
    fun lost_reply_after_send_admission_is_unknown_never_no_effect_and_is_not_retried() = runTest {
        val bridge = FakeBridge()
        val client = client(bridge)
        val call = async {
            runCatching { client.execute(send("send-7")) }
        }
        advanceUntilIdle()
        val pending = bridge.pending.single()
        pending.claim()
        pending.reply.complete(ExecuteOutcome.EndedAfterClaim(WaiterEnd.REPLY_LOST, "send-7", false))
        val failure = call.await().exceptionOrNull()
        assertTrue("got $failure", failure is OutcomeUnknownException)
        val outcome = (failure as OutcomeUnknownException).outcome
        assertEquals("send-7", outcome.operationId)
        assertEquals(WaiterEnd.REPLY_LOST, outcome.end)
        assertEquals("exactly one execution, and no new operation key", 1, bridge.pending.size)
        assertEquals(1, bridge.effects)
    }

    @Test
    fun deadline_before_claim_is_reported_as_not_executed() = runTest {
        val bridge = FakeBridge()
        val client = client(bridge)
        val call = async { runCatching { client.execute(send()) } }
        advanceUntilIdle()
        bridge.pending.single().reply.complete(ExecuteOutcome.EndedBeforeClaim(WaiterEnd.DEADLINE))
        val failure = call.await().exceptionOrNull()
        assertTrue("got $failure", failure is RequestNotExecutedException)
        assertEquals(0, bridge.effects)
    }

    @Test
    fun typed_core_error_is_thrown_unchanged() = runTest {
        val bridge = FakeBridge()
        val busy = CoreException.AccountBusy(ErrorDetail(18, "busy", null, 1_000u))
        bridge.failWith = busy
        val client = client(bridge)
        try {
            client.execute(send())
            fail("expected the core's typed error")
        } catch (error: CoreException.AccountBusy) {
            // Compared by value: coroutine stack-trace recovery may rethrow a copy.
            assertEquals(busy.detail, error.detail)
            assertEquals(18, error.detail.code)
        }
    }

    @Test
    fun credit_is_returned_only_after_the_collector_has_applied_rows() = runTest {
        val bridge = FakeBridge()
        val client = client(bridge)
        val gate = CompletableDeferred<Unit>()
        val applied = mutableListOf<ULong>()
        val collector = launch {
            client.updates(filter(), window = 4).collect { event ->
                if (event is UpdateEvent.Row) {
                    if (applied.isEmpty()) gate.await()
                    applied += event.row.journalSequence
                }
            }
        }
        advanceUntilIdle()
        assertEquals("the window is the initial credit", 4u, bridge.filter?.initialCredit)
        bridge.listener?.onUpdates(listOf(row(1u), row(2u), row(3u), row(4u)))
        advanceUntilIdle()
        assertTrue("no credit while the collector is still inside the first row", bridge.grants.isEmpty())
        gate.complete(Unit)
        advanceUntilIdle()
        assertEquals(listOf<ULong>(1u, 2u, 3u, 4u), applied)
        assertEquals("credit comes back in half-window steps", listOf<UInt>(2u, 2u), bridge.grants)
        collector.cancelAndJoin()
        assertTrue("cancelling the collector cancels the subscription", bridge.subscriptionCancelled)
    }

    @Test
    fun lag_unknown_content_and_end_are_elements_not_exceptions() = runTest {
        val bridge = FakeBridge()
        val client = client(bridge)
        val events = async {
            client.updates(filter(), window = 8).toList()
        }
        advanceUntilIdle()
        val listener = checkNotNull(bridge.listener)
        listener.onUpdates(listOf(row(1u, UpdateState.Unknown("{\"future\":1}"))))
        listener.onLag(1u, 12u)
        listener.onUpdates(listOf(row(14u, UpdateState.Unsupported("{}"))))
        listener.onEnd(SubscriptionEnd.SUSPENDED)
        val seen = events.await()
        assertEquals(4, seen.size)
        assertTrue(seen[0] is UpdateEvent.Row)
        assertEquals(UpdateEvent.Lagged(1u, 12u), seen[1])
        assertTrue((seen[2] as UpdateEvent.Row).row.state is UpdateState.Unsupported)
        assertEquals(UpdateEvent.Ended(SubscriptionEnd.SUSPENDED), seen[3])
        assertFalse("an ended stream needs no cancel to complete", events.isActive)
    }
}

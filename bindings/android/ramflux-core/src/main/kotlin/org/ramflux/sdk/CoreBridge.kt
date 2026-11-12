// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

package org.ramflux.sdk

import org.ramflux.sdk.ffi.CancelHandle
import org.ramflux.sdk.ffi.CoreConfig
import org.ramflux.sdk.ffi.CoreRequest
import org.ramflux.sdk.ffi.CoreState
import org.ramflux.sdk.ffi.ExecuteOutcome
import org.ramflux.sdk.ffi.Negotiated
import org.ramflux.sdk.ffi.NetworkChange
import org.ramflux.sdk.ffi.RamfluxCore
import org.ramflux.sdk.ffi.SubscribeFilter
import org.ramflux.sdk.ffi.Subscription
import org.ramflux.sdk.ffi.SuspendEvidence
import org.ramflux.sdk.ffi.UpdateListener

/** Explicit cancellation of one `execute`. UniFFI futures have no built-in cancellation. */
interface CancelToken : AutoCloseable {
    /** Stop waiting. Does not undo, and does not disprove, an execution already claimed. */
    fun cancel()
}

/** One open update stream. */
interface SubscriptionHandle : AutoCloseable {
    /** Allow the core to deliver [rows] more rows. */
    fun grant(rows: UInt)

    /** End the stream. Idempotent. */
    fun cancel()
}

/**
 * The generated UniFFI surface, narrowed to what [RamfluxClient] calls.
 *
 * It exists so that the coroutine mapping can be exercised on a plain JVM without the
 * native library. The production implementation is [UniffiCoreBridge]; it adds nothing.
 */
interface CoreBridge {
    fun negotiated(): Negotiated

    /** Blocking. */
    fun start()

    /** Blocking. Returns only after every store is closed and every file lock released. */
    fun suspend(): SuspendEvidence

    /** Blocking. */
    fun resume()

    /** Blocking, idempotent. Stops the supervisor for good. */
    fun shutdown()

    fun state(): CoreState

    fun networkChanged(change: NetworkChange)

    fun newCancelToken(): CancelToken

    suspend fun execute(request: CoreRequest, cancel: CancelToken): ExecuteOutcome

    fun subscribe(filter: SubscribeFilter, listener: UpdateListener): SubscriptionHandle
}

/** [CoreBridge] over the generated bindings of `crates/ramflux-ffi`. */
internal class UniffiCoreBridge(private val core: RamfluxCore) : CoreBridge {
    private class Token(val handle: CancelHandle) : CancelToken {
        override fun cancel() {
            try {
                handle.cancel()
            } catch (_: IllegalStateException) {
                // The handle was already released: the call has completed.
            }
        }

        override fun close() = handle.close()
    }

    private class Stream(private val subscription: Subscription) : SubscriptionHandle {
        override fun grant(rows: UInt) = subscription.grant(rows)

        override fun cancel() = subscription.cancel()

        override fun close() = subscription.close()
    }

    override fun negotiated(): Negotiated = core.negotiated()

    override fun start() = core.start()

    override fun suspend(): SuspendEvidence = core.suspend()

    override fun resume() = core.resume()

    override fun shutdown() {
        try {
            // `RamfluxCore.close` in Rust; renamed in uniffi.toml because the generated
            // class already has AutoCloseable.close().
            core.shutdown()
        } finally {
            core.close()
        }
    }

    override fun state(): CoreState = core.state()

    override fun networkChanged(change: NetworkChange) = core.networkChanged(change)

    override fun newCancelToken(): CancelToken = Token(CancelHandle())

    override suspend fun execute(request: CoreRequest, cancel: CancelToken): ExecuteOutcome {
        val token = cancel as? Token
            ?: throw IllegalArgumentException("cancel token was not created by this bridge")
        return core.execute(request, token.handle)
    }

    override fun subscribe(filter: SubscribeFilter, listener: UpdateListener): SubscriptionHandle =
        Stream(core.subscribe(filter, listener))

    companion object {
        /** Creates the core. Nothing is opened until `start`. Throws `CoreException`. */
        fun open(config: CoreConfig): UniffiCoreBridge = UniffiCoreBridge(RamfluxCore.open(config))
    }
}

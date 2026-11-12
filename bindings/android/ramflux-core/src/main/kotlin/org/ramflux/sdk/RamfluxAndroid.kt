// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

package org.ramflux.sdk

import android.app.Activity
import android.app.Application
import android.content.Context
import android.net.ConnectivityManager
import android.net.LinkProperties
import android.net.Network
import android.net.NetworkCapabilities
import android.os.Bundle
import java.io.File
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import org.ramflux.sdk.ffi.ApiVersion
import org.ramflux.sdk.ffi.CoreConfig
import org.ramflux.sdk.ffi.CoreState
import org.ramflux.sdk.ffi.HostHandshake
import org.ramflux.sdk.ffi.NetworkChange
import org.ramflux.sdk.ffi.descriptorFingerprint

/** Android placement of the core: where its data lives and when it must let go of it. */
object RamfluxAndroid {
    /** Binding API this wrapper was written against. */
    private val HOST_API = ApiVersion(major = 1u, minor = 0u)

    private val CAPABILITIES =
        listOf("execute.v1", "lifecycle.v1", "network.v1", "subscribe.credit.v1")

    /**
     * The data root: a child of `getNoBackupFilesDir()`. The database, its WAL, the object
     * spool and the wrapped vault blobs all live under it, so neither cloud backup nor
     * device-to-device transfer copies them.
     */
    fun dataRoot(context: Context): File = File(context.noBackupFilesDir, "ramflux")

    /** Configuration of the one core of this application. */
    fun config(context: Context, maxPendingUpdates: UInt = 256u): CoreConfig = CoreConfig(
        dataRoot = dataRoot(context.applicationContext).absolutePath,
        handshake = HostHandshake(
            api = HOST_API,
            descriptorFingerprint = descriptorFingerprint(),
            capabilities = CAPABILITIES,
        ),
        maxPendingUpdates = maxPendingUpdates,
    )

    /**
     * Tie the core to the application's foreground state and default network.
     *
     * When the last activity stops, the core is suspended: streams end, every store is
     * closed and the data-root lock is released before the process can be frozen. When an
     * activity starts again, the core resumes. Network changes go to the core's reconnect
     * policy; this code contains no reconnect logic of its own.
     *
     * Call once, from `Application.onCreate`, after [RamfluxClient.start].
     */
    fun bind(application: Application, client: RamfluxClient): Binding {
        val binding = Binding(application, client)
        application.registerActivityLifecycleCallbacks(binding)
        application.getSystemService(ConnectivityManager::class.java)
            ?.registerDefaultNetworkCallback(binding.network)
        return binding
    }

    class Binding internal constructor(
        private val application: Application,
        private val client: RamfluxClient,
    ) : Application.ActivityLifecycleCallbacks, AutoCloseable {
        private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)

        /** Serializes suspend and resume, so a quick stop/start pair cannot interleave. */
        private val transitions = Mutex()
        private var startedActivities = 0

        internal val network = object : ConnectivityManager.NetworkCallback() {
            private var current: Network? = null
            private var announced = false
            private var transport = "other"

            override fun onAvailable(network: Network) {
                // The platform always follows this with onCapabilitiesChanged for the same
                // network; the core is told there, once the transport is known, so one
                // network has one label for its whole life.
                current = network
                announced = false
            }

            override fun onCapabilitiesChanged(network: Network, capabilities: NetworkCapabilities) {
                if (network != current) return
                transport = transportOf(capabilities)
                val label = label(network, transport)
                if (announced) {
                    client.networkChanged(NetworkChange.Changed(label))
                } else {
                    announced = true
                    client.networkChanged(NetworkChange.Available(label))
                }
            }

            override fun onLinkPropertiesChanged(network: Network, properties: LinkProperties) {
                // An address or NAT64 prefix change on the same network.
                if (network == current && announced) {
                    client.networkChanged(NetworkChange.Changed(label(network, transport)))
                }
            }

            override fun onLost(network: Network) {
                if (network == current) {
                    current = null
                    client.networkChanged(NetworkChange.Lost)
                }
            }
        }

        override fun onActivityStarted(activity: Activity) {
            startedActivities += 1
            if (startedActivities == 1) {
                scope.launch {
                    transitions.withLock {
                        if (client.state == CoreState.SUSPENDED) client.resume()
                    }
                }
            }
        }

        override fun onActivityStopped(activity: Activity) {
            startedActivities = maxOf(0, startedActivities - 1)
            // A configuration change stops and restarts the activity; that is not background.
            if (startedActivities == 0 && !activity.isChangingConfigurations) {
                scope.launch {
                    transitions.withLock {
                        if (client.state == CoreState.RUNNING) client.suspend()
                    }
                }
            }
        }

        override fun onActivityCreated(activity: Activity, savedInstanceState: Bundle?) = Unit

        override fun onActivityResumed(activity: Activity) = Unit

        override fun onActivityPaused(activity: Activity) = Unit

        override fun onActivitySaveInstanceState(activity: Activity, outState: Bundle) = Unit

        override fun onActivityDestroyed(activity: Activity) = Unit

        override fun close() {
            application.unregisterActivityLifecycleCallbacks(this)
            application.getSystemService(ConnectivityManager::class.java)
                ?.unregisterNetworkCallback(network)
        }
    }

    /**
     * Opaque per-network label. The core hashes it and uses it only to remember which
     * transport last worked on this network; it is never stored or logged as it is.
     */
    private fun label(network: Network, transport: String): ByteArray =
        "${network.networkHandle}:$transport".toByteArray(Charsets.UTF_8)

    private fun transportOf(capabilities: NetworkCapabilities): String = when {
        capabilities.hasTransport(NetworkCapabilities.TRANSPORT_VPN) -> "vpn"
        capabilities.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) -> "wifi"
        capabilities.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) -> "cell"
        capabilities.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET) -> "eth"
        else -> "other"
    }
}

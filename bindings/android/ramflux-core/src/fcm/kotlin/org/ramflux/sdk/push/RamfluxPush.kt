// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

package org.ramflux.sdk.push

import android.app.PendingIntent
import android.content.Context

/**
 * Hooks the application sets once, in `Application.onCreate`. All are optional: with none
 * set, a wake shows the generic notification and nothing else happens.
 */
object RamfluxPush {
    /** Receives the provider registration token. Register it with the user's node. */
    @Volatile
    var tokenHandler: ((token: String) -> Unit)? = null

    /** Receives a fresh call wake and the time left before it must stop ringing. */
    @Volatile
    var callWakeHandler: ((wakeId: String, remainingMillis: Long) -> Unit)? = null

    /** Builds the intent that opens the application from the generic notification. */
    @Volatile
    var contentIntent: ((context: Context) -> PendingIntent)? = null
}

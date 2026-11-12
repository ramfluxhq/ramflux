// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

package org.ramflux.sdk.push

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import com.google.firebase.messaging.FirebaseMessagingService
import com.google.firebase.messaging.RemoteMessage
import org.ramflux.sdk.R

/**
 * Receives data-only wake messages.
 *
 * It runs in the application's own process and touches neither the core nor the store: it
 * opens no connection and no database, so there is never a second lock holder. A `message`
 * wake posts the fixed generic notification. A `call_wake` goes to the application's call
 * handler, and only while it is fresh. Everything else is dropped.
 *
 * The provider message carries two opaque fields, `class` and `wake_id`. Any other field
 * means the server leaked something, and the message is refused as a whole.
 */
class RamfluxMessagingService : FirebaseMessagingService() {
    override fun onMessageReceived(message: RemoteMessage) {
        when (val wake = Wake.parse(message.data)) {
            null -> Unit
            is Wake.Message -> postGenericNotification()
            is Wake.Call -> {
                val sentAt = message.sentTime
                val age = System.currentTimeMillis() - sentAt
                val remaining = CALL_WAKE_LIFETIME_MS - age
                // A call wake without a send time, or older than its lifetime, rings nobody.
                if (sentAt > 0 && remaining > 0) {
                    RamfluxPush.callWakeHandler?.invoke(wake.wakeId, remaining)
                }
            }
        }
    }

    override fun onNewToken(token: String) {
        // The token identifies this device to the provider. It is handed to the
        // application, which registers it with the user's own node; it is never logged.
        RamfluxPush.tokenHandler?.invoke(token)
    }

    private fun postGenericNotification() {
        val manager = getSystemService(NotificationManager::class.java) ?: return
        manager.createNotificationChannel(
            NotificationChannel(
                CHANNEL_ID,
                getString(R.string.ramflux_push_channel_name),
                NotificationManager.IMPORTANCE_DEFAULT,
            ),
        )
        val notification = Notification.Builder(this, CHANNEL_ID)
            .setSmallIcon(android.R.drawable.stat_notify_chat)
            .setContentText(getString(R.string.ramflux_push_generic_text))
            .setVisibility(Notification.VISIBILITY_SECRET)
            .setAutoCancel(true)
            .setContentIntent(RamfluxPush.contentIntent?.invoke(this))
            .build()
        // One slot: a burst of wakes shows one notification, not a count of messages.
        manager.notify(NOTIFICATION_ID, notification)
    }

    internal sealed interface Wake {
        data object Message : Wake

        data class Call(val wakeId: String) : Wake

        companion object {
            /** `null` for anything that is not exactly a well-formed wake. */
            fun parse(data: Map<String, String>): Wake? {
                if (data.keys != setOf("class", "wake_id")) return null
                val wakeId = data.getValue("wake_id")
                if (wakeId.isEmpty() || wakeId.length > MAX_WAKE_ID_LENGTH) return null
                // An id derived from an envelope id is the old, leaking format.
                if (wakeId.startsWith("wake_")) return null
                return when (data.getValue("class")) {
                    "message" -> Message
                    "call_wake" -> Call(wakeId)
                    else -> null
                }
            }
        }
    }

    private companion object {
        const val CHANNEL_ID = "ramflux_updates"
        const val NOTIFICATION_ID = 0x52464c58
        const val CALL_WAKE_LIFETIME_MS = 30_000L
        const val MAX_WAKE_ID_LENGTH = 128
    }
}

// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

package org.ramflux.harness

import android.util.Base64
import java.util.concurrent.atomic.AtomicLong
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.launch
import org.json.JSONArray
import org.json.JSONObject
import org.ramflux.sdk.RamfluxClient
import org.ramflux.sdk.UpdateEvent
import org.ramflux.sdk.ffi.CoreException
import org.ramflux.sdk.ffi.CoreRequest
import org.ramflux.sdk.ffi.CoreState
import org.ramflux.sdk.ffi.SubscribeFilter

/**
 * The Android core acceptance script, in two runs separated by a process kill.
 *
 * First run: start the in-process core, add the local node, create an account through the
 * recovery-phrase ceremony, import the
 * peer's card, send one direct message, record what was sent, and return to the caller,
 * which kills the process without suspending or closing anything.
 *
 * Second run: start again on the same data root, find the account and the message in the
 * core's own database, repeat the first send under its original operation id and expect
 * no second message, send a second message over the resumed session, then prove that a
 * suspension leaves the data root unlocked.
 *
 * Every step goes through the public binding API. The script opens no socket and no
 * database of its own.
 */
class M4Script(
    private val client: RamfluxClient,
    private val args: HarnessArgs,
    private val journal: Journal,
) {
    /** Rows seen on the update stream; proves the stream delivers while requests run. */
    val updatesSeen = AtomicLong(0)

    suspend fun firstRun() {
        journal.clear()
        client.start()
        check(client.state == CoreState.RUNNING) { "core did not reach RUNNING" }
        journal.put("started", "true")

        val node = call("node.add", null, JSONObject().put("url", args.nodeUrl).put("refresh", false))
        journal.put("node", node.toString())

        val account = createAccount(node.optString("node_id").ifEmpty { null })
        journal.put("account", account)
        val status = call("account.status", account, JSONObject())
        journal.put("principal", status.getString("principal_id"))
        journal.put("device", status.getString("device_id"))

        call("contact.card.import", account, JSONObject(args.peerCardImportBody), "m4-contact")

        val sent = call("message.submit", account, submitBody(FIRST_MESSAGE, "first"), FIRST_OPERATION)
        journal.put("first_send", sent.toString())
        // The last durable fact before the kill. The caller kills the process next.
        journal.put("ready_to_die", "true")
    }

    suspend fun resumedRun(scope: CoroutineScope) {
        val account = journal.require("account")
        check(journal["ready_to_die"] == "true") { "the first run did not finish its send" }

        // The dead process held the data-root lock; the kernel released it with the process.
        client.start()

        val listed = call("account.list", null, JSONObject())
        check(listed.getJSONArray("accounts").contains(account)) {
            "account $account is not in the database after the kill: $listed"
        }
        args.accountUnlockBody?.let { call("account.unlock", account, JSONObject(it), "m4-unlock-2") }

        val collector = collectUpdates(scope, account)

        val before = messages(account)
        check(before.count { it == FIRST_MESSAGE } == 1) {
            "the message sent before the kill must be stored exactly once, found $before"
        }

        // Reconcile, do not resend: the same operation id must not create a second message.
        call("message.submit", account, submitBody(FIRST_MESSAGE, "first"), FIRST_OPERATION)
        val reconciled = messages(account)
        check(reconciled.count { it == FIRST_MESSAGE } == 1) {
            "repeating an operation id duplicated the message: $reconciled"
        }

        // A new message over the session the core re-established after the kill.
        val second = call("message.submit", account, submitBody(SECOND_MESSAGE, "second"), SECOND_OPERATION)
        journal.put("second_send", second.toString())
        check(messages(account).contains(SECOND_MESSAGE)) { "second message is not stored" }

        // Background: every store closed and the data-root lock released before returning.
        val evidence = client.suspend()
        check(evidence.supervisorJoined && evidence.dataRootLockReleased) {
            "suspension left the data root locked: $evidence"
        }
        check(client.state == CoreState.SUSPENDED)
        collector.join()

        client.resume()
        check(call("account.list", null, JSONObject()).getJSONArray("accounts").contains(account))
        journal.put("resumed", "true")
    }

    /**
     * Production builds have no software vault. On a device or emulator whose Keystore is
     * not hardware-backed, account creation must be refused and must leave no account.
     */
    suspend fun expectVaultRefusal() {
        client.start()
        call("node.add", null, JSONObject().put("url", args.nodeUrl).put("refresh", false))
        val refused = try {
            createAccount(null)
            null
        } catch (error: CoreException) {
            error
        }
        checkNotNull(refused) { "account creation succeeded without a hardware-backed key" }
        val accounts = call("account.list", null, JSONObject()).getJSONArray("accounts")
        check(accounts.length() == 0) { "a refused creation left an account behind: $accounts" }
        journal.put("vault_refusal", refused.toString())
    }

    /**
     * The creation ceremony as a user would walk it: read the phrase once, then answer the
     * three positions the core asks for. Returns the new account id.
     */
    private suspend fun createAccount(nodeId: String?): String =
        client.beginAccountCreation(args.displayName, nodeId).use { ceremony ->
            val words = ceremony.showOnce().trim().split(Regex("\\s+"))
            val answer = ceremony.hiddenChallenge().map { position -> words[position - 1] }
            ceremony.confirm(answer, args.passphrase).accountId
        }

    private fun collectUpdates(scope: CoroutineScope, account: String): Job = scope.launch {
        client.updates(SubscribeFilter(account, emptyList(), null, 0u)).collect { event ->
            if (event is UpdateEvent.Row) updatesSeen.incrementAndGet()
        }
    }

    private suspend fun messages(account: String): List<String> {
        val body = JSONObject().put("conversation_id", args.conversationId)
        val listed = call("message.list", account, body)
        val rows = listed.optJSONArray("messages") ?: JSONArray()
        return (0 until rows.length()).map { rows.getJSONObject(it).getString("message_id") }
    }

    private fun submitBody(messageId: String, text: String): JSONObject = JSONObject()
        .put("conversation_id", args.conversationId)
        .put("message_id", messageId)
        .put("envelope_id", "env-$messageId")
        .put("source_principal_id", journal.require("principal"))
        .put("sender_id", journal.require("device"))
        .put("recipient_device_id", args.recipientDeviceId ?: JSONObject.NULL)
        .put("recipient_principal_commitment", args.recipientPrincipalCommitment ?: JSONObject.NULL)
        .put("target_delivery_id", args.targetDeliveryId)
        .put("encrypted_body_base64", "")
        .put("plaintext_body_base64", base64Url(text.toByteArray(Charsets.UTF_8)))
        .put("created_at", System.currentTimeMillis() / 1000)
        .put("ttl", 300)

    private suspend fun call(
        method: String,
        account: String?,
        body: JSONObject,
        operationId: String? = null,
    ): JSONObject {
        val response = client.execute(
            CoreRequest(
                method = method,
                accountId = account,
                bodyJson = body.toString(),
                deadlineMs = REQUEST_DEADLINE_MS,
                operationId = operationId,
            ),
        )
        return JSONObject(response.bodyJson)
    }

    private fun JSONArray.contains(value: String): Boolean =
        (0 until length()).any { optString(it) == value }

    private fun base64Url(bytes: ByteArray): String =
        Base64.encodeToString(bytes, Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP)

    companion object {
        const val FIRST_MESSAGE = "m4-msg-1"
        const val SECOND_MESSAGE = "m4-msg-2"
        const val FIRST_OPERATION = "m4-send-1"
        const val SECOND_OPERATION = "m4-send-2"
        private const val REQUEST_DEADLINE_MS: ULong = 60_000u
    }
}

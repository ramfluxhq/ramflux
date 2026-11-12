// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

package org.ramflux.harness

/**
 * Inputs of the acceptance script, passed as instrumentation arguments by the host driver.
 * The host driver owns the local gateway and the peer identity; the device owns nothing
 * but its own account.
 */
data class HarnessArgs(
    /** `first` creates and sends and is then killed; `resume` verifies and sends again. */
    val phase: String,
    /** Node URL of the local gateway as the emulator sees it, e.g. the host loopback alias. */
    val nodeUrl: String,
    /** Public key of that node, read by the driver, to pin instead of trusting first use. */
    val nodePublicKey: String?,
    /** Display name of the account the ceremony creates. */
    val displayName: String,
    /** Passphrase given to the creation ceremony. A fixture value, never a user's. */
    val passphrase: String,
    /** Body of `account.unlock` for the second run, or null when it is not needed. */
    val accountUnlockBody: String?,
    /** Body of `contact.card.import` carrying the peer's contact card. */
    val peerCardImportBody: String,
    /** Conversation and addressing of the direct message, taken from the peer's card. */
    val conversationId: String,
    val recipientDeviceId: String?,
    val recipientPrincipalCommitment: String?,
    val targetDeliveryId: String,
    /**
     * True on an emulator build that must prove the absence of a software vault: account
     * creation is then expected to be refused, and nothing else runs.
     */
    val expectVaultRefusal: Boolean,
) {
    companion object {
        fun from(arguments: (String) -> String?): HarnessArgs {
            fun required(name: String) =
                checkNotNull(arguments(name)) { "missing instrumentation argument -e $name" }
            return HarnessArgs(
                phase = required("phase"),
                nodeUrl = required("nodeUrl"),
                nodePublicKey = arguments("nodePublicKey"),
                displayName = arguments("displayName") ?: "m4-harness",
                passphrase = required("passphrase"),
                accountUnlockBody = arguments("accountUnlockBody"),
                peerCardImportBody = arguments("peerCardImportBody") ?: "{}",
                conversationId = arguments("conversationId") ?: "",
                recipientDeviceId = arguments("recipientDeviceId"),
                recipientPrincipalCommitment = arguments("recipientPrincipalCommitment"),
                targetDeliveryId = arguments("targetDeliveryId") ?: "",
                expectVaultRefusal = arguments("expectVaultRefusal") == "true",
            )
        }
    }
}

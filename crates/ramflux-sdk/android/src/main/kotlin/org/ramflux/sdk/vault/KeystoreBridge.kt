// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

package org.ramflux.sdk.vault

import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import android.security.keystore.UserNotAuthenticatedException
import java.security.KeyStore
import java.security.UnrecoverableKeyException
import javax.crypto.AEADBadTagException
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec

/**
 * Shows the user-presence prompt for one use of the authentication-bound key.
 *
 * The application implements this with `BiometricPrompt` and a `CryptoObject` wrapping the
 * given cipher. [authorize] is called on a worker thread and blocks until the user answered;
 * it returns the authorized cipher, or null when the user cancelled or authentication failed.
 */
fun interface PresencePrompter {
    fun authorize(cipher: Cipher): Cipher?
}

/**
 * The Android Keystore operations the Rust vault calls through JNI.
 *
 * The Keystore holds two AES-256-GCM keys and never a seed. Kind 0 is the background key:
 * no user authentication and no unlocked-device requirement, so it works after first unlock
 * while the device is locked. Kind 1 is the presence key: every use needs a fresh strong
 * biometric or device-credential authentication.
 *
 * A key that the platform does not report as held by the TEE or StrongBox is deleted and
 * refused. There is no software fallback.
 *
 * Integer methods return a non-negative value on success and `-status` on refusal.
 * Byte-array methods return the status in byte 0 followed by the payload.
 */
object KeystoreBridge {
    private const val PROVIDER = "AndroidKeyStore"
    private const val TRANSFORMATION = "AES/GCM/NoPadding"
    private const val BACKGROUND_ALIAS = "org.ramflux.vault.wrap.background.v1"
    private const val PRESENCE_ALIAS = "org.ramflux.vault.wrap.presence.v1"
    private const val IV_LENGTH = 12
    private const val TAG_BITS = 128

    private const val KIND_BACKGROUND = 0
    private const val KIND_PRESENCE = 1

    private const val LEVEL_SOFTWARE = 0
    private const val LEVEL_TEE = 1
    private const val LEVEL_STRONGBOX = 2
    private const val LEVEL_UNKNOWN = 3
    private const val LEVEL_UNKNOWN_SECURE = 4

    private const val OK = 0
    private const val NOT_HARDWARE_BACKED = 1
    private const val KEY_MISSING = 2
    private const val LOCKED = 3
    private const val PRESENCE_REFUSED = 4
    private const val AUTHENTICATION = 5
    private const val FAILED = 6

    @Volatile
    private var prompter: PresencePrompter? = null

    init {
        // The native library is loaded by the bindings before this class is first used.
        nativeRegister()
    }

    /** Hands the JavaVM and this class to the Rust vault. Returns 1 on first registration. */
    @JvmStatic
    private external fun nativeRegister(): Int

    /** Registers or clears the presence prompt. Without one, presence operations refuse. */
    @JvmStatic
    fun setPresencePrompter(value: PresencePrompter?) {
        prompter = value
    }

    @JvmStatic
    fun presenceAvailable(): Boolean = prompter != null

    private fun alias(kind: Int): String? = when (kind) {
        KIND_BACKGROUND -> BACKGROUND_ALIAS
        KIND_PRESENCE -> PRESENCE_ALIAS
        else -> null
    }

    private fun keyStore(): KeyStore = KeyStore.getInstance(PROVIDER).apply { load(null) }

    private fun loadKey(alias: String): SecretKey? = keyStore().getKey(alias, null) as? SecretKey

    private fun levelOf(key: SecretKey): Int {
        val factory = SecretKeyFactory.getInstance(key.algorithm, PROVIDER)
        val info = factory.getKeySpec(key, KeyInfo::class.java) as KeyInfo
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            return when (info.securityLevel) {
                KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT -> LEVEL_TEE
                KeyProperties.SECURITY_LEVEL_STRONGBOX -> LEVEL_STRONGBOX
                KeyProperties.SECURITY_LEVEL_SOFTWARE -> LEVEL_SOFTWARE
                KeyProperties.SECURITY_LEVEL_UNKNOWN_SECURE -> LEVEL_UNKNOWN_SECURE
                else -> LEVEL_UNKNOWN
            }
        }
        // Before API 31 the platform reports secure hardware without naming it, so a
        // StrongBox key is recorded as TEE there: an under-claim, never an over-claim.
        @Suppress("DEPRECATION")
        return if (info.isInsideSecureHardware) LEVEL_TEE else LEVEL_SOFTWARE
    }

    private fun spec(alias: String, kind: Int, strongBox: Boolean): KeyGenParameterSpec {
        val builder = KeyGenParameterSpec.Builder(
            alias,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
        )
            .setKeySize(256)
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            // The default: the Keystore chooses the IV and rejects a caller-supplied one.
            .setRandomizedEncryptionRequired(true)
        if (kind == KIND_PRESENCE) {
            builder.setUserAuthenticationRequired(true)
            builder.setInvalidatedByBiometricEnrollment(true)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                builder.setUserAuthenticationParameters(
                    0,
                    KeyProperties.AUTH_BIOMETRIC_STRONG or KeyProperties.AUTH_DEVICE_CREDENTIAL,
                )
            } else {
                @Suppress("DEPRECATION")
                builder.setUserAuthenticationValidityDurationSeconds(-1)
            }
        } else {
            // Usable after first unlock while the device is locked: no user authentication
            // and no setUnlockedDeviceRequired.
            builder.setUserAuthenticationRequired(false)
        }
        if (strongBox && Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            builder.setIsStrongBoxBacked(true)
        }
        return builder.build()
    }

    private fun generate(alias: String, kind: Int, strongBox: Boolean): SecretKey {
        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, PROVIDER)
        generator.init(spec(alias, kind, strongBox))
        return generator.generateKey()
    }

    /** Creates the key when absent. Returns its security level, or `-status`. */
    @JvmStatic
    fun ensureKey(kind: Int, strongBox: Boolean): Int {
        val alias = alias(kind) ?: return -FAILED
        return try {
            val existing = loadKey(alias)
            val key = existing ?: try {
                generate(alias, kind, strongBox)
            } catch (unavailable: StrongBoxUnavailableException) {
                // Opt-in StrongBox falls back to the TEE only; the level check below still
                // refuses a key that did not land in secure hardware.
                generate(alias, kind, false)
            }
            val level = levelOf(key)
            if (level != LEVEL_TEE && level != LEVEL_STRONGBOX) {
                if (existing == null) keyStore().deleteEntry(alias)
                return -NOT_HARDWARE_BACKED
            }
            level
        } catch (invalidated: KeyPermanentlyInvalidatedException) {
            -KEY_MISSING
        } catch (invalidated: UnrecoverableKeyException) {
            -KEY_MISSING
        } catch (failure: Exception) {
            -FAILED
        }
    }

    /** Security level of an existing key, or `-status`. Never creates a key. */
    @JvmStatic
    fun keyLevel(kind: Int): Int {
        val alias = alias(kind) ?: return -FAILED
        return try {
            val key = loadKey(alias) ?: return -KEY_MISSING
            levelOf(key)
        } catch (invalidated: UnrecoverableKeyException) {
            -KEY_MISSING
        } catch (failure: Exception) {
            -FAILED
        }
    }

    private fun authorized(kind: Int, cipher: Cipher): Cipher? =
        if (kind == KIND_PRESENCE) prompter?.authorize(cipher) else cipher

    private fun refusal(status: Int): ByteArray = byteArrayOf(status.toByte())

    private fun classify(failure: Exception): Int = when (failure) {
        is KeyPermanentlyInvalidatedException -> KEY_MISSING
        is UnrecoverableKeyException -> KEY_MISSING
        is UserNotAuthenticatedException -> LOCKED
        is AEADBadTagException -> AUTHENTICATION
        else -> FAILED
    }

    /** Encrypts [plaintext] bound to [aad]. Reply: status, then IV (12 bytes) and ciphertext. */
    @JvmStatic
    fun wrap(kind: Int, aad: ByteArray, plaintext: ByteArray): ByteArray {
        val alias = alias(kind) ?: return refusal(FAILED)
        return try {
            val key = loadKey(alias) ?: return refusal(KEY_MISSING)
            val level = levelOf(key)
            if (level != LEVEL_TEE && level != LEVEL_STRONGBOX) return refusal(NOT_HARDWARE_BACKED)
            val initial = Cipher.getInstance(TRANSFORMATION).apply { init(Cipher.ENCRYPT_MODE, key) }
            val cipher = authorized(kind, initial) ?: return refusal(PRESENCE_REFUSED)
            cipher.updateAAD(aad)
            val ciphertext = cipher.doFinal(plaintext)
            val iv = cipher.iv
            if (iv.size != IV_LENGTH) return refusal(FAILED)
            byteArrayOf(OK.toByte()) + iv + ciphertext
        } catch (failure: Exception) {
            refusal(classify(failure))
        } finally {
            plaintext.fill(0)
        }
    }

    /** Decrypts and authenticates. Reply: status, then the plaintext. The caller clears it. */
    @JvmStatic
    fun unwrap(kind: Int, aad: ByteArray, iv: ByteArray, ciphertext: ByteArray): ByteArray {
        val alias = alias(kind) ?: return refusal(FAILED)
        if (iv.size != IV_LENGTH) return refusal(FAILED)
        return try {
            val key = loadKey(alias) ?: return refusal(KEY_MISSING)
            val level = levelOf(key)
            if (level != LEVEL_TEE && level != LEVEL_STRONGBOX) return refusal(NOT_HARDWARE_BACKED)
            val initial = Cipher.getInstance(TRANSFORMATION).apply {
                init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(TAG_BITS, iv))
            }
            val cipher = authorized(kind, initial) ?: return refusal(PRESENCE_REFUSED)
            cipher.updateAAD(aad)
            val plaintext = cipher.doFinal(ciphertext)
            val reply = ByteArray(plaintext.size + 1)
            plaintext.copyInto(reply, 1)
            plaintext.fill(0)
            reply
        } catch (failure: Exception) {
            refusal(classify(failure))
        }
    }

    /** Deletes the key. A missing key succeeds. */
    @JvmStatic
    fun deleteKey(kind: Int): Int {
        val alias = alias(kind) ?: return -FAILED
        return try {
            keyStore().deleteEntry(alias)
            OK
        } catch (failure: Exception) {
            -FAILED
        }
    }
}

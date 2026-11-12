// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! JNI implementation of the Keystore seam.
//!
//! The Android Keystore has no NDK interface, so every operation calls the static methods of
//! the Kotlin helper `org.ramflux.sdk.vault.KeystoreBridge`. The helper registers itself by
//! calling its native `nativeRegister()` from its class initializer. That hands this module
//! the `JavaVM` and a global reference to the helper class, which is required because
//! `FindClass` on a natively attached thread resolves against the system class loader and
//! cannot see application classes.
//!
//! Status convention shared with the helper: integer methods return a non-negative value on
//! success and `-status` on refusal; byte-array methods return the status in byte 0 followed
//! by the payload.
// The exported native method needs `#[unsafe(no_mangle)]`; this file holds no other unsafe.
#![allow(unsafe_code)]

use std::sync::OnceLock;

use jni::objects::{Global, JByteArray, JClass, JValue};
use jni::{Env, EnvUnowned, JavaVM, jni_sig, jni_str};
use zeroize::{Zeroize as _, Zeroizing};

use super::keystore::{
    BridgeError, GCM_IV_LEN, GCM_TAG_LEN, KeyKind, KeystoreBridge, MAX_SECRET_LEN, SecurityLevel,
    StrongBoxPreference, Wrapped,
};

struct Registered {
    vm: JavaVM,
    class: Global<JClass<'static>>,
}

static REGISTERED: OnceLock<Registered> = OnceLock::new();

/// Called once by the Kotlin helper's class initializer. Returns 1 when this call registered
/// the helper and 0 when a helper was already registered.
// SAFETY: the symbol name is the JNI-mangled name of
// `org.ramflux.sdk.vault.KeystoreBridge.nativeRegister()`, a static native method taking no
// arguments and returning `int`; the signature below matches that contract exactly, and no
// other definition of this symbol exists in the crate.
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_ramflux_sdk_vault_KeystoreBridge_nativeRegister<'local>(
    mut env: EnvUnowned<'local>,
    class: JClass<'local>,
) -> i32 {
    env.with_env(|env| -> jni::errors::Result<i32> {
        let vm = env.get_java_vm()?;
        let class = env.new_global_ref(class)?;
        Ok(i32::from(REGISTERED.set(Registered { vm, class }).is_ok()))
    })
    .resolve::<jni::errors::ThrowRuntimeExAndDefault>()
}

fn status(code: i32) -> BridgeError {
    match code {
        1 => BridgeError::NotHardwareBacked,
        2 => BridgeError::KeyMissing,
        3 => BridgeError::Locked,
        4 => BridgeError::PresenceRefused,
        5 => BridgeError::Authentication,
        _ => BridgeError::Failed,
    }
}

fn level(value: i32) -> Result<SecurityLevel, BridgeError> {
    if value < 0 {
        return Err(status(value.saturating_neg()));
    }
    Ok(SecurityLevel::from_code(u8::try_from(value).map_err(|_| BridgeError::Failed)?))
}

/// Overwrite a Java byte array that carried plaintext. The runtime may already have copied
/// the array while compacting the heap; this clears the copy the helper and this call used.
fn clear_java_array(env: &mut Env<'_>, array: &JByteArray<'_>, length: usize) {
    let zeros = vec![0_i8; length];
    // A failure here leaves plaintext for the collector, which is the state before the call.
    let _ = array.set_region(env, 0, &zeros);
}

/// The Keystore reached through the registered Kotlin helper.
pub(super) struct JniKeystore {
    registered: &'static Registered,
}

impl JniKeystore {
    /// The helper registered for this process, or `NotInstalled`.
    pub(super) fn from_registered() -> Result<Self, BridgeError> {
        REGISTERED.get().map(|registered| Self { registered }).ok_or(BridgeError::NotInstalled)
    }

    fn with_env<T>(
        &self,
        call: impl FnOnce(&mut Env<'_>, &JClass<'static>) -> jni::errors::Result<T>,
    ) -> Result<T, BridgeError> {
        let class: &JClass<'static> = &self.registered.class;
        self.registered
            .vm
            .attach_current_thread(|env| call(env, class))
            // A Java exception was caught and cleared by the binding; it carries no detail
            // this layer may log.
            .map_err(|_: jni::errors::Error| BridgeError::Failed)
    }
}

impl KeystoreBridge for JniKeystore {
    fn ensure_key(
        &self,
        kind: KeyKind,
        strongbox: StrongBoxPreference,
    ) -> Result<SecurityLevel, BridgeError> {
        let prefer = strongbox == StrongBoxPreference::PreferStrongBox;
        let value = self.with_env(|env, class| {
            env.call_static_method(
                class,
                jni_str!("ensureKey"),
                jni_sig!("(IZ)I"),
                &[JValue::Int(i32::from(kind.code())), JValue::Bool(prefer)],
            )?
            .i()
        })?;
        level(value)
    }

    fn key_level(&self, kind: KeyKind) -> Result<SecurityLevel, BridgeError> {
        let value = self.with_env(|env, class| {
            env.call_static_method(
                class,
                jni_str!("keyLevel"),
                jni_sig!("(I)I"),
                &[JValue::Int(i32::from(kind.code()))],
            )?
            .i()
        })?;
        level(value)
    }

    fn wrap(&self, kind: KeyKind, aad: &[u8], plaintext: &[u8]) -> Result<Wrapped, BridgeError> {
        if plaintext.is_empty() || plaintext.len() > MAX_SECRET_LEN {
            return Err(BridgeError::Failed);
        }
        let reply = self.with_env(|env, class| {
            let aad = env.byte_array_from_slice(aad)?;
            let secret = env.byte_array_from_slice(plaintext)?;
            let result = env.call_static_method(
                class,
                jni_str!("wrap"),
                jni_sig!("(I[B[B)[B"),
                &[JValue::Int(i32::from(kind.code())), JValue::from(&aad), JValue::from(&secret)],
            );
            clear_java_array(env, &secret, plaintext.len());
            let reply = JByteArray::cast_local(env, result?.l()?)?;
            env.convert_byte_array(&reply)
        })?;
        let (code, body) = reply.split_first().ok_or(BridgeError::Failed)?;
        if *code != 0 {
            return Err(status(i32::from(*code)));
        }
        if body.len() != GCM_IV_LEN + plaintext.len() + GCM_TAG_LEN {
            return Err(BridgeError::Failed);
        }
        let (iv_bytes, ciphertext) = body.split_at(GCM_IV_LEN);
        let mut iv = [0_u8; GCM_IV_LEN];
        iv.copy_from_slice(iv_bytes);
        Ok(Wrapped { iv, ciphertext: ciphertext.to_vec() })
    }

    fn unwrap(
        &self,
        kind: KeyKind,
        aad: &[u8],
        wrapped: &Wrapped,
    ) -> Result<Zeroizing<Vec<u8>>, BridgeError> {
        let mut reply = Zeroizing::new(self.with_env(|env, class| {
            let aad = env.byte_array_from_slice(aad)?;
            let iv = env.byte_array_from_slice(&wrapped.iv)?;
            let ciphertext = env.byte_array_from_slice(&wrapped.ciphertext)?;
            let result = env.call_static_method(
                class,
                jni_str!("unwrap"),
                jni_sig!("(I[B[B[B)[B"),
                &[
                    JValue::Int(i32::from(kind.code())),
                    JValue::from(&aad),
                    JValue::from(&iv),
                    JValue::from(&ciphertext),
                ],
            )?;
            let reply = JByteArray::cast_local(env, result.l()?)?;
            let bytes = env.convert_byte_array(&reply);
            if let Ok(bytes) = &bytes {
                clear_java_array(env, &reply, bytes.len());
            }
            bytes
        })?);
        let code = *reply.first().ok_or(BridgeError::Failed)?;
        if code != 0 {
            return Err(status(i32::from(code)));
        }
        // Move the payload down over the status byte so no second plaintext copy is made.
        reply.copy_within(1.., 0);
        let length = reply.len() - 1;
        if let Some(last) = reply.get_mut(length..) {
            last.zeroize();
        }
        reply.truncate(length);
        Ok(reply)
    }

    fn presence_available(&self) -> bool {
        self.with_env(|env, class| {
            env.call_static_method(class, jni_str!("presenceAvailable"), jni_sig!("()Z"), &[])?.z()
        })
        .unwrap_or(false)
    }

    fn delete_key(&self, kind: KeyKind) -> Result<(), BridgeError> {
        let value = self.with_env(|env, class| {
            env.call_static_method(
                class,
                jni_str!("deleteKey"),
                jni_sig!("(I)I"),
                &[JValue::Int(i32::from(kind.code()))],
            )?
            .i()
        })?;
        if value < 0 { Err(status(value.saturating_neg())) } else { Ok(()) }
    }
}

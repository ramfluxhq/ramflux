# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2026 Span Brain
#
# Rules applied to every application that consumes the ramflux-core AAR.

# The generated UniFFI bindings are reached from native code through JNA by name:
# structures by field order, callbacks by method name.
-keep class org.ramflux.sdk.ffi.** { *; }

# JNA itself, and anything that extends its marker types.
-dontwarn java.awt.*
-keep class com.sun.jna.** { *; }
-keepclassmembers class * extends com.sun.jna.** { public *; }
-keep class * implements com.sun.jna.** { *; }

# The Keystore helper is called from Rust through JNI by class and method name, and it
# registers itself with a native method.
-keep class org.ramflux.sdk.vault.KeystoreBridge { *; }
-keepclasseswithmembernames class org.ramflux.sdk.** {
    native <methods>;
}

# Listener implementations are invoked from the delivery thread of the core.
-keep class * implements org.ramflux.sdk.ffi.UpdateListener { *; }

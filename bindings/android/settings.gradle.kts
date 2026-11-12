// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

// Android packaging of the ramflux core.
//
//   :ramflux-core  Android library (AAR): the per-ABI libramflux_ffi.so, the generated
//                  UniFFI Kotlin bindings and the coroutine wrapper.
//   :harness       Instrumented driver of the Android core acceptance script. Not a
//                  product UI and never published.
//
// The default flavour has no Google Play services dependency. The optional `fcm` flavour
// adds the push service; nothing in the core needs it.

pluginManagement {
    repositories {
        google()
        mavenCentral()
        gradlePluginPortal()
    }
}

dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        google()
        mavenCentral()
    }
}

rootProject.name = "ramflux-android"
include(":ramflux-core")
include(":harness")

// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

// Kotlin is compiled by the Android Gradle plugin's built-in Kotlin support (AGP 9), so no
// separate Kotlin Gradle plugin is applied in any module.
plugins {
    alias(libs.plugins.android.library) apply false
    alias(libs.plugins.android.application) apply false
}

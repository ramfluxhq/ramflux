// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

// Instrumented driver of the Android core acceptance script: create an account, send a
// direct message through a local gateway, get killed, resume. It has no user interface and
// is never published. Run it with scripts/run-m4-harness.sh.

plugins {
    alias(libs.plugins.android.application)
}

android {
    namespace = "org.ramflux.harness"
    compileSdk = libs.versions.compileSdk.get().toInt()

    defaultConfig {
        applicationId = "org.ramflux.harness"
        minSdk = libs.versions.minSdk.get().toInt()
        targetSdk = libs.versions.targetSdk.get().toInt()
        versionCode = 1
        versionName = "0"
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
        // The acceptance runs without any push provider: the default flavour of the core.
        missingDimensionStrategy("push", "foss")
    }

    buildTypes {
        release {
            // The acceptance must exercise the production configuration of the core, so
            // the instrumented tests run against the release build type.
            isMinifyEnabled = false
            // Debuggable so the host driver can read the harness journal with run-as. This
            // affects the harness APK only; the core library is still its release variant.
            isDebuggable = true
            signingConfig = signingConfigs.getByName("debug")
        }
    }
    testBuildType = "release"

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
}

dependencies {
    implementation(project(":ramflux-core"))
    implementation(libs.coroutines.android)

    androidTestImplementation(libs.junit)
    androidTestImplementation(libs.androidx.test.runner)
    androidTestImplementation(libs.androidx.test.ext.junit)
}

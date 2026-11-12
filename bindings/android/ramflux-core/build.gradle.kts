// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

import javax.inject.Inject
import org.gradle.process.ExecOperations

plugins {
    alias(libs.plugins.android.library)
}

/** Cross-compiles crates/ramflux-ffi into `<outputDir>/<abi>/libramflux_ffi.so`. */
abstract class BuildNativeLibraries @Inject constructor(
    private val execOperations: ExecOperations,
) : DefaultTask() {
    @get:InputFile
    @get:PathSensitive(PathSensitivity.NONE)
    abstract val script: RegularFileProperty

    /** Everything the native library is compiled from. */
    @get:InputFiles
    @get:PathSensitive(PathSensitivity.RELATIVE)
    abstract val rustSources: ConfigurableFileCollection

    @get:Input
    abstract val abis: Property<String>

    @get:Input
    abstract val cargoProfile: Property<String>

    @get:Input
    abstract val minApi: Property<Int>

    /** Cargo features of ramflux-ffi. A test-vault build is a different library. */
    @get:Input
    abstract val ffiFeatures: Property<String>

    /** `1` only for an emulator fixture build that enables the SDK test vault. */
    @get:Input
    abstract val itestBuild: Property<String>

    @get:OutputDirectory
    abstract val outputDir: DirectoryProperty

    @TaskAction
    fun build() {
        execOperations.exec {
            environment("RAMFLUX_ANDROID_API", minApi.get().toString())
            environment("RAMFLUX_FFI_FEATURES", ffiFeatures.get())
            environment("RAMFLUX_ITEST_BUILD", itestBuild.get())
            commandLine(
                "bash",
                script.get().asFile.absolutePath,
                outputDir.get().asFile.absolutePath,
                abis.get(),
                cargoProfile.get(),
            )
        }
    }
}

/** Generates the Kotlin bindings from one of the libraries built above. */
abstract class GenerateUniffiBindings @Inject constructor(
    private val execOperations: ExecOperations,
) : DefaultTask() {
    @get:InputFile
    @get:PathSensitive(PathSensitivity.NONE)
    abstract val script: RegularFileProperty

    @get:InputFile
    @get:PathSensitive(PathSensitivity.NONE)
    abstract val uniffiConfig: RegularFileProperty

    @get:InputDirectory
    @get:PathSensitive(PathSensitivity.RELATIVE)
    abstract val nativeLibraries: DirectoryProperty

    /** ABI directory whose library is read for the interface metadata. */
    @get:Input
    abstract val metadataAbi: Property<String>

    @get:OutputDirectory
    abstract val outputDir: DirectoryProperty

    @TaskAction
    fun generate() {
        val library = nativeLibraries.get().asFile.resolve("${metadataAbi.get()}/libramflux_ffi.so")
        execOperations.exec {
            commandLine(
                "bash",
                script.get().asFile.absolutePath,
                library.absolutePath,
                outputDir.get().asFile.absolutePath,
            )
        }
    }
}

val workspaceRoot = rootDir.resolve("../..")
val scriptsDir = rootDir.resolve("scripts")
val abiList = providers.gradleProperty("ramflux.abis").orElse("arm64-v8a,x86_64")
val cargoProfileName = providers.gradleProperty("ramflux.cargoProfile").orElse("release")
val ffiFeatureList = providers.gradleProperty("ramflux.ffiFeatures").orElse("embedded")
val itestBuildFlag = providers.gradleProperty("ramflux.itestBuild").orElse("0")
val minSdkLevel = libs.versions.minSdk.get().toInt()

android {
    namespace = "org.ramflux.sdk"
    compileSdk = libs.versions.compileSdk.get().toInt()
    ndkVersion = libs.versions.ndk.get()

    defaultConfig {
        minSdk = minSdkLevel
        consumerProguardFiles("consumer-rules.pro")
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }

    // Owner decision: the default flavour has no Google Play services dependency. `fcm` adds
    // the Firebase messaging service and nothing else; send and receive never depend on it.
    flavorDimensions += "push"
    productFlavors {
        create("foss") {
            dimension = "push"
            isDefault = true
        }
        create("fcm") {
            dimension = "push"
        }
    }

    buildTypes {
        release {
            // The library is not minified here; consumers apply consumer-rules.pro.
            isMinifyEnabled = false
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    lint {
        targetSdk = libs.versions.targetSdk.get().toInt()
        warningsAsErrors = true
    }

    testOptions {
        targetSdk = libs.versions.targetSdk.get().toInt()
    }

    packaging {
        jniLibs {
            // Uncompressed, page-aligned libraries (required for 16 KB devices).
            useLegacyPackaging = false
        }
    }

    publishing {
        singleVariant("fossRelease") { withSourcesJar() }
        singleVariant("fcmRelease") { withSourcesJar() }
    }
}

androidComponents {
    onVariants { variant ->
        val suffix = variant.name.replaceFirstChar { it.uppercase() }
        val buildNative = tasks.register<BuildNativeLibraries>("build${suffix}RamfluxNative") {
            group = "ramflux"
            description = "Cross-compiles libramflux_ffi.so for ${variant.name} with cargo-ndk."
            script.set(scriptsDir.resolve("build-native.sh"))
            rustSources.from(
                fileTree(workspaceRoot) {
                    include("Cargo.toml", "Cargo.lock", "rust-toolchain.toml")
                    include("crates/**", "vendor/**")
                    exclude("**/target/**")
                },
            )
            abis.set(abiList)
            cargoProfile.set(cargoProfileName)
            minApi.set(minSdkLevel)
            ffiFeatures.set(ffiFeatureList)
            itestBuild.set(itestBuildFlag)
        }
        val generateBindings =
            tasks.register<GenerateUniffiBindings>("generate${suffix}RamfluxBindings") {
                group = "ramflux"
                description = "Generates the UniFFI Kotlin bindings for ${variant.name}."
                script.set(scriptsDir.resolve("generate-bindings.sh"))
                uniffiConfig.set(rootDir.resolve("uniffi.toml"))
                nativeLibraries.set(buildNative.flatMap { it.outputDir })
                metadataAbi.set(abiList.map { it.substringBefore(',') })
            }
        // AGP assigns each task's output directory and wires it into the variant.
        variant.sources.jniLibs?.addGeneratedSourceDirectory(
            buildNative,
            BuildNativeLibraries::outputDir,
        )
        variant.sources.kotlin?.addGeneratedSourceDirectory(
            generateBindings,
            GenerateUniffiBindings::outputDir,
        )
    }
}

dependencies {
    // Required by the generated UniFFI bindings (JNA 5.12.0 or newer, coroutines 1.6 or newer).
    implementation("net.java.dev.jna:jna:${libs.versions.jna.get()}@aar")
    api(libs.coroutines.core)
    implementation(libs.coroutines.android)

    "fcmImplementation"(libs.firebase.messaging)

    testImplementation(libs.junit)
    testImplementation(libs.coroutines.test)
}

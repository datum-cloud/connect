import java.util.Properties

plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.android)
    alias(libs.plugins.kotlin.compose)
    alias(libs.plugins.kotlin.serialization)
}

// The Rust workspace that builds libconnect_share_ffi.so and its Kotlin bindings.
val connectLib = rootProject.file("../../connect-lib")
val rustProfile = providers.gradleProperty("rustProfile").orElse("release")
val rustAbis = providers.gradleProperty("rustAbis")
    .orElse("arm64-v8a,armeabi-v7a,x86_64")
    .map { it.split(",").map(String::trim).filter(String::isNotEmpty) }
val jniLibsDir = layout.projectDirectory.dir("src/main/jniLibs")

// Every build must have a higher versionCode than the one it replaces, or
// Android refuses the update. The commit count only grows on one branch.
fun git(vararg args: String): String? = runCatching {
    providers.exec { commandLine("git", *args) }.standardOutput.asText.get().trim()
}.getOrNull()?.takeIf { it.isNotEmpty() }
val buildNumber = providers.gradleProperty("versionCode").orNull?.toInt()
    ?: git("rev-list", "--count", "HEAD")?.toInt()
    ?: 1
val buildName = git("describe", "--tags", "--always", "--dirty") ?: "dev"

// Release signing comes from a properties file outside the repository:
// storeFile, storePassword, keyAlias, keyPassword. Without it, release
// builds are unsigned. See connect-mobile/android/README.md.
val signingProperties = System.getenv("DATUM_CONNECT_SIGNING")
    ?.let(::File)
    ?.takeIf(File::isFile)
    ?.let { file -> Properties().apply { file.inputStream().use { load(it) } } }
val bindingsDir = layout.buildDirectory.dir("generated/uniffi/kotlin")

android {
    namespace = "net.datum.connect.share.app"
    compileSdk = 35

    defaultConfig {
        applicationId = "net.datum.connect.share"
        minSdk = 29
        targetSdk = 35
        versionCode = buildNumber
        versionName = "0.1.0+$buildName"
        // Only ABIs that have libconnect_share_ffi.so; others would crash on load.
        ndk { abiFilters += rustAbis.get() }
    }

    signingConfigs {
        if (signingProperties != null) {
            create("release") {
                storeFile = File(signingProperties.getProperty("storeFile"))
                storePassword = signingProperties.getProperty("storePassword")
                keyAlias = signingProperties.getProperty("keyAlias")
                keyPassword = signingProperties.getProperty("keyPassword")
            }
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            signingConfig = signingConfigs.findByName("release")
            resValue("string", "app_name", "Datum Connect")
        }
        // Debug builds are a separate app, signed with each machine's debug
        // key. Sharing the release package name would make Android refuse
        // the next release update, and an uninstall would lose its data.
        debug {
            applicationIdSuffix = ".debug"
            versionNameSuffix = "-debug"
            resValue("string", "app_name", "Datum Connect (dev)")
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    buildFeatures {
        compose = true
    }

    sourceSets["main"].java.srcDir(bindingsDir)

    packaging {
        // cargo-ndk copies every cdylib in the target directory; iroh-relay
        // builds one the app never loads.
        jniLibs.excludes += "**/libiroh*.so"
    }
}

kotlin {
    jvmToolchain(17)
}

// Cross-compiles connect-share-ffi for each ABI into src/main/jniLibs.
val cargoNdk by tasks.registering(Exec::class) {
    group = "rust"
    description = "Build libconnect_share_ffi.so for Android with cargo-ndk"
    workingDir = connectLib
    val abis = rustAbis.get()
    val args = mutableListOf("cargo", "ndk")
    abis.forEach { args += listOf("-t", it) }
    args += listOf("-o", jniLibsDir.asFile.absolutePath, "build", "-p", "connect-share-ffi")
    if (rustProfile.get() == "release") args += "--release"
    commandLine(args)
}

// Host build of the same crate; uniffi-bindgen reads its exported interface.
val cargoHost by tasks.registering(Exec::class) {
    group = "rust"
    description = "Build connect-share-ffi for the host to generate bindings"
    workingDir = connectLib
    commandLine("cargo", "build", "-p", "connect-share-ffi")
}

// Generates the Kotlin bindings. They depend only on the crate's exported
// interface, so a host build is enough for every Android ABI.
val uniffiBindings by tasks.registering(Exec::class) {
    group = "rust"
    description = "Generate Kotlin bindings for connect-share-ffi"
    dependsOn(cargoHost)
    workingDir = connectLib
    val hostLib = connectLib.resolve("target/debug/libconnect_share_ffi.so")
    inputs.file(hostLib)
    inputs.file(connectLib.resolve("share-ffi/uniffi.toml"))
    outputs.dir(bindingsDir)
    commandLine(
        "cargo", "run", "-q", "-p", "connect-share-ffi", "--features", "bindgen",
        "--bin", "uniffi-bindgen", "--", "generate", "--no-format",
        "--library", hostLib.absolutePath,
        "--language", "kotlin",
        "--out-dir", bindingsDir.get().asFile.absolutePath,
    )
}

tasks.named("preBuild") {
    dependsOn(cargoNdk, uniffiBindings)
}

dependencies {
    implementation(libs.androidx.core.ktx)
    implementation(libs.androidx.activity.compose)
    implementation(libs.androidx.lifecycle.runtime.compose)
    implementation(platform(libs.androidx.compose.bom))
    implementation(libs.androidx.compose.ui)
    implementation(libs.androidx.compose.material3)
    implementation(libs.androidx.compose.ui.tooling.preview)
    implementation("${libs.jna.get()}@aar")
    implementation(libs.zxing.embedded)
    implementation(libs.androidx.biometric)
    // biometric 1.1.0 brings Fragment 1.2.5, whose FragmentActivity breaks
    // the ActivityResult APIs the export and import pickers use.
    implementation(libs.androidx.fragment)
    implementation(libs.kotlinx.serialization.json)

    testImplementation(libs.junit)
    testImplementation(libs.jna)
}

// Unit tests call the bindings on the host JVM against the host build of the
// Rust library. The end-to-end test also needs a host datum-connectd and runs
// only when -PconnectdPath=... is given.
tasks.withType<Test>().configureEach {
    dependsOn(cargoHost)
    systemProperty("jna.library.path", connectLib.resolve("target/debug").absolutePath)
    providers.gradleProperty("connectdPath").orNull?.let { systemProperty("connectd.path", it) }
}

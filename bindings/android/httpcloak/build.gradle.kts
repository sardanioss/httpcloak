import org.gradle.internal.os.OperatingSystem

plugins {
    id("com.android.library")
    `maven-publish`
}

group = "io.github.sardanioss"
version = "1.7.4-beta.1" // kept in step with the other bindings by bindings/bump-version.sh

val minSdkVersion = 24
val abis = providers.gradleProperty("httpcloak.abis").get()
    .split(',').map { it.trim() }.filter { it.isNotEmpty() }

android {
    namespace = "io.github.sardanioss.httpcloak"
    compileSdk = 36
    ndkVersion = "28.2.13676358"

    defaultConfig {
        minSdk = minSdkVersion
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
        consumerProguardFiles("consumer-rules.pro")
        ndk { abiFilters += abis }
        externalNativeBuild {
            cmake { arguments += "-DHTTPCLOAK_GO_OUT=${layout.buildDirectory.dir("go").get().asFile}" }
        }
    }

    externalNativeBuild {
        cmake {
            path = file("src/main/cpp/CMakeLists.txt")
            version = "3.22.1"
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_11
        targetCompatibility = JavaVersion.VERSION_11
    }

    publishing {
        singleVariant("release") { withSourcesJar() }
    }
}

publishing {
    publications {
        register<MavenPublication>("release") {
            artifactId = "httpcloak-android"
            afterEvaluate { from(components["release"]) }
        }
    }
}

dependencies {
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-core:1.10.2")

    androidTestImplementation("androidx.test:runner:1.7.0")
    androidTestImplementation("androidx.test.ext:junit:1.3.0")
}

// ---------------------------------------------------------------------------
// The Go library (bindings/clib) cross-compiled with the NDK, one task per ABI.
// CMake links the JNI bridge against the result and AGP packages both.
// ---------------------------------------------------------------------------

// Android ABI -> GOARCH and the NDK clang target triple.
val goTargets = mapOf(
    "arm64-v8a" to ("arm64" to "aarch64-linux-android"),
    "armeabi-v7a" to ("arm" to "armv7a-linux-androideabi"),
    "x86_64" to ("amd64" to "x86_64-linux-android"),
    "x86" to ("386" to "i686-linux-android"),
)

val repoRoot = rootDir.resolve("../..")
val ndkHostTag = when {
    OperatingSystem.current().isMacOsX -> "darwin-x86_64"
    OperatingSystem.current().isWindows -> "windows-x86_64"
    else -> "linux-x86_64"
}
val clangSuffix = if (OperatingSystem.current().isWindows) "-clang.cmd" else "-clang"
// A new Go toolchain has to rebuild the library even when no source changed.
val goVersion = providers.exec { commandLine("go", "env", "GOVERSION") }.standardOutput.asText.map { it.trim() }

val goBuildTasks = abis.map { abi ->
    val (goArch, triple) = goTargets[abi] ?: error("Unsupported ABI in httpcloak.abis: $abi")
    val outDir = layout.buildDirectory.dir("go/$abi")
    val compiler = androidComponents.sdkComponents.ndkDirectory.map {
        it.file("toolchains/llvm/prebuilt/$ndkHostTag/bin/$triple$minSdkVersion$clangSuffix").asFile.path
    }

    val goEnv = mapOf("CGO_ENABLED" to "1", "GOOS" to "android", "GOARCH" to goArch) +
        (if (goArch == "arm") mapOf("GOARM" to "7") else emptyMap())

    tasks.register<Exec>("buildGo-$abi") {
        description = "Cross-compiles libhttpcloak.so for $abi."
        // Sources, plus the files they //go:embed (the browser presets).
        inputs.files(fileTree(repoRoot) {
            include("**/*.go", "**/go.mod", "**/go.sum", "fingerprint/embedded/**", "bindings/clib/*.c", "bindings/clib/*.h")
            exclude("**/*_test.go", "bindings/android/**", "examples/**", "tests/**")
        })
        // Exec tracks the command line but not the environment or toolchain.
        inputs.property("goEnv", goEnv)
        inputs.property("goVersion", goVersion)
        inputs.property("compiler", compiler)
        outputs.dir(outDir)

        workingDir(repoRoot.resolve("bindings/clib"))
        environment(goEnv)
        doFirst { environment("CC", compiler.get()) }
        // The soname lets the JNI bridge find this library by name at runtime,
        // and 16 KB alignment is required by Android 15+ devices and Play.
        commandLine(
            "go", "build", "-buildmode=c-shared", "-trimpath",
            "-ldflags=-s -w -extldflags=-Wl,-soname,libhttpcloak.so,-z,max-page-size=16384",
            "-o", outDir.get().file("libhttpcloak.so").asFile.path, ".",
        )
        // The generated libhttpcloak.h includes httpcloak_api.h, which declares
        // the public functions, and callback_pool.h from the cgo preamble. The
        // JNI bridge sees only this folder, so both headers go next to it, as
        // build.sh does for dist/.
        doLast {
            for (h in listOf("httpcloak_api.h", "callback_pool.h")) {
                repoRoot.resolve("bindings/clib/$h")
                    .copyTo(outDir.get().file(h).asFile, overwrite = true)
            }
        }
    }
}

tasks.configureEach {
    if (name.startsWith("configureCMake") || name.startsWith("buildCMake")) dependsOn(goBuildTasks)
}

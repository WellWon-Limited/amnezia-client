import com.android.build.gradle.internal.api.BaseVariantOutputImpl

plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.android)
    alias(libs.plugins.kotlin.serialization)
    id("property-delegate")
    alias(libs.plugins.google.services) // AVPN (Task 9, FCM): читает client/android/google-services.json
}

kotlin {
    jvmToolchain(17)
}

// get values from gradle or local properties
val qtTargetSdkVersion: String by gradleProperties
val qtTargetAbiList: String by gradleProperties
val outputBaseName: String by gradleProperties

android {
    namespace = "org.amnezia.vpn"

    buildFeatures {
        buildConfig = true
        viewBinding = true
    }

    androidResources {
        // don't compress Qt binary resources file
        noCompress += "rcc"
    }

    packaging {
        // compress .so binary libraries
        jniLibs.useLegacyPackaging = true
    }

    val abiList = qtTargetAbiList.split(",")

    defaultConfig {
        // AVPN: наш applicationId (upstream org.amnezia.vpn). История: org.antivpn.client (эра ANTI VPN,
        // sideload-сборки до 2026-07) → com.tribevpn.client (решение владельца 2026-07-09; регистрируется
        // в Google Play — там НЕОБРАТИМ). load-bearing: обязан байт-в-байт совпадать с package в Play Console.
        applicationId = "com.tribevpn.client"
        targetSdk = qtTargetSdkVersion.toInt()

        // keeps language resources for only the locales specified below
        resourceConfigurations += listOf("en", "ru", "b+zh+Hans")
        // ndk.abiFilters is only used for single-ABI builds; multi-ABI uses splits below
        if (abiList.size == 1) {
            ndk.abiFilters += abiList
        }
    }

    signingConfigs {
        register("release") {
            storeFile = providers.environmentVariable("QT_ANDROID_KEYSTORE_PATH").orNull?.let { file(it) }
            storePassword = providers.environmentVariable("QT_ANDROID_KEYSTORE_STORE_PASS").orNull
            keyAlias = providers.environmentVariable("QT_ANDROID_KEYSTORE_ALIAS").orNull
            keyPassword = providers.environmentVariable("QT_ANDROID_KEYSTORE_STORE_PASS").orNull
        }
    }

    buildTypes {
        release {
            // exclude coroutine debug resource from release build
            packaging {
                resources.excludes += "DebugProbesKt.bin"
            }
            signingConfig = signingConfigs["release"]
        }

        create("fdroid") {
            initWith(getByName("release"))
            signingConfig = null
            matchingFallbacks += "release"
        }
    }

    flavorDimensions += "billing"

    productFlavors {
        create("oss") {
            dimension = "billing"
            buildConfigField("boolean", "IS_PLAY_BUILD", "false")
        }
        create("play") {
            dimension = "billing"
            buildConfigField("boolean", "IS_PLAY_BUILD", "true")
        }
    }

    sourceSets {
        getByName("main") {
            manifest.srcFile("AndroidManifest.xml")
            java.setSrcDirs(listOf("src"))
            res.setSrcDirs(listOf("res"))
            // androyddeployqt creates the folders below
            assets.setSrcDirs(listOf("assets"))
            jniLibs.setSrcDirs(listOf("libs"))
        }

        getByName("oss") {
            java.setSrcDirs(listOf("oss"))
        }

        getByName("play") {
            java.setSrcDirs(listOf("play"))
        }
    }

    splits {
        abi {
            // splits only make sense for multi-ABI builds; single-ABI uses ndk.abiFilters
            isEnable = abiList.size > 1
            reset()
            include(*abiList.toTypedArray())
            isUniversalApk = false
        }
    }

    // fix for Qt Creator to allow deploying the application to a device
    // to enable this fix, add the line outputBaseName=android-build to local.properties
    if (outputBaseName.isNotEmpty()) {
        applicationVariants.all {
            outputs.map { it as BaseVariantOutputImpl }
                .forEach { output ->
                    if (output.outputFileName.endsWith(".apk")) {
                        output.outputFileName = "$outputBaseName-${buildType.name}.apk"
                    }
                }
        }
    }

    // AVPN: androiddeployqt expects:
    //   APK: build/outputs/apk/{base}-{buildType}[-unsigned].apk  (no flavor subdir)
    //   AAB: build/outputs/bundle/{buildType}/{base}-{buildType}.aab (no flavor subdir)
    // where {base} = outputBaseName (set by Qt Creator) or "android-build" (CI fallback).
    // Release APK gets -unsigned suffix (Qt cmake signs it); debug does not.
    // Copy only oss flavor to the flat output dir that androiddeployqt/Qt Creator expect.
    // Play flavor is built via android_play_apk/android_play_aab cmake targets and uses
    // its native Gradle output paths directly.
    //
    // The copy MUST be its own task with declared inputs/outputs, not a doLast on the
    // package/bundle task: on an incremental build Gradle reports `packageOssRelease
    // UP-TO-DATE` and skips every doLast attached to it, so the flat file is never
    // (re)created and androiddeployqt dies with the opaque `FAILED: [code=20]`
    // (CannotCopyApk). A dedicated task is re-run whenever its declared output is
    // missing, and it is wired as a finalizer so it also runs for an up-to-date package.
    applicationVariants.all {
        val flavorName = productFlavors.firstOrNull()?.name ?: ""
        val buildTypeName = buildType.name
        if (flavorName == "oss") {
            val base = outputBaseName.ifEmpty { "android-build" }
            val unsignedSuffix = if (buildTypeName == "release") "-unsigned" else ""
            val variantName = name
            val variantCap = variantName.replaceFirstChar { it.uppercase() }

            val flatApk = tasks.register("avpnFlatApk$variantCap") {
                val srcDir = layout.buildDirectory.dir("outputs/apk/oss/$buildTypeName")
                val dstFile =
                    layout.buildDirectory.file("outputs/apk/$base-$buildTypeName$unsignedSuffix.apk")
                inputs.dir(srcDir).withPropertyName("flavorApkDir")
                outputs.file(dstFile).withPropertyName("flatApk")
                doLast {
                    val apks = srcDir.get().asFile.listFiles()
                        ?.filter { it.name.endsWith(".apk") }?.sortedBy { it.name }.orEmpty()
                    val src = apks.firstOrNull()
                        ?: throw GradleException("no .apk in ${srcDir.get().asFile}")
                    val dst = dstFile.get().asFile
                    dst.parentFile.mkdirs()
                    src.copyTo(dst, overwrite = true)
                }
            }
            packageApplicationProvider.configure { finalizedBy(flatApk) }

            val flatAab = tasks.register("avpnFlatAab$variantCap") {
                val srcDir = layout.buildDirectory.dir("outputs/bundle/$variantName")
                val dstFile =
                    layout.buildDirectory.file("outputs/bundle/$buildTypeName/$base-$buildTypeName.aab")
                inputs.dir(srcDir).withPropertyName("flavorBundleDir")
                outputs.file(dstFile).withPropertyName("flatAab")
                doLast {
                    val aabs = srcDir.get().asFile.listFiles()
                        ?.filter { it.name.endsWith(".aab") }?.sortedBy { it.name }.orEmpty()
                    val src = aabs.firstOrNull()
                        ?: throw GradleException("no .aab in ${srcDir.get().asFile}")
                    val dst = dstFile.get().asFile
                    dst.parentFile.mkdirs()
                    src.copyTo(dst, overwrite = true)
                }
            }
            tasks.named("bundle$variantCap") { finalizedBy(flatAab) }
        }
    }

    lint {
        disable += "InvalidFragmentVersionForActivityResult"
    }
}

dependencies {
    implementation(project(":qt"))
    implementation(project(":utils"))
    implementation(project(":protocolApi"))
    implementation(project(":wireguard"))
    implementation(project(":awg"))
    implementation(project(":openvpn"))
    implementation(project(":xray"))
    implementation(libs.androidx.core)
    implementation(libs.androidx.activity)
    implementation(libs.androidx.fragment)
    implementation(libs.kotlinx.coroutines)
    implementation(libs.firebase.messaging) // AVPN (Task 9, FCM): AvpnFcmService
    implementation(libs.kotlinx.serialization.protobuf)
    implementation(libs.bundles.androidx.camera)
    implementation(libs.google.mlkit)
    implementation(libs.androidx.datastore)
    implementation(libs.androidx.biometric)

    playImplementation(project(":billing"))
}

fun DependencyHandler.playImplementation(dependency: Any): Dependency? =
    add("playImplementation", dependency)

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
        viewBinding = true
    }

    androidResources {
        // don't compress Qt binary resources file
        noCompress += "rcc"
        // AGP 9 removes defaultConfig.resourceConfigurations. Keep the locale allowlist
        // on the public Android resources DSL so the pre-publication project is forward-safe.
        localeFilters += listOf("en", "ru", "b+zh+Hans")
    }

    packaging {
        // compress .so binary libraries
        jniLibs.useLegacyPackaging = true
    }

    defaultConfig {
        // AVPN: наш applicationId (upstream org.amnezia.vpn). История: org.antivpn.client (эра ANTI VPN,
        // sideload-сборки до 2026-07) → com.tribevpn.client (решение владельца 2026-07-09; регистрируется
        // в Google Play — там НЕОБРАТИМ). load-bearing: обязан байт-в-байт совпадать с package в Play Console.
        applicationId = "com.tribevpn.client"
        targetSdk = qtTargetSdkVersion.toInt()

        ndk.abiFilters += qtTargetAbiList.split(",")
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
        getByName("test") {
            java.setSrcDirs(listOf("tests"))
        }
    }

    buildTypes {
        release {
            // exclude coroutine debug resource from release build
            packaging {
                resources.excludes += "DebugProbesKt.bin"
            }
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
    testImplementation(kotlin("test-junit"))
    // Local JVM tests must execute the same strict JSONObject parser/serializer contract as the
    // Android runtime; android.jar exposes only throwing stubs outside a device.
    testImplementation("org.json:json:20240303")
}

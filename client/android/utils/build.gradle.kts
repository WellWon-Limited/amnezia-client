plugins {
    id(libs.plugins.android.library.get().pluginId)
    id(libs.plugins.kotlin.android.get().pluginId)
}

kotlin {
    jvmToolchain(17)
}

android {
    namespace = "org.amnezia.vpn.util"

    buildFeatures {
        // add BuildConfig class
        buildConfig = true
    }
}

dependencies {
    implementation(libs.androidx.core)
    implementation(libs.kotlinx.coroutines)
    implementation(libs.androidx.security.crypto)
    // AVPN (Android uplink): JVM unit tests of the physical uplink's pure state (src/test)
    testImplementation(kotlin("test-junit"))
    // AVPN (android2 P7): the session metadata helper (TribeSession) parses with org.json - the android.jar on the
    // unit-test classpath has only throwing stubs, the test needs the real parser (as the xray module)
    testImplementation("org.json:json:20240303")
}

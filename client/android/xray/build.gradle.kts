plugins {
    id(libs.plugins.android.library.get().pluginId)
    id(libs.plugins.kotlin.android.get().pluginId)
}

kotlin {
    jvmToolchain(17)
}

android {
    namespace = "org.amnezia.vpn.protocol.xray"
}

dependencies {
    compileOnly(project(":utils"))
    compileOnly(project(":protocolApi"))
    implementation(project(":xray:libXray"))
    implementation(libs.kotlinx.coroutines)
    // AVPN upstream nodes (lane A2): JVM unit tests of the seat-lease owner (src/test). org.json: the
    // android.jar on the unit-test classpath only has throwing stubs, the tests need the real parser.
    testImplementation(kotlin("test-junit"))
    testImplementation("org.json:json:20240303")
}

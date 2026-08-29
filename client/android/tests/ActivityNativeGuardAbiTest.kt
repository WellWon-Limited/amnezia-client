package org.amnezia.vpn

import kotlin.test.Test
import kotlin.test.assertEquals

/** JVM reflection gate for the method descriptors hard-coded by AndroidController/QJniObject. */
class ActivityNativeGuardAbiTest {
    @Test
    fun qJniNativeGuardMethodsHaveExactPublicDescriptors() {
        val string = String::class.java
        val methods: List<Pair<String, Array<Class<*>>>> = listOf(
            "prepareNativeSessionGuard" to Array<Class<*>>(6) { string },
            "activateNativeSession" to Array<Class<*>>(5) { string },
            "stopNativeSession" to Array<Class<*>>(2) { string },
            "releaseNativeSessionGuard" to Array<Class<*>>(3) { string },
            "resolveNativeSessionGuardRecovery" to Array<Class<*>>(3) { string },
            "requestNativeSessionGuardRecoveryStatus" to emptyArray(),
            "renewRuntimeAuthority" to Array<Class<*>>(2) { string },
        )
        for ((name, parameters) in methods) {
            val method = AmneziaActivity::class.java.getMethod(name, *parameters)
            assertEquals(Void.TYPE, method.returnType, name)
        }
    }
}

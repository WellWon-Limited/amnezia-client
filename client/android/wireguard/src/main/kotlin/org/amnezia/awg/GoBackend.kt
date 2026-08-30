package org.amnezia.awg

object GoBackend {
    external fun awgGetConfig(handle: Int): String?
    external fun awgGetSocketV4(handle: Int): Int
    external fun awgGetSocketV6(handle: Int): Int
    external fun awgTurnOff(handle: Int)
    external fun awgTurnOn(ifName: String, tunFd: Int, settings: String): Int
    external fun awgPrepareProtected(ifName: String, tunFd: Int, settings: String): Int
    external fun awgResumeProtected(handle: Int): Int
    external fun awgProtectedTurnOff(handle: Int)
    external fun awgProtectedGetSocketV4(handle: Int): Int
    external fun awgProtectedGetSocketV6(handle: Int): Int
    external fun awgProtectedGetConfig(handle: Int): String?
    external fun awgVersion(): String
}

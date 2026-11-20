package org.amnezia.vpn.util.net

import android.content.Context
import android.net.ConnectivityManager
import android.net.ConnectivityManager.NetworkCallback
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkCapabilities.NET_CAPABILITY_INTERNET
import android.net.NetworkCapabilities.NET_CAPABILITY_VALIDATED
import android.net.NetworkRequest
import android.os.Build
import android.os.Handler
import androidx.core.content.getSystemService
import kotlin.LazyThreadSafetyMode.NONE
import kotlinx.coroutines.delay
import org.amnezia.vpn.util.Log

private const val TAG = "NetworkState"

class NetworkState(
    private val context: Context,
    private val onNetworkChange: () -> Unit
) {
    private var currentNetwork: Network? = null
    private var validated: Boolean = false
    private var isListenerBound = false

    private val handler: Handler by lazy(NONE) {
        Handler(context.mainLooper)
    }

    private val connectivityManager: ConnectivityManager by lazy(NONE) {
        context.getSystemService<ConnectivityManager>()!!
    }

    private val networkRequest: NetworkRequest by lazy(NONE) {
        NetworkRequest.Builder()
            .addCapability(NET_CAPABILITY_INTERNET)
            .build()
    }

    private val networkCallback: NetworkCallback by lazy(NONE) {
        object : NetworkCallback() {
            override fun onAvailable(network: Network) {
                Log.v(TAG, "onAvailable: $network")
            }

            override fun onCapabilitiesChanged(network: Network, networkCapabilities: NetworkCapabilities) {
                Log.v(TAG, "onCapabilitiesChanged: $network, $networkCapabilities")
                checkNetworkState(network, networkCapabilities)
            }

            private fun checkNetworkState(network: Network, networkCapabilities: NetworkCapabilities) {
                if (currentNetwork == null) {
                    currentNetwork = network
                    validated = networkCapabilities.hasCapability(NET_CAPABILITY_VALIDATED)
                } else {
                    if (currentNetwork != network) {
                        currentNetwork = network
                        validated = false
                    }
                    if (!validated) {
                        validated = networkCapabilities.hasCapability(NET_CAPABILITY_VALIDATED)
                        if (validated) onNetworkChange()
                    }
                }
            }

            override fun onBlockedStatusChanged(network: Network, blocked: Boolean) {
                Log.v(TAG, "onBlockedStatusChanged: $network, $blocked")
            }

            override fun onLost(network: Network) {
                Log.v(TAG, "onLost: $network")
            }
        }
    }

    suspend fun bindNetworkListener() {
        if (isListenerBound) return
        Log.d(TAG, "Bind network listener")
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            connectivityManager.registerBestMatchingNetworkCallback(networkRequest, networkCallback, handler)
        } else {
            val numberAttempts = 300
            var attemptCount = 0
            while(true) {
                try {
                    connectivityManager.requestNetwork(networkRequest, networkCallback, handler)
                    break
                } catch (e: SecurityException) {
                    Log.e(TAG, "Failed to bind network listener: $e")
                    // Android 11 bug: https://issuetracker.google.com/issues/175055271
                    if (e.message?.startsWith("Package android does not belong to") == true) {
                        if (++attemptCount > numberAttempts) {
                            throw e
                        }
                        delay(1000)
                        continue
                    } else {
                        throw e
                    }
                }
            }
        }
        isListenerBound = true
    }

    fun unbindNetworkListener() {
        if (!isListenerBound) return
        Log.d(TAG, "Unbind network listener")
        connectivityManager.unregisterNetworkCallback(networkCallback)
        isListenerBound = false
        currentNetwork = null
        validated = false
    }
}

// AVPN (Android uplink, review round 20 R1): "is there a physical network" as the C++ UplinkMonitor asks it. The
// fact is the set of PHYSICAL networks with internet (the NOT_VPN set of ScanAppNetwork below): our own tunnel is
// not in it, so its teardown is never "no network" (the default network of our UID is our VPN while it exists -
// the QNetworkInformation fallback read that as a loss for 0.2-18 s after every teardown). up = the set is not
// empty. The initial value is the synchronous snapshot taken when the monitor starts watching (the same request:
// INTERNET + NOT_VPN), unless a callback already told the set; null = nothing known yet (C++ keeps its "until the
// first event - up"). Pure: unit tested in PhysicalUplinkTest.
class PhysicalUplink {
    var up: Boolean? = null
        private set
    private var fromCallback = false

    // The callback's set changed: true when `up` moved (the change is told to C++).
    fun onSet(physicalNetworks: Int): Boolean {
        fromCallback = true
        return set(physicalNetworks > 0)
    }

    // The snapshot at the start of the watch: the initial value, never over what a callback already told.
    fun onSnapshot(physicalNetworks: Int): Boolean = if (fromCallback) false else set(physicalNetworks > 0)

    private fun set(value: Boolean): Boolean {
        val moved = up != value
        up = value
        return moved
    }
}

// AVPN (Scanner, lane A3; plan scanner-client-plan.md v2.2 §2.11a): the app process's element of the strict
// network generation tuple (source "app": a random 64-bit epoch per process, a counter bumped when the set of
// UNDERLYING networks changes - the VPN network itself is excluded, NET_CAPABILITY_NOT_VPN) and the physical kind of
// that network (ethernet > wifi > cellular when several are up). Read by C++ through JNI
// (AndroidScanHost::appGeneration -> ScanEngineAdapter::network()). The monitor starts on the first read and lives
// as long as the process. The signature stays in memory, never sent or logged.
// The same set is the Android source of the physical uplink (PhysicalUplink above): UplinkMonitor.cpp registers
// onPhysicalUplink and calls watchUplink; every change of "the set is empty" is then told as it happens (on the
// ConnectivityManager callback thread; C++ moves it to its own thread).
object ScanAppNetwork {
    private val lock = Any()
    private val epoch = java.security.SecureRandom().nextLong()
    private var counter = 0L
    private var last: String? = null
    private var started = false
    private var registered = false
    private var uplinkWatched = false
    private val uplink = PhysicalUplink()
    private val networks = HashMap<Network, Pair<String, String>>() // transport, "iface|addresses"

    // Registered by UplinkMonitor.cpp (Android) before watchUplink: the physical uplink moved.
    external fun onPhysicalUplink(up: Boolean)

    // UplinkMonitor.cpp (Android): start watching. 1 = a physical network exists, 0 = none, -1 = not known yet,
    // -2 = no source (the callback could not be registered: the C++ side keeps its QNetworkInformation fallback).
    @JvmStatic
    fun watchUplink(context: Context): Int {
        start(context)
        val cm = context.applicationContext.getSystemService<ConnectivityManager>() ?: return -2
        synchronized(lock) {
            if (!registered) return -2
        }
        // After the registration: a network lost before it is not in the snapshot, one lost after it is told by onLost.
        @Suppress("DEPRECATION")
        val snapshot = runCatching {
            cm.allNetworks.count { n ->
                cm.getNetworkCapabilities(n)?.let {
                    it.hasCapability(NET_CAPABILITY_INTERNET) && it.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
                } == true
            }
        }.getOrNull()
        synchronized(lock) {
            if (snapshot != null) uplink.onSnapshot(snapshot)
            uplinkWatched = true
            return when (uplink.up) {
                true -> 1
                false -> 0
                null -> -1
            }
        }
    }

    // {"source":"app","epoch":"<16 hex>","counter":n,"kind":"wifi|cellular|ethernet|"}; "" before the first network.
    @JvmStatic
    fun element(context: Context): String {
        start(context)
        synchronized(lock) {
            if (last == null) return ""
            val hex = java.lang.Long.toHexString(epoch).padStart(16, '0')
            return "{\"source\":\"app\",\"epoch\":\"$hex\",\"counter\":$counter,\"kind\":\"${kindLocked()}\"}"
        }
    }

    private fun start(context: Context) {
        synchronized(lock) {
            if (started) return
            started = true
        }
        val cm = context.applicationContext.getSystemService<ConnectivityManager>() ?: return
        val request = NetworkRequest.Builder()
            .addCapability(NET_CAPABILITY_INTERNET)
            .addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
            .build()
        val ok = runCatching {
            cm.registerNetworkCallback(request, object : NetworkCallback() {
                override fun onCapabilitiesChanged(network: Network, caps: NetworkCapabilities) {
                    val transport = when {
                        caps.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET) -> "ethernet"
                        caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) -> "wifi"
                        caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) -> "cellular"
                        else -> "other"
                    }
                    update(network) { old -> transport to (old?.second ?: "") }
                }

                override fun onLinkPropertiesChanged(network: Network, lp: android.net.LinkProperties) {
                    val link = (lp.interfaceName ?: "") + "|" + lp.linkAddresses.map { it.toString() }.sorted().joinToString(",")
                    update(network) { old -> (old?.first ?: "other") to link }
                }

                override fun onLost(network: Network) {
                    synchronized(lock) {
                        if (networks.remove(network) != null) observeLocked()
                    }
                }
            })
        }.onFailure { Log.w(TAG, "Scan app network monitor not started: ${it.javaClass.simpleName}") }.isSuccess
        synchronized(lock) { registered = ok }
    }

    private fun update(network: Network, change: (Pair<String, String>?) -> Pair<String, String>) {
        synchronized(lock) {
            networks[network] = change(networks[network])
            observeLocked()
        }
    }

    private fun observeLocked() {
        val signature = networks.values.map { it.first + "|" + it.second }.sorted().joinToString(";")
        val previous = last
        last = signature
        if (previous != null && previous != signature) counter++
        // Told under the lock: C++ gets the changes in the order the set saw them, after watchUplink's initial value.
        if (uplink.onSet(networks.size) && uplinkWatched) {
            val up = uplink.up == true
            Log.i(TAG, "Physical uplink ${if (up) "up" else "down"}")
            runCatching { onPhysicalUplink(up) }
                .onFailure { Log.w(TAG, "Physical uplink not told: ${it.javaClass.simpleName}") }
        }
    }

    private fun kindLocked(): String {
        val kinds = networks.values.map { it.first }.toSet()
        return when {
            "ethernet" in kinds -> "ethernet"
            "wifi" in kinds -> "wifi"
            "cellular" in kinds -> "cellular"
            else -> ""
        }
    }
}

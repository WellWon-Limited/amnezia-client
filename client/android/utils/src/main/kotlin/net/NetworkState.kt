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

// AVPN (Scanner, lane A3; plan scanner-client-plan.md v2.2 §2.11a): the app process's element of the strict
// network generation tuple (source "app": a random 64-bit epoch per process, a counter bumped when the set of
// UNDERLYING networks changes - the VPN network itself is excluded, NET_CAPABILITY_NOT_VPN) and the physical kind of
// that network (ethernet > wifi > cellular when several are up). Read by C++ through JNI
// (AndroidScanHost::appGeneration -> ScanEngineAdapter::network()). The monitor starts on the first read and lives
// as long as the process. The signature stays in memory, never sent or logged.
object ScanAppNetwork {
    private val lock = Any()
    private val epoch = java.security.SecureRandom().nextLong()
    private var counter = 0L
    private var last: String? = null
    private var started = false
    private val networks = HashMap<Network, Pair<String, String>>() // transport, "iface|addresses"

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
        runCatching {
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
        }.onFailure { Log.w(TAG, "Scan app network monitor not started: ${it.javaClass.simpleName}") }
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

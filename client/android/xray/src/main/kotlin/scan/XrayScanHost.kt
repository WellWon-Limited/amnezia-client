package org.amnezia.vpn.protocol.xray.scan

import android.app.ActivityManager
import android.content.Context
import android.net.ConnectivityManager
import android.net.LinkProperties
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import java.security.SecureRandom
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.RejectedExecutionException
import java.util.concurrent.ThreadPoolExecutor
import java.util.concurrent.TimeUnit
import org.amnezia.vpn.protocol.xray.libXray.LibXray
import org.amnezia.vpn.protocol.xray.libXray.TribeScanProtector
import org.amnezia.vpn.util.Log

private const val TAG = "XrayScanHost"

// AVPN (Scanner, lane A3; plan scanner-client-plan.md v2.2 §2.2a, §2.5, §2.11a): the Android glue of ScanHostCore
// inside :amneziaXrayService (decision A-7: probes run only in the process that runs the Xray core). Owns:
//  - ONE worker thread: every message runs there, in arrival order; at most QUEUE_MAX wait (a further message is
//    answered ipc_refused/queue_full at once). The epoch a message belongs to is read on receipt (submit), before
//    it waits in the queue.
//  - the scan's OWN socket protector (LibXray.tribeScanSetProtector): VpnService.protect(fd) and its result, nothing
//    else - never LibXray.registerSocketControllers / registerDialerController (the tunnel's one slot), never the
//    tunnel's failure path; a false answer fails that probe only (bind_failed). Installed by open() after the core
//    runs, removed by stopAllAndClose() AFTER the engine's stop-all (removal waits for protect calls in flight).
//  - the generation element of this process (source "xray_service"): a random epoch per host start, a counter
//    bumped when the set of underlying (non-VPN) networks changes (ConnectivityManager callbacks).
//  - the memory headroom (ActivityManager.MemoryInfo) the caps and the start guard use.
// The host never starts, stops or reconfigures the tunnel. Xray.kt calls open() after a successful start and
// stopAllAndClose() before the core stops (user stop, node switch, terminal lease, service end).
class XrayScanHost(context: Context) {
    companion object {
        const val QUEUE_MAX = 16
    }

    private val app = context.applicationContext
    private val generation = ScanPathGeneration(SecureRandom().nextLong())
    private val core = ScanHostCore(LibXrayScanEngine, { generation.element() }, ::deviceSpareMb, { Log.i(TAG, it) })
    private val worker = ThreadPoolExecutor(1, 1, 0L, TimeUnit.MILLISECONDS, LinkedBlockingQueue(QUEUE_MAX)) { r ->
        Thread(r, "tribe-scan-host").apply { isDaemon = true }
    }
    private val netLock = Any()
    private var netCallback: ConnectivityManager.NetworkCallback? = null
    private val networks = HashMap<Network, String>()

    // ServiceEvent.SCAN_HOST_STATE payload on every change of open / gen (set by the service; any thread).
    @Volatile
    var onStateChanged: ((String) -> Unit)? = null

    // The tunnel core runs: arm the scan protector, start the network monitor, admit scans.
    fun open(protect: (Int) -> Boolean, goLimitBytes: Long) {
        LibXray.tribeScanSetProtector(object : TribeScanProtector {
            override fun protectFd(fd: Long): Boolean = runCatching { protect(fd.toInt()) }.getOrDefault(false)
        })
        startNetMonitor()
        core.open(goLimitBytes)
        notifyState()
    }

    // Before the tunnel core stops: end every scan (bounded), close the host, then remove the protector.
    fun stopAllAndClose(reason: String) {
        val wasOpen = core.isOpen()
        core.stopAllAndClose(reason)
        runCatching { LibXray.tribeScanSetProtector(null) }
        stopNetMonitor()
        if (wasOpen) notifyState()
    }

    // One message of the app; `reply` runs once, on the worker thread (or at once when refused).
    fun submit(request: String, reply: (String) -> Unit) {
        val receivedEpoch = core.receive()
        try {
            worker.execute {
                val answer = runCatching { core.handle(request, receivedEpoch) }.getOrElse {
                    Log.e(TAG, "Tribe scan: handler failed (${it.javaClass.simpleName})")
                    "{\"error\":\"internal\",\"detail\":\"host\"}"
                }
                reply(answer)
            }
        } catch (_: RejectedExecutionException) {
            reply(ScanHostCore.QUEUE_FULL)
        }
    }

    // {"open":bool,"gen":{...}}: whether new scans are admitted, and this process's element.
    fun stateJson(): String = "{\"open\":${core.isOpen()},\"gen\":${generation.element().json}}"

    private fun notifyState() {
        onStateChanged?.invoke(stateJson())
    }

    // ---- memory -----------------------------------------------------------------------------------------------

    private fun deviceSpareMb(): Double? = runCatching {
        val am = app.getSystemService(Context.ACTIVITY_SERVICE) as ActivityManager
        val info = ActivityManager.MemoryInfo()
        am.getMemoryInfo(info)
        if (info.lowMemory) 0.0 else (info.availMem - info.threshold).coerceAtLeast(0L) / (1024.0 * 1024.0)
    }.getOrNull()

    // ---- underlying networks ------------------------------------------------------------------------------------

    private fun startNetMonitor() {
        synchronized(netLock) {
            if (netCallback != null) return
            val cm = app.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
            val request = NetworkRequest.Builder()
                .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
                .addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
                .build()
            val cb = object : ConnectivityManager.NetworkCallback() {
                override fun onCapabilitiesChanged(network: Network, caps: NetworkCapabilities) =
                    update(network, transportOf(caps), null)
                override fun onLinkPropertiesChanged(network: Network, lp: LinkProperties) =
                    update(network, null, lp)
                override fun onLost(network: Network) = remove(network)
            }
            runCatching { cm.registerNetworkCallback(request, cb) }.onSuccess { netCallback = cb }
                .onFailure { Log.w(TAG, "Tribe scan: network monitor not started (${it.javaClass.simpleName})") }
        }
    }

    private fun stopNetMonitor() {
        synchronized(netLock) {
            val cb = netCallback ?: return
            netCallback = null
            val cm = app.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
            runCatching { cm.unregisterNetworkCallback(cb) }
            networks.clear()
        }
    }

    private fun transportOf(caps: NetworkCapabilities): String = when {
        caps.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET) -> "ethernet"
        caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) -> "wifi"
        caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) -> "cellular"
        else -> "other"
    }

    // One entry per underlying network: "transport|interface|addresses" (kept in memory, never sent or logged).
    private fun update(network: Network, transport: String?, lp: LinkProperties?) {
        val changed = synchronized(netLock) {
            val old = networks[network]
            val parts = (old ?: "other||").split('|', limit = 3)
            val t = transport ?: parts[0]
            val iface = lp?.interfaceName ?: parts.getOrElse(1) { "" }
            val addrs = lp?.linkAddresses?.map { it.toString() }?.sorted()?.joinToString(",") ?: parts.getOrElse(2) { "" }
            networks[network] = "$t|$iface|$addrs"
            generation.observe(signatureLocked())
        }
        if (changed) notifyState()
    }

    private fun remove(network: Network) {
        val changed = synchronized(netLock) {
            if (networks.remove(network) == null) return
            generation.observe(signatureLocked())
        }
        if (changed) notifyState()
    }

    private fun signatureLocked(): String = networks.values.sorted().joinToString(";")
}

// The engine of libxray tribe.3 (root gomobile exports, ABI libxray-tribe-scan-v1).
object LibXrayScanEngine : ScanEngine {
    override fun message(request: String, hostOptions: String): String = LibXray.tribeScanMessage(request, hostOptions)
    override fun stopAll(waitMs: Long): String = LibXray.tribeScanStopAll(waitMs)
}

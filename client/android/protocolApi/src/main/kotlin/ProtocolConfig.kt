package org.amnezia.vpn.protocol

import android.net.ProxyInfo
import android.os.Build
import androidx.annotation.RequiresApi
import java.net.InetAddress
import org.amnezia.vpn.util.Log
import org.amnezia.vpn.util.net.InetNetwork
import org.amnezia.vpn.util.net.IpRange
import org.amnezia.vpn.util.net.IpRangeSet

// AVPN «Доступ к сайтам РФ» (owner 26.11.2026): the hard ceiling of split routes the service hands Android 13+ in one
// build - the platform's limit (above it the build's LinkProperties overran the system's binder: 10,841 routes = 0 of 3
// connects; 1000 = the largest count measured clean for binder on the phone of 26.11, a placeholder the owner sets). The
// engine's route budget is clamped to the same number: RouteBudget.h kAndroidSplitRouteCeiling (two constants, one value -
// check_android_bypass_apps_wiring.sh A6). A config over it (a saved config of an older build, started without the app:
// Always-on, the tile, the notification, a redelivered start) gets none of its split routes: that start runs as with the
// mode off for sites - a subset is the safe direction; the selection itself is the engine's (RouteReduce.h), not repeated here.
const val ANDROID_SPLIT_ROUTE_CEILING = 1000

private const val CONFIG_TAG = "ProtocolConfig"

open class ProtocolConfig protected constructor(
    val addresses: Set<InetNetwork>,
    val dnsServers: Set<InetAddress>,
    val searchDomain: String?,
    val routes: Set<Route>,
    val includedAddresses: Set<InetNetwork>,
    val excludedAddresses: Set<InetNetwork>,
    val includedApplications: Set<String>,
    val excludedApplications: Set<String>,
    val httpProxy: ProxyInfo?,
    val allowAllAF: Boolean,
    val blockingMode: Boolean,
    val mtu: Int
) {

    protected constructor(builder: Builder) : this(
        builder.addresses,
        builder.dnsServers,
        builder.searchDomain,
        builder.routes,
        builder.includedAddresses,
        builder.excludedAddresses,
        builder.includedApplications,
        builder.excludedApplications,
        builder.httpProxy,
        builder.allowAllAF,
        builder.blockingMode,
        builder.mtu
    )

    open class Builder(blockingMode: Boolean) {
        internal val addresses: MutableSet<InetNetwork> = hashSetOf()
        internal val dnsServers: MutableSet<InetAddress> = hashSetOf()
        internal val routes: MutableSet<Route> = mutableSetOf()
        internal val includedAddresses: MutableSet<InetNetwork> = hashSetOf()
        internal val excludedAddresses: MutableSet<InetNetwork> = hashSetOf()
        internal val includedApplications: MutableSet<String> = hashSetOf()
        internal val excludedApplications: MutableSet<String> = hashSetOf()

        internal var searchDomain: String? = null
            private set

        internal var httpProxy: ProxyInfo? = null
            private set

        internal var allowAllAF: Boolean = false
            private set

        internal var blockingMode: Boolean = blockingMode
            private set

        internal var allowSplitTunneling: Boolean = true
            private set

        open var mtu: Int = 0
            protected set

        fun addAddress(addr: InetNetwork) = apply { this.addresses += addr }
        fun addAddresses(addresses: Collection<InetNetwork>) = apply { this.addresses += addresses }
        fun clearAddresses() = apply { this.addresses.clear() }

        fun addDnsServer(dnsServer: InetAddress) = apply { this.dnsServers += dnsServer }
        fun addDnsServers(dnsServers: Collection<InetAddress>) = apply { this.dnsServers += dnsServers }

        fun setSearchDomain(domain: String) = apply { this.searchDomain = domain }

        fun addRoute(route: InetNetwork) = apply { this.routes += Route(route, true) }
        fun addRoutes(routes: Collection<InetNetwork>) = apply { this.routes += routes.map { Route(it, true) } }

        fun excludeRoute(route: InetNetwork) = apply { this.routes += Route(route, false) }
        fun excludeRoutes(routes: Collection<InetNetwork>) = apply { this.routes += routes.map { Route(it, false) } }

        fun removeRoute(route: InetNetwork) = apply { this.routes.removeIf { it.inetNetwork == route } }
        fun clearRoutes() = apply { this.routes.clear() }

        fun prependRoutes(block: Builder.() -> Unit) = apply {
            val savedRoutes = mutableListOf<Route>().apply { addAll(routes) }
            routes.clear()
            block()
            routes.addAll(savedRoutes)
        }

        fun includeAddress(addr: InetNetwork) = apply { this.includedAddresses += addr }
        fun includeAddresses(addresses: Collection<InetNetwork>) = apply { this.includedAddresses += addresses }

        fun excludeAddress(addr: InetNetwork) = apply { this.excludedAddresses += addr }
        fun excludeAddresses(addresses: Collection<InetNetwork>) = apply { this.excludedAddresses += addresses }

        fun includeApplication(application: String) = apply { this.includedApplications += application }
        fun includeApplications(applications: Collection<String>) = apply { this.includedApplications += applications }

        fun excludeApplication(application: String) = apply { this.excludedApplications += application }
        fun excludeApplications(applications: Collection<String>) = apply { this.excludedApplications += applications }

        @RequiresApi(Build.VERSION_CODES.Q)
        fun setHttpProxy(httpProxy: ProxyInfo) = apply { this.httpProxy = httpProxy }

        fun setAllowAllAF(allowAllAF: Boolean) = apply { this.allowAllAF = allowAllAF }

        fun setBlockingMode(blockingMode: Boolean) = apply { this.blockingMode = blockingMode }

        fun disableSplitTunneling() = apply { this.allowSplitTunneling = false }

        fun setMtu(mtu: Int) = apply { this.mtu = mtu }

        private fun processSplitTunneling() {
            if (includedAddresses.isNotEmpty() && excludedAddresses.isNotEmpty()) {
                throw BadConfigException("Config contains addresses for inclusive and exclusive split tunneling at the same time")
            }

            if (includedAddresses.isNotEmpty()) {
                // remove default routes, if any
                removeRoute(InetNetwork("0.0.0.0", 0))
                removeRoute(InetNetwork("::", 0))
                removeRoute(InetNetwork("2000::", 3))
                prependRoutes {
                    addRoutes(includedAddresses)
                }
            } else if (excludedAddresses.isNotEmpty() && Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU &&
                excludedAddresses.size > ANDROID_SPLIT_ROUTE_CEILING) {
                // AVPN: over the platform's ceiling - none applied (see ANDROID_SPLIT_ROUTE_CEILING)
                Log.w(CONFIG_TAG, "bypass routes refused=${excludedAddresses.size} ceiling=$ANDROID_SPLIT_ROUTE_CEILING: " +
                    "none applied")
                excludedAddresses.clear()
            } else if (excludedAddresses.isNotEmpty()) {
                prependRoutes {
                    addRoute(InetNetwork("0.0.0.0", 0))
                    addRoute(InetNetwork("2000::", 3))
                    excludeRoutes(excludedAddresses)
                }
            }
        }

        private fun processRoutes() {
            // replace ::/0 as it may cause LAN connection issues
            val ipv6DefaultRoute = InetNetwork("::", 0)
            if (routes.removeIf { it.include && it.inetNetwork == ipv6DefaultRoute }) {
                prependRoutes {
                    addRoute(InetNetwork("2000::", 3))
                }
            }
            // for older versions of Android, build a list of subnets without excluded routes
            // and add them to routes
            if (Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU && routes.any { !it.include }) {
                val ipRangeSet = IpRangeSet()
                routes.forEach {
                    if (it.include) ipRangeSet.add(IpRange(it.inetNetwork))
                    else ipRangeSet.remove(IpRange(it.inetNetwork))
                }
                ipRangeSet.remove(IpRange("127.0.0.0", 8))
                ipRangeSet.remove(IpRange("::1", 128))
                routes.clear()
                ipRangeSet.subnets().forEach(::addRoute)
            }
            // filter ipv4 and ipv6 loopback addresses
            val ipv6Loopback = InetNetwork("::1", 128)
            routes.removeIf {
                it.include &&
                    if (it.inetNetwork.isIpv4) it.inetNetwork.address.address[0] == 127.toByte()
                    else it.inetNetwork == ipv6Loopback
            }
        }

        private fun validate() {
            val errorMessage = StringBuilder()

            with(errorMessage) {
                if (addresses.isEmpty()) appendLine("VPN interface network address not specified.")
                if (routes.isEmpty()) appendLine("VPN interface route not specified.")
                if (mtu == 0) appendLine("MTU not set.")
            }

            if (errorMessage.isNotEmpty()) throw BadConfigException(errorMessage.toString())
        }

        protected fun configBuild() {
            processSplitTunneling()
            processRoutes()
            validate()
        }

        open fun build(): ProtocolConfig = configBuild().run { ProtocolConfig(this@Builder) }
    }

    companion object {
        inline fun build(blockingMode: Boolean, block: Builder.() -> Unit): ProtocolConfig =
            Builder(blockingMode).apply(block).build()
    }
}

data class Route(val inetNetwork: InetNetwork, val include: Boolean)

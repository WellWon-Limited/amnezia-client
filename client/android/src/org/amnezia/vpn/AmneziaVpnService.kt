package org.amnezia.vpn

import android.annotation.SuppressLint
import android.app.ActivityManager
import android.app.ActivityManager.RunningAppProcessInfo.IMPORTANCE_FOREGROUND_SERVICE
import android.app.NotificationManager
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo.FOREGROUND_SERVICE_TYPE_MANIFEST
import android.content.pm.ServiceInfo.FOREGROUND_SERVICE_TYPE_SYSTEM_EXEMPTED
import android.net.VpnService
import android.os.Bundle
import android.os.Build
import android.os.Handler
import android.os.IBinder
import android.os.Looper
import android.os.Message
import android.os.Messenger
import android.os.PowerManager
import android.os.Process
import android.os.SystemClock
import androidx.annotation.MainThread
import androidx.core.app.ServiceCompat
import androidx.core.content.ContextCompat
import androidx.core.content.getSystemService
import java.net.UnknownHostException
import java.util.concurrent.ConcurrentHashMap
import kotlin.LazyThreadSafetyMode.NONE
import kotlinx.coroutines.CoroutineExceptionHandler
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.TimeoutCancellationException
import kotlinx.coroutines.cancel
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.drop
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeout
import org.amnezia.vpn.protocol.BadConfigException
import org.amnezia.vpn.protocol.ProtocolState.CONNECTED
import org.amnezia.vpn.protocol.ProtocolState.CONNECTING
import org.amnezia.vpn.protocol.ProtocolState.DISCONNECTED
import org.amnezia.vpn.protocol.ProtocolState.DISCONNECTING
import org.amnezia.vpn.protocol.ProtocolState.RECONNECTING
import org.amnezia.vpn.protocol.ProtocolState.UNKNOWN
import org.amnezia.vpn.protocol.VpnException
import org.amnezia.vpn.protocol.VpnStartException
import org.amnezia.vpn.protocol.putStatistics
import org.amnezia.vpn.protocol.putStatus
import org.amnezia.vpn.protocol.xray.UpstreamStatusChange
import org.amnezia.vpn.protocol.xray.Xray
import org.amnezia.vpn.util.LoadLibraryException
import org.amnezia.vpn.util.Log
import org.amnezia.vpn.util.Prefs
import org.amnezia.vpn.util.TribeSession
import org.amnezia.vpn.util.TribeStart
import org.amnezia.vpn.util.net.NetworkState
import org.amnezia.vpn.util.net.TrafficStats
import org.json.JSONException
import org.json.JSONObject

private const val TAG = "AmneziaVpnService"

const val ACTION_DISCONNECT = "org.amnezia.vpn.action.disconnect"
const val ACTION_CONNECT = "org.amnezia.vpn.action.connect"

const val MSG_VPN_CONFIG = "VPN_CONFIG"
const val MSG_ERROR = "ERROR"
const val MSG_SAVE_LOGS = "SAVE_LOGS"
const val MSG_CLIENT_NAME = "CLIENT_NAME"

const val AFTER_PERMISSION_CHECK = "AFTER_PERMISSION_CHECK"
private const val PREFS_CONFIG_KEY = "LAST_CONF"
private const val PREFS_SERVER_NAME = "LAST_SERVER_NAME"
private const val PREFS_SERVER_INDEX = "LAST_SERVER_INDEX"
private const val STATISTICS_SENDING_TIMEOUT = 1000L // AVPN: restored for the Xray path (decision A-5)
private const val TRAFFIC_STATS_UPDATE_TIMEOUT = 1000L
private const val DISCONNECT_TIMEOUT = 5000L
private const val STOP_SERVICE_TIMEOUT = 5000L

@SuppressLint("Registered")
open class AmneziaVpnService : VpnService() {

    private lateinit var mainScope: CoroutineScope
    private lateinit var connectionScope: CoroutineScope
    private var isServiceBound = false
    private var vpnProto: VpnProto? = null
    private var protocolState = MutableStateFlow(UNKNOWN)
    private var serverName: String? = null
    private var serverIndex: Int = -1

    private val isConnected
        get() = protocolState.value == CONNECTED

    private val isDisconnected
        get() = protocolState.value == DISCONNECTED

    private val isUnknown
        get() = protocolState.value == UNKNOWN

    private var connectionJob: Job? = null
    private var disconnectionJob: Job? = null
    private var trafficStatsUpdateJob: Job? = null
    private var statisticsSendingJob: Job? = null // AVPN: Xray path only (decision A-5)
    private lateinit var networkState: NetworkState
    private lateinit var trafficStats: TrafficStats
    private var controlReceiver: BroadcastReceiver? = null
    private var notificationStateReceiver: BroadcastReceiver? = null
    private var screenOnReceiver: BroadcastReceiver? = null
    private var screenOffReceiver: BroadcastReceiver? = null
    private val clientMessengers = ConcurrentHashMap<Messenger, IpcMessenger>()

    private val isActivityConnected
        get() = clientMessengers.any { it.value.name == ACTIVITY_MESSENGER_NAME }

    // AVPN (decisions A-1, A-5): the Xray protocol object of this session, or null. Every AVPN addition below
    // (statistics sender, upstream status, seat hand-over) runs only through it, so the AWG, WireGuard and
    // OpenVPN paths do exactly what they did before.
    private val xrayProtocol: Xray?
        get() = when (vpnProto) {
            VpnProto.XRAY, VpnProto.SSXRAY -> vpnProto?.protocol as? Xray
            else -> null
        }

    private val connectionExceptionHandler = CoroutineExceptionHandler { _, e ->
        connectionJob?.cancel()
        connectionJob = null
        disconnectionJob?.cancel()
        disconnectionJob = null
        protocolState.value = DISCONNECTED
        when (e) {
            is IllegalArgumentException,
            is VpnStartException,
            is VpnException -> onError(e.message ?: e.toString())

            is JSONException,
            is BadConfigException -> onError("VPN config format error: ${e.message}")

            is LoadLibraryException -> onError("${e.message}. Caused: ${e.cause?.message}")

            is UnknownHostException -> onError("Unknown host")

            else -> throw e
        }
    }

    private val actionMessageHandler: Handler by lazy(NONE) {
        object : Handler(Looper.getMainLooper()) {
            override fun handleMessage(msg: Message) {
                val action = msg.extractIpcMessage<Action>()
                Log.d(TAG, "Handle action: $action")
                when (action) {
                    Action.REGISTER_CLIENT -> {
                        val clientName = msg.data.getString(MSG_CLIENT_NAME)
                        val messenger = IpcMessenger(msg.replyTo, clientName)
                        clientMessengers[msg.replyTo] = messenger
                        Log.d(TAG, "Messenger client '$clientName' was registered")
                        // AVPN (local build): the first start comes with the service's start command, before the
                        // activity registered - it learns the build in progress now
                        if (buildingSeq != 0) messenger.send { tunnelBuildMessage(TUNNEL_BUILDING, buildingSeq, buildingLeg) }
                        if (clientName == ACTIVITY_MESSENGER_NAME && isConnected) launchSendingStatistics()
                    }

                    Action.UNREGISTER_CLIENT -> {
                        clientMessengers.remove(msg.replyTo)?.let {
                            Log.d(TAG, "Messenger client '${it.name}' was unregistered")
                            if (it.name == ACTIVITY_MESSENGER_NAME && !isActivityConnected) stopSendingStatistics()
                        }
                    }

                    Action.CONNECT -> {
                        // AVPN: конфиг мог приехать файлом (binder-лимит) — см. TribeConfigFile
                        connect(
                            msg.data.getString(MSG_VPN_CONFIG)
                                ?: TribeConfigFile.read(msg.data.getString(TribeConfigFile.MSG_VPN_CONFIG_FILE))
                        )
                    }

                    Action.DISCONNECT -> {
                        disconnect()
                    }

                    Action.REQUEST_STATUS -> {
                        clientMessengers[msg.replyTo]?.let { clientMessenger ->
                            clientMessenger.send {
                                ServiceEvent.STATUS.packToMessage {
                                    putStatus(this@AmneziaVpnService.protocolState.value)
                                    putSessionMetadata()
                                }
                            }
                            // AVPN (android-ipc-contract.md section 3 rule 3): a recreated activity learns the
                            // upstream state right after STATUS; nothing for a session without upstream metadata.
                            xrayProtocol?.upstreamStatusEvent()?.let { sendUpstreamStatus(it, clientMessenger) }
                            // AVPN (Scanner, lane A3): the probe host's state, Xray sessions only.
                            xrayProtocol?.scanHost?.stateJson()?.let { sendScanHostState(it, clientMessenger) }
                        }
                    }

                    Action.SCAN_MESSAGE -> {
                        // AVPN (Scanner, lane A3): relayed to the Xray service's probe host; the reply goes back to
                        // replyTo with the request's id. Not an Xray session (AmneziaWG, OpenVPN): no probe host
                        // here (decision A-7) - no_vpn.
                        val id = msg.data?.getLong(MSG_SCAN_ID) ?: 0L
                        val request = msg.data?.getString(MSG_SCAN_REQUEST) ?: ""
                        val replyTo = msg.replyTo?.let { clientMessengers[it] ?: IpcMessenger(it, "ScanReply") }
                        val reply: (String) -> Unit = { answer -> mainScope.launch { sendScanReply(id, answer, replyTo) } }
                        val host = if (isConnected) xrayProtocol?.scanHost else null
                        if (host != null) host.submit(request, reply) else reply("{\"error\":\"no_vpn\"}")
                    }

                    Action.UPSTREAM_LEASE_SET -> {
                        // AVPN (android-ipc-contract.md section 2): always answered with UPSTREAM_STATUS.
                        val message = msg.data?.getString(MSG_UPSTREAM_LEASE_SET)
                        val replyTo = msg.replyTo?.let { clientMessengers[it] ?: IpcMessenger(it, "UpstreamReply") }
                        handleUpstreamLeaseSet(message, replyTo)
                    }

                    Action.NOTIFICATION_PERMISSION_GRANTED -> {
                        enableNotification()
                    }

                    Action.SET_SAVE_LOGS -> {
                        Log.saveLogs = msg.data.getBoolean(MSG_SAVE_LOGS)
                    }
                }
            }
        }
    }

    private val vpnServiceMessenger: Messenger by lazy(NONE) {
        Messenger(actionMessageHandler)
    }

    /**
     * Notification setup
     */
    private val foregroundServiceTypeCompat
        get() = when {
            Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE -> FOREGROUND_SERVICE_TYPE_SYSTEM_EXEMPTED
            Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q -> FOREGROUND_SERVICE_TYPE_MANIFEST
            else -> 0
        }

    private val serviceNotification: ServiceNotification by lazy(NONE) { ServiceNotification(this) }

    /**
     * Service overloaded methods
     */
    override fun onCreate() {
        super.onCreate()
        Log.d(TAG, "Create Amnezia VPN service")
        mainScope = CoroutineScope(SupervisorJob() + Dispatchers.Main.immediate)
        connectionScope = CoroutineScope(SupervisorJob() + Dispatchers.IO + connectionExceptionHandler)
        loadServerData()
        launchProtocolStateHandler()
        networkState = NetworkState(this, ::reconnect)
        trafficStats = TrafficStats()
        registerBroadcastReceivers()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        // AVPN (review R3): the app's stop of a start it gave as an intent, sent the same way (AmneziaActivity.sendStopIntent)
        // - after that start in Android's order, whether or not the app is bound. A start-service intent obliges the
        // foreground start; with nothing running and no client the service ends at once.
        if (intent?.action == ACTION_DISCONNECT) {
            Log.d(TAG, "Stop service command")
            ServiceCompat.startForeground(
                this, NOTIFICATION_ID,
                serviceNotification.buildNotification(serverName, vpnProto?.label, protocolState.value),
                foregroundServiceTypeCompat
            )
            disconnect()
            if ((isUnknown || isDisconnected) && !isServiceBound) stopService()
            return START_NOT_STICKY
        }
        val isAlwaysOn = intent != null && intent.action == SERVICE_INTERFACE

        if (isAlwaysOn) {
            Log.d(TAG, "Start service via Always-on")
            connect()
        } else if (intent?.getBooleanExtra(AFTER_PERMISSION_CHECK, false) == true) {
            Log.d(TAG, "Start service after permission check")
            connect()
        } else {
            Log.d(TAG, "Start service")
            // AVPN: конфиг мог приехать файлом (binder-лимит) — см. TribeConfigFile
            connect(
                intent?.getStringExtra(MSG_VPN_CONFIG)
                    ?: TribeConfigFile.read(intent?.getStringExtra(TribeConfigFile.MSG_VPN_CONFIG_FILE))
            )
        }
        ServiceCompat.startForeground(
            this, NOTIFICATION_ID,
            serviceNotification.buildNotification(serverName, vpnProto?.label, protocolState.value),
            foregroundServiceTypeCompat
        )
        return START_REDELIVER_INTENT
    }

    override fun onBind(intent: Intent?): IBinder? {
        Log.d(TAG, "onBind by $intent")
        if (intent?.action == SERVICE_INTERFACE) return super.onBind(intent)
        isServiceBound = true
        return vpnServiceMessenger.binder
    }

    override fun onUnbind(intent: Intent?): Boolean {
        Log.d(TAG, "onUnbind by $intent")
        if (intent?.action != SERVICE_INTERFACE) {
            if (clientMessengers.isEmpty()) {
                isServiceBound = false
                if (isUnknown || isDisconnected) stopService()
            }
        }
        return true
    }

    override fun onRebind(intent: Intent?) {
        Log.d(TAG, "onRebind by $intent")
        if (intent?.action != SERVICE_INTERFACE) {
            isServiceBound = true
        }
        super.onRebind(intent)
    }

    override fun onRevoke() {
        Log.d(TAG, "onRevoke")
        // Calls to onRevoke() method may not happen on the main thread of the process
        mainScope.launch {
            disconnect()
        }
    }

    override fun onDestroy() {
        Log.d(TAG, "Destroy service")
        unregisterBroadcastReceivers()
        runBlocking {
            disconnect()
            disconnectionJob?.join()
        }
        connectionScope.cancel()
        mainScope.cancel()
        super.onDestroy()
    }

    private fun stopService() {
        Log.d(TAG, "Stop service")
        // the coroutine below will be canceled during the onDestroy call
        mainScope.launch {
            delay(STOP_SERVICE_TIMEOUT)
            Log.w(TAG, "Stop service timeout, kill process")
            Process.killProcess(Process.myPid())
        }
        stopSelf()
    }

    private fun registerBroadcastReceivers() {
        Log.d(TAG, "Register broadcast receivers")
        controlReceiver = registerBroadcastReceiver(
            arrayOf(ACTION_CONNECT, ACTION_DISCONNECT), ContextCompat.RECEIVER_NOT_EXPORTED
        ) {
            it?.action?.let { action ->
                Log.v(TAG, "Broadcast request received: $action")
                when (action) {
                    ACTION_CONNECT -> connect()
                    ACTION_DISCONNECT -> disconnect()
                    else -> Log.w(TAG, "Unknown action received: $action")
                }
            }
        }

        notificationStateReceiver = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            registerBroadcastReceiver(
                arrayOf(
                    NotificationManager.ACTION_NOTIFICATION_CHANNEL_BLOCK_STATE_CHANGED,
                    NotificationManager.ACTION_APP_BLOCK_STATE_CHANGED
                )
            ) {
                val state = it?.getBooleanExtra(NotificationManager.EXTRA_BLOCKED_STATE, false)
                Log.v(TAG, "Notification state changed: ${it?.action}, blocked = $state")
                if (state == false) {
                    enableNotification()
                } else {
                    disableNotification()
                }
            }
        } else null

        registerScreenStateBroadcastReceivers()
    }

    private fun registerScreenStateBroadcastReceivers() {
        if (serviceNotification.isNotificationEnabled()) {
            Log.d(TAG, "Register screen state broadcast receivers")
            screenOnReceiver = registerBroadcastReceiver(Intent.ACTION_SCREEN_ON) {
                if (isConnected && serviceNotification.isNotificationEnabled()) startTrafficStatsUpdateJob()
            }

            screenOffReceiver = registerBroadcastReceiver(Intent.ACTION_SCREEN_OFF) {
                stopTrafficStatsUpdateJob()
            }
        }
    }

    private fun unregisterScreenStateBroadcastReceivers() {
        Log.d(TAG, "Unregister screen state broadcast receivers")
        unregisterBroadcastReceiver(screenOnReceiver)
        unregisterBroadcastReceiver(screenOffReceiver)
        screenOnReceiver = null
        screenOffReceiver = null
    }

    private fun unregisterBroadcastReceivers() {
        Log.d(TAG, "Unregister broadcast receivers")
        unregisterBroadcastReceiver(controlReceiver)
        unregisterBroadcastReceiver(notificationStateReceiver)
        unregisterScreenStateBroadcastReceivers()
        controlReceiver = null
        notificationStateReceiver = null
    }

    /**
     * Methods responsible for processing VPN connection
     */
    private fun launchProtocolStateHandler() {
        mainScope.launch {
            // drop first default UNKNOWN state
            protocolState.drop(1).collect { protocolState ->
                Log.d(TAG, "Protocol state changed: $protocolState")

                serviceNotification.updateNotification(serverName, vpnProto?.label, protocolState)

                clientMessengers.send {
                    ServiceEvent.STATUS_CHANGED.packToMessage {
                        putStatus(protocolState)
                        putSessionMetadata()
                    }
                }

                VpnStateStore.store { VpnState(protocolState, serverName, serverIndex, vpnProto) }

                when (protocolState) {
                    CONNECTED -> {
                        networkState.bindNetworkListener()
                        if (isActivityConnected) launchSendingStatistics()
                        launchTrafficStatsUpdate()
                    }

                    DISCONNECTED -> {
                        networkState.unbindNetworkListener()
                        stopTrafficStatsUpdateJob()
                        stopSendingStatistics()
                        if (!isServiceBound) stopService()
                    }

                    DISCONNECTING -> {
                        networkState.unbindNetworkListener()
                        stopTrafficStatsUpdateJob()
                        stopSendingStatistics()
                    }

                    RECONNECTING -> {
                        stopTrafficStatsUpdateJob()
                        stopSendingStatistics()
                    }

                    CONNECTING, UNKNOWN -> {}
                }
            }
        }
    }

    // AVPN (decision A-5): the upstream statistics sender, restored for the Xray protocol only - the engine's
    // health loop needs rx/tx (CONNECT-INVARIANTS §17.1: cumulative since tunnel start; the Xray protocol
    // reads the tunnel interface counters). Every second while connected and the activity is registered,
    // to the activity only (the one STATISTICS_UPDATE consumer). Never for AWG/WireGuard/OpenVPN: their
    // behaviour stays as before (no sender at all).
    @MainThread
    private fun launchSendingStatistics() {
        stopSendingStatistics()
        val xray = xrayProtocol ?: return
        if (!isConnected || !isActivityConnected) return
        statisticsSendingJob = mainScope.launch {
            while (true) {
                val statistics = xray.statistics
                clientMessengers.values
                    .filter { it.name == ACTIVITY_MESSENGER_NAME }
                    .forEach { messenger ->
                        messenger.send {
                            ServiceEvent.STATISTICS_UPDATE.packToMessage {
                                putStatistics(statistics)
                            }
                        }
                    }
                delay(STATISTICS_SENDING_TIMEOUT)
            }
        }
    }

    @MainThread
    private fun stopSendingStatistics() {
        statisticsSendingJob?.cancel()
        statisticsSendingJob = null
    }

    // AVPN (upstream nodes, android-ipc-contract.md section 3): the payload {"upstream":{contract section 5}}
    // to one messenger (a reply) or to every registered client (a change). Status fields only - no lease id,
    // token or host.
    @MainThread
    private fun sendUpstreamStatus(payload: String, to: IpcMessenger? = null) {
        val message = {
            ServiceEvent.UPSTREAM_STATUS.packToMessage {
                putString(MSG_UPSTREAM_STATUS, payload)
            }
        }
        if (to != null) to.send(message) else clientMessengers.send(message)
    }

    // AVPN (android-ipc-contract.md section 2): the hand-over runs off the main thread (the lease session
    // may wait for its state thread); the reply goes back on the main thread, always.
    @MainThread
    private fun sendScanReply(id: Long, reply: String, to: IpcMessenger?) {
        val message = {
            ServiceEvent.SCAN_REPLY.packToMessage {
                putLong(MSG_SCAN_ID, id)
                putString(MSG_SCAN_REPLY, reply)
            }
        }
        if (to != null) to.send(message) else clientMessengers.send(message)
    }

    // AVPN (Scanner, lane A3): {"open":bool,"gen":{...}} of the probe host, to one messenger or every client.
    @MainThread
    private fun sendScanHostState(state: String, to: IpcMessenger? = null) {
        val message = {
            ServiceEvent.SCAN_HOST_STATE.packToMessage {
                putString(MSG_SCAN_STATE, state)
            }
        }
        if (to != null) to.send(message) else clientMessengers.send(message)
    }

    private fun handleUpstreamLeaseSet(message: String?, replyTo: IpcMessenger?) {
        val xray = xrayProtocol
        mainScope.launch {
            val payload = withContext(Dispatchers.IO) {
                runCatching { xray?.upstreamLeaseSetMessage(message) }.getOrNull()
            } ?: JSONObject().put("upstream", UpstreamStatusChange.none()).toString()
            sendUpstreamStatus(payload, replyTo)
        }
    }

    @MainThread
    private fun enableNotification() {
        registerScreenStateBroadcastReceivers()
        serviceNotification.updateNotification(serverName, vpnProto?.label, protocolState.value)
        launchTrafficStatsUpdate()
    }

    @MainThread
    private fun disableNotification() {
        unregisterScreenStateBroadcastReceivers()
        stopTrafficStatsUpdateJob()
    }

    @MainThread
    private fun launchTrafficStatsUpdate() {
        stopTrafficStatsUpdateJob()
        if (isConnected &&
            serviceNotification.isNotificationEnabled() &&
            getSystemService<PowerManager>()?.isInteractive != false
        ) {
            Log.v(TAG, "Launch traffic stats update")
            trafficStats.reset()
            startTrafficStatsUpdateJob()
        }
    }

    @MainThread
    private fun startTrafficStatsUpdateJob() {
        if (trafficStatsUpdateJob == null && trafficStats.isSupported()) {
            Log.d(TAG, "Start traffic stats update")
            trafficStatsUpdateJob = mainScope.launch {
                while (true) {
                    trafficStats.getSpeed().let { speed ->
                        if (isConnected) {
                            serviceNotification.updateSpeed(speed)
                        }
                    }
                    delay(TRAFFIC_STATS_UPDATE_TIMEOUT)
                }
            }
        }
    }

    @MainThread
    private fun stopTrafficStatsUpdateJob() {
        Log.d(TAG, "Stop traffic stats update")
        trafficStatsUpdateJob?.cancel()
        trafficStatsUpdateJob = null
    }

    // AVPN (local build, emulator round 20.11): with «Доступ к сайтам РФ» on Android installs ~10 800 routes inside
    // VpnService.Builder.establish() - 7-10 s on the emulator - before the tunnel interface exists. That is the device's
    // time, not the server's: every start is numbered and reported "building" from the start command (config file,
    // prefs, parse, builder, establish) until the protocol's start returned - the interface is established and the
    // backend runs - or the start ended without it ("built"). The engine stops the leg's start clock in between
    // (AttemptOwner.h "Local build"). Main thread only.
    // android2 V2 (21.11): every report also names the engine leg of its start (TribeStart.legOf: the start config's
    // tribeStartLeg; 0 for the saved config of a restart), so a report of an earlier start is never the running leg's;
    // a start that ends without a tunnel is TUNNEL_NOT_STARTED, never "built".
    private var buildSeq = 0
    private var buildingSeq = 0 // the start being built now (0: none)
    // android2 P7 (21.11): the tribeSessionMetadata of the start this service launched last - the session it runs (or
    // brings up), returned with STATUS / STATUS_CHANGED so a UI process that comes back knows the live session's node.
    private var sessionMetadata: String? = null

    private fun Bundle.putSessionMetadata() {
        sessionMetadata?.let { putString(MSG_SESSION_METADATA, it) }
    }
    private var buildingLeg = 0L // its engine leg

    private fun tunnelBuildMessage(state: Int, seq: Int, leg: Long) =
        ServiceEvent.TUNNEL_BUILD.packToMessage {
            putInt(MSG_TUNNEL_BUILD_STATE, state)
            putInt(MSG_TUNNEL_BUILD_SEQ, seq)
            putLong(MSG_TUNNEL_BUILD_LEG, leg)
        }

    @MainThread
    private fun reportTunnelBuild(state: Int, seq: Int, leg: Long) {
        if (state == TUNNEL_BUILDING) {
            buildingSeq = seq
            buildingLeg = leg
        } else if (buildingSeq == seq) {
            buildingSeq = 0
            buildingLeg = 0L
        }
        clientMessengers.send { tunnelBuildMessage(state, seq, leg) }
    }

    @MainThread
    private fun connect(vpnConfig: String? = null) {
        val seq = ++buildSeq
        val leg = TribeStart.legOf(vpnConfig)
        val begin = SystemClock.elapsedRealtime()
        reportTunnelBuild(TUNNEL_BUILDING, seq, leg)
        Log.i(TAG, "Tunnel build $seq: begin leg=$leg")
        val launched = if (vpnConfig == null) {
            connectToVpn(Prefs.load(PREFS_CONFIG_KEY), seq, leg, begin)
        } else {
            Prefs.save(PREFS_CONFIG_KEY, vpnConfig)
            connectToVpn(vpnConfig, seq, leg, begin)
        }
        if (!launched) {
            Log.i(TAG, "Tunnel build $seq: end, not started leg=$leg")
            reportTunnelBuild(TribeStart.endState(started = false), seq, leg)
        }
    }

    // true: the start job was launched (it reports the end of the build itself)
    @MainThread
    private fun connectToVpn(vpnConfig: String, seq: Int, leg: Long, begin: Long): Boolean {
        if (isConnected || protocolState.value == CONNECTING) return false

        Log.d(TAG, "Start VPN connection")

        val config = parseConfigToJson(vpnConfig)
        saveServerData(config)
        if (config == null) {
            onError("Invalid VPN config")
            protocolState.value = DISCONNECTED
            return false
        }

        try {
            vpnProto = VpnProto.get(config.getString("protocol"))
        } catch (e: Exception) {
            onError("Invalid VPN config: ${e.message}")
            protocolState.value = DISCONNECTED
            return false
        }

        protocolState.value = CONNECTING

        // AVPN (android-ipc-contract.md section 3 rule 1): changes of an upstream session's status go to every
        // client. Called from the lease session's worker thread. Xray only.
        xrayProtocol?.upstreamStatusSink = { payload -> mainScope.launch { sendUpstreamStatus(payload) } }
        // AVPN (Scanner, lane A3): the probe host's state changes (open / close / network generation) go to every
        // client. Called from the host's threads. Xray only.
        xrayProtocol?.scanStateSink = { state -> mainScope.launch { sendScanHostState(state) } }

        if (!checkPermission()) {
            protocolState.value = DISCONNECTED
            return false
        }

        val prepared = SystemClock.elapsedRealtime()
        sessionMetadata = TribeSession.metadataOf(config) // the session this start brings up (android2 P7)
        connectionJob = connectionScope.launch {
            var started = false
            var startAt = prepared
            try {
                disconnectionJob?.join()
                disconnectionJob = null
                startAt = SystemClock.elapsedRealtime()

                vpnProto?.protocol?.let { protocol ->
                    protocol.initialize(applicationContext, protocolState, ::onError)
                    protocol.startVpn(config, Builder(), ::protect)
                    started = true
                }
            } finally {
                val end = SystemClock.elapsedRealtime()
                Log.i(TAG, "Tunnel build $seq: end, started=$started leg=$leg prepare_ms=${prepared - begin} " +
                    "wait_stop_ms=${startAt - prepared} start_ms=${end - startAt} total_ms=${end - begin}")
                mainScope.launch { reportTunnelBuild(TribeStart.endState(started), seq, leg) }
            }
        }
        return true
    }

    @MainThread
    private fun disconnect() {
        if (isUnknown || isDisconnected || protocolState.value == DISCONNECTING) return

        Log.d(TAG, "Stop VPN connection")

        protocolState.value = DISCONNECTING

        disconnectionJob = connectionScope.launch {
            connectionJob?.cancelAndJoin()
            connectionJob = null

            vpnProto?.protocol?.stopVpn()

            try {
                withTimeout(DISCONNECT_TIMEOUT) {
                    // waiting for disconnect state
                    protocolState.first { it == DISCONNECTED }
                }
            } catch (e: TimeoutCancellationException) {
                Log.w(TAG, "Disconnect timeout")
                stopService()
            }
        }
    }

    @MainThread
    private fun reconnect() {
        if (!isConnected) return

        Log.d(TAG, "Reconnect VPN")

        protocolState.value = RECONNECTING

        connectionJob = connectionScope.launch {
            vpnProto?.protocol?.reconnectVpn(Builder(), ::protect)
        }
    }

    /**
     * Utils methods
     */
    private fun onError(msg: String) {
        Log.e(TAG, msg)
        mainScope.launch {
            clientMessengers.send {
                ServiceEvent.ERROR.packToMessage {
                    putString(MSG_ERROR, msg)
                }
            }
        }
    }

    private fun parseConfigToJson(vpnConfig: String): JSONObject? =
        if (vpnConfig.isBlank()) {
            null
        } else {
            try {
                JSONObject(vpnConfig)
            } catch (e: JSONException) {
                onError("Invalid VPN config json format: ${e.message}")
                null
            }
        }

    private fun saveServerData(config: JSONObject?) {
        serverName = config?.opt("description") as String?
        serverIndex = config?.opt("serverIndex") as Int? ?: -1
        Log.d(TAG, "Save server data: ($serverIndex, $serverName)")
        Prefs.save(PREFS_SERVER_NAME, serverName)
        Prefs.save(PREFS_SERVER_INDEX, serverIndex)
    }

    private fun loadServerData() {
        serverName = Prefs.load<String>(PREFS_SERVER_NAME).ifBlank { null }
        if (serverName != null) serverIndex = Prefs.load(PREFS_SERVER_INDEX)
        Log.d(TAG, "Load server data: ($serverIndex, $serverName)")
    }

    private fun checkPermission(): Boolean =
        if (prepare(applicationContext) != null) {
            Intent(this, VpnRequestActivity::class.java).apply {
                addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                putExtra(EXTRA_PROTOCOL, vpnProto)
            }.also {
                startActivity(it)
            }
            false
        } else {
            true
        }

    companion object {
        // AVPN: имена процессов в VpnProto захардкожены под апстрим-пакет ("org.amnezia.vpn:…"),
        // а реальный процесс = "<applicationId>:суффикс" (manifest android:process=":amneziaAwgService").
        // После ребренда пакета (org.antivpn.client) хардкод НИКОГДА не совпадал → isRunning()==false →
        // activity/tile не ре-байндились к живому сервису при возврате → REQUEST_STATUS не уходил →
        // рассинхрон «UI выключен, туннель жив» (stop при этом ноль-оп). Строим ожидаемое имя из
        // фактического пакета + суффикса хардкода — переживает смену applicationId и апстрим-мержи.
        fun isRunning(context: Context, processName: String): Boolean {
            val expected = "${context.packageName}:${processName.substringAfter(':')}"
            return context.getSystemService<ActivityManager>()!!.runningAppProcesses.any {
                it.processName == expected && it.importance <= IMPORTANCE_FOREGROUND_SERVICE
            }
        }
    }
}

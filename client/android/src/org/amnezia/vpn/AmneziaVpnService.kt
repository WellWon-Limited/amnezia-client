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
import android.os.Build
import android.os.Handler
import android.os.IBinder
import android.os.Looper
import android.os.Message
import android.os.Messenger
import android.os.ParcelFileDescriptor
import android.os.PowerManager
import androidx.annotation.MainThread
import androidx.core.app.ServiceCompat
import androidx.core.content.ContextCompat
import androidx.core.content.getSystemService
import java.net.UnknownHostException
import java.util.ArrayDeque
import java.util.concurrent.ConcurrentHashMap
import java.util.UUID
import kotlin.LazyThreadSafetyMode.NONE
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.TimeoutCancellationException
import kotlinx.coroutines.cancel
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.collect
import kotlinx.coroutines.flow.drop
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.channels.Channel
import org.amnezia.vpn.protocol.BadConfigException
import org.amnezia.vpn.protocol.ProtocolState.CONNECTED
import org.amnezia.vpn.protocol.ProtocolState.CONNECTING
import org.amnezia.vpn.protocol.ProtocolState.DISCONNECTED
import org.amnezia.vpn.protocol.ProtocolState.DISCONNECTING
import org.amnezia.vpn.protocol.ProtocolState.RECONNECTING
import org.amnezia.vpn.protocol.ProtocolState.UNKNOWN
import org.amnezia.vpn.protocol.Protocol
import org.amnezia.vpn.protocol.VpnException
import org.amnezia.vpn.protocol.VpnStartException
import org.amnezia.vpn.protocol.Statistics
import org.amnezia.vpn.protocol.TunnelRuntimeStatus
import org.amnezia.vpn.protocol.putStatistics
import org.amnezia.vpn.protocol.putStatus
import org.amnezia.vpn.protocol.putEngineManifest
import org.amnezia.vpn.protocol.putTunnelRuntimeStatus
import org.amnezia.vpn.util.LoadLibraryException
import org.amnezia.vpn.util.Log
import org.amnezia.vpn.util.Prefs
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
const val MSG_CLIENT_PROCESS_EPOCH = "CLIENT_PROCESS_EPOCH_V1"

const val AFTER_PERMISSION_CHECK = "AFTER_PERMISSION_CHECK"
private const val PREFS_SERVER_NAME = "LAST_SERVER_NAME"
private const val PREFS_SERVER_INDEX = "LAST_SERVER_INDEX"
private const val STATISTICS_SENDING_TIMEOUT = 1000L
private const val TRAFFIC_STATS_UPDATE_TIMEOUT = 1000L
private const val DISCONNECT_TIMEOUT = 5000L
private const val MAX_PENDING_GUARD_EVENTS = 16

@SuppressLint("Registered")
open class AmneziaVpnService : VpnService() {

    private sealed interface NativeGuardCommand {
        data class Prepare(
            val rawConfig: String?, val operation: String?, val session: String?,
            val policySha256: String?, val expectedRuntimeSessionId: String?,
            val requestedOuterSessionId: String?,
        ) : NativeGuardCommand
        data class Activate(
            val rawConfig: String?, val operation: String?, val session: String?,
            val outerSessionId: String?, val expectedRuntimeSessionId: String?,
        ) : NativeGuardCommand
        data class Stop(
            val outerSessionId: String?, val expectedRuntimeSessionId: String?,
        ) : NativeGuardCommand
        data class Release(
            val operation: String?, val session: String?, val outerSessionId: String?,
        ) : NativeGuardCommand
        data class ReconcileArm(
            val operation: String?, val session: String?, val policySha256: String?,
            val outerSessionId: String?, val expectedRuntimeSessionId: String?,
        ) : NativeGuardCommand
        data class ReconcileRelease(
            val operation: String?, val session: String?, val policySha256: String?,
            val outerSessionId: String?, val expectedRuntimeSessionId: String?,
        ) : NativeGuardCommand
        data class Recover(
            val eventJson: String?, val action: String?, val rawConfig: String?,
        ) : NativeGuardCommand
        data class Renew(
            val rawConfig: String,
            val request: RuntimeAuthorityRenewalContract.Request,
        ) : NativeGuardCommand
        data class Restore(
            val record: AndroidVpnConfigVault.RecoveryRecord,
        ) : NativeGuardCommand
    }

    private data class CatalogGuardLease(
        val request: NativeSessionGuardContract.RequestIdentity,
        val outerSessionId: String,
        val dispatchPolicySha256: String,
        val tunnelPolicySha256: String,
        val configIdentitySha256: String,
        val rawConfig: String,
        val protocolKind: VpnProto,
        val protocol: Protocol,
        val prepared: Protocol.PreparedVpnSession,
        val runtimeAuthority: RuntimeAuthority,
        val authorityAnchor: RuntimeAuthorityAnchor,
        val serviceSessionId: Long,
        val serviceOperationToken: Long,
        val state: MutableStateFlow<org.amnezia.vpn.protocol.ProtocolState>,
    )

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
    private var statisticsSendingJob: Job? = null
    private var protocolStateForwardJob: Job? = null
    private var authorityWatchdogJob: Job? = null
    private val authorityWatchdogFence = RuntimeAuthorityWatchdogFence()
    private val protocolOperationMutex = Mutex()
    private val nativeGuardCommands = Channel<NativeGuardCommand>(Channel.UNLIMITED)
    private var nativeGuardCommandJob: Job? = null
    private val durableGuardBootstrap = CompletableDeferred<Unit>()
    private val nativeGuardStopTombstones = NativeGuardCommandTombstones()
    private var guardReconciliationJournal = NativeGuardReconciliationJournal()
    @Volatile private var guardReconciliationJournalTrusted = false
    @Volatile private var operationGeneration = 0L
    @Volatile private var sessionId = 0L
    private val serviceEpoch = UUID.randomUUID().toString().lowercase()
    private var activeProtocolState: MutableStateFlow<org.amnezia.vpn.protocol.ProtocolState>? = null
    private var runtimeFailureReason: String? = null
    private var runtimeFailureSessionId = 0L
    private var masterTun: ParcelFileDescriptor? = null
    private var preparedSession: Protocol.PreparedVpnSession? = null
    private var activeInnerToken: String? = null
    private var activePolicyHash: String? = null
    private var activeConfig: String? = null
    private var activeRuntimeAuthority: RuntimeAuthority? = null
    private var activeAuthorityAnchor: RuntimeAuthorityAnchor? = null
    private var pendingRecoveryRecord: AndroidVpnConfigVault.RecoveryRecord? = null
    private var pendingPermissionConfig: String? = null
    @Volatile private var catalogGuardLease: CatalogGuardLease? = null
    private val sessionGuard = AndroidSessionGuard()
    private lateinit var networkState: NetworkState
    private lateinit var trafficStats: TrafficStats
    private var controlReceiver: BroadcastReceiver? = null
    private var notificationStateReceiver: BroadcastReceiver? = null
    private var screenOnReceiver: BroadcastReceiver? = null
    private var screenOffReceiver: BroadcastReceiver? = null
    private val clientMessengers = ConcurrentHashMap<Messenger, IpcMessenger>()
    private val pendingGuardEvents = ArrayDeque<String>()
    private val pendingGuardRecoveryReceipts = ArrayDeque<String>()
    private val pendingAuthorityRenewalReceipts = ArrayDeque<String>()
    @Volatile private var nativeGuardRecoveryPending = false
    @Volatile private var durableGuardRecoveryLoaded = false
    @Volatile private var registeredCatalogClientEpoch: String? = null

    private val actionMessageHandler: Handler by lazy(NONE) {
        object : Handler(Looper.getMainLooper()) {
            override fun handleMessage(msg: Message) {
                val action = msg.extractIpcMessage<Action>()
                Log.d(TAG, "Handle action: $action")
                when (action) {
                    Action.REGISTER_CLIENT -> {
                        val clientName = msg.data.getString(MSG_CLIENT_NAME)
                        val clientEpoch = msg.data.getString(MSG_CLIENT_PROCESS_EPOCH)
                            ?.takeIf(NativeSessionGuardContract::isCanonicalUuid)
                        val messenger = IpcMessenger(msg.replyTo, clientName)
                        clientMessengers[msg.replyTo] = messenger
                        Log.d(TAG, "Messenger client '$clientName' was registered")
                        if (catalogGuardLease != null && registeredCatalogClientEpoch != null
                            && clientEpoch != registeredCatalogClientEpoch) {
                            nativeGuardRecoveryPending = true
                        }
                        if (clientEpoch != null) registeredCatalogClientEpoch = clientEpoch
                        flushPendingGuardEvents(messenger)
                        flushPendingGuardRecoveryReceipts(messenger)
                        flushPendingAuthorityRenewalReceipts(messenger)
                        sendCurrentGuardRecoverySnapshot(messenger)
                        if (isConnected) launchSendingStatistics()
                    }

                    Action.UNREGISTER_CLIENT -> {
                        clientMessengers.remove(msg.replyTo)?.let {
                            Log.d(TAG, "Messenger client '${it.name}' was unregistered")
                            if (clientMessengers.isEmpty()) stopSendingStatistics()
                        }
                    }

                    Action.CONNECT -> {
                        connect(consumeConfigReference(
                            msg.data.getString(TribeConfigFile.MSG_VPN_CONFIG_REF),
                        ))
                    }

                    Action.DISCONNECT -> {
                        disconnect()
                    }

                    Action.REQUEST_STATUS -> {
                        clientMessengers[msg.replyTo]?.let { clientMessenger ->
                            clientMessenger.send {
                                ServiceEvent.STATUS.packToMessage {
                                    putStatus(this@AmneziaVpnService.protocolState.value)
                                    // AVPN: additive Bundle fields; older activities ignore them.
                                    putEngineManifest(vpnProto?.protocol?.engineManifest)
                                    putTunnelRuntimeStatus(currentRuntimeStatus())
                                }
                            }
                        }
                    }

                    Action.NOTIFICATION_PERMISSION_GRANTED -> {
                        enableNotification()
                    }

                    Action.SET_SAVE_LOGS -> {
                        Log.saveLogs = msg.data.getBoolean(MSG_SAVE_LOGS)
                    }

                    Action.RENEW_RUNTIME_AUTHORITY -> {
                        val request = runCatching {
                            RuntimeAuthorityRenewalContract.parseRequest(
                                msg.data.getString(
                                    RuntimeAuthorityRenewalContract.MSG_REQUEST_JSON,
                                ).orEmpty(),
                            )
                        }.getOrNull() ?: return
                        val refreshed = runCatching {
                            TribeConfigFile.read(
                                applicationContext,
                                msg.data.getString(TribeConfigFile.MSG_VPN_CONFIG_REF),
                            )
                        }.getOrElse {
                            publishAuthorityRenewalReceipt(
                                RuntimeAuthorityRenewalContract.rejected(
                                    request, "config_handoff_rejected",
                                ).json(),
                            )
                            return
                        } ?: run {
                            publishAuthorityRenewalReceipt(
                                RuntimeAuthorityRenewalContract.rejected(
                                    request, "config_handoff_rejected",
                                ).json(),
                            )
                            return
                        }
                        if (nativeGuardCommands.trySend(
                                NativeGuardCommand.Renew(refreshed, request),
                            ).isFailure) {
                            publishAuthorityRenewalReceipt(
                                RuntimeAuthorityRenewalContract.rejected(
                                    request, "renewal_channel_unavailable",
                                ).json(),
                            )
                        }
                    }

                    Action.PREPARE_NATIVE_SESSION_GUARD -> {
                        prepareNativeSessionGuard(
                            consumeConfigReference(msg.data.getString(TribeConfigFile.MSG_VPN_CONFIG_REF)),
                            msg.data.getString(NativeSessionGuardContract.MSG_OPERATION),
                            msg.data.getString(NativeSessionGuardContract.MSG_SESSION),
                            msg.data.getString(NativeSessionGuardContract.MSG_POLICY_SHA256),
                            msg.data.getString(
                                NativeSessionGuardContract.MSG_EXPECTED_RUNTIME_SESSION_ID,
                            ),
                            msg.data.getString(NativeSessionGuardContract.MSG_OUTER_SESSION_ID),
                        )
                    }

                    Action.ACTIVATE_NATIVE_SESSION -> {
                        activateNativeSession(
                            consumeConfigReference(msg.data.getString(TribeConfigFile.MSG_VPN_CONFIG_REF)),
                            msg.data.getString(NativeSessionGuardContract.MSG_OPERATION),
                            msg.data.getString(NativeSessionGuardContract.MSG_SESSION),
                            msg.data.getString(NativeSessionGuardContract.MSG_OUTER_SESSION_ID),
                            msg.data.getString(
                                NativeSessionGuardContract.MSG_EXPECTED_RUNTIME_SESSION_ID,
                            ),
                        )
                    }

                    Action.STOP_NATIVE_SESSION -> {
                        stopNativeSession(
                            msg.data.getString(NativeSessionGuardContract.MSG_OUTER_SESSION_ID),
                            msg.data.getString(
                                NativeSessionGuardContract.MSG_EXPECTED_RUNTIME_SESSION_ID,
                            ),
                        )
                    }

                    Action.RELEASE_NATIVE_SESSION_GUARD -> {
                        releaseNativeSessionGuard(
                            msg.data.getString(NativeSessionGuardContract.MSG_OPERATION),
                            msg.data.getString(NativeSessionGuardContract.MSG_SESSION),
                            msg.data.getString(NativeSessionGuardContract.MSG_OUTER_SESSION_ID),
                        )
                    }

                    Action.RECONCILE_NATIVE_SESSION_GUARD_ARM -> {
                        reconcileNativeSessionGuardArm(
                            msg.data.getString(NativeSessionGuardContract.MSG_OPERATION),
                            msg.data.getString(NativeSessionGuardContract.MSG_SESSION),
                            msg.data.getString(NativeSessionGuardContract.MSG_POLICY_SHA256),
                            msg.data.getString(NativeSessionGuardContract.MSG_OUTER_SESSION_ID),
                            msg.data.getString(
                                NativeSessionGuardContract.MSG_EXPECTED_RUNTIME_SESSION_ID,
                            ),
                        )
                    }

                    Action.RECONCILE_NATIVE_SESSION_GUARD_RELEASE -> {
                        reconcileNativeSessionGuardRelease(
                            msg.data.getString(NativeSessionGuardContract.MSG_OPERATION),
                            msg.data.getString(NativeSessionGuardContract.MSG_SESSION),
                            msg.data.getString(NativeSessionGuardContract.MSG_POLICY_SHA256),
                            msg.data.getString(NativeSessionGuardContract.MSG_OUTER_SESSION_ID),
                            msg.data.getString(
                                NativeSessionGuardContract.MSG_EXPECTED_RUNTIME_SESSION_ID,
                            ),
                        )
                    }

                    Action.REQUEST_NATIVE_SESSION_GUARD_RECOVERY -> {
                        sendCurrentGuardRecoverySnapshot(
                            clientMessengers[msg.replyTo] ?: return,
                        )
                    }

                    Action.RESOLVE_NATIVE_SESSION_GUARD_RECOVERY -> {
                        resolveNativeSessionGuardRecovery(
                            msg.data.getString(NativeSessionGuardContract.MSG_EVENT_JSON),
                            msg.data.getString(NativeSessionGuardContract.MSG_RECOVERY_ACTION),
                            consumeConfigReference(
                                msg.data.getString(TribeConfigFile.MSG_VPN_CONFIG_REF),
                            ),
                        )
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
        connectionScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
        nativeGuardCommandJob = connectionScope.launch {
            // No guard command may overtake restoration of the encrypted exact owner/journal.
            // This is a one-shot completion barrier, not polling.
            durableGuardBootstrap.await()
            for (command in nativeGuardCommands) {
                try {
                    when (command) {
                        is NativeGuardCommand.Prepare -> executePrepareNativeSessionGuard(command)
                        is NativeGuardCommand.Activate -> executeActivateNativeSession(command)
                        is NativeGuardCommand.Stop -> executeStopNativeSession(command)
                        is NativeGuardCommand.Release -> executeReleaseNativeSessionGuard(command)
                        is NativeGuardCommand.ReconcileArm ->
                            executeReconcileNativeSessionGuardArm(command)
                        is NativeGuardCommand.ReconcileRelease ->
                            executeReconcileNativeSessionGuardRelease(command)
                        is NativeGuardCommand.Recover -> executeNativeSessionGuardRecovery(command)
                        is NativeGuardCommand.Renew -> executeRuntimeAuthorityRenewal(command)
                        is NativeGuardCommand.Restore -> executeRestoreNativeSessionGuard(command.record)
                    }
                } catch (cancelled: CancellationException) {
                    throw cancelled
                } catch (_: Throwable) {
                    runtimeFailureReason = "native_guard_command_failed"
                    nativeGuardRecoveryPending = catalogGuardLease != null
                    mainScope.launch {
                        protocolState.value = UNKNOWN
                        onError("Native session guard command failed closed")
                    }
                }
            }
        }
        connectionScope.launch {
            runCatching { AndroidVpnConfigVault.loadGuardReconciliationJournal(applicationContext) }
                .onSuccess { records ->
                    guardReconciliationJournal = NativeGuardReconciliationJournal(records)
                    guardReconciliationJournalTrusted = true
                }
                .onFailure {
                    guardReconciliationJournalTrusted = false
                    onError("Encrypted native guard reconciliation journal is unavailable")
                }
            val recovery = runCatching { AndroidVpnConfigVault.loadRecovery(applicationContext) }
                .onFailure {
                    AndroidVpnConfigVault.wipe(applicationContext)
                    onError("Encrypted VPN guard recovery record is unavailable")
                }.getOrNull()
            val releaseAlreadyCommitted = recovery?.nativeGuardLease?.let { persisted ->
                if (!guardReconciliationJournalTrusted) return@let false
                val identity = NativeSessionGuardContract.RequestIdentity(
                    persisted.operation, persisted.session, persisted.expectedRuntimeSessionId,
                )
                guardReconciliationJournal.outcome(
                    identity, recovery.dispatchPolicySha256, persisted.outerSessionId,
                ) == NativeGuardReconciliationJournal.Outcome.RELEASED
            } == true
            if (releaseAlreadyCommitted) {
                // RELEASE commits its exact tombstone before deleting the encrypted active lease.
                // A crash in that narrow window must not resurrect a blackhole and turn an exact
                // Released proof into ReleaseRejected after process restart.
                AndroidVpnConfigVault.wipe(applicationContext)
                durableGuardRecoveryLoaded = true
            } else if (recovery?.nativeGuardLease != null) {
                // Restore directly before opening the consumer barrier. Enqueuing Restore would
                // allow an already queued PREPARE/query to overtake it or deadlock the barrier.
                executeRestoreNativeSessionGuard(recovery)
            } else {
                durableGuardRecoveryLoaded = true
            }
            durableGuardBootstrap.complete(Unit)
        }
        loadServerData()
        removeLegacyPlaintextVpnConfig()
        launchProtocolStateHandler()
        networkState = NetworkState(this, ::reconnect)
        trafficStats = TrafficStats()
        registerBroadcastReceivers()
    }

    @SuppressLint("ApplySharedPref", "UseKtx")
    private fun removeLegacyPlaintextVpnConfig() {
        // Intentional synchronous durability boundary: startup must not proceed while a legacy
        // bearer profile can still be pending in SharedPreferences. Do not replace with apply().
        Prefs.prefs.edit().remove("LAST_CONF").commit()
        java.io.File(filesDir, "tribe/vpn_config.json").delete()
        java.io.File(filesDir, "tribe/vpn_config.json.tmp").delete()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val isAlwaysOn = intent != null && intent.action == SERVICE_INTERFACE

        if (intent?.action == NativeSessionGuardContract.ACTION_PREPARE) {
            prepareNativeSessionGuard(
                consumeConfigReference(intent.getStringExtra(TribeConfigFile.MSG_VPN_CONFIG_REF)),
                intent.getStringExtra(NativeSessionGuardContract.MSG_OPERATION),
                intent.getStringExtra(NativeSessionGuardContract.MSG_SESSION),
                intent.getStringExtra(NativeSessionGuardContract.MSG_POLICY_SHA256),
                intent.getStringExtra(
                    NativeSessionGuardContract.MSG_EXPECTED_RUNTIME_SESSION_ID,
                ),
                intent.getStringExtra(NativeSessionGuardContract.MSG_OUTER_SESSION_ID),
            )
        } else if (intent?.action == NativeSessionGuardContract.ACTION_ACTIVATE) {
            activateNativeSession(
                consumeConfigReference(intent.getStringExtra(TribeConfigFile.MSG_VPN_CONFIG_REF)),
                intent.getStringExtra(NativeSessionGuardContract.MSG_OPERATION),
                intent.getStringExtra(NativeSessionGuardContract.MSG_SESSION),
                intent.getStringExtra(NativeSessionGuardContract.MSG_OUTER_SESSION_ID),
                intent.getStringExtra(
                    NativeSessionGuardContract.MSG_EXPECTED_RUNTIME_SESSION_ID,
                ),
            )
        } else if (intent?.action == NativeSessionGuardContract.ACTION_STOP_INNER) {
            stopNativeSession(
                intent.getStringExtra(NativeSessionGuardContract.MSG_OUTER_SESSION_ID),
                intent.getStringExtra(
                    NativeSessionGuardContract.MSG_EXPECTED_RUNTIME_SESSION_ID,
                ),
            )
        } else if (intent?.action == NativeSessionGuardContract.ACTION_RELEASE) {
            releaseNativeSessionGuard(
                intent.getStringExtra(NativeSessionGuardContract.MSG_OPERATION),
                intent.getStringExtra(NativeSessionGuardContract.MSG_SESSION),
                intent.getStringExtra(NativeSessionGuardContract.MSG_OUTER_SESSION_ID),
            )
        } else if (intent?.action == NativeSessionGuardContract.ACTION_RECONCILE_ARM) {
            reconcileNativeSessionGuardArm(
                intent.getStringExtra(NativeSessionGuardContract.MSG_OPERATION),
                intent.getStringExtra(NativeSessionGuardContract.MSG_SESSION),
                intent.getStringExtra(NativeSessionGuardContract.MSG_POLICY_SHA256),
                intent.getStringExtra(NativeSessionGuardContract.MSG_OUTER_SESSION_ID),
                intent.getStringExtra(
                    NativeSessionGuardContract.MSG_EXPECTED_RUNTIME_SESSION_ID,
                ),
            )
        } else if (intent?.action == NativeSessionGuardContract.ACTION_RECONCILE_RELEASE) {
            reconcileNativeSessionGuardRelease(
                intent.getStringExtra(NativeSessionGuardContract.MSG_OPERATION),
                intent.getStringExtra(NativeSessionGuardContract.MSG_SESSION),
                intent.getStringExtra(NativeSessionGuardContract.MSG_POLICY_SHA256),
                intent.getStringExtra(NativeSessionGuardContract.MSG_OUTER_SESSION_ID),
                intent.getStringExtra(
                    NativeSessionGuardContract.MSG_EXPECTED_RUNTIME_SESSION_ID,
                ),
            )
        } else if (intent?.action == NativeSessionGuardContract.ACTION_RECOVERY_STATUS) {
            // A bound Messenger client receives the level-triggered snapshot on REGISTER.
        } else if (intent?.action == NativeSessionGuardContract.ACTION_RECOVERY_RESOLVE) {
            resolveNativeSessionGuardRecovery(
                intent.getStringExtra(NativeSessionGuardContract.MSG_EVENT_JSON),
                intent.getStringExtra(NativeSessionGuardContract.MSG_RECOVERY_ACTION),
                consumeConfigReference(intent.getStringExtra(TribeConfigFile.MSG_VPN_CONFIG_REF)),
            )
        } else if (isAlwaysOn) {
            Log.d(TAG, "Start service via Always-on")
            connect()
        } else if (intent?.getBooleanExtra(AFTER_PERMISSION_CHECK, false) == true) {
            Log.d(TAG, "Start service after permission check")
            // The permission round-trip is process-local. Never turn a missing pending value into
            // an implicit recovery/downgrade path.
            val pending = pendingPermissionConfig
            pendingPermissionConfig = null
            connect(pending, allowRecovery = false)
        } else {
            Log.d(TAG, "Start service")
            connect(consumeConfigReference(
                intent?.getStringExtra(TribeConfigFile.MSG_VPN_CONFIG_REF),
            ))
        }
        ServiceCompat.startForeground(
            this, NOTIFICATION_ID,
            serviceNotification.buildNotification(serverName, vpnProto?.label, protocolState.value),
            foregroundServiceTypeCompat
        )
        val transactionalNativeCommand = intent?.action in setOf(
            NativeSessionGuardContract.ACTION_PREPARE,
            NativeSessionGuardContract.ACTION_ACTIVATE,
            NativeSessionGuardContract.ACTION_STOP_INNER,
            NativeSessionGuardContract.ACTION_RELEASE,
            NativeSessionGuardContract.ACTION_RECONCILE_ARM,
            NativeSessionGuardContract.ACTION_RECONCILE_RELEASE,
            NativeSessionGuardContract.ACTION_RECOVERY_STATUS,
            NativeSessionGuardContract.ACTION_RECOVERY_RESOLVE,
        )
        // Re-delivering a half-completed PREPARE/ACTIVATE/STOP/RELEASE is unsafe. The encrypted
        // exact lease and level-triggered recovery protocol resolve ambiguity instead.
        return if (transactionalNativeCommand) START_NOT_STICKY else START_REDELIVER_INTENT
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
        val lease = catalogGuardLease
        if (lease == null) {
            if (masterTun != null || activeInnerToken != null || sessionGuard.snapshot().armed) {
                // Legacy/manual AWG and Xray have no catalog identity for an exact terminal
                // transaction. Revocation already removed the outer route guard; killing the
                // dedicated VPN process is the only synchronous proof that native sockets die.
                terminateVpnProcessFailClosed("vpn_permission_revoked_legacy_guard")
            }
            mainScope.launch {
                AndroidVpnConfigVault.wipe(applicationContext)
                disconnect()
            }
            return
        }

        nativeGuardCommands.close()
        if (!boundedCatalogGuardTeardownForProcessLoss(lease, "vpn_permission_revoked")) {
            terminateVpnProcessFailClosed("vpn_permission_revoked")
        }
        mainScope.launch {
            publishNativeGuardEvent(
                lease.request,
                "lost",
                lease.dispatchPolicySha256,
                lease.outerSessionId,
                "vpn_permission_revoked",
            )
        }
        // Closing the native command channel makes this Service instance terminal. Do not leave
        // it alive for a later permission grant/bind with an unusable command queue.
        stopSelf()
    }

    override fun onDestroy() {
        Log.d(TAG, "Destroy service")
        unregisterBroadcastReceivers()
        nativeGuardCommands.close()
        val lease = catalogGuardLease
        if (lease != null) {
            if (!boundedCatalogGuardTeardownForProcessLoss(lease, "service_destroyed")) {
                terminateVpnProcessFailClosed("service_destroyed")
            }
        } else if (masterTun != null || activeInnerToken != null || sessionGuard.snapshot().armed) {
            // The ordinary disconnect path returns early for UNKNOWN and therefore cannot prove
            // a legacy/manual native reader dead. The service runs in its own process; terminate
            // it instead of releasing the outer TUN after an ambiguous AWG/Xray stop.
            terminateVpnProcessFailClosed("service_destroyed_legacy_guard")
        } else {
            runBlocking {
                disconnect()
                disconnectionJob?.join()
            }
        }
        connectionScope.cancel()
        cancelAuthorityWatchdog()
        mainScope.cancel()
        super.onDestroy()
    }

    /**
     * Service/process loss is not the reducer's ordinary queued STOP path. Freeze that queue,
     * cancel and join its consumer, then prove the exact inner reader dead under the same mutex.
     * A blocked JNI call is bounded externally; its only safe timeout outcome is process death.
     */
    private fun boundedCatalogGuardTeardownForProcessLoss(
        exactLease: CatalogGuardLease,
        reason: String,
    ): Boolean = GuardedServiceTermination.proveWithin(DISCONNECT_TIMEOUT) {
        runBlocking {
            nativeGuardCommandJob?.cancelAndJoin()
            protocolOperationMutex.withLock {
                if (catalogGuardLease !== exactLease) {
                    return@withLock catalogGuardLease == null
                        && activeInnerToken == null && masterTun == null
                }
                cancelAuthorityWatchdog()
                try {
                    if (!proveCatalogInnerStoppedForProcessLoss(exactLease, reason)) {
                        return@withLock false
                    }
                    // Durable blackhole precedes releasing the outer OS route owner. If the process
                    // dies between these writes, recovery still never claims that an inner is live.
                    persistCatalogGuardLease(exactLease, "blackhole")
                    masterTun?.close()
                    masterTun = null
                    sessionGuard.markOuterLost(exactLease.outerSessionId)
                    exactLease.state.value = DISCONNECTED
                    protocolState.value = DISCONNECTED
                    clearCatalogGuardLease(exactLease)
                    true
                } catch (_: Throwable) {
                    retainCatalogGuardAmbiguity(exactLease, reason)
                }
            }
        }
    }

    private fun proveCatalogInnerStoppedForProcessLoss(
        exactLease: CatalogGuardLease,
        reason: String,
    ): Boolean {
        val outer = exactLease.outerSessionId
        val token = activeInnerToken
        val initialState = sessionGuard.snapshot().state
        if (token == null) {
            return when (initialState) {
                "blackhole" -> true
                "quarantined" -> runCatching {
                    sessionGuard.proveQuarantinedInnerStopped(outer)
                    true
                }.getOrDefault(false)
                else -> retainCatalogGuardAmbiguity(exactLease, reason)
            }
        }
        if (token != exactLease.request.expectedRuntimeSessionId) {
            return retainCatalogGuardAmbiguity(exactLease, reason)
        }

        val proven = runCatching {
            when (initialState) {
                "starting" -> {
                    if (exactLease.protocol.abortInnerStart(token)) {
                        sessionGuard.confirmInnerStartAborted(outer, token)
                    } else {
                        sessionGuard.quarantineInnerStart(outer, token)
                        exactLease.protocol.stopInner(token)
                        sessionGuard.confirmQuarantinedInnerStopped(outer, token)
                        sessionGuard.proveQuarantinedInnerStopped(outer)
                    }
                }
                "running" -> {
                    sessionGuard.beginInnerStop(outer, token)
                    exactLease.protocol.stopInner(token)
                    sessionGuard.confirmInnerStopped(outer, token)
                }
                "stopping" -> {
                    exactLease.protocol.stopInner(token)
                    sessionGuard.confirmInnerStopped(outer, token)
                }
                "quarantined" -> {
                    exactLease.protocol.stopInner(token)
                    sessionGuard.confirmQuarantinedInnerStopped(outer, token)
                    sessionGuard.proveQuarantinedInnerStopped(outer)
                }
                else -> return@runCatching false
            }
            activeInnerToken = null
            true
        }.getOrDefault(false)
        return proven || retainCatalogGuardAmbiguity(exactLease, reason)
    }

    /** Always returns false; best-effort persistence must never become a clean teardown proof. */
    private fun retainCatalogGuardAmbiguity(
        exactLease: CatalogGuardLease,
        reason: String,
    ): Boolean {
        val token = activeInnerToken
        val snapshot = sessionGuard.snapshot()
        if (token != null) {
            runCatching {
                when (snapshot.state) {
                    "starting" -> sessionGuard.quarantineInnerStart(
                        exactLease.outerSessionId, token,
                    )
                    "running" -> sessionGuard.quarantineActiveInner(
                        exactLease.outerSessionId, token,
                    )
                    "stopping" -> sessionGuard.quarantineStoppingInner(
                        exactLease.outerSessionId, token,
                    )
                }
            }
        }
        nativeGuardRecoveryPending = true
        runtimeFailureReason = "${reason}_native_stop_ambiguous"
        runtimeFailureSessionId = exactLease.serviceSessionId
        // Persist the conservative recovery state even if an in-memory transition itself failed.
        // The dedicated process is terminated immediately after this function returns false.
        runCatching { persistCatalogGuardLease(exactLease, "quarantined") }
        return false
    }

    private fun terminateVpnProcessFailClosed(reason: String): Nothing {
        Log.e(TAG, "Fail-closed VPN process termination: $reason")
        android.os.Process.killProcess(android.os.Process.myPid())
        // killProcess normally never returns to app code. Throw as a second terminal mechanism
        // for instrumented/mocked runtimes so teardown can never continue as if it were clean.
        throw IllegalStateException("Fail-closed VPN process termination: $reason")
    }

    private fun stopService() {
        Log.d(TAG, "Stop service")
        if (masterTun != null || activeInnerToken != null || sessionGuard.snapshot().armed) {
            // A failed/ambiguous native teardown is quarantined behind the still-established outer
            // default-route TUN. stopSelf/process kill would remove that guard and create a WAN
            // route before exact inner death was proven.
            Log.w(TAG, "Refuse to stop service while guarded native session is quarantined")
            return
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
                        putTunnelRuntimeStatus(currentRuntimeStatus(protocolState))
                    }
                }

                VpnStateStore.store { VpnState(protocolState, serverName, serverIndex, vpnProto) }

                when (protocolState) {
                    CONNECTED -> {
                        networkState.bindNetworkListener()
                        launchSendingStatistics()
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
                        // Keep runtime IPC alive while native sockets switch;
                        // notification visibility is unrelated to liveness.
                        launchSendingStatistics()
                    }

                    CONNECTING, UNKNOWN -> {}
                }
            }
        }
    }

    @MainThread
    private fun launchSendingStatistics() {
        if (statisticsSendingJob == null && clientMessengers.isNotEmpty() &&
            (isConnected || protocolState.value == RECONNECTING)
        ) {
            statisticsSendingJob = mainScope.launch {
                while (true) {
                    val runtimeStatus = currentRuntimeStatus()
                    clientMessengers.send {
                        ServiceEvent.STATISTICS_UPDATE.packToMessage {
                            putStatistics(runtimeStatus?.statistics ?: Statistics.EMPTY_STATISTICS)
                            putTunnelRuntimeStatus(runtimeStatus)
                        }
                    }
                    delay(STATISTICS_SENDING_TIMEOUT)
                }
            }
        }
    }

    @MainThread
    private fun stopSendingStatistics() {
        statisticsSendingJob?.cancel()
        statisticsSendingJob = null
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

    @MainThread
    private fun connect(vpnConfig: String? = null, allowRecovery: Boolean = true) {
        pendingRecoveryRecord = null
        val recovery = if (vpnConfig == null && allowRecovery) runCatching {
            AndroidVpnConfigVault.loadRecovery(applicationContext)
        }.onFailure {
            AndroidVpnConfigVault.wipe(applicationContext)
            onError("Encrypted VPN recovery record is unavailable")
        }.getOrNull() else null
        val acceptedRecovery = recovery?.let { record ->
            val observation = AndroidAuthorityClock.observe()
            val verdict = AndroidAuthorityClock.evaluate(
                record.authority,
                record.clockAnchor,
                observation,
            )
            if (!verdict.accepted || verdict.effectiveNow == null) {
                AndroidVpnConfigVault.wipe(applicationContext)
                onError("VPN recovery authority was rejected")
                null
            } else {
                record.copy(clockAnchor = RuntimeAuthorityAnchor.reanchor(
                    record.authority,
                    verdict.effectiveNow,
                    observation,
                ))
            }
        }
        if (acceptedRecovery?.nativeGuardLease != null) {
            // Catalog-v2 recovery is resolved only through the exact durable guard lease. Never
            // downgrade it into the broad legacy CONNECT path or auto-start an inner core.
            pendingRecoveryRecord = null
            protocolState.value = UNKNOWN
            return
        }
        pendingRecoveryRecord = acceptedRecovery
        val resolved = vpnConfig ?: acceptedRecovery?.config
        if (resolved.isNullOrBlank()) {
            protocolState.value = DISCONNECTED
            return
        }
        connectToVpn(resolved)
    }

    @MainThread
    private fun connectToVpn(vpnConfig: String) {
        // Server switches are serialized by the caller as disconnect ->
        // connect.  Starting while the prior protocol is still disconnecting
        // would replace vpnProto before its native stop completes.
        if (runtimeFailureReason != null) {
            // Retry in the same bound service is allowed only after exact
            // teardown left neither an inner core token nor a master TUN.
            if (activeInnerToken != null || masterTun != null) return
            runtimeFailureReason = null
            runtimeFailureSessionId = 0L
            protocolState.value = DISCONNECTED
        }
        if (!isUnknown && !isDisconnected) return

        Log.d(TAG, "Start VPN connection")

        val config = parseConfigToJson(vpnConfig)
        saveServerData(config)
        if (config == null) {
            onError("Invalid VPN config")
            protocolState.value = DISCONNECTED
            return
        }

        val runtimeAuthority = try {
            RuntimeAuthority.fromConfig(config)
        } catch (_: Throwable) {
            AndroidVpnConfigVault.wipe(applicationContext)
            onError("Invalid VPN runtime authority")
            protocolState.value = DISCONNECTED
            return
        }
        if (runtimeAuthority != null && pendingRecoveryRecord == null) {
            // A live catalog-v2 dispatch is legal only through PREPARE/Armed/ACTIVATE.  CONNECT is
            // retained for positively-discriminated legacy profiles and encrypted Always-on
            // recovery; stripping the two-phase coordinator cannot downgrade into this path.
            AndroidVpnConfigVault.wipe(applicationContext)
            onError("Catalog-v2 profile requires the native session guard transaction")
            protocolState.value = DISCONNECTED
            return
        }

        val selectedProto = try {
            VpnProto.get(config.getString("protocol"))
        } catch (e: Exception) {
            onError("Invalid VPN config: ${e.message}")
            protocolState.value = DISCONNECTED
            return
        }
        vpnProto = selectedProto

        if (!checkPermission()) {
            // Keep bearer material only in this process while Android displays its VPN consent UI.
            // Process death deliberately requires the app to dispatch a fresh authorized profile.
            pendingPermissionConfig = vpnConfig
            protocolState.value = DISCONNECTED
            return
        }
        pendingPermissionConfig = null

        sessionId = nextToken(sessionId)
        val thisSessionId = sessionId
        operationGeneration = nextToken(operationGeneration)
        val operationToken = operationGeneration
        val sessionState = MutableStateFlow(CONNECTING)
        runtimeFailureReason = null
        runtimeFailureSessionId = 0L
        activeProtocolState = sessionState
        bindProtocolState(sessionState, thisSessionId)

        protocolState.value = CONNECTING

        connectionJob = connectionScope.launch {
            val protocol = selectedProto.protocol
            try {
                disconnectionJob?.join()
                disconnectionJob = null

                protocolOperationMutex.withLock {
                    if (!isCurrentOperation(operationToken, thisSessionId, protocol)) return@withLock
                    protocol.initialize(applicationContext, sessionState) { message ->
                        reportProtocolError(message, operationToken, thisSessionId, protocol)
                    }
                    if (protocol.supportsSessionOwnedTun) {
                        startSessionOwnedProtocol(
                            protocol,
                            config,
                            vpnConfig,
                            runtimeAuthority,
                            thisSessionId,
                            operationToken,
                        )
                    } else {
                        protocol.startVpn(config, Builder(), ::protect)
                    }
                }
            } catch (cancelled: CancellationException) {
                throw cancelled
            } catch (error: Throwable) {
                reportOperationFailure(
                    error, operationToken, thisSessionId, protocol,
                    "start_failed", forceProcessStop = true,
                )
            }
        }
    }

    @MainThread
    private fun disconnect() {
        catalogGuardLease?.let { lease ->
            // Broad legacy disconnect is never allowed to tear down a catalog-v2 outer guard.
            // The reducer must first obtain exact Stopped, then issue RELEASE for this owner.
            stopNativeSession(
                lease.outerSessionId,
                lease.request.expectedRuntimeSessionId,
            )
            return
        }
        if (isUnknown || isDisconnected || protocolState.value == DISCONNECTING) return

        Log.d(TAG, "Stop VPN connection")

        operationGeneration = nextToken(operationGeneration)
        val operationToken = operationGeneration
        val thisSessionId = sessionId
        val protocolToStop = vpnProto?.protocol
        val stateToObserve = activeProtocolState
        protocolStateForwardJob?.cancel()
        protocolStateForwardJob = null
        protocolState.value = DISCONNECTING

        disconnectionJob = connectionScope.launch {
            try {
                connectionJob?.cancelAndJoin()
                connectionJob = null

                protocolOperationMutex.withLock {
                    if (protocolToStop != null &&
                        isCurrentOperation(operationToken, thisSessionId, protocolToStop)
                    ) {
                        if (protocolToStop.supportsSessionOwnedTun) {
                            stopSessionOwnedProtocol(protocolToStop, thisSessionId, explicit = true)
                            stateToObserve?.value = DISCONNECTED
                        } else {
                            protocolToStop.stopVpn()
                        }
                    }
                }

                withTimeout(DISCONNECT_TIMEOUT) {
                    // waiting for disconnect state
                    (stateToObserve ?: protocolState).first { it == DISCONNECTED }
                }
                mainScope.launch {
                    if (sessionId == thisSessionId && operationGeneration == operationToken) {
                        protocolState.value = DISCONNECTED
                    }
                }
            } catch (e: TimeoutCancellationException) {
                Log.w(TAG, "Disconnect timeout")
                reportOperationFailure(
                    VpnException("Disconnect timeout"), operationToken, thisSessionId,
                    protocolToStop, "disconnect_timeout", forceProcessStop = true,
                )
            } catch (cancelled: CancellationException) {
                throw cancelled
            } catch (error: Throwable) {
                reportOperationFailure(
                    error, operationToken, thisSessionId, protocolToStop,
                    "stop_failed", forceProcessStop = true,
                )
            }
        }
    }

    @MainThread
    private fun reconnect() {
        if (!isConnected) return

        Log.d(TAG, "Reconnect VPN")

        operationGeneration = nextToken(operationGeneration)
        val operationToken = operationGeneration
        val thisSessionId = sessionId
        val protocolToReconnect = vpnProto?.protocol ?: return
        protocolStateForwardJob?.cancel()
        protocolStateForwardJob = null
        protocolState.value = RECONNECTING

        connectionJob = connectionScope.launch {
            try {
                protocolOperationMutex.withLock {
                    if (!isCurrentOperation(operationToken, thisSessionId, protocolToReconnect)) return@withLock
                    if (protocolToReconnect.supportsSessionOwnedTun) {
                        reconnectSessionOwnedProtocol(
                            protocolToReconnect,
                            thisSessionId,
                            operationToken,
                        )
                    } else {
                        protocolToReconnect.reconnectVpn(Builder(), ::protect)
                    }
                }
                mainScope.launch {
                    if (isCurrentOperation(operationToken, thisSessionId, protocolToReconnect)) {
                        activeProtocolState?.let { stateFlow ->
                            bindProtocolState(stateFlow, thisSessionId)
                            protocolState.value = stateFlow.value
                        }
                    }
                }
            } catch (cancelled: CancellationException) {
                throw cancelled
            } catch (error: Throwable) {
                reportOperationFailure(
                    error, operationToken, thisSessionId, protocolToReconnect,
                    "reconnect_failed", forceProcessStop = true,
                )
            }
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

    private fun currentRuntimeStatus(
        state: org.amnezia.vpn.protocol.ProtocolState = protocolState.value,
    ): TunnelRuntimeStatus? = TunnelRuntimeStatus.from(
        catalogGuardLease?.request?.expectedRuntimeSessionId ?: "$serviceEpoch:$sessionId",
        state,
        vpnProto?.protocol,
        runtimeStateOverride = if (runtimeFailureSessionId == sessionId) "failed" else null,
        failureReason = runtimeFailureReason.takeIf { runtimeFailureSessionId == sessionId },
    )

    private fun isCurrentOperation(token: Long, expectedSessionId: Long, protocol: Any): Boolean =
        operationGeneration == token && sessionId == expectedSessionId && vpnProto?.protocol === protocol

    private fun reportProtocolError(
        message: String,
        token: Long,
        expectedSessionId: Long,
        protocol: Any,
    ) {
        mainScope.launch {
            if (isCurrentOperation(token, expectedSessionId, protocol)) onError(message)
        }
    }

    private fun reportOperationFailure(
        error: Throwable,
        token: Long,
        expectedSessionId: Long,
        protocol: Any?,
        reason: String,
        forceProcessStop: Boolean = false,
    ) {
        mainScope.launch {
            if (protocol == null || !isCurrentOperation(token, expectedSessionId, protocol)) return@launch
            runtimeFailureReason = reason
            runtimeFailureSessionId = expectedSessionId
            protocolState.value = UNKNOWN
            onError(formatOperationError(error))
            if (forceProcessStop && (activeInnerToken != null || masterTun != null)) {
                stopService()
            }
        }
    }

    private fun formatOperationError(error: Throwable): String = when (error) {
        is IllegalArgumentException,
        is VpnStartException,
        is VpnException -> error.message ?: error.toString()

        is JSONException,
        is BadConfigException -> "VPN config format error: ${error.message}"

        is LoadLibraryException -> "${error.message}. Caused: ${error.cause?.message}"
        is UnknownHostException -> "Unknown host"
        else -> "VPN runtime error: ${error.message ?: error::class.java.simpleName}"
    }

    private fun nextToken(value: Long): Long = if (value == Long.MAX_VALUE) 1L else value + 1L

    private fun bindProtocolState(
        sessionState: MutableStateFlow<org.amnezia.vpn.protocol.ProtocolState>,
        expectedSessionId: Long,
    ) {
        protocolStateForwardJob?.cancel()
        protocolStateForwardJob = mainScope.launch {
            sessionState.collect { forwardedState ->
                if (sessionId == expectedSessionId) protocolState.value = forwardedState
            }
        }
    }

    @MainThread
    private fun prepareNativeSessionGuard(
        rawConfig: String?,
        operationText: String?,
        sessionText: String?,
        requestedPolicySha256: String?,
        expectedRuntimeSessionId: String?,
        requestedOuterSessionId: String?,
    ) {
        if (nativeGuardCommands.trySend(NativeGuardCommand.Prepare(
                rawConfig, operationText, sessionText, requestedPolicySha256,
                expectedRuntimeSessionId, requestedOuterSessionId,
            )).isFailure) {
            onError("Native session guard command channel is unavailable")
        }
    }

    private suspend fun executePrepareNativeSessionGuard(command: NativeGuardCommand.Prepare) {
        val identity = parseNativeGuardIdentity(
            command.operation, command.session, command.expectedRuntimeSessionId,
        ) ?: return
        val policySha256 = runCatching {
            NativeSessionGuardContract.requirePolicySha256(command.policySha256.orEmpty())
        }.getOrElse {
            mainScope.launch {
                publishNativeGuardEvent(
                    identity, "arm_rejected", "0".repeat(64), reason = "policy_invalid",
                )
            }
            return
        }
        val requestedOuter = runCatching {
            NativeSessionGuardContract.requireOuterSessionId(
                command.requestedOuterSessionId.orEmpty(),
            )
        }.getOrElse {
            mainScope.launch {
                publishNativeGuardEvent(
                    identity, "arm_rejected", policySha256, reason = "outer_identity_invalid",
                )
            }
            return
        }
        if (!guardReconciliationJournalTrusted) {
            onError("Native guard reconciliation journal is unavailable")
            return
        }
        if (guardReconciliationJournal.blocksPrepare(identity, policySha256, requestedOuter)) {
            mainScope.launch {
                publishNativeGuardEvent(
                    identity, "arm_rejected", policySha256, requestedOuter,
                    "arm_timeout_fenced",
                )
            }
            return
        }
        if (command.rawConfig.isNullOrBlank() || prepare(applicationContext) != null) {
            mainScope.launch {
                publishNativeGuardEvent(
                    identity, "arm_rejected", policySha256,
                    reason = if (command.rawConfig.isNullOrBlank()) {
                        "config_unavailable"
                    } else {
                        "vpn_permission_missing"
                    },
                )
            }
            return
        }

        var newlyEstablishedTun: ParcelFileDescriptor? = null
        var eventOuter = ""
        var ownershipTransferred = false
        try {
                val config = JSONObject(command.rawConfig)
                val authority = RuntimeAuthority.fromConfig(config)
                    ?: throw SecurityException("catalog_authority_required")
                val recomputed = NativeDispatchPolicyDigest.sha256(config, authority)
                require(recomputed == policySha256 && recomputed == authority.dispatchPolicySha256) {
                    "dispatch_policy_mismatch"
                }
                val selected = VpnProto.get(config.getString("protocol"))
                require(selected == VpnProto.AWG || selected == VpnProto.XRAY) {
                    "catalog_transport_unsupported"
                }
                val protocol = selected.protocol
                require(protocol.supportsSessionOwnedTun) { "session_owned_tun_unsupported" }
                val localSessionId = nextToken(sessionId)
                val localOperation = nextToken(operationGeneration)
                val localState = MutableStateFlow(CONNECTING)
                protocol.initialize(applicationContext, localState) { message ->
                    reportProtocolError(message, localOperation, localSessionId, protocol)
                }
                val prepared = protocol.prepareVpn(config)
                val anchor = RuntimeAuthorityAnchor.capture(authority)
                val clockObservation = AndroidAuthorityClock.observe()
                val verdict = AndroidAuthorityClock.evaluate(authority, anchor, clockObservation)
                require(verdict.accepted && verdict.effectiveNow != null) {
                    "runtime_authority_rejected"
                }
                val exactAnchor = RuntimeAuthorityAnchor.reanchor(
                    authority, verdict.effectiveNow, clockObservation,
                )
                val configIdentity = RuntimeAuthority.configIdentitySha256(config)
                val outerSessionId = requestedOuter

                protocolOperationMutex.withLock {
                    require(activeInnerToken == null) { "native_inner_still_owned" }
                    val previous = catalogGuardLease
                    if (previous == null) {
                        require(masterTun == null && !sessionGuard.snapshot().armed) {
                            "foreign_outer_session_present"
                        }
                        val builder = Builder()
                        protocol.configureOuterTunnel(prepared.tunnelConfig, builder)
                        newlyEstablishedTun = builder.establish()
                            ?: throw VpnStartException("outer_tun_establish_failed")
                        sessionGuard.arm(outerSessionId, prepared.policyHash)
                        masterTun = newlyEstablishedTun
                        newlyEstablishedTun = null
                    } else {
                        val previousTun = masterTun
                            ?: throw VpnException("previous_outer_tun_missing")
                        require(sessionGuard.snapshot().state == "blackhole") {
                            "previous_guard_not_blackholed"
                        }
                        if (previous.tunnelPolicySha256 == prepared.policyHash) {
                            sessionGuard.replaceBlackhole(
                                previous.outerSessionId, outerSessionId, prepared.policyHash,
                            )
                        } else {
                            // Android's VpnService contract explicitly supports two interfaces
                            // for seamless handover: the old interface remains active if
                            // establish() fails and is deactivated only after the new interface is
                            // created successfully. Both inner engines are already stopped here,
                            // so either descriptor is a route-owning blackhole throughout.
                            sessionGuard.validateBlackholeTunHandover(
                                previous.outerSessionId, outerSessionId, prepared.policyHash,
                            )
                            val builder = Builder()
                            protocol.configureOuterTunnel(prepared.tunnelConfig, builder)
                            newlyEstablishedTun = builder.establish()
                                ?: throw VpnStartException("outer_tun_handover_establish_failed")
                            sessionGuard.commitBlackholeTunHandover(
                                previous.outerSessionId, outerSessionId, prepared.policyHash,
                            )
                            masterTun = newlyEstablishedTun
                            newlyEstablishedTun = null
                            // Android has already deactivated this descriptor. Failure to close
                            // it is a bounded fd-cleanup issue, not permission to tear down the
                            // newly active blackhole.
                            runCatching { previousTun.close() }
                                .onFailure { Log.w(TAG, "Retired outer TUN close failed") }
                        }
                    }

                    sessionId = localSessionId
                    operationGeneration = localOperation
                    vpnProto = selected
                    protocolStateForwardJob?.cancel()
                    protocolStateForwardJob = null
                    activeProtocolState = localState
                    preparedSession = prepared
                    activePolicyHash = prepared.policyHash
                    activeConfig = command.rawConfig
                    activeRuntimeAuthority = authority
                    activeAuthorityAnchor = exactAnchor
                    runtimeFailureReason = null
                    runtimeFailureSessionId = 0L
                    catalogGuardLease = CatalogGuardLease(
                        identity,
                        outerSessionId,
                        recomputed,
                        prepared.policyHash,
                        configIdentity,
                        command.rawConfig,
                        selected,
                        protocol,
                        prepared,
                        authority,
                        exactAnchor,
                        localSessionId,
                        localOperation,
                        localState,
                    )
                    ownershipTransferred = true
                    eventOuter = outerSessionId
                    persistCatalogGuardLease(catalogGuardLease!!, "blackhole")
                }
                mainScope.launch {
                    publishNativeGuardEvent(
                        identity, "armed", policySha256, eventOuter,
                    )
                }
        } catch (cancelled: CancellationException) {
                runCatching { newlyEstablishedTun?.close() }
                throw cancelled
        } catch (error: Throwable) {
                runCatching { newlyEstablishedTun?.close() }
                val rejection = guardReason(error, "arm_rejected")
                if (ownershipTransferred) {
                    // Outer TUN ownership changed before durable receipt persistence completed.
                    // This is ambiguous, never a clean arm rejection: retain the blackhole and
                    // force exact recovery/stop while the service process is still alive.
                    nativeGuardRecoveryPending = true
                    runtimeFailureReason = "guard_prepare_ambiguous"
                    runtimeFailureSessionId = sessionId
                }
                mainScope.launch {
                    publishNativeGuardEvent(
                        identity,
                        if (ownershipTransferred) "lost" else "arm_rejected",
                        policySha256,
                        if (ownershipTransferred) eventOuter else "",
                        rejection,
                    )
                }
        }
    }

    @MainThread
    private fun activateNativeSession(
        rawConfig: String?,
        operationText: String?,
        sessionText: String?,
        outerSessionId: String?,
        expectedRuntimeSessionId: String?,
    ) {
        if (nativeGuardCommands.trySend(NativeGuardCommand.Activate(
                rawConfig, operationText, sessionText, outerSessionId,
                expectedRuntimeSessionId,
            )).isFailure) {
            onError("Native session activation channel is unavailable")
        }
    }

    private suspend fun executeActivateNativeSession(command: NativeGuardCommand.Activate) {
        val identity = parseNativeGuardIdentity(
            command.operation, command.session, command.expectedRuntimeSessionId,
        ) ?: return
        val outer = runCatching {
            NativeSessionGuardContract.requireOuterSessionId(command.outerSessionId.orEmpty())
        }.getOrElse {
            onError("Native session activation identity was rejected")
            return
        }
        if (command.rawConfig.isNullOrBlank()) {
            onError("Native session activation profile was unavailable")
            return
        }
        if (!guardReconciliationJournalTrusted
            || guardReconciliationJournal.blocksActivation(identity, outer)) {
            onError("Native session activation was fenced after timeout")
            return
        }
            val lease = catalogGuardLease
            try {
                require(nativeGuardStopTombstones.activationAllowed(
                    outer, identity.expectedRuntimeSessionId,
                )) { "activation_stop_requested" }
                require(lease != null
                    && lease.request == identity
                    && lease.outerSessionId == outer
                    && lease.request.expectedRuntimeSessionId == command.expectedRuntimeSessionId) {
                    "stale_activation"
                }
                val config = JSONObject(command.rawConfig)
                val authority = RuntimeAuthority.fromConfig(config)
                    ?: throw SecurityException("catalog_authority_required")
                val recomputed = NativeDispatchPolicyDigest.sha256(config, authority)
                require(recomputed == lease.dispatchPolicySha256
                    && authority == lease.runtimeAuthority
                    && RuntimeAuthority.configIdentitySha256(config) == lease.configIdentitySha256) {
                    "activation_profile_mismatch"
                }
                protocolOperationMutex.withLock {
                    require(nativeGuardStopTombstones.activationAllowed(
                        outer, identity.expectedRuntimeSessionId,
                    )) { "activation_stop_requested" }
                    require(catalogGuardLease === lease && masterTun != null
                        && activeInnerToken == null
                        && sessionGuard.canAdopt(outer, lease.tunnelPolicySha256)
                        && sessionGuard.snapshot().state == "blackhole") {
                        "guard_not_armed_for_activation"
                    }
                    val currentVerdict = AndroidAuthorityClock.evaluate(
                        lease.runtimeAuthority,
                        lease.authorityAnchor,
                        AndroidAuthorityClock.observe(),
                    )
                    require(currentVerdict.accepted) { "runtime_authority_rejected" }
                    val protocol = lease.protocol
                    val innerToken = lease.request.expectedRuntimeSessionId
                    sessionGuard.beginInnerStart(outer, innerToken, lease.tunnelPolicySha256)
                    activeInnerToken = innerToken
                    bindProtocolState(lease.state, lease.serviceSessionId)
                    mainScope.launch { protocolState.value = CONNECTING }
                    var startBegan = false
                    try {
                        startBegan = true
                        val receipt = startWithDuplicatedTun(
                            protocol, lease.prepared, innerToken,
                        )
                        require(receipt.exactSessionToken == innerToken) {
                            "native_start_receipt_mismatch"
                        }
                        // Commit the exact running receipt durably while the in-memory guard is
                        // still `starting`. If persistence throws, abortInnerStart() below can
                        // prove teardown and restore the still-established outer TUN blackhole.
                        // Neither readiness nor the authority watchdog is published before both
                        // the durable write and exact in-memory transition have completed.
                        persistCatalogGuardLease(lease, "running")
                        sessionGuard.markInnerReady(
                            outer, innerToken, lease.tunnelPolicySha256,
                        )
                        launchAuthorityWatchdog(lease.serviceSessionId)
                    } catch (error: Throwable) {
                        val aborted = startBegan && runCatching {
                            protocol.abortInnerStart(innerToken)
                        }.getOrDefault(false)
                        if (aborted) {
                            sessionGuard.confirmInnerStartAborted(outer, innerToken)
                            activeInnerToken = null
                        } else {
                            sessionGuard.quarantineInnerStart(outer, innerToken)
                            runtimeFailureReason = "native_start_quarantined"
                            runtimeFailureSessionId = lease.serviceSessionId
                            persistCatalogGuardLease(lease, "quarantined")
                        }
                        throw error
                    }
                }
            } catch (cancelled: CancellationException) {
                throw cancelled
            } catch (error: Throwable) {
                lease?.let { exactLease -> runCatching {
                    val state = sessionGuard.snapshot().state
                    if (state in setOf("blackhole", "running", "starting", "stopping", "quarantined")) {
                        persistCatalogGuardLease(exactLease, state)
                    }
                } }
                mainScope.launch {
                    runtimeFailureReason = guardReason(error, "activation_failed")
                    runtimeFailureSessionId = lease?.serviceSessionId ?: sessionId
                    protocolState.value = UNKNOWN
                    onError("Native session activation failed")
                }
            }
    }

    @MainThread
    private fun stopNativeSession(outerSessionId: String?, expectedRuntimeSessionId: String?) {
        nativeGuardStopTombstones.requestStop(
            outerSessionId.orEmpty(), expectedRuntimeSessionId.orEmpty(),
        )
        if (nativeGuardCommands.trySend(NativeGuardCommand.Stop(
                outerSessionId, expectedRuntimeSessionId,
            )).isFailure) {
            onError("Native session stop channel is unavailable")
        }
    }

    private suspend fun executeStopNativeSession(command: NativeGuardCommand.Stop) {
        val outer = command.outerSessionId.orEmpty()
        val runtime = command.expectedRuntimeSessionId.orEmpty()
            val lease = catalogGuardLease
            if (lease == null || lease.outerSessionId != outer
                || lease.request.expectedRuntimeSessionId != runtime) return
            try {
                protocolOperationMutex.withLock {
                    if (catalogGuardLease !== lease) return@withLock
                    val token = activeInnerToken
                    val guardState = sessionGuard.snapshot().state
                    if (token == null) {
                        if (guardState == "quarantined") {
                            sessionGuard.proveQuarantinedInnerStopped(outer)
                        } else {
                            require(guardState == "blackhole") {
                                "native_stop_ownership_ambiguous"
                            }
                        }
                    } else {
                        require(token == runtime) { "stale_native_stop" }
                        if (guardState == "quarantined") {
                            lease.protocol.stopInner(token)
                            sessionGuard.confirmQuarantinedInnerStopped(outer, token)
                            sessionGuard.proveQuarantinedInnerStopped(outer)
                        } else {
                            sessionGuard.beginInnerStop(outer, token)
                            try {
                                lease.protocol.stopInner(token)
                            } catch (error: Throwable) {
                                // Once native stop has begun, a throw cannot prove that the reader
                                // released the dup. Retain the exact token in quarantine and make
                                // that ambiguity durable before allowing a repeated exact stop.
                                sessionGuard.quarantineStoppingInner(outer, token)
                                try {
                                    persistCatalogGuardLease(lease, "quarantined")
                                } catch (persistError: Throwable) {
                                    error.addSuppressed(persistError)
                                }
                                throw error
                            }
                            sessionGuard.confirmInnerStopped(outer, token)
                        }
                        activeInnerToken = null
                    }
                    persistCatalogGuardLease(lease, "blackhole")
                    lease.state.value = DISCONNECTED
                    mainScope.launch { protocolState.value = DISCONNECTED }
                }
            } catch (error: Throwable) {
                runCatching {
                    val state = sessionGuard.snapshot().state
                    if (state in setOf("blackhole", "running", "starting", "stopping", "quarantined")) {
                        persistCatalogGuardLease(lease, state)
                    }
                }
                mainScope.launch {
                    runtimeFailureReason = "native_stop_quarantined"
                    runtimeFailureSessionId = lease.serviceSessionId
                    protocolState.value = UNKNOWN
                    onError("Native session stop failed")
                }
            }
    }

    @MainThread
    private fun releaseNativeSessionGuard(
        operationText: String?,
        sessionText: String?,
        outerSessionId: String?,
    ) {
        if (nativeGuardCommands.trySend(NativeGuardCommand.Release(
                operationText, sessionText, outerSessionId,
            )).isFailure) {
            onError("Native session release channel is unavailable")
        }
    }

    private suspend fun executeReleaseNativeSessionGuard(command: NativeGuardCommand.Release) {
        val lease = catalogGuardLease
        val expectedRuntime = lease?.request?.expectedRuntimeSessionId
            ?: "00000000-0000-0000-0000-000000000000"
        val identity = parseNativeGuardIdentity(
            command.operation, command.session, expectedRuntime,
        ) ?: return
        val requestedOuter = runCatching {
            NativeSessionGuardContract.requireOuterSessionId(command.outerSessionId.orEmpty())
        }.getOrElse {
            onError("Native session guard release identity was rejected")
            return
        }
            var kind = "release_rejected"
            var reason = "stale_release"
            var policy = lease?.dispatchPolicySha256 ?: "0".repeat(64)
            var releaseMutationStarted = false
            var releaseProofDurable = false
            try {
                require(lease != null && lease.request.operation == identity.operation
                    && lease.request.session == identity.session
                    && lease.outerSessionId == requestedOuter) { "stale_release" }
                policy = lease.dispatchPolicySha256
                protocolOperationMutex.withLock {
                    require(catalogGuardLease === lease && activeInnerToken == null
                        && sessionGuard.snapshot().state == "blackhole") {
                        "inner_teardown_not_proven"
                    }
                    val tun = masterTun ?: throw VpnException("outer_tun_missing")
                    // First make the exact release attempt recoverable.  A persistence failure
                    // here leaves the established blackhole untouched and may be rejected.  Once
                    // this succeeds, any close/disarm failure is ambiguous and terminates the
                    // dedicated VPN process; restart rebuilds a blackhole from this sealed lease.
                    persistCatalogGuardLease(lease, "releasing")
                    releaseMutationStarted = true
                    tun.close()
                    masterTun = null
                    sessionGuard.disarm(lease.outerSessionId)
                    guardReconciliationJournal.rememberReleased(
                        lease.request, lease.dispatchPolicySha256, lease.outerSessionId,
                    )
                    persistGuardReconciliationJournal()
                    releaseProofDurable = true
                    clearCatalogGuardLease(lease)
                    nativeGuardStopTombstones.clearAfterRelease(
                        lease.outerSessionId, lease.request.expectedRuntimeSessionId,
                    )
                    kind = "released"
                    reason = ""
                }
            } catch (error: Throwable) {
                when {
                    releaseProofDurable -> {
                        // The exact Released tombstone and absent outer owner are already durable;
                        // later best-effort cleanup cannot downgrade that proof to rejection.
                        kind = "released"
                        reason = ""
                    }
                    releaseMutationStarted -> {
                        nativeGuardRecoveryPending = true
                        runtimeFailureReason = "guard_release_commit_ambiguous"
                        runtimeFailureSessionId = lease?.serviceSessionId ?: 0L
                        terminateVpnProcessFailClosed("guard_release_commit_ambiguous")
                    }
                    else -> reason = guardReason(error, "release_rejected")
                }
            }
            mainScope.launch {
                publishNativeGuardEvent(
                    identity,
                    kind,
                    policy,
                    requestedOuter,
                    reason,
                )
            }
    }

    @MainThread
    private fun reconcileNativeSessionGuardArm(
        operationText: String?,
        sessionText: String?,
        policySha256: String?,
        outerSessionId: String?,
        expectedRuntimeSessionId: String?,
    ) {
        if (nativeGuardCommands.trySend(NativeGuardCommand.ReconcileArm(
                operationText, sessionText, policySha256, outerSessionId,
                expectedRuntimeSessionId,
            )).isFailure) {
            onError("Native session guard arm reconciliation channel is unavailable")
        }
    }

    private suspend fun executeReconcileNativeSessionGuardArm(
        command: NativeGuardCommand.ReconcileArm,
    ) {
        val identity = parseNativeGuardIdentity(
            command.operation, command.session, command.expectedRuntimeSessionId,
        ) ?: return
        val policy = runCatching {
            NativeSessionGuardContract.requirePolicySha256(command.policySha256.orEmpty())
        }.getOrNull() ?: return
        val outer = runCatching {
            NativeSessionGuardContract.requireOuterSessionId(command.outerSessionId.orEmpty())
        }.getOrNull() ?: return
        if (!guardReconciliationJournalTrusted) return

        val lease = catalogGuardLease
        if (lease != null) {
            if (!exactGuardLease(lease, identity, policy, outer)) return
            val snapshot = sessionGuard.snapshot()
            val provenArmed = masterTun != null && snapshot.armed
                && snapshot.ownerSessionId == outer && snapshot.state == "blackhole"
                && !nativeGuardRecoveryPending
            mainScope.launch {
                publishNativeGuardEvent(
                    identity,
                    if (provenArmed) "armed" else "lost",
                    policy,
                    outer,
                    if (provenArmed) "" else "arm_reconcile_ambiguous",
                )
            }
            return
        }

        val outcome = guardReconciliationJournal.outcome(identity, policy, outer)
        if (outcome == null) {
            // The command consumer runs only after encrypted recovery and strictly after the
            // original PREPARE in this same channel. No exact lease therefore proves absence.
            // Seal that proof before publishing it, so a delayed duplicate PREPARE cannot arm.
            guardReconciliationJournal.rememberArmRejected(identity, policy, outer)
            persistGuardReconciliationJournal()
        }
        mainScope.launch {
            publishNativeGuardEvent(
                identity, "arm_rejected", policy, outer, "arm_timeout_fenced",
            )
        }
    }

    @MainThread
    private fun reconcileNativeSessionGuardRelease(
        operationText: String?,
        sessionText: String?,
        policySha256: String?,
        outerSessionId: String?,
        expectedRuntimeSessionId: String?,
    ) {
        if (nativeGuardCommands.trySend(NativeGuardCommand.ReconcileRelease(
                operationText, sessionText, policySha256, outerSessionId,
                expectedRuntimeSessionId,
            )).isFailure) {
            onError("Native session guard release reconciliation channel is unavailable")
        }
    }

    private suspend fun executeReconcileNativeSessionGuardRelease(
        command: NativeGuardCommand.ReconcileRelease,
    ) {
        val identity = parseNativeGuardIdentity(
            command.operation, command.session, command.expectedRuntimeSessionId,
        ) ?: return
        val policy = runCatching {
            NativeSessionGuardContract.requirePolicySha256(command.policySha256.orEmpty())
        }.getOrNull() ?: return
        val outer = runCatching {
            NativeSessionGuardContract.requireOuterSessionId(command.outerSessionId.orEmpty())
        }.getOrNull() ?: return
        if (!guardReconciliationJournalTrusted) return

        val lease = catalogGuardLease
        if (lease != null) {
            if (!exactGuardLease(lease, identity, policy, outer)) return
            // The retained exact owner is terminal proof only of non-release. Never clear it.
            mainScope.launch {
                publishNativeGuardEvent(
                    identity, "release_rejected", policy, outer,
                    "release_not_committed",
                )
            }
            return
        }
        if (guardReconciliationJournal.outcome(identity, policy, outer)
            != NativeGuardReconciliationJournal.Outcome.RELEASED) return
        mainScope.launch {
            publishNativeGuardEvent(identity, "released", policy, outer)
        }
    }

    private fun exactGuardLease(
        lease: CatalogGuardLease,
        identity: NativeSessionGuardContract.RequestIdentity,
        policySha256: String,
        outerSessionId: String,
    ): Boolean = lease.request == identity
        && lease.dispatchPolicySha256 == policySha256
        && lease.outerSessionId == outerSessionId

    private fun persistGuardReconciliationJournal() {
        AndroidVpnConfigVault.storeGuardReconciliationJournal(
            applicationContext, guardReconciliationJournal.snapshot(),
        )
    }

    private fun clearCatalogGuardLease(exact: CatalogGuardLease) {
        if (catalogGuardLease !== exact) return
        catalogGuardLease = null
        preparedSession = null
        activePolicyHash = null
        activeConfig = null
        activeRuntimeAuthority = null
        activeAuthorityAnchor = null
        activeProtocolState = null
        cancelAuthorityWatchdog()
        runtimeFailureReason = null
        runtimeFailureSessionId = 0L
        nativeGuardRecoveryPending = false
        AndroidVpnConfigVault.wipe(applicationContext)
    }

    private fun persistedGuardLease(
        lease: CatalogGuardLease,
        state: String,
    ) = AndroidVpnConfigVault.NativeGuardLease(
        lease.request.operation,
        lease.request.session,
        lease.outerSessionId,
        lease.request.expectedRuntimeSessionId,
        state,
    )

    /** Must complete durably before an Armed/running/stopped receipt is published. */
    private fun persistCatalogGuardLease(lease: CatalogGuardLease, state: String) {
        AndroidVpnConfigVault.storeRecovery(
            applicationContext,
            lease.rawConfig,
            lease.request.expectedRuntimeSessionId,
            lease.dispatchPolicySha256,
            lease.tunnelPolicySha256,
            lease.runtimeAuthority,
            lease.authorityAnchor,
            persistedGuardLease(lease, state),
        )
    }

    private fun guardRecoveryEvent(lease: CatalogGuardLease, reason: String): String =
        NativeSessionGuardContract.eventJson(
            lease.request,
            "lost",
            lease.dispatchPolicySha256,
            lease.outerSessionId,
            reason,
        )

    @MainThread
    private fun sendCurrentGuardRecoverySnapshot(client: IpcMessenger) {
        val lease = catalogGuardLease ?: return
        if (!nativeGuardRecoveryPending) return
        client.send {
            ServiceEvent.NATIVE_SESSION_GUARD.packToMessage {
                putString(
                    NativeSessionGuardContract.MSG_EVENT_JSON,
                    guardRecoveryEvent(lease, "client_recovery_required"),
                )
            }
        }
    }

    @MainThread
    private fun publishGuardRecoveryReceipt(json: String) {
        if (clientMessengers.isEmpty()) {
            while (pendingGuardRecoveryReceipts.size >= MAX_PENDING_GUARD_EVENTS) {
                pendingGuardRecoveryReceipts.removeFirst()
            }
            pendingGuardRecoveryReceipts.addLast(json)
            return
        }
        clientMessengers.send {
            ServiceEvent.NATIVE_SESSION_GUARD_RECOVERY.packToMessage {
                putString(NativeSessionGuardContract.MSG_RECOVERY_RECEIPT_JSON, json)
            }
        }
    }

    @MainThread
    private fun flushPendingGuardRecoveryReceipts(client: IpcMessenger) {
        while (pendingGuardRecoveryReceipts.isNotEmpty()) {
            val json = pendingGuardRecoveryReceipts.removeFirst()
            client.send {
                ServiceEvent.NATIVE_SESSION_GUARD_RECOVERY.packToMessage {
                    putString(NativeSessionGuardContract.MSG_RECOVERY_RECEIPT_JSON, json)
                }
            }
        }
    }

    @MainThread
    private fun publishAuthorityRenewalReceipt(json: String) {
        // Only exact locally-produced receipts can enter the queue.
        RuntimeAuthorityRenewalContract.parseReceipt(json)
        if (clientMessengers.isEmpty()) {
            while (pendingAuthorityRenewalReceipts.size >= MAX_PENDING_GUARD_EVENTS) {
                pendingAuthorityRenewalReceipts.removeFirst()
            }
            pendingAuthorityRenewalReceipts.addLast(json)
            return
        }
        clientMessengers.send {
            ServiceEvent.RUNTIME_AUTHORITY_RENEWAL.packToMessage {
                putString(RuntimeAuthorityRenewalContract.MSG_RECEIPT_JSON, json)
            }
        }
    }

    @MainThread
    private fun flushPendingAuthorityRenewalReceipts(client: IpcMessenger) {
        while (pendingAuthorityRenewalReceipts.isNotEmpty()) {
            val json = pendingAuthorityRenewalReceipts.removeFirst()
            client.send {
                ServiceEvent.RUNTIME_AUTHORITY_RENEWAL.packToMessage {
                    putString(RuntimeAuthorityRenewalContract.MSG_RECEIPT_JSON, json)
                }
            }
        }
    }

    @MainThread
    private fun resolveNativeSessionGuardRecovery(
        eventJson: String?,
        action: String?,
        rawConfig: String?,
    ) {
        if (nativeGuardCommands.trySend(NativeGuardCommand.Recover(
                eventJson, action, rawConfig,
            )).isFailure) {
            onError("Native session recovery channel is unavailable")
        }
    }

    private suspend fun executeNativeSessionGuardRecovery(command: NativeGuardCommand.Recover) {
        val parsed = runCatching {
            NativeSessionGuardContract.parseEvent(command.eventJson.orEmpty())
        }.getOrNull()
        val action = command.action.orEmpty()
        val parsedIdentity = parsed?.let {
            runCatching { NativeSessionGuardContract.RequestIdentity(
                it.getValue("operation"), it.getValue("session"),
                it.getValue("expected_runtime_session_id"),
            ) }.getOrNull()
        }
        val lease = catalogGuardLease
        if (lease == null) {
            if (!durableGuardRecoveryLoaded || parsed == null || parsedIdentity == null
                || action != "stop" || masterTun != null || sessionGuard.snapshot().armed) return
            val policy = parsed.getValue("policy_sha256")
            val outer = parsed.getValue("outer_session_id")
            val receipt = NativeSessionGuardContract.recoveryReceiptJson(
                parsedIdentity, "stop", "stopped_released", policy, outer,
            )
            mainScope.launch { publishGuardRecoveryReceipt(receipt) }
            return
        }
        val identityMatches = parsed != null
            && parsed["operation"] == lease.request.operation
            && parsed["session"] == lease.request.session
            && parsed["policy_sha256"] == lease.dispatchPolicySha256
            && parsed["outer_session_id"] == lease.outerSessionId
            && parsed["expected_runtime_session_id"] == lease.request.expectedRuntimeSessionId
        var kind = "rejected"
        var reason = "recovery_identity_mismatch"
        if (nativeGuardRecoveryPending && identityMatches && action in setOf("adopt", "stop")) {
            if (action == "adopt") {
                val config = runCatching { JSONObject(command.rawConfig.orEmpty()) }.getOrNull()
                val matches = config != null
                    && RuntimeAuthority.fromConfig(config) == lease.runtimeAuthority
                    && NativeDispatchPolicyDigest.sha256(config, lease.runtimeAuthority) ==
                        lease.dispatchPolicySha256
                    && RuntimeAuthority.configIdentitySha256(config) == lease.configIdentitySha256
                if (!matches) {
                    reason = "recovery_profile_mismatch"
                } else {
                    val snapshot = sessionGuard.snapshot()
                    if (snapshot.state == "blackhole" && activeInnerToken == null) {
                        executeActivateNativeSession(NativeGuardCommand.Activate(
                            command.rawConfig,
                            lease.request.operation,
                            lease.request.session,
                            lease.outerSessionId,
                            lease.request.expectedRuntimeSessionId,
                        ))
                    }
                    val adopted = sessionGuard.snapshot().let {
                        it.state == "running"
                            && it.ownerSessionId == lease.outerSessionId
                            && it.activeInnerToken == lease.request.expectedRuntimeSessionId
                    }
                    if (adopted) {
                        kind = "adopted"
                        reason = ""
                        nativeGuardRecoveryPending = false
                    } else {
                        reason = "recovery_runtime_not_running"
                    }
                }
            } else {
                executeStopNativeSession(NativeGuardCommand.Stop(
                    lease.outerSessionId, lease.request.expectedRuntimeSessionId,
                ))
                val stopped = catalogGuardLease === lease && activeInnerToken == null
                    && sessionGuard.snapshot().state == "blackhole"
                if (stopped) {
                    protocolOperationMutex.withLock {
                        require(catalogGuardLease === lease && activeInnerToken == null
                            && sessionGuard.snapshot().state == "blackhole") {
                            "recovery_inner_teardown_not_proven"
                        }
                        masterTun?.close()
                        masterTun = null
                        sessionGuard.disarm(lease.outerSessionId)
                        guardReconciliationJournal.rememberReleased(
                            lease.request, lease.dispatchPolicySha256, lease.outerSessionId,
                        )
                        persistGuardReconciliationJournal()
                        clearCatalogGuardLease(lease)
                        nativeGuardStopTombstones.clearAfterRelease(
                            lease.outerSessionId, lease.request.expectedRuntimeSessionId,
                        )
                    }
                    kind = "stopped_released"
                    reason = ""
                    nativeGuardRecoveryPending = false
                    mainScope.launch {
                        publishNativeGuardEvent(
                            lease.request, "released", lease.dispatchPolicySha256,
                            lease.outerSessionId,
                        )
                    }
                } else {
                    reason = "recovery_stop_not_proven"
                }
            }
        }
        val receipt = NativeSessionGuardContract.recoveryReceiptJson(
            lease.request,
            action.takeIf { it in setOf("adopt", "stop") } ?: "stop",
            kind,
            lease.dispatchPolicySha256,
            lease.outerSessionId,
            reason,
        )
        mainScope.launch { publishGuardRecoveryReceipt(receipt) }
    }

    private suspend fun executeRestoreNativeSessionGuard(
        record: AndroidVpnConfigVault.RecoveryRecord,
    ) {
        val persisted = record.nativeGuardLease ?: return
        if (catalogGuardLease != null || masterTun != null || sessionGuard.snapshot().armed) return
        var newlyEstablishedTun: ParcelFileDescriptor? = null
        try {
            val observation = AndroidAuthorityClock.observe()
            val verdict = AndroidAuthorityClock.evaluate(
                record.authority, record.clockAnchor, observation,
            )
            require(verdict.accepted && verdict.effectiveNow != null) {
                "recovery_authority_rejected"
            }
            val exactAnchor = RuntimeAuthorityAnchor.reanchor(
                record.authority, verdict.effectiveNow, observation,
            )
            val config = JSONObject(record.config)
            val recomputed = NativeDispatchPolicyDigest.sha256(config, record.authority)
            require(recomputed == record.dispatchPolicySha256
                && recomputed == record.authority.dispatchPolicySha256) {
                "recovery_dispatch_policy_mismatch"
            }
            val selected = VpnProto.get(config.getString("protocol"))
            require(selected == VpnProto.AWG || selected == VpnProto.XRAY) {
                "recovery_transport_unsupported"
            }
            val protocol = selected.protocol
            require(protocol.supportsSessionOwnedTun) { "recovery_tun_unsupported" }
            val localSessionId = nextToken(sessionId)
            val localOperation = nextToken(operationGeneration)
            val localState = MutableStateFlow(CONNECTING)
            protocol.initialize(applicationContext, localState) { message ->
                reportProtocolError(message, localOperation, localSessionId, protocol)
            }
            val prepared = protocol.prepareVpn(config)
            require(prepared.policyHash == record.tunnelPolicySha256) {
                "recovery_tunnel_policy_mismatch"
            }
            val identity = NativeSessionGuardContract.RequestIdentity(
                persisted.operation, persisted.session, persisted.expectedRuntimeSessionId,
            )
            protocolOperationMutex.withLock {
                val builder = Builder()
                protocol.configureOuterTunnel(prepared.tunnelConfig, builder)
                newlyEstablishedTun = builder.establish()
                    ?: throw VpnStartException("recovery_outer_tun_establish_failed")
                sessionGuard.arm(persisted.outerSessionId, prepared.policyHash)
                masterTun = newlyEstablishedTun
                newlyEstablishedTun = null
                sessionId = localSessionId
                operationGeneration = localOperation
                vpnProto = selected
                activeProtocolState = localState
                preparedSession = prepared
                activePolicyHash = prepared.policyHash
                activeConfig = record.config
                activeRuntimeAuthority = record.authority
                activeAuthorityAnchor = exactAnchor
                catalogGuardLease = CatalogGuardLease(
                    identity, persisted.outerSessionId, record.dispatchPolicySha256,
                    record.tunnelPolicySha256, RuntimeAuthority.configIdentitySha256(config),
                    record.config, selected, protocol, prepared, record.authority, exactAnchor,
                    localSessionId, localOperation, localState,
                )
                persistCatalogGuardLease(catalogGuardLease!!, "blackhole")
                nativeGuardRecoveryPending = true
            }
            mainScope.launch {
                protocolState.value = UNKNOWN
                clientMessengers.forEach { (_, client) -> sendCurrentGuardRecoverySnapshot(client) }
            }
        } catch (error: Throwable) {
            runCatching { newlyEstablishedTun?.close() }
            AndroidVpnConfigVault.wipe(applicationContext)
            runtimeFailureReason = "guard_recovery_failed"
            mainScope.launch {
                protocolState.value = UNKNOWN
                onError("Native session guard recovery failed closed")
            }
        } finally {
            durableGuardRecoveryLoaded = true
        }
    }

    private fun parseNativeGuardIdentity(
        operationText: String?,
        sessionText: String?,
        expectedRuntimeSessionId: String?,
    ): NativeSessionGuardContract.RequestIdentity? = runCatching {
        NativeSessionGuardContract.RequestIdentity(
            operationText.orEmpty(), sessionText.orEmpty(), expectedRuntimeSessionId.orEmpty(),
        )
    }.onFailure {
        onError("Native session guard identity was rejected")
    }.getOrNull()

    @MainThread
    private fun publishNativeGuardEvent(
        identity: NativeSessionGuardContract.RequestIdentity,
        kind: String,
        policySha256: String,
        outerSessionId: String = "",
        reason: String = "",
    ) {
        val json = NativeSessionGuardContract.eventJson(
            identity, kind, policySha256, outerSessionId, reason,
        )
        if (clientMessengers.isEmpty()) {
            while (pendingGuardEvents.size >= MAX_PENDING_GUARD_EVENTS) {
                pendingGuardEvents.removeFirst()
            }
            pendingGuardEvents.addLast(json)
            return
        }
        clientMessengers.send {
            ServiceEvent.NATIVE_SESSION_GUARD.packToMessage {
                putString(NativeSessionGuardContract.MSG_EVENT_JSON, json)
            }
        }
    }

    @MainThread
    private fun flushPendingGuardEvents(client: IpcMessenger) {
        while (pendingGuardEvents.isNotEmpty()) {
            val json = pendingGuardEvents.removeFirst()
            client.send {
                ServiceEvent.NATIVE_SESSION_GUARD.packToMessage {
                    putString(NativeSessionGuardContract.MSG_EVENT_JSON, json)
                }
            }
        }
    }

    private fun guardReason(error: Throwable, fallback: String): String {
        val candidate = error.message.orEmpty()
        return candidate.takeIf {
            it.length in 1..96 && it.all { character ->
                character in 'a'..'z' || character in '0'..'9' || character == '_'
            }
        } ?: fallback
    }

    private fun startWithDuplicatedTun(
        protocol: Protocol,
        prepared: Protocol.PreparedVpnSession,
        exactSessionToken: String,
    ): Protocol.NativeStartReceipt {
        val owner = masterTun ?: throw VpnException("Master VPN interface is absent")
        val protectCallback: (Int) -> Boolean = ::protect
        return ParcelFileDescriptor.dup(owner.fileDescriptor).use { duplicate ->
            // startWithTun owns the detached dup from call entry on every success/failure path.
            // The wrapper is already empty after detachFd(), so this `use` only closes a dup when
            // detach itself fails; it never closes the raw integer after a native throw.
            protocol.startWithTun(
                prepared, duplicate.detachFd(), exactSessionToken, protectCallback,
            )
        }
    }

    private suspend fun startSessionOwnedProtocol(
        protocol: Protocol,
        config: JSONObject,
        rawConfig: String,
        runtimeAuthority: RuntimeAuthority?,
        expectedSessionId: Long,
        operationToken: Long,
    ) {
        check(masterTun == null && activeInnerToken == null) { "Outer VPN session already exists" }
        val prepared = protocol.prepareVpn(config)
        val recovery = pendingRecoveryRecord
        val authorityAnchor = runtimeAuthority?.let { authority ->
            val initialAnchor = if (recovery != null) {
                require(recovery.authority == authority) { "Recovery authority identity mismatch" }
                require(recovery.dispatchPolicySha256 == authority.dispatchPolicySha256) {
                    "Recovered native dispatch policy changed"
                }
                require(recovery.tunnelPolicySha256 == prepared.policyHash) {
                    "Recovered outer VPN policy changed"
                }
                recovery.clockAnchor
            } else {
                RuntimeAuthorityAnchor.capture(authority)
            }
            val observation = AndroidAuthorityClock.observe()
            val verdict = AndroidAuthorityClock.evaluate(authority, initialAnchor, observation)
            require(verdict.accepted && verdict.effectiveNow != null) {
                "VPN runtime authority is not current"
            }
            RuntimeAuthorityAnchor.reanchor(
                authority,
                verdict.effectiveNow,
                observation,
            )
        }
        if (recovery != null && runtimeAuthority == null) {
            throw SecurityException("Recovery authority was removed from VPN profile")
        }
        val builder = Builder()
        protocol.configureOuterTunnel(prepared.tunnelConfig, builder)
        val established = builder.establish()
            ?: throw VpnStartException("Unable to establish guarded VPN interface")
        masterTun = established
        preparedSession = prepared
        activePolicyHash = prepared.policyHash
        activeConfig = rawConfig
        val ownerSession = ownerSessionId(expectedSessionId)
        sessionGuard.arm(ownerSession, prepared.policyHash)
        val innerToken = "$serviceEpoch:$expectedSessionId:$operationToken"
        var startBegan = false
        try {
            if (runtimeAuthority != null && authorityAnchor != null) {
                AndroidVpnConfigVault.storeRecovery(
                    applicationContext,
                    rawConfig,
                    "$serviceEpoch:$expectedSessionId",
                    runtimeAuthority.dispatchPolicySha256,
                    prepared.policyHash,
                    runtimeAuthority,
                    authorityAnchor,
                )
            } else {
                // Legacy/manual profiles may run under the live app coordinator but are never
                // granted unattended recovery authority.
                AndroidVpnConfigVault.wipe(applicationContext)
            }
            sessionGuard.beginInnerStart(ownerSession, innerToken, prepared.policyHash)
            activeInnerToken = innerToken
            startBegan = true
            val receipt = protocol.startWithTun(
                prepared,
                duplicateMasterTun(),
                innerToken,
                ::protect,
            )
            require(receipt.exactSessionToken == innerToken) { "Native start receipt mismatch" }
            sessionGuard.markInnerReady(ownerSession, innerToken, prepared.policyHash)
            activeRuntimeAuthority = runtimeAuthority
            activeAuthorityAnchor = authorityAnchor
            pendingRecoveryRecord = null
            launchAuthorityWatchdog(expectedSessionId)
        } catch (error: Throwable) {
            val innerStopped = if (!startBegan) {
                true
            } else {
                val aborted = runCatching { protocol.abortInnerStart(innerToken) }
                    .getOrDefault(false)
                if (aborted) {
                    sessionGuard.confirmInnerStartAborted(ownerSession, innerToken)
                    activeInnerToken = null
                } else {
                    sessionGuard.quarantineInnerStart(ownerSession, innerToken)
                }
                aborted
            }
            if (innerStopped) {
                activeInnerToken = null
                runCatching { masterTun?.close() }
                masterTun = null
                preparedSession = null
                activePolicyHash = null
                activeConfig = null
                sessionGuard.disarm(ownerSession)
                AndroidVpnConfigVault.wipe(applicationContext)
            } else {
                runtimeFailureReason = "native_start_quarantined"
                runtimeFailureSessionId = expectedSessionId
            }
            pendingRecoveryRecord = null
            throw error
        }
    }

    private fun stopSessionOwnedProtocol(
        protocol: Protocol,
        expectedSessionId: Long,
        explicit: Boolean,
    ) {
        val token = activeInnerToken ?: throw VpnException("Missing exact inner session token")
        if (!token.startsWith("$serviceEpoch:$expectedSessionId:")) {
            throw VpnException("Stale Android VPN session token")
        }
        val ownerSession = ownerSessionId(expectedSessionId)
        sessionGuard.beginInnerStop(ownerSession, token)
        protocol.stopInner(token)
        sessionGuard.confirmInnerStopped(ownerSession, token)
        activeInnerToken = null
        if (explicit) {
            // Guard/routing teardown is last, after exact native stop.
            masterTun?.close()
            masterTun = null
            preparedSession = null
            activePolicyHash = null
            activeConfig = null
            activeRuntimeAuthority = null
            activeAuthorityAnchor = null
            cancelAuthorityWatchdog()
            sessionGuard.disarm(ownerSession)
            AndroidVpnConfigVault.wipe(applicationContext)
        }
    }

    private fun reconnectSessionOwnedProtocol(
        protocol: Protocol,
        expectedSessionId: Long,
        operationToken: Long,
    ) {
        requireActiveAuthorityCurrent()
        val prepared = preparedSession ?: throw VpnException("Missing prepared VPN session")
        val policy = activePolicyHash ?: throw VpnException("Missing outer VPN policy")
        if (masterTun == null || prepared.policyHash != policy) {
            throw VpnException("Outer VPN policy changed; guarded reconnect refused")
        }
        stopSessionOwnedProtocol(protocol, expectedSessionId, explicit = false)
        // With no dup reader the still-established master TUN is a blackhole.
        val ownerSession = ownerSessionId(expectedSessionId)
        sessionGuard.validateReplacement(ownerSession, prepared.policyHash)
        val replacementToken = "$serviceEpoch:$expectedSessionId:$operationToken"
        activeInnerToken = replacementToken
        sessionGuard.beginInnerStart(ownerSession, replacementToken, prepared.policyHash)
        try {
            val receipt = protocol.startWithTun(
                prepared,
                duplicateMasterTun(),
                replacementToken,
                ::protect,
            )
            require(receipt.exactSessionToken == replacementToken) {
                "Native reconnect receipt mismatch"
            }
            sessionGuard.markInnerReady(ownerSession, replacementToken, prepared.policyHash)
        } catch (error: Throwable) {
            val aborted = runCatching { protocol.abortInnerStart(replacementToken) }
                .getOrDefault(false)
            if (aborted) {
                sessionGuard.confirmInnerStartAborted(ownerSession, replacementToken)
                activeInnerToken = null
            } else {
                sessionGuard.quarantineInnerStart(ownerSession, replacementToken)
                runtimeFailureReason = "native_reconnect_quarantined"
                runtimeFailureSessionId = expectedSessionId
            }
            throw error
        }
    }

    private fun launchAuthorityWatchdog(expectedSessionId: Long) {
        cancelAuthorityWatchdog()
        val authority = activeRuntimeAuthority ?: return
        val verdict = activeAuthorityVerdict()
        val token = authorityWatchdogFence.arm(expectedSessionId, authority)
        val remainingMillis = runCatching {
            require(verdict.accepted && verdict.effectiveNow != null) {
                "Runtime authority is not current"
            }
            RuntimeAuthorityWatchdogPlanner.remainingMillis(
                authority, requireNotNull(verdict.effectiveNow),
            )
        }.getOrElse {
            if (authorityWatchdogFence.consume(token)) {
                handleExpiredRuntimeAuthority(token, authority,
                                              verdict.reason.ifBlank { "authority_rejected" })
            }
            return
        }
        authorityWatchdogJob = mainScope.launch {
            delay(remainingMillis)
            if (!authorityWatchdogFence.consume(token)) return@launch
            authorityWatchdogJob = null
            if (sessionId != expectedSessionId || activeRuntimeAuthority !== authority) return@launch
            val lateVerdict = activeAuthorityVerdict()
            if (lateVerdict.accepted) {
                // Millisecond conversion can wake just before a sub-ms Instant deadline.
                launchAuthorityWatchdog(expectedSessionId)
                return@launch
            }
            handleExpiredRuntimeAuthority(
                token, authority, lateVerdict.reason.ifBlank { "authority_rejected" },
            )
        }
    }

    private fun cancelAuthorityWatchdog() {
        authorityWatchdogFence.cancel()
        authorityWatchdogJob?.cancel()
        authorityWatchdogJob = null
    }

    private fun handleExpiredRuntimeAuthority(
        token: RuntimeAuthorityWatchdogFence.Token,
        authority: RuntimeAuthority,
        reason: String,
    ) {
        val lease = catalogGuardLease ?: return
        connectionScope.launch {
            var exact = false
            protocolOperationMutex.withLock {
                if (sessionId != token.serviceSessionId || lease.serviceSessionId != token.serviceSessionId
                    || catalogGuardLease !== lease || activeRuntimeAuthority !== authority
                    || authority.catalogRevision != token.catalogRevision
                    || authority.hardDeadline != token.hardDeadline) return@withLock
                val inner = activeInnerToken ?: return@withLock
                val guard = sessionGuard.snapshot()
                if (guard.ownerSessionId != lease.outerSessionId
                    || guard.activeInnerToken != inner || guard.state != "running") return@withLock
                exact = true
                runtimeFailureReason = reason
                runtimeFailureSessionId = token.serviceSessionId
                // Quarantine and persist before the potentially blocking native stop. The outer
                // TUN remains established; only an exact recovery stop may return to blackhole.
                sessionGuard.quarantineActiveInner(lease.outerSessionId, inner)
                val outcome = RuntimeAuthorityExpiryCoordinator.execute(
                    persistQuarantine = { persistCatalogGuardLease(lease, "quarantined") },
                    stopInner = { lease.protocol.stopInner(inner) },
                    markStopped = {
                        sessionGuard.confirmQuarantinedInnerStopped(lease.outerSessionId, inner)
                        activeInnerToken = null
                    },
                    persistStoppedState = { persistCatalogGuardLease(lease, "quarantined") },
                    onDurabilityFailure = {
                        // Recovery must not trust a stale durable "running" lease after a failed
                        // quarantine write. Wiping forces a process restart into disconnected,
                        // fail-closed recovery while the current outer TUN stays established.
                        AndroidVpnConfigVault.wipe(applicationContext)
                    },
                )
                if (!outcome.quarantinePersisted || !outcome.stoppedStatePersisted) {
                    runtimeFailureReason = "runtime_authority_expired_durability_failed"
                }
            }
            if (!exact) return@launch
            mainScope.launch {
                protocolState.value = UNKNOWN
                publishNativeGuardEvent(
                    lease.request, "lost", lease.dispatchPolicySha256,
                    lease.outerSessionId, "runtime_authority_expired",
                )
                onError("VPN runtime authority expired or became unverifiable")
            }
        }
    }

    private fun activeAuthorityVerdict(): RuntimeAuthorityVerdict {
        val authority = activeRuntimeAuthority ?: return RuntimeAuthorityVerdict(true)
        val anchor = activeAuthorityAnchor
            ?: return RuntimeAuthorityVerdict(false, reason = "authority_anchor_missing")
        return AndroidAuthorityClock.evaluate(authority, anchor, AndroidAuthorityClock.observe())
    }

    private fun requireActiveAuthorityCurrent() {
        if (activeRuntimeAuthority == null) return // explicitly legacy/manual, never persisted
        val snapshot = sessionGuard.snapshot()
        require(snapshot.state != "quarantined") { "Guarded VPN session is quarantined" }
        val verdict = activeAuthorityVerdict()
        require(verdict.accepted) { "VPN runtime authority is no longer current" }
    }

    private suspend fun executeRuntimeAuthorityRenewal(command: NativeGuardCommand.Renew) {
        val request = command.request
        var durableWriteStarted = false
        val accepted = runCatching {
            val lease = catalogGuardLease ?: throw SecurityException("No catalog guard lease")
            val oldAuthority = activeRuntimeAuthority
                ?: throw SecurityException("No active runtime authority")
            val oldConfig = activeConfig ?: throw SecurityException("No active configuration")
            val tunnelPolicy = activePolicyHash ?: throw SecurityException("No active tunnel policy")
            val guard = sessionGuard.snapshot()
            val effectiveNow = activeAuthorityVerdict().let { verdict ->
                if (verdict.accepted) verdict.effectiveNow else null
            } ?: throw SecurityException("Active runtime authority is not current")
            require(request.operation == lease.request.operation
                && request.session == lease.request.session
                && request.policySha256 == lease.dispatchPolicySha256
                && request.outerSessionId == lease.outerSessionId
                && request.expectedRuntimeSessionId == lease.request.expectedRuntimeSessionId) {
                "Renewal session identity mismatch"
            }
            require(guard.ownerSessionId == lease.outerSessionId
                && guard.policyHash == tunnelPolicy
                && guard.state == "running"
                && activeInnerToken == lease.request.expectedRuntimeSessionId) {
                "Renewal target is not the exact live session"
            }

            val refreshedJson = JSONObject(command.rawConfig)
            val recomputedRequest = RuntimeAuthorityRenewalContract.requestFromConfig(
                refreshedJson, command.rawConfig, request.operation, request.session,
                request.outerSessionId,
                request.expectedRuntimeSessionId, request.renewalId,
                request.authorityCommitmentSha256,
            )
            require(recomputedRequest == request) { "Renewal request/config mismatch" }
            val next = RuntimeAuthority.fromConfig(refreshedJson)
                ?: throw SecurityException("Renewal authority missing")
            require(oldAuthority.acceptsRenewal(next, effectiveNow)) {
                "Renewal is stale or changes identity"
            }
            require(RuntimeAuthority.configIdentitySha256(refreshedJson)
                == RuntimeAuthority.configIdentitySha256(JSONObject(oldConfig))) {
                "Renewal changed native profile"
            }
            val anchor = RuntimeAuthorityAnchor.capture(next)
            val verdict = AndroidAuthorityClock.evaluate(next, anchor, AndroidAuthorityClock.observe())
            require(verdict.accepted) { "Renewal authority is not current" }
            val replacement = lease.copy(
                rawConfig = command.rawConfig,
                runtimeAuthority = next,
                authorityAnchor = anchor,
            )

            protocolOperationMutex.withLock {
                val commitEffectiveNow = activeAuthorityVerdict().let { verdict ->
                    if (verdict.accepted) verdict.effectiveNow else null
                } ?: throw SecurityException("Authority expired before renewal commit")
                require(catalogGuardLease === lease
                    && activeRuntimeAuthority == oldAuthority
                    && activeConfig == oldConfig
                    && activePolicyHash == tunnelPolicy
                    && sessionGuard.snapshot().let {
                        it.state == "running" && it.ownerSessionId == lease.outerSessionId
                            && it.policyHash == tunnelPolicy
                    }
                    && activeInnerToken == lease.request.expectedRuntimeSessionId
                    && oldAuthority.acceptsRenewal(next, commitEffectiveNow)) {
                    "Renewal target changed before commit"
                }
                durableWriteStarted = true
                RuntimeAuthorityRenewalContract.commitPersistFirst(
                    replacement,
                    persist = { durable ->
                        AndroidVpnConfigVault.storeRecovery(
                            applicationContext,
                            durable.rawConfig,
                            durable.request.expectedRuntimeSessionId,
                            durable.dispatchPolicySha256,
                            durable.tunnelPolicySha256,
                            durable.runtimeAuthority,
                            durable.authorityAnchor,
                            persistedGuardLease(durable, "running"),
                        )
                    },
                    commit = { durable ->
                        activeConfig = durable.rawConfig
                        activeRuntimeAuthority = durable.runtimeAuthority
                        activeAuthorityAnchor = durable.authorityAnchor
                        catalogGuardLease = durable
                    },
                )
            }
            true
        }.getOrDefault(false)

        val receipt = if (accepted) {
            RuntimeAuthorityRenewalContract.applied(request)
        } else {
            RuntimeAuthorityRenewalContract.rejected(
                request,
                if (durableWriteStarted) "durable_persist_failed" else "renewal_rejected",
            )
        }
        mainScope.launch {
            if (accepted) launchAuthorityWatchdog(sessionId)
            publishAuthorityRenewalReceipt(receipt.json())
        }
    }

    private fun duplicateMasterTun(): Int {
        val owner = masterTun ?: throw VpnException("Master VPN interface is absent")
        return ParcelFileDescriptor.dup(owner.fileDescriptor).detachFd()
    }

    private fun ownerSessionId(expectedSessionId: Long): String =
        "$serviceEpoch:$expectedSessionId"

    private fun consumeConfigReference(reference: String?): String? = try {
        TribeConfigFile.read(applicationContext, reference)
    } catch (_: Throwable) {
        onError("Encrypted VPN handoff was rejected")
        null
    }

    private fun parseConfigToJson(vpnConfig: String): JSONObject? =
        if (vpnConfig.isBlank()) {
            null
        } else {
            try {
                JSONObject(vpnConfig)
            } catch (_: JSONException) {
                onError("Invalid VPN config json format")
                null
            }
        }

    private fun saveServerData(config: JSONObject?) {
        serverName = config?.optString("description", "")?.trim()?.takeIf {
            it.isNotEmpty() && it.length <= 160
        }
        serverIndex = config?.optInt("serverIndex", -1) ?: -1
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

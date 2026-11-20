package org.amnezia.vpn.protocol.xray.upstream

import android.os.SystemClock
import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.net.HttpURLConnection
import java.net.ProtocolException
import java.net.SocketTimeoutException
import java.net.URL
import java.net.UnknownHostException
import java.util.concurrent.Callable
import java.util.concurrent.CountDownLatch
import java.util.concurrent.ExecutionException
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.RejectedExecutionException
import java.util.concurrent.ScheduledExecutorService
import java.util.concurrent.ThreadFactory
import java.util.concurrent.TimeUnit
import java.util.concurrent.TimeoutException
import java.util.concurrent.atomic.AtomicReference
import javax.net.ssl.SSLException
import kotlin.concurrent.thread
import org.json.JSONObject

// AVPN upstream nodes (plan provider-pool, release C, lane A2; contract client-envelope-contract.md): the
// seat-lease owner inside the Android Xray service process (decision A-1: Android kills the activity
// process in the background while the foreground service keeps the tunnel). The Kotlin twin of
// client/platforms/ios/UpstreamLeaseRenewer.swift. Owns one UpstreamLeaseMachine (RENEW_UNTIL_GONE),
// feeds it the tunnel's cumulative byte counters and a sleep-proof clock (SystemClock.elapsedRealtime),
// sends its renew / release reports as plain HTTPS from this process - its sockets are not protected, so
// they go THROUGH the tunnel (decision A-3) - and reports the status object of contract section 5.
//
// It never acts on the tunnel (CONNECT-INVARIANTS: no new actor may stop or switch it): on a terminal
// answer it stops renewing and reports `state: terminal` with the server's code; the existing engine
// decides. One one-shot timer, re-armed to the machine's next wake-up and capped at 60 s ahead (the
// executor's clock pauses in deep sleep; the cap bounds how late a tick comes after wake-up, the
// machine decides on its own `now`). It is not a health watchdog: it only sends lease reports.
//
// Secrets: the renew token and the URL path (lease id) are never logged; logs carry codes and seq only.

data class UpstreamHttpResult(
    val status: Int = 0,                 // 0 = no HTTP response
    val body: ByteArray = ByteArray(0),
    val errorCode: String = "",          // transport | timeout | tls | dns | interrupted (journal only)
    val fromTribeApi: Boolean = false,   // the answer carried `X-Tribe-Api: 1`
)

fun interface UpstreamLeaseTransport {
    // Blocking; one HTTPS exchange through the tunnel, bounded to timeoutMs. Never called under the
    // renewer's lock.
    fun send(method: String, url: String, headers: Map<String, String>, body: String, timeoutMs: Long): UpstreamHttpResult
}

fun interface UpstreamTimerCancel {
    fun cancel()
}

// One-shot timer source (tests inject a manual one).
fun interface UpstreamLeaseScheduler {
    fun schedule(delayMs: Long, task: Runnable): UpstreamTimerCancel
}

data class UpstreamLeaseStatus(
    val state: String = "none",          // none | pending | active | terminal
    val code: String = "",
    val seq: Long = 0,
    val renewedMsAgo: Long = -1,
    val expiresInMs: Long = 0,
    val revision: Long = 0,
    val configChanged: Boolean = false,
    val appliedBytes: Long = 0,
    val shadowBytes: Long = 0,
    val meterScope: UpstreamMeterScope = UpstreamMeterScope.TUNNEL,
) {
    // Contract section 5, key for key.
    fun toJson(): JSONObject = JSONObject()
        .put("state", state)
        .put("code", code)
        .put("seq", seq)
        .put("renewed_ms_ago", renewedMsAgo)
        .put("expires_in_ms", expiresInMs)
        .put("revision", revision)
        .put("config_changed", configChanged)
        .put("applied_bytes", appliedBytes)
        .put("shadow_bytes", shadowBytes)
        .put("meter_scope", meterScope.wire)
}

private fun daemonThreads(name: String) = ThreadFactory { r -> Thread(r, name).apply { isDaemon = true } }

class UpstreamLeaseRenewer(
    val profileId: String,
    private val transport: UpstreamLeaseTransport,
    private val meter: UpstreamMeter,
    private val nowMs: () -> Long,
    private val onStatus: (UpstreamLeaseStatus) -> Unit,
    private val log: (String) -> Unit = {},
    timing: UpstreamLeaseTiming = UpstreamLeaseTiming(),
    scheduler: UpstreamLeaseScheduler? = null, // null = an own single-thread ScheduledExecutorService
) {
    companion object {
        const val RENEW_TIMEOUT_MS: Long = 12_000  // Swift renewTimeoutMs (C++ 15 s): well inside renew_after_s
        const val RELEASE_TIMEOUT_MS: Long = 1_500 // contract section 6
        const val MAX_TIMER_AHEAD_MS: Long = 60_000
    }

    private val lock = Any()
    private val machine = UpstreamLeaseMachine(timing, UpstreamExpiryPolicy.RENEW_UNTIL_GONE)
    private val io: ExecutorService = Executors.newSingleThreadExecutor(daemonThreads("tribe-upstream-lease-io"))
    private val callbacks: ExecutorService = Executors.newSingleThreadExecutor(daemonThreads("tribe-upstream-lease-cb"))
    private val ownTimer: ScheduledExecutorService? =
        if (scheduler == null) Executors.newSingleThreadScheduledExecutor(daemonThreads("tribe-upstream-lease")) else null
    private val scheduler: UpstreamLeaseScheduler = scheduler ?: UpstreamLeaseScheduler { delayMs, task ->
        val f = ownTimer!!.schedule(task, delayMs, TimeUnit.MILLISECONDS)
        UpstreamTimerCancel { f.cancel(false) }
    }
    private var timer: UpstreamTimerCancel? = null
    private var stopped = false // no more renewals (a stop, or a terminal answer)
    private var released = false // the final release was taken (or the renewer ended without one): at most once
    private var lastEmitted: UpstreamLeaseStatus? = null
    private var scope = UpstreamMeterScope.TUNNEL
    private var meterTags: List<String> = emptyList()

    // The delay of the last armed timer (-1 = none armed); tests check the cap and the cadence with it.
    @Volatile
    internal var lastTimerDelayMs: Long = -1
        private set

    // ---- lifecycle (any thread) -------------------------------------------------------------------------

    // A start envelope with `upstream_lease`: the session is accounted from now on.
    fun startActive(lease: UpstreamLeaseEnvelope) {
        synchronized(lock) {
            if (stopped) return
            adoptLocked(lease)
        }
    }

    // A provisional start (no `upstream_lease` yet): "pending", bytes counted from tunnel start.
    fun startPending() {
        synchronized(lock) {
            if (stopped) return
            machine.beginPending(profileId, nowMs())
            log("Tribe upstream: pending (provisional start)")
            emitStatusLocked()
        }
    }

    // App message `upstream_lease_set`. Accepted only while pending (a second hand-over, or one after a
    // terminal answer, changes nothing). Returns the status after the hand-over.
    fun handOver(lease: UpstreamLeaseEnvelope): UpstreamLeaseStatus = synchronized(lock) {
        if (!stopped && machine.phase == UpstreamLeasePhase.PROVISIONAL) {
            adoptLocked(lease)
        } else {
            log("Tribe upstream: lease hand-over ignored (state ${statusLocked().state})")
        }
        statusLocked()
    }

    fun status(): UpstreamLeaseStatus = synchronized(lock) { statusLocked() }

    // A terminal answer arrived: the session is over for the provider node.
    val isTerminal: Boolean
        get() = synchronized(lock) { machine.phase == UpstreamLeasePhase.LEFT }

    // User disconnect (contract section 6): DELETE with the final report through the tunnel BEFORE the core
    // stops, bounded to RELEASE_TIMEOUT_MS; `completion` runs exactly once (on the answer, on failure or at
    // the bound). Nothing is sent after a terminal answer or before a lease exists.
    fun release(completion: () -> Unit) {
        val request = synchronized(lock) {
            // A terminal answer ends RENEWING only (stopped); the final report is still owed at the stop (the server meters a
            // release with the tenure's token even after the lease ended), so only `released` blocks a second release.
            if (released) {
                null
            } else {
                released = true
                stopped = true
                cancelTimerLocked()
                feedBytesLocked()
                machine.disconnect(nowMs()).find(UpstreamLeaseActionKind.SEND_RELEASE)?.let { action ->
                    log("Tribe upstream: release seq=${action.meter.seq}")
                    // DELIBERATE: the body is the plain meter report, WITHOUT the `renew_token` field (the token travels only in the
                    // Authorization header). A DELETE without the field keeps the old server behaviour: it ends the lease named by
                    // its id and applies the final report. That is safe: every start has its own lease id, so a token-less DELETE
                    // can only end this renewer's own lease. The C++ app owner then sends its own DELETE after the confirmed stop,
                    // WITH the token and WITHOUT a report (UpstreamLeaseOwner ReleaseAfterStop): the lease is already ended, nothing
                    // applies twice (the server meters per seq; a report at or below the last seq applies nothing).
                    // IF the token is ever added here, change together: the server drops the final report of a release whose token
                    // is not the lease's current one, so this body must carry exactly the token this renewer was granted
                    // (as UpstreamLeaseWire.swift releaseBody does) and the wire test must cover it.
                    Triple(leaseUrl(action), headers(action), UpstreamLeaseWire.meterBody(action.meter))
                }
            }
        }
        shutdownWorkers()
        if (request == null) {
            completion()
            return
        }
        // Own threads, not the renewal I/O thread: a renewal in flight must not delay the release.
        thread(name = "tribe-upstream-lease-release", isDaemon = true) {
            val sender = thread(name = "tribe-upstream-lease-release-send", isDaemon = true) {
                val r = transport.send("DELETE", request.first, request.second, request.third, RELEASE_TIMEOUT_MS)
                log("Tribe upstream: release answered status=${r.status} error=${r.errorCode}")
            }
            try {
                sender.join(RELEASE_TIMEOUT_MS + 100)
            } catch (e: InterruptedException) {
                Thread.currentThread().interrupt()
            }
            completion()
        }
    }

    // Ends the renewer without a release (a stop without a lease, the service
    // going away). A status already queued (the terminal one) is still delivered.
    fun stop() {
        synchronized(lock) {
            stopped = true
            released = true
            cancelTimerLocked()
        }
        shutdownWorkers()
    }

    // ---- test hooks -------------------------------------------------------------------------------------

    // Runs the tick a timer would run (tests drive time through `nowMs`).
    internal fun fireForTest() {
        synchronized(lock) { tickLocked() }
    }

    // Waits until the renewal in flight was answered and applied, and its status delivered.
    internal fun drainForTest() {
        runCatching { io.submit {}.get(5, TimeUnit.SECONDS) }
        runCatching { callbacks.submit {}.get(5, TimeUnit.SECONDS) }
    }

    // ---- under the lock ---------------------------------------------------------------------------------

    private fun adoptLocked(lease: UpstreamLeaseEnvelope) {
        // Scope fixed here for the life of the lease (contract section 4).
        val effective = lease.copy(meterScope = UpstreamMeterPlan.scope(lease.meterScope, lease.meterTags, meter.proxyAvailable))
        if (effective.meterScope != lease.meterScope) {
            log("Tribe upstream: meter_scope proxy not measurable (tags=${lease.meterTags.size} proxy=${meter.proxyAvailable}), reporting tunnel")
        }
        scope = effective.meterScope
        meterTags = if (scope == UpstreamMeterScope.PROXY) lease.meterTags else emptyList()
        val step = machine.adopt(effective, profileId, nowMs())
        log("Tribe upstream: active seq=${lease.seq} epoch=${lease.epoch} scope=${scope.wire}")
        apply(step)
        emitStatusLocked()
    }

    private fun statusLocked(): UpstreamLeaseStatus {
        val now = nowMs()
        return UpstreamLeaseStatus(
            state = when (machine.phase) {
                UpstreamLeasePhase.ACTIVE -> "active"
                UpstreamLeasePhase.PROVISIONAL -> "pending"
                UpstreamLeasePhase.LEFT -> "terminal"
                else -> "none"
            },
            code = if (machine.phase == UpstreamLeasePhase.LEFT) machine.leaveReason else "",
            seq = machine.lastAcceptedSeq,
            renewedMsAgo = if (machine.lastRenewOkMs >= 0) maxOf(0L, now - machine.lastRenewOkMs) else -1,
            expiresInMs = if (machine.phase == UpstreamLeasePhase.ACTIVE) maxOf(0L, machine.deadlineMs - now) else 0,
            revision = machine.knownRevision,
            configChanged = machine.configChangedNoted,
            appliedBytes = machine.appliedBytesTotal,
            shadowBytes = machine.shadowBytesTotal,
            meterScope = if (machine.phase == UpstreamLeasePhase.IDLE) UpstreamMeterScope.TUNNEL else scope,
        )
    }

    // Pushed only when something the engine acts on changed (android-ipc-contract.md section 3: state, code,
    // seq, revision, config_changed, meter_scope; never on byte or clock ticks). status() is the pull.
    private fun emitStatusLocked() {
        val snapshot = statusLocked()
        val last = lastEmitted
        if (last != null && last.state == snapshot.state && last.code == snapshot.code && last.seq == snapshot.seq &&
            last.revision == snapshot.revision && last.configChanged == snapshot.configChanged &&
            last.meterScope == snapshot.meterScope) return
        lastEmitted = snapshot
        try {
            callbacks.execute {
                try {
                    onStatus(snapshot)
                } catch (e: Exception) {
                    log("Tribe upstream: status callback failed: ${e.javaClass.simpleName}")
                }
            }
        } catch (e: RejectedExecutionException) {
            // Stopped: nobody listens any more.
        }
    }

    private fun feedBytesLocked() {
        val totals = meter.totals(scope, meterTags) ?: return
        machine.onTunnelBytes(totals.rx, totals.tx)
    }

    private fun tickLocked() {
        if (stopped) return
        feedBytesLocked()
        apply(machine.tick(nowMs()))
    }

    private fun apply(step: UpstreamLeaseStep) {
        for (action in step.actions) {
            when (action.kind) {
                UpstreamLeaseActionKind.SEND_RENEW -> sendRenew(action)
                UpstreamLeaseActionKind.LEAVE_NODE -> {
                    // Report only: the engine leaves the node through its existing path.
                    log("Tribe upstream: terminal code=${action.reason}")
                    stopped = true
                    cancelTimerLocked()
                }
                UpstreamLeaseActionKind.RESTART_BYTE_COUNTERS -> {
                    // rebaseline: zero bytes of the report were charged; restart from the current totals.
                    meter.totals(scope, meterTags)?.let { machine.baselineBytes(it.rx, it.tx) }
                    log("Tribe upstream: rebaseline epoch=${machine.accountingEpoch}")
                }
                UpstreamLeaseActionKind.REVISION_CHANGED -> log("Tribe upstream: revision ${action.upstreamRevision}")
                UpstreamLeaseActionKind.CONFIG_CHANGED -> log("Tribe upstream: config changed (applies at the next connect)")
                // The service never acquires (RENEW_UNTIL_GONE); a release only comes from release().
                UpstreamLeaseActionKind.SEND_ACQUIRE, UpstreamLeaseActionKind.SEND_RELEASE,
                UpstreamLeaseActionKind.LEASE_READY, UpstreamLeaseActionKind.LEASE_CONFIRMED,
                UpstreamLeaseActionKind.TRY_NEXT_CANDIDATE -> Unit
            }
        }
        if (!stopped) schedule(step.wakeAtMs)
    }

    private fun sendRenew(action: UpstreamLeaseAction) {
        val url = leaseUrl(action) + "/renew"
        val headers = headers(action)
        val body = UpstreamLeaseWire.meterBody(action.meter)
        val requestId = action.requestId
        val seq = action.meter.seq
        try {
            io.execute {
                val result = transport.send("POST", url, headers, body, RENEW_TIMEOUT_MS)
                synchronized(lock) {
                    if (stopped) return@synchronized
                    val reply = UpstreamLeaseWire.classifyRenewReply(result.status, result.body)
                    log("Tribe upstream: renew seq=$seq -> ${describe(reply, result)}")
                    feedBytesLocked()
                    apply(machine.onRenewReply(requestId, reply, nowMs()))
                    emitStatusLocked()
                }
            }
        } catch (e: RejectedExecutionException) {
            // Stopped between the decision and the send: nothing to do.
        }
    }

    private fun leaseUrl(action: UpstreamLeaseAction): String =
        // lease_id is validated ([A-Za-z0-9_-]{32,64}) and api_base normalized at parse time.
        action.route.apiBase + "/v1/upstream/lease/" + action.leaseId

    private fun headers(action: UpstreamLeaseAction): Map<String, String> =
        mapOf("Authorization" to "Bearer " + action.route.renewToken, "Content-Type" to "application/json")

    private fun schedule(wakeAtMs: Long) {
        cancelTimerLocked()
        if (wakeAtMs < 0) return // a renewal is in flight: its answer re-arms the timer
        val delayMs = (wakeAtMs - nowMs()).coerceIn(0L, MAX_TIMER_AHEAD_MS)
        lastTimerDelayMs = delayMs
        timer = try {
            scheduler.schedule(delayMs) { synchronized(lock) { tickLocked() } }
        } catch (e: RejectedExecutionException) {
            null
        }
    }

    private fun cancelTimerLocked() {
        timer?.cancel()
        timer = null
        lastTimerDelayMs = -1
    }

    private fun shutdownWorkers() {
        ownTimer?.shutdownNow()
        io.shutdown() // a renewal in flight finishes on its own bound; its answer is ignored (stopped)
        callbacks.shutdown()
    }

    private fun describe(reply: UpstreamRenewReply, result: UpstreamHttpResult): String = when (reply.kind) {
        UpstreamReplyKind.GRANTED -> if (reply.renewal.rebaseline) "rebaseline" else "ok"
        UpstreamReplyKind.REFUSED -> "refused code=${reply.error.code.wire}"
        UpstreamReplyKind.FAILED ->
            if (result.errorCode.isEmpty()) "failed ${reply.why}" else "failed ${reply.why} error=${result.errorCode}"
    }
}

// Plain HTTPS from this process (decision A-3: the socket is not protected, so it goes into the tunnel).
// The whole exchange (DNS, connect, TLS, write, read) is bounded to timeoutMs: HttpURLConnection's own
// timeouts do not cover name resolution. Redirects are never followed (the bearer token stays on the
// lease's host). Answers above 2 MiB are cut (C++ kMaxLeaseAnswerBytes).
class HttpsUpstreamTransport(private val maxAnswerBytes: Int = 2 * 1024 * 1024) : UpstreamLeaseTransport {
    private companion object {
        // One pool for every session of the process; idle threads end after 60 s.
        val pool: ExecutorService by lazy { Executors.newCachedThreadPool(daemonThreads("tribe-upstream-http")) }
    }

    override fun send(method: String, url: String, headers: Map<String, String>, body: String,
                      timeoutMs: Long): UpstreamHttpResult {
        val connection = AtomicReference<HttpURLConnection?>()
        val future = try {
            pool.submit(Callable { exchange(method, url, headers, body, timeoutMs, connection) })
        } catch (e: RejectedExecutionException) {
            return UpstreamHttpResult(errorCode = "transport")
        }
        return try {
            future.get(timeoutMs, TimeUnit.MILLISECONDS)
        } catch (e: TimeoutException) {
            connection.get()?.disconnect()
            future.cancel(true)
            UpstreamHttpResult(errorCode = "timeout")
        } catch (e: ExecutionException) {
            UpstreamHttpResult(errorCode = errorCode(e.cause))
        } catch (e: InterruptedException) {
            Thread.currentThread().interrupt()
            future.cancel(true)
            UpstreamHttpResult(errorCode = "interrupted")
        }
    }

    private fun exchange(method: String, url: String, headers: Map<String, String>, body: String, timeoutMs: Long,
                         holder: AtomicReference<HttpURLConnection?>): UpstreamHttpResult {
        val c = URL(url).openConnection() as HttpURLConnection
        holder.set(c)
        try {
            val t = timeoutMs.coerceIn(1L, Int.MAX_VALUE.toLong()).toInt()
            c.connectTimeout = t
            c.readTimeout = t
            c.instanceFollowRedirects = false
            c.useCaches = false
            c.requestMethod = method
            for ((k, v) in headers) c.setRequestProperty(k, v)
            if (body.isNotEmpty()) {
                val bytes = body.toByteArray(Charsets.UTF_8)
                try {
                    c.doOutput = true
                    c.setFixedLengthStreamingMode(bytes.size)
                    c.outputStream.use { it.write(bytes) }
                } catch (e: ProtocolException) {
                    // An HttpURLConnection that refuses a DELETE body: free the seat without the final report
                    // rather than not at all (the bytes since the last renewal are then not charged).
                    if (method != "DELETE") throw e
                    c.disconnect()
                    return exchange(method, url, headers, "", timeoutMs, holder)
                }
            }
            val status = c.responseCode
            if (status <= 0) return UpstreamHttpResult(errorCode = "transport")
            val stream: InputStream? = if (status >= 400) c.errorStream else c.inputStream
            val data = stream?.use { readBounded(it) } ?: ByteArray(0)
            return UpstreamHttpResult(status, data, "",
                UpstreamLeaseWire.upstreamFromTribeApi(c.getHeaderField(UpstreamLeaseWire.TRIBE_API_HEADER)))
        } finally {
            c.disconnect()
        }
    }

    private fun readBounded(input: InputStream): ByteArray {
        val out = ByteArrayOutputStream()
        val buf = ByteArray(8192)
        while (out.size() < maxAnswerBytes) {
            val n = input.read(buf, 0, minOf(buf.size, maxAnswerBytes - out.size()))
            if (n < 0) break
            out.write(buf, 0, n)
        }
        return out.toByteArray()
    }

    private fun errorCode(e: Throwable?): String = when (e) {
        is SocketTimeoutException -> "timeout"
        is SSLException -> "tls"
        is UnknownHostException -> "dns"
        else -> "transport"
    }
}

// The upstream_lease of an upstream session is present but malformed: fail the start. `why` is a field
// name, never a value.
class UpstreamEnvelopeException(val why: String) : Exception("upstream_lease invalid: $why")

// The one entry class of the runtime lane (Xray.kt): see ~/avpn-build/plans/provider-pool/android-lease-api.md.
// upstreamLease == null = a provisional start: "pending" until onLeaseSet.
class UpstreamLeaseSession(
    profileId: String,
    upstreamLease: JSONObject?,
    meter: UpstreamMeter = TunnelInterfaceMeter(),
    onStatus: (JSONObject) -> Unit,
    private val log: (String) -> Unit = {},
    transport: UpstreamLeaseTransport = HttpsUpstreamTransport(),
    nowMs: () -> Long = { SystemClock.elapsedRealtime() },
    scheduler: UpstreamLeaseScheduler? = null,
) {
    private val lease: UpstreamLeaseEnvelope? = upstreamLease?.let {
        val (env, why) = UpstreamLeaseWire.parseLeaseEnvelope(it)
        env ?: throw UpstreamEnvelopeException(why)
    }
    private val renewer = UpstreamLeaseRenewer(profileId, transport, meter, nowMs, { onStatus(it.toJson()) }, log,
        scheduler = scheduler)
    private val startLock = Any()
    private var started = false

    // Once, right after the core and tun2socks run (the tunnel is up).
    fun start() {
        synchronized(startLock) {
            if (started) return
            started = true
        }
        if (lease != null) renewer.startActive(lease) else renewer.startPending()
    }

    // App message `upstream_lease_set` (contract section 2): only while pending. Returns the status.
    fun onLeaseSet(upstreamLease: JSONObject): JSONObject {
        start()
        val (env, why) = UpstreamLeaseWire.parseLeaseEnvelope(upstreamLease)
        if (env == null) {
            log("Tribe upstream: lease hand-over refused (field $why)")
            return renewer.status().toJson()
        }
        return renewer.handOver(env).toJson()
    }

    fun status(): JSONObject = renewer.status().toJson()

    // The IPC payloads of android-ipc-contract.md (lane P1), string in, string out:
    // ServiceEvent.UPSTREAM_STATUS = {"upstream": <status>} (compact JSON).
    fun statusEvent(): String = statusEventOf(status())

    // Action.UPSTREAM_LEASE_SET with the iOS provider message verbatim:
    // {"action":"upstream_lease_set","upstream_lease":{...}}. Returns the UPSTREAM_STATUS reply. A malformed
    // message changes nothing (the reply keeps `pending`).
    fun onLeaseSetMessage(message: String): String {
        val o = try {
            JSONObject(message)
        } catch (e: Exception) {
            null
        }
        val lease = o?.optJSONObject("upstream_lease")
        if (o == null || o.optString("action") != "upstream_lease_set" || lease == null) {
            log("Tribe upstream: lease hand-over message ignored (not an upstream_lease_set)")
            start()
            return statusEvent()
        }
        return statusEventOf(onLeaseSet(lease))
    }

    val isTerminal: Boolean
        get() = renewer.isTerminal

    // User disconnect: the bounded release BEFORE the core stops; completion runs once (<= 1.6 s).
    fun release(completion: () -> Unit) = renewer.release(completion)

    // The same, waiting for the completion. Never on the main thread.
    fun releaseBlocking() {
        val done = CountDownLatch(1)
        renewer.release { done.countDown() }
        done.await(UpstreamLeaseRenewer.RELEASE_TIMEOUT_MS + 500, TimeUnit.MILLISECONDS)
    }

    // End without a release (tunnel already gone, service destroyed). The status keeps a terminal code.
    fun close() = renewer.stop()

    internal val renewerForTest: UpstreamLeaseRenewer
        get() = renewer

    companion object {
        // {"upstream": <status>}: the ServiceEvent.UPSTREAM_STATUS payload for a status object of onStatus.
        fun statusEventOf(status: JSONObject): String = JSONObject().put("upstream", status).toString()

        // The whole start config of Xray.startVpn. null = not an upstream session (AWG, own Xray): nothing
        // to do. Throws UpstreamEnvelopeException when the session is upstream but its lease is malformed.
        fun fromEnvelope(envelope: JSONObject, meter: UpstreamMeter = TunnelInterfaceMeter(),
                         onStatus: (JSONObject) -> Unit, log: (String) -> Unit = {}): UpstreamLeaseSession? {
            val profileId = UpstreamLeaseWire.upstreamProfileId(envelope.opt("tribeSessionMetadata")) ?: return null
            if (profileId.isEmpty()) throw UpstreamEnvelopeException("profile_id")
            val lease = envelope.opt("upstream_lease")
            val leaseObject = when {
                UpstreamLeaseWire.isAbsent(lease) -> null
                lease is JSONObject -> lease
                else -> throw UpstreamEnvelopeException("not_object")
            }
            return UpstreamLeaseSession(profileId, leaseObject, meter, onStatus, log)
        }
    }
}

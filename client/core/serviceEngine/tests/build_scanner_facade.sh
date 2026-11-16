#!/bin/bash
# AVPN Scanner lane L6a: build + run the coordinator checks (tests/scanner_facade_check.cpp): TribeScanner +
# ScanApiClient end to end on a fake clock with a fake tribe-scan-v1 host, a fake HTTP server (signed
# manifest + ETag/304, token, signed probe-batch, release, outcomes) and a fake engine; one case drives the
# production QNAM layer against a local QTcpServer (the byte cut). QtCore + QtNetwork + libcrypto (a test key
# from a public seed, never a real key). No tunnel, no service, no device.
#   --mutate : every coordinator rule in MUTATIONS is broken one at a time in a copy of its source file; the
#              checks must fail for each (exit 0 only when every mutation is caught).
# QT_ROOT=$HOME/Qt/6.11.1/macos (default).
set -euo pipefail
QT="${QT_ROOT:-$HOME/Qt/6.11.1/macos}"
SSL="${OPENSSL_ROOT:-$(brew --prefix openssl@3)}"
HERE="$(cd "$(dirname "$0")" && pwd)"
SE="$(cd "$HERE/.." && pwd)"
CLIENT="$(cd "$HERE/../../.." && pwd)"
WORK="$(mktemp -d /tmp/tribe-scanner-facade.XXXXXX)"
trap 'rm -rf -- "${WORK:?}"' EXIT
ARCH_FLAGS=()
[ "$(uname -m)" = "arm64" ] && ARCH_FLAGS=(-include arm_acle.h)
FLAGS=(-std=c++17 -fPIC ${ARCH_FLAGS[@]+"${ARCH_FLAGS[@]}"} -Wall -Wextra -Wno-unused-parameter
  -I"$SE" -I"$CLIENT" -I"$QT/include" -I"$QT/lib/QtCore.framework/Headers" -I"$QT/lib/QtNetwork.framework/Headers"
  -I"$SSL/include" -F"$QT/lib")
LINK=(-F"$QT/lib" -framework QtCore -framework QtNetwork -L"$SSL/lib" -lcrypto -Wl,-rpath,"$QT/lib")

# Objects that never change between mutations: built once.
"$QT/libexec/moc" -f"TribeScanner.h" "$SE/TribeScanner.h" -o "$WORK/moc_TribeScanner.cpp"
"$QT/libexec/moc" -f"ScanApiClient.h" "$SE/ScanApiClient.h" -o "$WORK/moc_ScanApiClient.cpp"
"$QT/libexec/moc" -f"UpstreamLeaseClient.h" "$SE/UpstreamLeaseClient.h" -o "$WORK/moc_UpstreamLeaseClient.cpp"
for src in "$SE/Ed25519Verify.cpp" "$WORK/moc_TribeScanner.cpp" "$WORK/moc_ScanApiClient.cpp" \
           "$WORK/moc_UpstreamLeaseClient.cpp" "$HERE/scanner_facade_check.cpp"; do
  clang++ "${FLAGS[@]}" -c "$src" -o "$WORK/$(basename "${src%.cpp}").o" &
done
wait
FIXED=("$WORK/Ed25519Verify.o" "$WORK/moc_TribeScanner.o" "$WORK/moc_ScanApiClient.o"
  "$WORK/moc_UpstreamLeaseClient.o" "$WORK/scanner_facade_check.o")

# $1 = directory with TribeScanner.cpp + ScanApiClient.cpp + UpstreamLeaseClient.cpp, $2 = output binary.
build_with() {
  clang++ "${FLAGS[@]}" -c "$1/TribeScanner.cpp" -o "$1/TribeScanner.o" &
  clang++ "${FLAGS[@]}" -c "$1/ScanApiClient.cpp" -o "$1/ScanApiClient.o" &
  clang++ "${FLAGS[@]}" -c "$1/UpstreamLeaseClient.cpp" -o "$1/UpstreamLeaseClient.o" &
  wait
  clang++ "${FIXED[@]}" "$1/TribeScanner.o" "$1/ScanApiClient.o" "$1/UpstreamLeaseClient.o" "${LINK[@]}" -o "$2"
}

if [ "${1:-}" = "--mutate" ]; then
  mkdir -p "$WORK/base"
  cp "$SE/TribeScanner.cpp" "$SE/ScanApiClient.cpp" "$SE/UpstreamLeaseClient.cpp" "$WORK/base/"
  build_with "$WORK/base" "$WORK/base/check"
  QT_PLUGIN_PATH="$QT/plugins" "$WORK/base/check" >/dev/null 2>&1 || { echo "baseline checks fail - fix them before mutating"; exit 1; }
  # name@@file@@from@@to   (literal text of the file; "\n" = newline; each "from" must occur exactly once;
  # several sites: name@@file@@from1@@to1%%from2@@to2)
  MUTATIONS=(
    "abandoned-manifest-bytes-dropped@@TribeScanner.cpp@@        dispatch(m_m.appRequestDone(id, r.bytes, t));\n        return;@@        return;"
    "no-poll-while-draining@@TribeScanner.cpp@@if (!(running && it.key() == m_m.scanId()) && !m_m.draining()) {@@if (!(running && it.key() == m_m.scanId())) {"
    "connect-row-without-user-origin@@TribeScanner.cpp@@m_engine->connectRow(a.nodeId, a.ids, a.hintTtlMs, a.userOrigin, a.forceConnect);@@m_engine->connectRow(a.nodeId, a.ids, a.hintTtlMs, false, a.forceConnect);"
    "connect-row-without-force@@TribeScanner.cpp@@m_engine->connectRow(a.nodeId, a.ids, a.hintTtlMs, a.userOrigin, a.forceConnect);@@m_engine->connectRow(a.nodeId, a.ids, a.hintTtlMs, a.userOrigin, false);"
    "connect-row-dropped@@TribeScanner.cpp@@        m_engine->connectRow(a.nodeId, a.ids, a.hintTtlMs, a.userOrigin, a.forceConnect);\n@@"
    "cancel-pending-connect-dropped@@TribeScanner.cpp@@        m_engine->cancelPendingConnect();\n@@"
    "user-connect-for-scan-dropped@@TribeScanner.cpp@@        m_engine->userConnectForScan();\n@@"
    "freeze-ack-not-delivered@@TribeScanner.cpp@@            self->hostEvent(\"host_freeze_ack\", scanId, self->m_m.hostFreezeAck(scanId, r.bytesSpent, r.bytesReserved, self->now()));@@            ;"
    "cancel-ack-final-not-delivered@@TribeScanner.cpp@@            self->hostEvent(\"host_cancel_ack\", scanId, self->m_m.hostCancelAck(scanId, r.bytesSpent, self->now()));\n            return;@@            return;"
    "host-gen-change-not-folded@@TribeScanner.cpp@@    setHostGen(g);\n    notifyNetwork();\n}@@}"
    "refusal-code-lost@@TribeScanner.cpp@@self->m_m.probeLeaseRefused(cand, it.code, self->now())@@self->m_m.probeLeaseRefused(cand, QString(), self->now())"
    "release-without-lease-ids@@TribeScanner.cpp@@            leaseIds << it->leaseId;\n@@"
    "token-of-abandoned-manifest@@TribeScanner.cpp@@    if (id != m_manifestReqId) {@@    if (r.ok) m_active.token = r.scanToken;\n    if (id != m_manifestReqId) {"
    "sticky-access-from-older-scan@@TribeScanner.cpp@@        in.access = ScanAccess(); // the host's own attempt@@        in.access = g_stickyAccess; // the host's own attempt%%void TribeScanner::deliverProgress(ScanHostProgress p, const HostAsk &ask, const QString &startToken)\n{@@void TribeScanner::deliverProgress(ScanHostProgress p, const HostAsk &ask, const QString &startToken)\n{\n    if (p.access.hasFacts()) g_stickyAccess = p.access.facts;%%QString scanCacheStoreKey(@@static ScanAccess g_stickyAccess;\nQString scanCacheStoreKey("
    "tick-not-delivered@@TribeScanner.cpp@@        dispatch(m_m.tick(t)); // a wake-up@@        afterStep(); // a wake-up"
    "caps-not-applied@@TribeScanner.cpp@@            self->m_m.setCaps(caps); // the machine is built@@            ; // the machine is built"
    "view-wake-ignored@@TribeScanner.cpp@@    for (qint64 t : {m_machineWake, m_viewWake, m_shadeWake, m_nextPollAt, m_heldUntil, m_resolveUntil})@@    for (qint64 t : {m_machineWake, m_shadeWake, m_nextPollAt, m_heldUntil, m_resolveUntil})"
    "host-start-on-unavailable@@TribeScanner.cpp@@    if (!m_host || m_host->availability() != ScanHostAvailability::Available) {\n        emitLog(QStringLiteral(\"action start_host_scan refused@@    if (!m_host) {\n        emitLog(QStringLiteral(\"action start_host_scan refused"
    "url-logged@@ScanApiClient.cpp@@    rq.maxBytes = run->left();\n    QPointer<ScanApiClient> self(this);\n    m_http->send(rq, [self, run](const IScanHttp::Response &r) {\n        if (!self)\n            return;\n        run->spent += r.bytes;\n        run->result.statusManifest@@    rq.maxBytes = run->left();\n    emitLog(rq.url);\n    QPointer<ScanApiClient> self(this);\n    m_http->send(rq, [self, run](const IScanHttp::Response &r) {\n        if (!self)\n            return;\n        run->spent += r.bytes;\n        run->result.statusManifest"
    "if-none-match-not-sent@@ScanApiClient.cpp@@        rq.headers << qMakePair(QByteArrayLiteral(\"If-None-Match\"), run->stored.etag);@@        ;"
    "stored-token-after-304@@ScanApiClient.cpp@@        run->result.scanToken = token;\n        run->result.tokenExpiresAtMs@@        run->result.scanToken = run->stored.obj.value(QLatin1String(\"scan_token\")).toObject().value(QLatin1String(\"token\")).toString();\n        run->result.tokenExpiresAtMs"
    "manifest-signature-not-checked@@ScanApiClient.cpp@@    if (!verifyDetachedWithContext(key, QLatin1String(kScanManifestSigContext), body, sig))\n        return false;@@"
    "batch-signature-not-checked@@ScanApiClient.cpp@@            if (!sigOk || o.value@@            if (o.value"
    "batch-cut-missing@@ScanApiClient.cpp@@    rq.body = QJsonDocument(QJsonObject{{QStringLiteral(\"profile_ids\"), arr}, {QStringLiteral(\"include_config\"), includeConfig}})\n                  .toJson(QJsonDocument::Compact);\n    rq.maxBytes = costBytes;@@    rq.body = QJsonDocument(QJsonObject{{QStringLiteral(\"profile_ids\"), arr}, {QStringLiteral(\"include_config\"), includeConfig}})\n                  .toJson(QJsonDocument::Compact);"
    "revision-refetch-skipped@@ScanApiClient.cpp@@        if (rev > run->stored.revision && !run->refetched) {@@        if (false) {"
    "release-bytes-not-reported@@TribeScanner.cpp@@[self, reqId](qint64 bytes) {\n        if (self)\n            self->dispatch(self->m_m.appRequestDone(reqId, bytes, self->now()));@@[self, reqId](qint64 bytes) {\n        if (self)\n            ;"
    "outcomes-bytes-not-reported@@TribeScanner.cpp@@[self, reqId](int, qint64 bytes) {\n        if (self)\n            self->dispatch(self->m_m.appRequestDone(reqId, bytes, self->now()));@@[self, reqId](int, qint64 bytes) {\n        if (self)\n            ;"
    "batch-bytes-not-reported@@TribeScanner.cpp@@        self->dispatch(self->m_m.appRequestDone(reqId, b.bytes, self->now()));@@        ;"
    "start-refusal-as-accepted@@TribeScanner.cpp@@    machineStartNotTaken(id, r.error, scanHostFailureDetail(r));@@    it->state = HostStart::Accepted;\n    dispatch(m_m.hostFailed(id, r.error, now(), true, scanHostFailureDetail(r)));"
    "unreached-start-as-accepted@@TribeScanner.cpp@@m_m.hostFailed(a.scanId, hostUnavailableError(), t, /*startAccepted=*/false)@@m_m.hostFailed(a.scanId, hostUnavailableError(), t)"
    "host-death-not-reported@@TribeScanner.cpp@@        dispatch(m_m.hostFailed(sid, hostUnavailableError(), now()));@@        ;"
    "lost-scan-ignored@@TribeScanner.cpp@@if (r.error != ScanHostError::UnknownScan || running)@@if (r.error != ScanHostError::UnknownScan)"
    "dead-host-polled@@TribeScanner.cpp@@        if (it->pollInFlight || !hostUp || startUnanswered(it.key()))@@        if (it->pollInFlight || startUnanswered(it.key()))"
    "caps-gen-ignored@@TribeScanner.cpp@@                self->m_capsGenKnown = true;@@                ;"
    "unavailable-host-started@@TribeScanner.cpp@@    if (r.ok && m_host && m_host->availability() == ScanHostAvailability::Unavailable) {@@    if (false) {"
    "version-reason-collapsed@@TribeScanner.cpp@@        return hostReason;\n    return QStringLiteral(\"service_off\");@@        return QStringLiteral(\"service_off\");\n    return QStringLiteral(\"service_off\");"
    "connecting-not-waited@@TribeScanner.cpp@@        && m_host->unavailableReason() == QLatin1String(\"connecting\")) {\n        // The desktop service@@        && false) {\n        // The desktop service"
    "connecting-wait-unbounded@@TribeScanner.cpp@@    if (m_heldUntil >= 0 && t >= m_heldUntil)\n        resolveHeld(true);@@"
    "held-not-resumed-when-ready@@TribeScanner.cpp@@                if (self)\n                    self->resolveHeld(false);@@                Q_UNUSED(self);"
    "poll-refusal-ends-scan@@TribeScanner.cpp@@    if (refusedRound) {@@    if (false) {"
    "shutting-down-as-round@@TribeScanner.cpp@@(r.errorCode == QLatin1String(\"ipc_refused\") && r.detail != QLatin1String(\"shutting_down\"))@@r.errorCode == QLatin1String(\"ipc_refused\")"
    "row-version-missing@@TribeScanner.cpp@@        r.insert(QStringLiteral(\"version\"), v.rows.at(i).transportVersion);@@        ;"
    "card-server-label-missing@@TribeScanner.cpp@@        card.insert(QStringLiteral(\"server_label\"), v.card.serverLabel);@@        ;"
    "country-name-missing@@TribeScanner.cpp@@        c.insert(QStringLiteral(\"name\"), doctor::countryDisplayName(c.value(QLatin1String(\"cc\")).toString(), lang));@@        ;"
    "return-home-flag-ignored@@TribeScanner.cpp@@    m_returnHome = home;@@    Q_UNUSED(home);"
    "network-shade-missing@@TribeScanner.cpp@@    if (m_m.screenOpen() && (restarted || resultsVoided)) {@@    if (false) {"
    "network-shade-results-missing@@TribeScanner.cpp@@    if (m_m.screenOpen() && (restarted || resultsVoided)) {@@    if (m_m.screenOpen() && restarted) {"
    "builder-refusal-not-reported@@TribeScanner.cpp@@    for (const auto &x : refused)\n        dispatch(m_m.candidateRefused(x.first, x.second, now()));\n}@@}"
    "awg-api-ip-not-from-base@@TribeScanner.cpp@@    in.probeIp = m_active.baseIps.isEmpty() ? QString() : m_active.baseIps.first();@@    in.probeIp = QString();"
    "awg-echo-target-dropped@@TribeScanner.cpp@@    in.echoTarget = c.awgEchoTarget;\n    return in;@@    in.echoTarget = QStringLiteral(\"10.9.9.9\");\n    return in;"
    "base-ips-not-passed@@TribeScanner.cpp@@        in.probeBaseIps = baseIps;@@        ;"
    "engine-ips-ignored@@TribeScanner.cpp@@scanBaseIpsOf(m_engine->knownHostIps(host))@@QStringList()"
    "resolve-bound-ignored@@TribeScanner.cpp@@        finishResolve(QStringList()); // the name did not resolve in time@@        ; // the name did not resolve in time"
    "host-detail-not-passed@@TribeScanner.cpp@@    machineStartNotTaken(id, r.error, scanHostFailureDetail(r));@@    machineStartNotTaken(id, r.error, QString());"
    "report-refused-not-forwarded@@TribeScanner.cpp@@    dispatch(m_m.reportCheckRefused(reportId, reason, now()));@@    Q_UNUSED(reportId); Q_UNUSED(reason);"
    "speed-budget-skipped@@TribeScanner.cpp@@    if (!admitOutsideScan(cost + (tokenOk ? 0 : qint64(t.costApiBytes)), &cellular))\n        return fail(\"budget\");@@    admitOutsideScan(0, &cellular);"
    "speed-not-charged@@TribeScanner.cpp@@        self->chargeOutsideScan(cost, cellular);@@        ;"
    "speed-token-not-fetched@@TribeScanner.cpp@@    if (tokenOk) {\n        run(token);\n        return;\n    }@@    if (true) {\n        run(token);\n        return;\n    }"
    "speed-without-live-tunnel@@TribeScanner.cpp@@    if (!c.working())\n        return fail(\"no_tunnel\");@@"
    "speed-digest-trusted@@ScanApiClient.cpp@@                     && d.bodySha256Hex.toLower() == tribeProbeExpectedSha256Hex(rq.nonce, rq.bytes);@@;"
    "awg-live-peer-as-failure@@TribeScanner.cpp@@    if (attempt == HostAttempt::First && scanAwgLivePeerUnknown(r) && scanHasAwg(req.candidates) && running) {@@    if (false) {"
    "awg-live-peer-retry-keeps-awg@@TribeScanner.cpp@@        if (c.kind == ScanProbeKind::AwgMini)\n            dropped << c.id;\n        else\n            again.candidates << c;@@        again.candidates << c;"
    "manifest-failure-worst-case@@TribeScanner.cpp@@        dispatch(m_m.manifestUnavailable(r.reason, t, r.bytes));@@        dispatch(m_m.manifestUnavailable(r.reason, t));"
    "manifest-404-as-service-off@@ScanApiClient.cpp@@            run->result.reason = QStringLiteral(\"scanner_off\");@@            run->result.reason = QStringLiteral(\"service_off\");"
    "token-404-as-unavailable@@ScanApiClient.cpp@@                                 : r.status == 404 ? QStringLiteral(\"scanner_off\")@@                                 : r.status == 404 ? QStringLiteral(\"manifest_unavailable\")"
    "server-off-not-sticky@@TribeScanner.cpp@@            m_serverOff = true;@@            ;"
    "server-off-never-cleared@@TribeScanner.cpp@@    m_serverOff = false; // the switches changed@@    ; // the switches changed"
    "stale-live-probe-delivered@@TribeScanner.cpp@@                         if (self->bindingCurrent(asked))\n                             self->dispatch(self->m_m.liveProbeResult@@                         if (true)\n                             self->dispatch(self->m_m.liveProbeResult"
    "stale-batch-applied@@TribeScanner.cpp@@        if (!self->bindingCurrent(asked)) {\n            // A reply of an older scan@@        if (false) {\n            // A reply of an older scan"
    "stale-seats-kept@@TribeScanner.cpp@@            self->releaseStaleLeases(stale);@@            ;"
    "light-ask-id-ignored@@TribeScanner.cpp@@    if (askId != m_lightAskId) {@@    if (false) {"
    "wire-cap-ignored@@UpstreamLeaseClient.cpp@@    const qint64 wireCap = pr.maxWireBytes;@@    const qint64 wireCap = -1;"
    "headers-not-counted@@UpstreamLeaseClient.cpp@@        facts->wireBytes += h;@@        ;"
    "live-spent-clamped@@ScanApiClient.cpp@@            f.spentBytes = base + w.wireBytes; // what really came@@            f.spentBytes = qMin(costBytes, base + w.wireBytes); // what really came"
    "live-allowance-not-passed@@ScanApiClient.cpp@@    warm.maxWireBytes = wireLeft;@@    ;"
    "not-now-treated-as-host-failed@@TribeScanner.cpp@@    if (attempt != HostAttempt::NotNowRetry && scanHostNotNow(r) && running) {\n        holdStart(ask, req, r);@@    if (false) {\n        holdStart(ask, req, r);"
    "not-now-retry-loop@@TribeScanner.cpp@@        finishHeldStart(id, &r); // the second refusal: no third attempt@@        holdStart(ask, req, r); // the second refusal: no third attempt"
    "not-now-no-retry@@TribeScanner.cpp@@            emitLog(QStringLiteral(\"host start: once more\"));\n            sendStart(h.ask, h.start, HostAttempt::NotNowRetry);@@            finishHeldStart(h.ask.hostScanId, nullptr);"
    "not-now-ignores-vpn-event@@TribeScanner.cpp@@    fireNotNow(true); // a start refused with tunnel_changed@@    ; // a start refused with tunnel_changed"
    "not-now-held-start-polled@@TribeScanner.cpp@@        if (it->pollInFlight || !hostUp || startUnanswered(it.key()))@@        if (it->pollInFlight || !hostUp)"
    "not-now-stop-freezes-host@@TribeScanner.cpp@@    if (it != m_records.end() && (it->state == HostStart::Held || it->state == HostStart::Refused)) {@@    if (false) {"
    "teardown-pending-unknown@@TribeScanner.cpp@@               || r.errorCode == QLatin1String(\"teardown_pending\"));@@               || false);"
    "not-now-add-refused-at-once@@TribeScanner.cpp@@        holdAdd(ask, cands, r); // once more@@        refuseAdd(ask, QStringLiteral(\"host_busy\")); // once more"
    "engine-stopping-unknown@@TribeScanner.cpp@@               || r.detail == QLatin1String(\"stopping\")              // the engine@@               || false              // the engine"
    "stale-epoch-on-a-timer@@TribeScanner.cpp@@    return r.errorCode == QLatin1String(\"tunnel_changed\") || r.errorCode == QLatin1String(\"stale_epoch\");@@    return r.errorCode == QLatin1String(\"tunnel_changed\");"
    "awg-withheld-ignored@@TribeScanner.cpp@@            self->m_awgWithheld = (w.isBool() && w.toBool()) || (w.isString() && !w.toString().isEmpty());@@            self->m_awgWithheld = false;"
    "report-fact-unbound@@TribeScanner.cpp@@    if (reportId.isEmpty() || reportId != m_checkReportId || !bindingCurrent(m_checkAsked)) {@@    if (false) {"
    "report-fact-new-scan-kept@@TribeScanner.cpp@@    if (reportId.isEmpty() || reportId != m_checkReportId || !bindingCurrent(m_checkAsked)) {@@    if (reportId.isEmpty() || reportId != m_checkReportId) {"
    "awg-withheld-reason-lost@@TribeScanner.cpp@@            *refused << qMakePair(scanProbeIdOf(c), m_awgWithheldReason);@@            *refused << qMakePair(scanProbeIdOf(c), QStringLiteral(\"config\"));"
    "held-add-unbound@@TribeScanner.cpp@@void TribeScanner::refuseAdd(const HostAsk &ask, const QString &reason)\n{\n    if (!bindingCurrent(ask.binding)) {@@void TribeScanner::refuseAdd(const HostAsk &ask, const QString &reason)\n{\n    if (false) {"
    "sent-retry-settled-as-never-taken@@TribeScanner.cpp@@    if (it != m_records.end() && (it->state == HostStart::Held || it->state == HostStart::Refused)) {@@    if (it != m_records.end() && (it->state == HostStart::Held || it->state == HostStart::Refused || it->state == HostStart::InFlight)) {"
    "late-accept-not-cancelled@@TribeScanner.cpp@@            if (it->settled && r.kind == ScanHostReplyKind::Ack && !it->cancelAcked && !it->cancelInFlight)\n                sendRecordCancel(id);@@            ;"
    "unconfirmed-unknown-not-zero@@TribeScanner.cpp@@    else\n        settleRecord(ask.hostScanId, HostCharge::NotTaken);@@    else\n        settleRecord(ask.hostScanId, HostCharge::Conservative);"
    "wire-read-and-buffer-unbounded@@UpstreamLeaseClient.cpp@@                want = qMin(want, left());@@                ;%%            r->setReadBufferSize(qMin(kChunk, left())); // never 0@@            ; // never 0%%        r->setReadBufferSize(qMin(kChunk, qMax<qint64>(1, wireCap))); // before the event loop@@        ; // before the event loop"
    "wire-left-zero-read-on@@UpstreamLeaseClient.cpp@@                if (left() <= 0) {\n                    if (r->bytesAvailable() > 0 || r->isRunning())\n                        cut(); // nothing is left of the allowance: stop at once\n                    return;\n                }@@"
    "live-probe-digest-trusted@@ScanApiClient.cpp@@                      && d.bodySha256Hex.toLower() == tribeProbeExpectedSha256Hex(data.nonce, data.bytes);@@;"
    "binding-read-at-reply-time@@TribeScanner.cpp@@        handler(ask, reply);\n        self->driveRecords();@@        HostAsk late = ask;\n        late.binding = self->bindingNow();\n        handler(late, reply);\n        self->driveRecords();"
    "settlement-not-idempotent@@TribeScanner.cpp@@        const qint64 add = target - qMax<qint64>(0, rec.charged);@@        const qint64 add = target;"
    "possibly-accepted-settled-at-zero@@TribeScanner.cpp@@        it->ours = true;@@        it->ours = false;"
    "conservative-charge-zero@@TribeScanner.cpp@@        target = rec.grant >= 0 ? rec.grant : qMax<qint64>(0, rec.lastSpent + rec.lastReserved);@@        target = 0;"
    "unknown-overtaking-start-conclusive@@TribeScanner.cpp@@    if (it == m_records.end() || !it->ours || it->settled || !ask.afterStartReply)@@    if (it == m_records.end() || !it->ours || it->settled)"
    "later-start-ignored@@TribeScanner.cpp@@    if (it->state == HostStart::Accepted || it->laterStart)@@    if (it->state == HostStart::Accepted)"
    "tombstone-never-expires@@TribeScanner.cpp@@        if ((done && it->pending == 0) || (it->dropAt >= 0 && t >= it->dropAt))@@        if (done && it->pending == 0)"
    "record-deadline-ignored@@TribeScanner.cpp@@        if (it->deadline >= 0 && t >= it->deadline) {\n            settleRecord(id, HostCharge::Conservative);@@        if (false) {\n            settleRecord(id, HostCharge::Conservative);"
    "progress-gen-folded-before-ownership@@TribeScanner.cpp@@    if (p.hasGen && owned)\n        foldHostGen(p.gen, true);@@    if (p.hasGen)\n        foldHostGen(p.gen, true);"
    "host-gen-moved-back@@TribeScanner.cpp@@    if (hostGenStale(g)) {@@    if (false) {"
    "left-epoch-forgotten@@TribeScanner.cpp@@        m_hostGenLeft << m_hostGen;\n@@"
    "held-start-stopped-kept-held@@TribeScanner.cpp@@        it->state = HostStart::Refused; // the held retry is never sent now\n@@"
  )
  caught=0; missed=0; broken=0
  printf '%-38s %s\n' "mutation" "result"
  for m in "${MUTATIONS[@]}"; do
    name="${m%%@@*}"; rest="${m#*@@}"; file="${rest%%@@*}"; sites="${rest#*@@}"
    if [ -n "${MUT_ONLY:-}" ] && [ "$name" != "$MUT_ONLY" ]; then continue; fi
    dir="$WORK/m-$name"; mkdir -p "$dir"
    cp "$SE/TribeScanner.cpp" "$SE/ScanApiClient.cpp" "$SE/UpstreamLeaseClient.cpp" "$dir/"
    if ! SITES="$sites" python3 -I - "$dir/$file" <<'PY'
import os, sys
path = sys.argv[1]
src = open(path, encoding="utf-8").read()
for site in os.environ["SITES"].split("%%"):
    frm, to = site.split("@@", 1)
    frm = frm.replace("\\n", "\n")
    to = to.replace("\\n", "\n")
    n = src.count(frm)
    if n != 1:
        sys.stderr.write("pattern occurs %d times: %r\n" % (n, frm[:60]))
        sys.exit(3)
    src = src.replace(frm, to)
open(path, "w", encoding="utf-8").write(src)
PY
    then
      printf '%-38s %s\n' "$name" "NOT APPLIED"; broken=$((broken + 1)); continue
    fi
    if ! build_with "$dir" "$dir/check" 2>"$dir/build.log"; then
      printf '%-38s %s\n' "$name" "BUILD FAILED"; head -5 "$dir/build.log"; broken=$((broken + 1)); continue
    fi
    if QT_PLUGIN_PATH="$QT/plugins" "$dir/check" >"$dir/run.log" 2>&1; then
      printf '%-38s %s\n' "$name" "MISSED"; missed=$((missed + 1))
    else
      first="$(grep -m1 -E '^FAIL|LEAK' "$dir/run.log" | sed -E 's#^FAIL [^ ]*/([^/ ]+:[0-9]+)#\1#' | cut -c1-90 || true)"
      printf '%-38s caught (%s)\n' "$name" "${first:-non-zero exit}"; caught=$((caught + 1))
    fi
  done
  echo ">>> mutations: ${#MUTATIONS[@]}, caught $caught, missed $missed, not applied/build $broken"
  [ "$missed" -eq 0 ] && [ "$broken" -eq 0 ]
  exit $?
fi

mkdir -p "$WORK/main"
cp "$SE/TribeScanner.cpp" "$SE/ScanApiClient.cpp" "$SE/UpstreamLeaseClient.cpp" "$WORK/main/"
build_with "$WORK/main" "$WORK/scanner_facade_check"
echo ">>> build ok"
QT_PLUGIN_PATH="$QT/plugins" "$WORK/scanner_facade_check"

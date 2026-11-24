#!/bin/bash
# AVPN (owner's Mac 24.11.2026: the crash in the tun2socks stderr reader, the 30 s quit with own Xray up, the
# orphan tun2socks the service could not end). The rules are tested by behaviour in tun2socks_reader_check.cpp
# (build_tun2socks_reader.sh) and ipc_process_owner_check.cpp (build_ipc_process_owner.sh); what is checked
# here is where they are CALLED FROM - each line below fails if its call site is reverted.
#   Q1  XrayProtocol reads the tun2socks stderr only through ProcessStderrReader: no blocking read, no own
#       readyReadStandardError handler, no disconnect of the wrong signal;
#   Q2  the finished handler reads stdout without waiting; the routing is set up once per tun2socks;
#   Q3  every step after an IPC wait checks that its session is still the current one (start, the routing,
#       the retry, the end of the routing setup);
#   Q4  stop() cuts the replica off before the teardown, tears the service down once per session and never
#       waits on the replica of another thread; no waitForFinished(1000) on the replica;
#   Q5  the service ends a previous instance by handle before a start (macOS/Linux); pkill by name only on
#       Windows; terminate/kill/close count as a requested end;
#   Q6  the service binds a child to its controlling connections and, when a tun2socks loses its client without
#       a stop, ends that Xray session in XrayProtocol::stop's order, then the child; not during its shutdown;
#   Q7  macOS quit: a session the daemon does not hold by itself (not WireguardProtocol) is ended on the
#       VpnConnection thread while it runs; Windows/Linux keep upstream's disconnect.
# Run by the check sweep (every check_*.sh of this directory).
set -eu
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../../../.." && pwd)"
XP="$ROOT/client/core/protocols/xrayProtocol.cpp"
XH="$ROOT/client/core/protocols/xrayProtocol.h"
PROC="$ROOT/ipc/ipcserverprocess.cpp"
SRV="$ROOT/ipc/ipcserver.cpp"
APP="$ROOT/client/amneziaApplication.cpp"
fail=0
bad() { echo "FAIL: $1"; fail=1; }
code() { grep -v '^[[:space:]]*//' "$1" || true; }
# The body of a C++ function: from its definition line to the first line that is exactly "}".
body() { code "$1" | awk -v sig="$2" 'index($0, sig) == 1 { on = 1 } on { print } on && /^}$/ { exit }'; }
has() { printf '%s\n' "$1" | grep -F -- "$2" > /dev/null; }
cnt() { printf '%s\n' "$1" | grep -cF -- "$2" || true; }
# Line number of the first line of $1 (text) containing fixed string $2; 0 when absent.
at() { local n; n="$(printf '%s\n' "$1" | grep -nF -- "$2" | head -1 | cut -d: -f1)"; echo "${n:-0}"; }

xp="$(code "$XP")"
start="$(body "$XP" 'ErrorCode XrayProtocol::start()')"
stop="$(body "$XP" 'void XrayProtocol::stop()')"
tun="$(body "$XP" 'ErrorCode XrayProtocol::startTun2Socks(quint64 session)')"
lines="$(body "$XP" 'void XrayProtocol::onTun2SocksLines(quint64 session, const QList<QByteArray> &lines)')"
finished="$(body "$XP" 'void XrayProtocol::onTun2SocksFinished(quint64 session, int exitCode, QProcess::ExitStatus exitStatus)')"
exitb="$(body "$XP" 'void XrayProtocol::onTun2SocksExit(quint64 session, bool resourceBusy, int exitCode, QProcess::ExitStatus exitStatus)')"
routing="$(body "$XP" 'ErrorCode XrayProtocol::setupRouting(quint64 session)')"

# ---- Q1 ------------------------------------------------------------------------------------------------
[ "$(cnt "$xp" 'readAllStandardError(')" = "0" ] || bad "Q1: XrayProtocol reads the tun2socks stderr itself (a blocking read in a queued slot)"
[ "$(cnt "$xp" 'IpcProcessInterfaceReplica::readyReadStandardError')" = "0" ] || bad "Q1: XrayProtocol handles readyReadStandardError itself"
[ "$(cnt "$xp" 'readyReadStandardOutput')" = "0" ] || bad "Q1: the disconnect of readyReadStandardOutput (a signal nobody connects) is back"
has "$tun" 'new avpn::ProcessStderrReader(' || bad "Q1: startTun2Socks does not read the stderr through ProcessStderrReader"
has "$tun" 'onTun2SocksLines(session, lines);' || bad "Q1: the reader's lines do not reach onTun2SocksLines with their session"

# ---- Q2 ------------------------------------------------------------------------------------------------
has "$finished" 'new QRemoteObjectPendingCallWatcher(m_tun2socksProcess->readAllStandardOutput(), this);' \
    || bad "Q2: the finished handler does not read stdout through a pending-call watcher"
[ "$(cnt "$finished" 'waitForFinished')" = "0" ] || bad "Q2: the finished handler waits on the service"
has "$finished" 'onTun2SocksExit(session, resourceBusy, exitCode, exitStatus);' || bad "Q2: the exit decision is not taken on the read's completion"
has "$lines" 'if (!stackUp || m_tun2socksStackUp)' || bad "Q2: the routing is not set up once per tun2socks"
has "$tun" 'm_tun2socksStackUp = false;' || bad "Q2: a new tun2socks does not reset the routing mark"

# ---- Q3 ------------------------------------------------------------------------------------------------
has "$start" 'const quint64 session = ++m_session;' || bad "Q3: start() does not open a new session"
has "$start" 'if (!self || m_session != session)' || bad "Q3: start() goes on after xrayStart without checking its session"
has "$tun" 'if (!self || m_session != session)' || bad "Q3: startTun2Socks goes on after creating the replica without checking its session"
[ "$(cnt "$routing" 'if (ended()) return ErrorCode::NoError;')" -ge 4 ] || bad "Q3: setupRouting does not check its session between the steps"
has "$routing" 'const auto ended = [&]() { return !self || m_session != session; };' || bad "Q3: setupRouting's session check changed"
lr=$(at "$lines" 'const ErrorCode res = setupRouting(session);')
lc=$(at "$lines" 'return; // stopped (or destroyed) while the routing was being set up')
[ "$lr" -gt 0 ] && [ "$lc" -gt "$lr" ] || bad "Q3: onTun2SocksLines acts on the routing result without checking its session"
has "$exitb" 'const ErrorCode err = startTun2Socks(session);' || bad "Q3: the retry does not keep its session"
has "$exitb" 'if (!self || m_session != session)' || bad "Q3: the retry acts on its result without checking its session"

# ---- Q4 ------------------------------------------------------------------------------------------------
bump=$(at "$stop" '++m_session;')
cut=$(at "$stop" 'QObject::disconnect(m_tun2socksProcess.data(), nullptr, this, nullptr);')
teardown=$(at "$stop" 'iface->disableKillSwitch();')
[ "$bump" -gt 0 ] && [ "$cut" -gt "$bump" ] && [ "$teardown" -gt "$cut" ] \
    || bad "Q4: stop() does not end the session and cut the replica off before the teardown"
has "$stop" 'const bool tearDown = std::exchange(m_sessionOpen, false);' || bad "Q4: stop() tears the service down more than once per session"
has "$stop" 'if (tearDown) {' || bad "Q4: the teardown is not gated by the session"
has "$stop" 'm_tun2socksReader->stop();' || bad "Q4: stop() does not stop the reader"
[ "$(cnt "$stop" 'waitForFinished(1000)')" = "0" ] || bad "Q4: stop() waits on the tun2socks replica again (30 s on quit)"
has "$stop" 'if (QThread::currentThread() == process->thread()) {' || bad "Q4: stop() uses the replica from another thread"
has "$stop" 'delivered.waitForFinished(tun2socksStopReplyMs);' || bad "Q4: the one round trip of stop() is not bounded"
grep -qF 'static constexpr int tun2socksStopReplyMs = 1000;' "$XH" || bad "Q4: the bound of stop()'s round trip changed"
has "$stop" 'std::exchange(m_tun2socksProcess, {});' || bad "Q4: the replica is not taken out before the waits"

# ---- Q5 ------------------------------------------------------------------------------------------------
pstart="$(body "$PROC" 'void IpcServerProcess::start()')"
w=$(at "$pstart" '#ifdef Q_OS_WIN')
k=$(at "$pstart" 'Utils::killProcessByName(m_process->program());')
e=$(at "$pstart" '#else')
o=$(at "$pstart" 'avpn::OwnedChildren::service().endOthersOf(m_program, m_process.data())')
s=$(at "$pstart" 'm_process->start();')
[ "$w" -gt 0 ] && [ "$k" -gt "$w" ] && [ "$e" -gt "$k" ] && [ "$o" -gt "$e" ] && [ "$s" -gt "$o" ] \
    || bad "Q5: IpcServerProcess::start does not end the previous instance by handle (pkill by name outside Windows?)"
[ "$(code "$PROC" | grep -cF 'killProcessByName')" = "1" ] || bad "Q5: killProcessByName is called outside the Windows branch"
for f in terminate kill close; do
  has "$(body "$PROC" "void IpcServerProcess::$f()")" 'm_control.onEndRequested();' || bad "Q5: $f() does not count as a requested end"
done
code "$PROC" | grep -qF 'avpn::OwnedChildren::service().add(m_process.data(), m_program);' || bad "Q5: a child is not registered"
code "$PROC" | grep -qF 'avpn::OwnedChildren::service().remove(m_process.data());' || bad "Q5: a child is not unregistered"
has "$(body "$PROC" 'void IpcServerProcess::setProgram(int programId)')" 'avpn::OwnedChildren::service().setProgram(m_process.data(), m_program);' \
    || bad "Q5: the registry does not learn the program"

# ---- Q6 ------------------------------------------------------------------------------------------------
create="$(body "$SRV" 'int IpcServer::createPrivilegedProcess()')"
has "$create" 'process->controllerConnected();' || bad "Q6: a connection to a privileged process does not count as its controller"
has "$create" '[this, process]() { onProcessControllerLost(process); }, Qt::SingleShotConnection);' \
    || bad "Q6: the end of a controlling connection does not reach onProcessControllerLost"
lost="$(body "$SRV" 'void IpcServer::onProcessControllerLost(IpcServerProcess *process)')"
has "$lost" 'if (m_closing)' || bad "Q6: the service's own shutdown is taken for a lost client"
has "$lost" 'loss == avpn::ControllerLoss::Abandoned && process->program() == amnezia::PermittedProcess::Tun2Socks;' \
    || bad "Q6: the Xray session is not ended for an abandoned tun2socks only"
prev=0
for step in 'disableKillSwitch();' 'StartRoutingIpv6();' 'restoreResolvers();' 'deleteTun(device);' 'xrayStop();' \
            'process->endChild();' 'clearSavedRoutes();' 'flushDns();'; do
  n=$(at "$lost" "$step")
  [ "$n" -gt "$prev" ] || bad "Q6: '$step' is missing or out of XrayProtocol::stop's order"
  prev=$n
done
has "$(body "$SRV" 'IpcServer::~IpcServer()')" 'm_closing = true;' || bad "Q6: the shutdown mark is not set"

# ---- Q7 ------------------------------------------------------------------------------------------------
dtor="$(body "$APP" 'AmneziaApplication::~AmneziaApplication()')"
nm=$(at "$dtor" '#ifndef Q_OS_MACOS')
up=$(at "$dtor" 'QMetaObject::invokeMethod(m_vpnConnection.get(), "disconnectFromVpn", Qt::BlockingQueuedConnection);')
el=$(at "$dtor" '#else')
keep=$(at "$dtor" 'if (protocol && !qobject_cast<WireguardProtocol *>(protocol.data()))')
dis=$(at "$dtor" 'connection->disconnectFromVpn();')
quit=$(at "$dtor" 'm_vpnConnectionThread.quit();')
[ "$nm" -gt 0 ] && [ "$up" -gt "$nm" ] && [ "$el" -gt "$up" ] || bad "Q7: Windows/Linux no longer disconnect on quit as upstream"
[ "$keep" -gt "$el" ] && [ "$dis" -gt "$keep" ] || bad "Q7: macOS quit does not end a session the daemon does not hold"
[ "$(printf '%s\n' "$dtor" | sed -n "${el},${quit}p" | grep -cF 'Qt::BlockingQueuedConnection);')" -ge 1 ] && [ "$quit" -gt "$dis" ] \
    || bad "Q7: the macOS quit stop does not run on the VpnConnection thread before it stops"

[ "$fail" = "0" ] && echo "check_xray_quit_wiring: ok"
exit "$fail"

#!/bin/bash
# AVPN (round mac-E2): the service is a part of the app - an INCOMPATIBLE service (its IPC contract differs from this
# app's: the replica's SignatureMismatch) must be replaced before any connect. Guards the production wiring of the
# decision that facade_policy_check tests (DebugSnapshot.h macServicePlan / macServiceStepAfterConfirm):
#   C1 the fact comes from the replica (IpcClient::interfaceIncompatible reads QRemoteObjectReplica::SignatureMismatch),
#      never from a version string;
#   C2 Connect (guardedStart) and the Scanner's tap pass that fact into macServicePlan; the step after the dialog is
#      macServiceStepAfterConfirm and the dialog gets the required wording;
#   C3 a replica that met a mismatched service is acquired again (Interface / InterfaceIfReady, and on both threads
#      right after a successful install) - it never recovers by itself;
#   C4 the kill switch lease is not sent while incompatible (it can only fail) and is logged once.
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../../../.." && pwd)"
ENG="$ROOT/client/core/serviceEngine/AvpnEngineQml.cpp"
IPC="$ROOT/client/core/utils/ipcClient.cpp"
MSI="$ROOT/client/core/serviceEngine/MacServiceInstaller.mm"
fail=0
bad() { echo "FAIL: $*"; fail=1; }
body() { awk -v sig="$2" 'index($0, sig) == 1 { on = 1 } on { print } on && /^}$/ { exit }' "$1"; }
has() { printf '%s\n' "$1" | grep -qF -- "$2"; }
# C1
inc="$(body "$IPC" 'bool IpcClient::interfaceIncompatible()')"
has "$inc" 'rep->state() == QRemoteObjectReplica::SignatureMismatch' || bad "C1: the incompatibility is not the replica's own state"
if printf '%s\n' "$inc" | grep -qiE 'version|marker'; then bad "C1: the incompatibility compares versions"; fi
# C2
gs="$(body "$ENG" 'void AvpnEngineQml::guardedStart()')"
has "$gs" 'avpn::macServiceOutdated(), m_svcUpgradeDeclined,' && has "$gs" 'IpcClient::interfaceIncompatible());' || bad "C2: Connect does not pass the replica's fact into macServicePlan"
has "$gs" 'avpn::macInstallServiceConfirm(&cerr, plan.required);' || bad "C2: the dialog is not worded as required for an incompatible service"
has "$gs" 'avpn::macServiceStepAfterConfirm(plan, accepted);' || bad "C2: the step after the dialog is not the tested decision"
grep -qF 'IpcClient::interfaceIncompatible()); // round mac-E2' "$ENG" || bad "C2: the Scanner's tap does not pass the fact"
grep -qF 'Без обновления службы VPN подключиться нельзя' "$MSI" || bad "C2: no honest line for a declined required update"
# C3
for f in 'QSharedPointer<IpcInterfaceReplica> IpcClient::Interface()' 'QSharedPointer<IpcInterfaceReplica> IpcClient::InterfaceIfReady()'; do
  has "$(body "$IPC" "$f")" 'refreshIfMismatched(3000);' || bad "C3: $f does not ask a mismatched replica again"
done
has "$(body "$IPC" 'void IpcClient::refreshIfMismatched(qint64 minIntervalMs)')" 'c.m_interface.reset(c.m_node.acquire<IpcInterfaceReplica>());' || bad "C3: refreshIfMismatched does not acquire a new replica"
fs="$(body "$ENG" 'void AvpnEngineQml::finishSvcInstall(bool ok, const QString &err)')"
has "$fs" 'IpcClient::refreshIfMismatched(0);' && has "$fs" 'QMetaObject::invokeMethod(m_conn, []() { IpcClient::refreshIfMismatched(0); }, Qt::QueuedConnection);' \
  || bad "C3: a successful install does not refresh the replicas of both threads"
# C4
kh="$(body "$ENG" 'void AvpnEngineQml::syncKillSwitchHold()')"
a=$(printf '%s\n' "$kh" | grep -nF 'if (IpcClient::interfaceIncompatible()) {' | head -1 | cut -d: -f1)
b=$(printf '%s\n' "$kh" | grep -nF '"syncKillSwitchHold", Qt::QueuedConnection' | head -1 | cut -d: -f1)
[ -n "$a" ] && [ -n "$b" ] && [ "$a" -lt "$b" ] || bad "C4: the lease is sent over an incompatible service"
has "$kh" 'if (!m_svcIncompatibleLogged) {' || bad "C4: the paused lease is not logged once"
[ "$fail" = 0 ] && echo "check_mac_service_contract_wiring: ok"
exit "$fail"

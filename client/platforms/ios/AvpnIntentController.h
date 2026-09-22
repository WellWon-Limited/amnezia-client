#pragma once
#include <QString>
#include <QVariantMap>
#include <functional>

QString Avpn_currentIntentGeneration();
QVariantMap Avpn_currentIntent();
QVariantMap Avpn_lastStop();
bool Avpn_resumeIntentIfCurrent(const QString &generation);
// AVPN (C6): NotCurrent — поколение намерения уже другое, action НЕ выполнялся; Performed —
// выполнен, поколение не сменилось; Superseded — выполнен, но за время действия записали новое
// намерение (вызывающий откатывает действие). Лок не держится на время action.
enum class AvpnIntentPerform { NotCurrent, Performed, Superseded };
AvpnIntentPerform Avpn_performIfCurrent(const QString &generation, const std::function<void()> &action);
void Avpn_ackIntentAction(const QString &generation);
void Avpn_recordLifecycle(const QString &event, const QVariantMap &fields = {});
QString Avpn_lifecycleLogTail();
extern "C" void Avpn_recordGuiIntent(bool enabled);

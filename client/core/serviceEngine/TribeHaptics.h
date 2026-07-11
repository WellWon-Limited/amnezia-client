// AVPN (haptics, спека 2026-07-11): семантический тактильный отклик для QML —
// TribeHaptics.play("selection"|"light"|"medium"|"success"|"warning"|"error").
// Платформа решает, чем сыграть: iOS — UIFeedbackGenerator (TribeHapticsIos.mm),
// Android — View.performHapticFeedback (JNI-ветка в .cpp), desktop/превью — no-op.
// Обе платформы сами уважают системные настройки вибрации; отдельного тумблера в UI нет.
// Kill-switch — флаг features["haptics"] (TuningStore, default TRUE): бэкенд может
// выключить всю хаптику без релиза.
#pragma once

#include <QElapsedTimer>
#include <QObject>
#include <QString>

namespace avpn {

class TribeHaptics : public QObject
{
    Q_OBJECT
public:
    explicit TribeHaptics(QObject *parent = nullptr);

    // Никогда не кидает и не блокирует: неизвестный kind / выключенный флаг /
    // отсутствие нативного пути = тишина.
    Q_INVOKABLE void play(const QString &kind);

private:
    QElapsedTimer m_last; // троттлинг: не чаще одного отклика в ~30 мс (дребезг тапов)
};

} // namespace avpn

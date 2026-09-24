// client/core/serviceEngine/TribeJournal.h
//
// AVPN (журнал тестирования, Tribe-Backend docs/specs/2026-09-23-tester-journal-design.md).
// По умолчанию выключен; включают тестировщики (TestFlight), админ-устройства или удалённо из
// /panel. Когда включён:
//  - TribeJournal::append() пишет структурные события приложения (кольцо надёжности, жизненный
//    цикл iOS, переходы туннеля, выход на экран/уход в фон, сеть, ответы control plane) в JSONL;
//  - фасад включает штатные файловые логи апстрима (лог Qt приложения + ne.log туннеля в App Group);
//  - TribeJournalUploader досылает всё новое пачками на POST /v1/diag/journal по смещениям.
// Решения (пачки, смещения, обрезка) — чистые, в JournalPolicy.h.
#pragma once

#include "JournalPolicy.h"

#include <QDateTime>
#include <QElapsedTimer>
#include <QJsonObject>
#include <QObject>
#include <QPointer>
#include <QString>
#include <functional>

class QNetworkAccessManager;
class QNetworkReply;

namespace avpn {

class TribeJournal {
public:
    static QString dir();
    static QString structuredPath();
    static QString structuredRotatedPath();
    // Включить/выключить журнал (с главного потока). keepFileLogs — пользователь сам включил
    // штатные файловые логи апстрима: при выключении журнала их не гасим.
    // Переход выкл→вкл сдвигает смещения текстовых логов в их конец: старую историю не шлём.
    static void setActive(bool on, bool keepFileLogs);
    static bool active();
    // Потокобезопасно; no-op, пока журнал выключен. Поля — только технические метки/числа.
    static void append(const QString &ev, const QJsonObject &fields = {});
    // Источники пачек по порядку: структурный (*.1, затем текущий), лог Qt, логи App Group (iOS).
    static QList<journal::JournalSource> sources();
    // Сборка из TestFlight (iOS); на других платформах false.
    static bool isTestFlight();
};

class TribeJournalUploader : public QObject {
    Q_OBJECT

public:
    TribeJournalUploader(QNetworkAccessManager *nam, std::function<QString()> baseUrl,
                         std::function<QString()> token, QObject *parent = nullptr);

    // Досылка всего нового. snapshot — текст снимка диагностики (кнопка «Отправить накопленное»),
    // уходит первым отдельным событием. Повторный вызов во время отправки — запоминается и
    // выполняется сразу после текущей.
    void flush(const QString &reason, const QString &snapshot = QString());
    bool sending() const { return m_inFlight; }
    // Оборвать запрос, висящий дольше maxAgeMs (iOS заморозила приложение посреди отправки —
    // после выхода на экран сокет мёртв, а таймаут Qt отсчитывается заново). true — оборван;
    // досылка завершится как неудачная и отпустит очередь.
    bool kickIfStale(int maxAgeMs);
    QDateTime lastSentAt() const { return m_lastSentAt; }
    QString lastError() const { return m_lastError; }
    qint64 pendingBytes() const;

signals:
    void statusChanged();
    void flushFinished(bool ok);
    // Очередь досылок пуста (после последней отправки или если досылка не стартовала) —
    // момент, когда можно отпускать фоновое время iOS.
    void idle();

private:
    void sendNext();
    void post(const QByteArray &jsonl, const QString &srcTag, int events, std::function<void(int)> done);
    void finish(bool ok);
    void maintain();

    QNetworkAccessManager *m_nam = nullptr;
    std::function<QString()> m_baseUrl;
    std::function<QString()> m_token;
    bool m_inFlight = false;
    int m_batches = 0;
    bool m_anyOk = false;
    bool m_flushAgain = false;
    QString m_againReason;
    QString m_pendingSnapshot;
    QPointer<QNetworkReply> m_reply;
    QList<QJsonObject> m_uploadLog; // результаты отправок — в журнал по окончании досылки
    QElapsedTimer m_replyClock;
    QDateTime m_lastSentAt;
    QString m_lastError;
};

} // namespace avpn

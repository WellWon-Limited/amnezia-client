// ServiceProbe: reachability-голос не трогает освобождённую память, когда его таймаут-таймер
// срабатывает ПОСЛЕ finished (до отложенного удаления reply). Так бывает после сна macOS: просроченный
// таймер и ответ приходят одной пачкой. Краш 5.1.99 (129): таймер писал *timedOut в уже удалённый bool,
// ячейку успевал занять новый QTcpSocket пробы Telegram → испорченный vptr → SIGBUS на abort().
// Сборка с AddressSanitizer (build_svcprobe_late_timer.sh): старый код падает heap-use-after-free.
// Плюс фиксируем вердикты кворума, чтобы правка не поменяла поведение чипов.
#include "../ServiceProbe.h"

#include <QCoreApplication>
#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QNetworkRequest>
#include <QPointer>
#include <QTimer>
#include <QTimerEvent>

#include <cstdio>
#include <cstdlib>

class Reply final : public QNetworkReply {
public:
    Reply(const QNetworkRequest &request, QObject *parent) : QNetworkReply(parent) {
        setRequest(request); setUrl(request.url()); open(QIODevice::ReadOnly);
    }
    // Как QNetworkReplyHttpImpl: abort завершённого ответа — no-op; иначе finished синхронно.
    void abort() override {
        if (isFinished()) return;
        setError(OperationCanceledError, QStringLiteral("cancelled"));
        setFinished(true);
        emit finished();
    }
    void complete(int status) {
        setAttribute(QNetworkRequest::HttpStatusCodeAttribute, status);
        emit metaDataChanged();
        setFinished(true);
        emit finished();
    }
    void refuse() {
        setError(ConnectionRefusedError, QStringLiteral("refused"));
        setFinished(true);
        emit finished();
    }
    // Просроченный таймаут-таймер этого ответа срабатывает «сейчас» (как пачка таймеров после сна).
    void fireTimeout() {
        QTimer *t = findChild<QTimer *>();
        if (!t) { std::fprintf(stderr, "FAIL no timeout timer\n"); std::exit(1); }
        QTimerEvent ev(t->timerId());
        QCoreApplication::sendEvent(t, &ev);
    }
protected:
    qint64 readData(char *, qint64) override { return -1; }
};

class Nam final : public QNetworkAccessManager {
public:
    QList<QPointer<Reply>> replies;
protected:
    QNetworkReply *createRequest(Operation, const QNetworkRequest &request, QIODevice *) override {
        auto *reply = new Reply(request, this);
        replies.append(reply);
        return reply;
    }
};

static void check(bool ok, const char *label)
{
    if (!ok) { std::fprintf(stderr, "FAIL %s\n", label); std::exit(1); }
}

int main(int argc, char **argv)
{
    QCoreApplication app(argc, argv);
    Nam nam;
    avpn::ServiceProbe probe(&nam);
    avpn::ServiceProbeConfig c;
    c.key = QStringLiteral("instagram"); // не youtube: без цепочки качества InnerTube
    c.kind = avpn::ServiceProbeConfig::Goodput;
    c.reachUrls = {QStringLiteral("https://a.invalid/"), QStringLiteral("https://b.invalid/")};
    probe.setServices({c});

    int results = 0, state = -100;
    QObject::connect(&probe, &avpn::ServiceProbe::result,
                     [&](const QString &, int st, int) { ++results; state = st; });

    const auto round = [&]() -> std::pair<Reply *, Reply *> {
        results = 0; state = -100;
        const int before = nam.replies.size();
        probe.probeAll();
        check(nam.replies.size() == before + 2, "two reachability voices started");
        return {nam.replies.at(before), nam.replies.at(before + 1)};
    };

    // 1. Краш после сна: ответ пришёл, затем просроченный таймер того же ответа — до deleteLater.
    {
        auto [a, b] = round();
        a->complete(204);
        a->fireTimeout(); // старый код: запись в удалённый *timedOut (ASan: heap-use-after-free)
        b->complete(204);
        check(results == 1 && state == 2, "late timer after finished: works, one result");
    }
    // 2. Оба голоса молчат (таймаут) — заблокировано.
    {
        auto [a, b] = round();
        a->fireTimeout();
        b->fireTimeout();
        check(results == 1 && state == 0, "both timed out: blocked");
    }
    // 3. Один таймаут, второй жив — работает (мягкий фейл не наказываем).
    {
        auto [a, b] = round();
        a->fireTimeout();
        b->complete(204);
        check(results == 1 && state == 2, "soft fail + alive: works");
    }
    // 4. Один жёстко срезан (RST), второй жив — потолок «медленно».
    {
        auto [a, b] = round();
        a->refuse();
        a->fireTimeout();
        b->complete(204);
        check(results == 1 && state == 1, "hard fail + alive: slow");
    }
    // 5. RST у обоих — заблокировано; поздние таймеры ничего не ломают.
    {
        auto [a, b] = round();
        a->refuse();
        b->refuse();
        a->fireTimeout();
        b->fireTimeout();
        check(results == 1 && state == 0, "both refused: blocked");
    }

    QCoreApplication::sendPostedEvents(nullptr, QEvent::DeferredDelete);
    std::puts("svcprobe_late_timer_check: OK (5 scenarios)");
    return 0;
}

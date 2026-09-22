#include "../QualityProbe.h"
#include "../ReportDelivery.h"
#include <QCoreApplication>
#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QNetworkRequest>
#include <QPointer>
#include <cstdio>

class Reply final : public QNetworkReply {
public:
    Reply(const QNetworkRequest &request, QObject *parent) : QNetworkReply(parent) {
        setRequest(request); setUrl(request.url()); open(QIODevice::ReadOnly);
    }
    void abort() override {
        setError(OperationCanceledError, QStringLiteral("cancelled"));
        emit finished(); // synchronous abort is the cancellation race under test.
    }
    void complete(int status = 204) {
        setAttribute(QNetworkRequest::HttpStatusCodeAttribute, status);
        emit metaDataChanged();
        emit finished();
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
int main(int argc, char **argv) {
    QCoreApplication app(argc, argv);
    Nam nam;
    avpn::QualityProbe probe(&nam);
    int results = 0;
    bool reachable = false;
    QObject::connect(&probe, &avpn::QualityProbe::result, [&](int, bool ok) { ++results; reachable = ok; });
    const auto check = [](bool ok, const char *label) { if (!ok) { std::fprintf(stderr,"FAIL %s\n",label); std::exit(1); } };
    probe.setEndpoints({QStringLiteral("https://probe.invalid/one"), QStringLiteral("https://probe.invalid/two")});
    probe.measure();
    auto old = nam.replies.last();
    probe.cancel();
    check(!probe.inFlight() && results == 0 && nam.replies.size() == 1, "abort cannot emit failure or start fallback");
    probe.measure();
    old->complete();
    check(probe.inFlight() && results == 0, "old completion cannot finish new round");
    nam.replies.last()->complete();
    check(results == 1 && reachable && !probe.inFlight(), "new session receives its own result");
    probe.measure();
    old = nam.replies.last();
    probe.setEndpoints({QStringLiteral("https://probe.invalid/new")});
    old->complete();
    check(results == 1 && !probe.inFlight(), "endpoint replacement cancels old round");
    probe.setEndpoints({QStringLiteral("https://probe.invalid/one"), QStringLiteral("https://probe.invalid/two")});
    probe.measure();
    const int before = nam.replies.size();
    nam.replies.last()->complete(500);
    check(nam.replies.size() == before + 1 && probe.inFlight(), "failure advances within current generation");
    probe.cancel();
    check(results == 1, "cancelled fallback is silent");
    probe.measure();
    nam.replies.last()->complete(500);
    nam.replies.last()->complete(500);
    check(results == 2 && !reachable && !probe.inFlight(), "current round failure is reported once");
    const QByteArray receipt = R"({"id":"0a450529-6a3c-49cc-bd19-70c18307955c"})";
    check(!avpn::reportAcknowledgement(201, true, receipt).isEmpty(), "persisted server receipt accepts delivery");
    check(avpn::reportAcknowledgement(201, false, receipt).isEmpty(), "aborted response is not delivery");
    check(avpn::reportAcknowledgement(200, true, "{}").isEmpty(), "bare 2xx without receipt keeps outbox");
    check(avpn::reportAcknowledgement(429, true, receipt).isEmpty(), "429 keeps outbox");
    check(avpn::reportContentId("report") == avpn::reportContentId("report")
          && avpn::reportContentId("report") != avpn::reportContentId("new report"), "stable content dedup");
    std::puts("quality_probe_generation_check: OK (7 cancellation + 5 report delivery assertions)");
}

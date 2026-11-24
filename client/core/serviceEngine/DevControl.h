// AVPN (desktop test rig, 24.11.2026): the test command channel of DESKTOP development builds - a local socket in
// the app's own data directory through which an agent (over SSH on the test Mac) presses the app's buttons and reads
// its state without Accessibility or Screen Recording grants. Compiled only with AVPN_DESKTOP_TEST_CHANNEL
// (cmake/avpn.cmake: AVPN_DEV_TOOLS=ON on macOS desktop, Windows, Linux); a release build has neither these sources
// nor a string of them (tests/check_dev_control_release.sh). What each command calls: DevControlApp.h.
//
// This file is the transport and the protocol only (no app object is known here; tests/dev_control_check.cpp drives
// it against fakes):
//  - Unix: QLocalServer at <data dir>/dev/control.sock. The directory is created 0700 (and must be ours, not a
//    symlink), the socket is 0600, and a connecting peer must have our uid (getpeereid / SO_PEERCRED). A stale socket
//    of a dead instance is removed at start; a live one is never taken over. Never under /tmp or ~/Documents.
//  - Windows: a named pipe "AVPN-devctl-<user>" with the user-only ACL of QLocalServer::UserAccessOption (untested).
//  - Protocol: one JSON object per line in - {"id": <any>, "cmd": "<name>", "args": {...}} (id and args optional) -
//    and one JSON object per line out - {"id": .., "ok": true, "result": {...}} | {"id": .., "ok": false,
//    "error": "..."}. The requests of one client run in order: a command that completes later (wait) holds only that
//    client's queue. A line over kMaxLineBytes, a full queue or a client beyond kMaxClients ends that connection
//    after one error line. A client that leaves cancels its running command (its context object is deleted).
#pragma once

#include <QByteArray>
#include <QHash>
#include <QJsonObject>
#include <QJsonValue>
#include <QObject>
#include <QPointer>
#include <QString>

#include <functional>

class QLocalServer;
class QLocalSocket;

namespace avpn::devctl {

inline constexpr int kMaxLineBytes = 64 * 1024; // one request line, without its newline
inline constexpr int kMaxClients = 4;           // connections at the same time
inline constexpr int kMaxQueued = 32;           // lines of one client waiting behind its running command

struct Request {
    QJsonValue id;    // echoed as given (null when absent)
    QString cmd;      // [a-z.]{1,32}
    QJsonObject args; // {} when absent
    QString error;    // non-empty: the line is refused with this error (bad_json, not_an_object, bad_cmd, bad_args)
};
Request parseRequest(const QByteArray &line);
// One reply line (compact JSON + '\n'): ok = error.isEmpty().
QByteArray encodeReply(const QJsonValue &id, const QJsonObject &result, const QString &error);

// <dataDir>/dev and <dataDir>/dev/control.sock (Windows: the pipe name; dataDir unused).
QString channelDir(const QString &dataDir);
QString channelPath(const QString &dataDir);

class Handler {
public:
    using Done = std::function<void(const QJsonObject &result, const QString &error)>;
    virtual ~Handler() = default;
    // One request on the GUI thread. done() at most once, now or later. Work that outlives this call (a wait) keeps
    // its connections and timers on ctx: the server deletes ctx when the client leaves, and done() is then a no-op.
    virtual void handle(const QString &cmd, const QJsonObject &args, QObject *ctx, const Done &done) = 0;
};

class Server : public QObject {
    Q_OBJECT
public:
    Server(const QString &dataDir, Handler *handler, QObject *parent = nullptr);
    ~Server() override;
    // Creates the directory, removes a stale socket, listens, sets the modes. false + *why on any refusal.
    bool start(QString *why = nullptr);
    QString path() const { return m_path; }
    int clientCount() const { return int(m_clients.size()); }

signals:
    void clientCountChanged(int count);

private:
    struct Client {
        QByteArray buf;
        QList<QByteArray> queue;
        QPointer<QObject> ctx; // the running request's context (null = idle)
        bool closing = false;
    };
    void onNewConnection();
    void onReadyRead(QLocalSocket *s);
    void pump(QLocalSocket *s);
    void refuse(QLocalSocket *s, const QString &why);
    void drop(QLocalSocket *s);

    QString m_dataDir;
    QString m_path;
    Handler *m_handler = nullptr;
    QLocalServer *m_server = nullptr;
    QHash<QLocalSocket *, Client *> m_clients;
};

} // namespace avpn::devctl

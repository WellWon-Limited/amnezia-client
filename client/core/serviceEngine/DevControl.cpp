// AVPN (desktop test rig): the test command channel's transport and protocol (DevControl.h).
#include "DevControl.h"

#include <QDir>
#include <QFile>
#include <QJsonDocument>
#include <QLocalServer>
#include <QLocalSocket>
#include <QRegularExpression>
#include <QTimer>

#if defined(Q_OS_UNIX)
    #include <sys/socket.h>
    #include <sys/stat.h>
    #include <sys/un.h>
    #include <unistd.h>
#endif
#if defined(Q_OS_WIN)
    #include <QCryptographicHash>
    #include <QProcessEnvironment>
#endif

namespace avpn::devctl {

Request parseRequest(const QByteArray &line)
{
    Request r;
    QJsonParseError pe{};
    const QJsonDocument doc = QJsonDocument::fromJson(line, &pe);
    if (pe.error != QJsonParseError::NoError) {
        r.error = QStringLiteral("bad_json");
        return r;
    }
    if (!doc.isObject()) {
        r.error = QStringLiteral("not_an_object");
        return r;
    }
    const QJsonObject o = doc.object();
    r.id = o.value(QStringLiteral("id"));
    if (r.id.isUndefined())
        r.id = QJsonValue(QJsonValue::Null);
    static const QRegularExpression cmdRe(QStringLiteral("^[a-z][a-z.]{0,31}$"));
    const QJsonValue cmd = o.value(QStringLiteral("cmd"));
    if (!cmd.isString() || !cmdRe.match(cmd.toString()).hasMatch()) {
        r.error = QStringLiteral("bad_cmd");
        return r;
    }
    r.cmd = cmd.toString();
    const QJsonValue args = o.value(QStringLiteral("args"));
    if (!args.isUndefined() && !args.isNull()) {
        if (!args.isObject()) {
            r.error = QStringLiteral("bad_args");
            return r;
        }
        r.args = args.toObject();
    }
    return r;
}

QByteArray encodeReply(const QJsonValue &id, const QJsonObject &result, const QString &error)
{
    QJsonObject o;
    o.insert(QStringLiteral("id"), id.isUndefined() ? QJsonValue(QJsonValue::Null) : id);
    o.insert(QStringLiteral("ok"), error.isEmpty());
    if (error.isEmpty())
        o.insert(QStringLiteral("result"), result);
    else
        o.insert(QStringLiteral("error"), error);
    return QJsonDocument(o).toJson(QJsonDocument::Compact) + '\n';
}

QString channelDir(const QString &dataDir)
{
    return dataDir + QStringLiteral("/dev");
}

QString channelPath(const QString &dataDir)
{
#if defined(Q_OS_WIN)
    // A pipe name, not a file: one per Windows user (the ACL of UserAccessOption admits that user only).
    const QString user = QProcessEnvironment::systemEnvironment().value(QStringLiteral("USERNAME"));
    return QStringLiteral("AVPN-devctl-")
        + QString::fromLatin1(QCryptographicHash::hash(user.toUtf8(), QCryptographicHash::Sha256).toHex().left(12));
#else
    return channelDir(dataDir) + QStringLiteral("/control.sock");
#endif
}

namespace {

#if defined(Q_OS_UNIX)
// The peer runs as our user. The socket's 0600 and the directory's 0700 already keep others out; this is the check
// that does not depend on the platform honouring socket file modes.
bool peerIsUs(QLocalSocket *s)
{
    const qintptr fd = s->socketDescriptor();
    if (fd < 0)
        return false;
#if defined(Q_OS_LINUX)
    struct ucred cr {};
    socklen_t len = sizeof(cr);
    if (::getsockopt(int(fd), SOL_SOCKET, SO_PEERCRED, &cr, &len) != 0)
        return false;
    return cr.uid == ::geteuid();
#else
    uid_t uid = 0;
    gid_t gid = 0;
    if (::getpeereid(int(fd), &uid, &gid) != 0)
        return false;
    return uid == ::geteuid();
#endif
}

// The channel directory exists, is a real directory (not a symlink) owned by us, mode 0700.
bool prepareDir(const QString &dir, QString *why)
{
    if (!QDir().mkpath(dir)) {
        *why = QStringLiteral("mkdir_failed");
        return false;
    }
    const QByteArray d = QFile::encodeName(dir);
    struct stat st {};
    if (::lstat(d.constData(), &st) != 0 || !S_ISDIR(st.st_mode) || st.st_uid != ::geteuid()) {
        *why = QStringLiteral("dir_not_ours");
        return false;
    }
    if (::chmod(d.constData(), S_IRWXU) != 0) {
        *why = QStringLiteral("dir_chmod_failed");
        return false;
    }
    return true;
}
#else
bool peerIsUs(QLocalSocket *) { return true; } // the pipe's ACL (UserAccessOption)
bool prepareDir(const QString &, QString *) { return true; }
#endif

} // namespace

Server::Server(const QString &dataDir, Handler *handler, QObject *parent)
    : QObject(parent), m_dataDir(dataDir), m_path(channelPath(dataDir)), m_handler(handler)
{
}

Server::~Server()
{
    const auto sockets = m_clients.keys();
    for (QLocalSocket *s : sockets) {
        Client *c = m_clients.take(s);
        if (c) {
            delete c->ctx.data();
            delete c;
        }
        s->disconnect(this);
        s->abort();
        delete s;
    }
    if (m_server)
        m_server->close(); // removes the socket file it created
}

bool Server::start(QString *why)
{
    QString w;
    auto fail = [&](const QString &reason) {
        if (why)
            *why = reason;
        return false;
    };
#if defined(Q_OS_UNIX)
    if (!prepareDir(channelDir(m_dataDir), &w))
        return fail(w);
    const QByteArray enc = QFile::encodeName(m_path);
    if (enc.size() >= int(sizeof(sockaddr_un::sun_path)))
        return fail(QStringLiteral("path_too_long"));
    struct stat st {};
    if (::lstat(enc.constData(), &st) == 0) {
        if (!S_ISSOCK(st.st_mode))
            return fail(QStringLiteral("path_not_a_socket")); // never delete a file that is not ours to delete
        QLocalSocket probe;
        probe.connectToServer(m_path);
        if (probe.waitForConnected(300)) { // a live instance answers: never take its channel over
            probe.abort();
            return fail(QStringLiteral("in_use"));
        }
        QLocalServer::removeServer(m_path); // stale: its process is gone
    }
#endif
    m_server = new QLocalServer(this);
    m_server->setSocketOptions(QLocalServer::UserAccessOption);
    m_server->setMaxPendingConnections(kMaxClients);
    if (!m_server->listen(m_path)) {
        const QString e = m_server->errorString();
        delete m_server;
        m_server = nullptr;
        return fail(QStringLiteral("listen_failed: ") + e);
    }
#if defined(Q_OS_UNIX)
    // UserAccessOption leaves the socket 0700; the channel needs read and write only.
    if (::chmod(enc.constData(), S_IRUSR | S_IWUSR) != 0 || ::lstat(enc.constData(), &st) != 0
        || (st.st_mode & 0777) != (S_IRUSR | S_IWUSR)) {
        m_server->close();
        delete m_server;
        m_server = nullptr;
        return fail(QStringLiteral("socket_mode"));
    }
#endif
    connect(m_server, &QLocalServer::newConnection, this, &Server::onNewConnection);
    return true;
}

void Server::onNewConnection()
{
    while (QLocalSocket *s = m_server->nextPendingConnection()) {
        if (!peerIsUs(s)) {
            s->abort();
            s->deleteLater();
            continue;
        }
        if (m_clients.size() >= kMaxClients) {
            s->write(encodeReply(QJsonValue(), {}, QStringLiteral("too_many_clients")));
            connect(s, &QLocalSocket::disconnected, s, &QObject::deleteLater);
            s->disconnectFromServer(); // after the error line is written
            continue;
        }
        m_clients.insert(s, new Client);
        connect(s, &QLocalSocket::readyRead, this, [this, s] { onReadyRead(s); });
        connect(s, &QLocalSocket::disconnected, this, [this, s] { drop(s); });
        emit clientCountChanged(int(m_clients.size()));
        if (s->bytesAvailable() > 0)
            onReadyRead(s);
    }
}

void Server::onReadyRead(QLocalSocket *s)
{
    Client *c = m_clients.value(s);
    if (!c || c->closing)
        return;
    c->buf += s->readAll();
    qsizetype nl;
    while ((nl = c->buf.indexOf('\n')) >= 0) {
        QByteArray line = c->buf.left(nl);
        c->buf.remove(0, nl + 1);
        if (line.endsWith('\r'))
            line.chop(1);
        if (line.size() > kMaxLineBytes) {
            refuse(s, QStringLiteral("line_too_long"));
            return;
        }
        if (line.trimmed().isEmpty())
            continue;
        if (c->queue.size() >= kMaxQueued) {
            refuse(s, QStringLiteral("queue_full"));
            return;
        }
        c->queue.append(line);
    }
    if (c->buf.size() > kMaxLineBytes) { // no newline within the limit
        refuse(s, QStringLiteral("line_too_long"));
        return;
    }
    pump(s);
}

void Server::pump(QLocalSocket *s)
{
    Client *c = m_clients.value(s);
    if (!c || c->closing || c->ctx || c->queue.isEmpty())
        return;
    const Request r = parseRequest(c->queue.takeFirst());
    const QPointer<QLocalSocket> ps(s);
    auto next = [this, ps] {
        QTimer::singleShot(0, this, [this, ps] {
            if (ps)
                pump(ps.data());
        });
    };
    if (!r.error.isEmpty()) {
        s->write(encodeReply(r.id, {}, r.error));
        s->flush();
        next();
        return;
    }
    auto *ctx = new QObject(this);
    c->ctx = ctx;
    const QPointer<QObject> pctx(ctx);
    auto fired = std::make_shared<bool>(false);
    const QJsonValue id = r.id;
    m_handler->handle(r.cmd, r.args, ctx, [this, ps, pctx, id, fired, next](const QJsonObject &result, const QString &error) {
        if (*fired)
            return;
        *fired = true;
        if (!ps || !pctx)
            return; // the client left: nobody to answer
        Client *cl = m_clients.value(ps.data());
        if (!cl || cl->ctx != pctx)
            return;
        ps->write(encodeReply(id, result, error));
        ps->flush(); // into the kernel now: a client that has already shut its sending side (nc) still gets it
        cl->ctx = nullptr;
        pctx->deleteLater();
        next();
    });
}

void Server::refuse(QLocalSocket *s, const QString &why)
{
    Client *c = m_clients.value(s);
    if (!c || c->closing)
        return;
    c->closing = true;
    c->queue.clear();
    c->buf.clear();
    delete c->ctx.data(); // a running command of this client ends here
    s->write(encodeReply(QJsonValue(), {}, why));
    s->flush();
    s->disconnectFromServer(); // after the error line, then disconnected() -> drop()
}

void Server::drop(QLocalSocket *s)
{
    Client *c = m_clients.take(s);
    if (!c)
        return;
    delete c->ctx.data(); // cancels a running wait: its connections and timer live on ctx
    delete c;
    s->deleteLater();
    emit clientCountChanged(int(m_clients.size()));
}

} // namespace avpn::devctl

// AVPN (desktop test rig): fakes for tests/dev_control_check.cpp - the engine, the Scanner and PageController with
// the same QML-visible names as the app's (AvpnEngineQml.h, TribeScanner.h, pageController.h). Every call is
// recorded; check_dev_control_wiring.sh keeps the real names in step.
#pragma once

#include <QJsonArray>
#include <QJsonObject>
#include <QObject>
#include <QStringList>
#include <QVariantList>
#include <QVariantMap>

class FakeEngine : public QObject {
    Q_OBJECT
    Q_PROPERTY(QString state MEMBER m_state NOTIFY changed)
    Q_PROPERTY(bool busy MEMBER m_busy NOTIFY changed)
    Q_PROPERTY(bool stopping MEMBER m_stopping NOTIFY changed)
    Q_PROPERTY(bool ownStopping MEMBER m_ownStopping NOTIFY changed)
    Q_PROPERTY(bool waitingUplink MEMBER m_waitingUplink NOTIFY changed)
    Q_PROPERTY(bool adopting MEMBER m_adopting NOTIFY changed)
    Q_PROPERTY(bool verifying MEMBER m_verifying NOTIFY changed)
    Q_PROPERTY(bool dataFlowing MEMBER m_dataFlowing NOTIFY dataFlowingChanged)
    Q_PROPERTY(QString pathCheck MEMBER m_pathCheck NOTIFY changed)
    Q_PROPERTY(QString activeProto MEMBER m_activeProto NOTIFY changed)
    Q_PROPERTY(QString transportMode MEMBER m_transportMode NOTIFY changed)
    Q_PROPERTY(bool paused MEMBER m_paused NOTIFY changed)
    Q_PROPERTY(bool whitelistMode MEMBER m_whitelistMode NOTIFY changed)
    Q_PROPERTY(int liveRttMs MEMBER m_liveRttMs NOTIFY changed)
    Q_PROPERTY(QVariantMap currentNode MEMBER m_currentNode NOTIFY changed)
    Q_PROPERTY(QVariantList nodePool MEMBER m_nodePool NOTIFY changed)
    Q_PROPERTY(bool scannerEnabled MEMBER m_scannerEnabled NOTIFY changed)
    Q_PROPERTY(bool doctorLegacy MEMBER m_doctorLegacy NOTIFY changed)
public:
    QStringList calls;
    QString m_state = QStringLiteral("disconnected");
    bool m_busy = false, m_stopping = false, m_ownStopping = false, m_waitingUplink = false, m_adopting = false;
    bool m_verifying = false, m_dataFlowing = false, m_paused = false, m_whitelistMode = false;
    bool m_scannerEnabled = true, m_doctorLegacy = false;
    QString m_pathCheck, m_activeProto, m_transportMode = QStringLiteral("auto");
    int m_liveRttMs = -1;
    QVariantMap m_currentNode;
    QVariantList m_nodePool;
    QVariantMap snapshot;

    Q_INVOKABLE QVariantMap debugSnapshot() const { return snapshot; }
    Q_INVOKABLE QString networkKind() const { return QStringLiteral("wifi"); }
    // The orb's policy is the engine's (decideOrbTap); the fake only moves to the next phase.
    Q_INVOKABLE QString orbTap()
    {
        calls << QStringLiteral("orbTap");
        if (m_state == QLatin1String("disconnected") && !m_busy) {
            set(QStringLiteral("connecting"), true);
            return QStringLiteral("start");
        }
        m_stopping = true;
        m_ownStopping = true;
        emit changed();
        return QStringLiteral("stop");
    }
    Q_INVOKABLE void start() { calls << QStringLiteral("start"); }
    Q_INVOKABLE void stop() { calls << QStringLiteral("stop"); }
    Q_INVOKABLE void pinAndReconnect(const QString &id) { calls << QStringLiteral("pinAndReconnect:") + id; }
    Q_INVOKABLE void selectAuto() { calls << QStringLiteral("selectAuto"); }
    Q_INVOKABLE void reprobe() { calls << QStringLiteral("reprobe"); }
    Q_INVOKABLE void setWhitelistAcked(bool on) { calls << QStringLiteral("setWhitelistAcked:%1").arg(on); }
    Q_INVOKABLE void setTransportMode(const QString &mode)
    {
        calls << QStringLiteral("setTransportMode:") + mode;
        m_transportMode = mode;
        emit changed();
    }

    void set(const QString &state, bool busy, bool verifying = false, bool flowing = false)
    {
        m_state = state;
        m_busy = busy;
        m_verifying = verifying;
        m_stopping = false;
        m_ownStopping = false;
        emit changed();
        if (m_dataFlowing != flowing) {
            m_dataFlowing = flowing;
            emit dataFlowingChanged();
        }
    }
    int changedReceivers() const { return receivers(SIGNAL(changed())); }

signals:
    void changed();
    void dataFlowingChanged();
    void error(const QString &message);
};

class FakeScanner : public QObject {
    Q_OBJECT
    Q_PROPERTY(bool enabled MEMBER m_enabled NOTIFY viewChanged)
    Q_PROPERTY(QJsonObject view MEMBER m_view NOTIFY viewChanged)
    Q_PROPERTY(bool screenOpen MEMBER m_open NOTIFY viewChanged)
public:
    QStringList calls;
    bool m_enabled = true;
    bool m_open = false;
    QJsonObject m_view;

    Q_INVOKABLE void show() { calls << QStringLiteral("show"); m_open = true; emit viewChanged(); }
    Q_INVOKABLE void close() { calls << QStringLiteral("close"); m_open = false; emit viewChanged(); }
    Q_INVOKABLE void stop() { calls << QStringLiteral("stop"); setPhase(QStringLiteral("idle")); }
    Q_INVOKABLE void retry() { calls << QStringLiteral("retry"); setPhase(QStringLiteral("preparing")); }
    Q_INVOKABLE void connectAndScan() { calls << QStringLiteral("connectAndScan"); }
    Q_INVOKABLE void chooseCountry(const QString &cc) { calls << QStringLiteral("chooseCountry:") + cc; }
    Q_INVOKABLE void showSlot(const QString &cc) { calls << QStringLiteral("showSlot:") + cc; }
    Q_INVOKABLE void findMore(const QString &cc = QString()) { calls << QStringLiteral("findMore:") + cc; }
    Q_INVOKABLE void tapRow(const QString &id) { calls << QStringLiteral("tapRow:") + id; }

    void setPhase(const QString &phase)
    {
        m_view.insert(QStringLiteral("phase"), phase);
        emit viewChanged();
    }
    void setButton(const QString &button, bool enabled = true)
    {
        QJsonObject bar = m_view.value(QStringLiteral("bar")).toObject();
        bar.insert(QStringLiteral("button"), button);
        bar.insert(QStringLiteral("button_enabled"), enabled);
        m_view.insert(QStringLiteral("bar"), bar);
        emit viewChanged();
    }

signals:
    void viewChanged();
};

class FakePageController : public QObject {
    Q_OBJECT
public:
    QStringList calls;
public slots:
    void keyPressEvent(Qt::Key key)
    {
        calls << QStringLiteral("keyPressEvent:%1").arg(int(key));
        if (key == Qt::Key_Escape)
            emit escapePressed();
    }
    void showNotificationMessage(const QString &message) { calls << QStringLiteral("toast:") + message; }
signals:
    void raiseMainWindow();
    void escapePressed();
};

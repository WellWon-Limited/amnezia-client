// Stub of client/secureQSettings.h for the host check of the macOS kill switch (mac_pf_session_check.cpp):
// an in-memory store shared by every instance, so a value outlives a "service restart" (a new KillSwitch)
// the way the service's settings file does. No keychain.
#pragma once
#include <QMap>
#include <QObject>
#include <QString>
#include <QVariant>

class SecureQSettings
{
public:
    explicit SecureQSettings(const QString &, const QString & = QString(), QObject * = nullptr, bool = true) {}
    QVariant value(const QString &key, const QVariant &defaultValue = QVariant()) const
    {
        return store().value(key, defaultValue);
    }
    void setValue(const QString &key, const QVariant &value) { store().insert(key, value); }
    void remove(const QString &key) { store().remove(key); }
    static QMap<QString, QVariant> &store()
    {
        static QMap<QString, QVariant> s;
        return s;
    }
};

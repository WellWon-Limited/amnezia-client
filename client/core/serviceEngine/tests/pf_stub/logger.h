// Stub of common/logger/logger.h for the host check of the macOS pf code (mac_pf_session_check.cpp):
// the service's Logger("Class").info() << ... streams, printed only with PF_CHECK_VERBOSE=1.
#pragma once
#include <QByteArray>
#include <QString>
#include <QStringList>

#include <cstdio>
#include <cstdlib>

class Logger {
public:
    explicit Logger(const char *) {}

    class Stream {
    public:
        Stream() = default;
        Stream(const Stream &) = delete;
        ~Stream()
        {
            if (std::getenv("PF_CHECK_VERBOSE"))
                std::fprintf(stderr, "  [log] %s\n", qPrintable(m_text));
        }
        Stream &operator<<(const QString &v) { return add(v); }
        Stream &operator<<(const char *v) { return add(QString::fromUtf8(v)); }
        Stream &operator<<(const QByteArray &v) { return add(QString::fromUtf8(v)); }
        Stream &operator<<(int v) { return add(QString::number(v)); }

    private:
        Stream &add(const QString &v)
        {
            if (!m_text.isEmpty())
                m_text += QLatin1Char(' ');
            m_text += v;
            return *this;
        }
        QString m_text;
    };

    Stream error() { return {}; }
    Stream warning() { return {}; }
    Stream info() { return {}; }
    Stream debug() { return {}; }
};

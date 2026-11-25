// Stub of the service's logger.h for the host check of the shared desktop daemon (daemon_server_switch_check.cpp):
// Logger("Daemon").debug() << ... keeps every line (strings and numbers; other values as "<v>") in
// daemonStubLogLines(), so the check can read which path Daemon::activate took. Printed with DAEMON_CHECK_VERBOSE=1.
#pragma once
#include <QString>
#include <QStringList>

#include <cstdio>
#include <cstdlib>
#include <type_traits>

inline QStringList &daemonStubLogLines()
{
    static QStringList lines;
    return lines;
}

class Logger {
public:
    explicit Logger(const char *) {}

    class Stream {
    public:
        Stream() = default;
        Stream(const Stream &) = delete;
        ~Stream()
        {
            daemonStubLogLines() << m_text;
            if (std::getenv("DAEMON_CHECK_VERBOSE"))
                std::fprintf(stderr, "  [log] %s\n", qPrintable(m_text));
        }
        template <typename T>
        Stream &operator<<(const T &v)
        {
            if constexpr (std::is_convertible_v<const T &, QString>)
                return add(QString(v));
            else if constexpr (std::is_same_v<T, bool>)
                return add(v ? QStringLiteral("true") : QStringLiteral("false"));
            else if constexpr (std::is_integral_v<T>)
                return add(QString::number(v));
            else
                return add(QStringLiteral("<v>"));
        }

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

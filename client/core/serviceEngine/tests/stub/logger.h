// Заглушка common/logger/logger.h для автономных проверок журнала (journal_upload_check.cpp).
#pragma once
#include <QString>
class Logger {
public:
    static QString userLogsFilePath();
    static QString serviceLogsFilePath();
    static bool setServiceLogsEnabled(bool enabled);
    static bool init(bool isServiceLogger);
    static void deInit();
};

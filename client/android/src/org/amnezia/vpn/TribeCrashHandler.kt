// AVPN (наблюдаемость, волна CR-1) — Android-половина CrashGuard: ловец НЕОБРАБОТАННЫХ
// Java/Kotlin-исключений. Пишет stacktrace в тот же каталог crash/, что читает C++ CrashGuard на
// следующем старте (subtype "java"). Нативные (SIGSEGV и пр.) краши ловит POSIX-хендлер в
// CrashGuard.cpp — тут только JVM-ветка. Overlay-файл нашего слоя (рядом с AvpnFcmService.kt);
// апстрим (AmneziaApplication/манифест/gradle) НЕ трогаем — подключение см. wiring-инструкцию CR-1.
//
// ЖИВУЧЕСТЬ: цепляемся к ПРЕЖНЕМУ default-хендлеру (Qt/Android ставят свой) и вызываем его после
// записи — иначе сломаем штатный путь падения (ANR-репорт/ре-райз процесса).
package org.amnezia.vpn

import android.content.Context
import android.util.Log
import java.io.File
import java.io.PrintWriter
import java.io.StringWriter

object TribeCrashHandler {

    private const val TAG = "TribeCrash"

    @Volatile
    private var installed = false

    // Каталог crash/ ДОЛЖЕН совпадать с тем, что C++ CrashGuard получает в install(dirPath):
    // QStandardPaths::AppDataLocation + "/crash". На Qt-Android AppDataLocation = filesDir, поэтому
    // дефолт = <filesDir>/crash. Если движок вычисляет путь иначе — передать его в install(dir).
    fun install(context: Context) = install(File(context.filesDir, "crash"))

    @Synchronized
    fun install(crashDir: File) {
        if (installed) return
        installed = true
        try {
            crashDir.mkdirs()
        } catch (e: Exception) {
            Log.w(TAG, "cannot mkdir crash: $e")
        }
        val prev = Thread.getDefaultUncaughtExceptionHandler()
        Thread.setDefaultUncaughtExceptionHandler { thread, throwable ->
            try {
                writeStack(crashDir, thread, throwable)
            } catch (e: Throwable) {
                Log.w(TAG, "crash write failed: $e")
            }
            // Цепочка к прежнему хендлеру — штатный путь падения не ломаем.
            prev?.uncaughtException(thread, throwable)
        }
    }

    // Пишет java.txt (перезапись): thread + полный stacktrace. Скраб секретов делает C++ при чтении
    // (scrubLogTail), тут не дублируем — держим Kotlin-слой тонким.
    private fun writeStack(crashDir: File, thread: Thread, throwable: Throwable) {
        val sw = StringWriter()
        PrintWriter(sw).use { pw ->
            pw.println("thread=${thread.name}")
            throwable.printStackTrace(pw)
        }
        File(crashDir, "java.txt").writeText(sw.toString())
    }
}

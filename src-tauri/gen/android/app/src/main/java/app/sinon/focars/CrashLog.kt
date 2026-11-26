package app.sinon.focars

import android.app.ActivityManager
import android.app.ApplicationExitInfo
import android.content.Context
import android.os.Build
import app.sinon.focars.platform.FLog
import app.sinon.focars.platform.RecoveryLogic
import java.io.File
import java.io.PrintWriter
import java.io.StringWriter
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/** Writes Java/Kotlin crashes and Rust panics to files so they can be shown on the next launch. */
object CrashLog {
  const val JAVA = "java_crash.txt"
  const val RUST = "rust_panic.txt"
  private var installed = false

  fun install(ctx: Context) {
    val dir = ctx.filesDir
    FLog.init(ctx)
    try { android.system.Os.setenv("FOCA_CRASH_DIR", dir.absolutePath, true) } catch (_: Throwable) {}
    // Log directory for Rust (a panic may happen before the engine opens): <data>/logs
    try { android.system.Os.setenv("FOCA_LOG_DIR", FLog.logDir(ctx).absolutePath, true) } catch (_: Throwable) {}
    if (installed) return
    installed = true
    val prev = Thread.getDefaultUncaughtExceptionHandler()
    Thread.setDefaultUncaughtExceptionHandler { t, e ->
      try {
        val sw = StringWriter(); e.printStackTrace(PrintWriter(sw))
        File(dir, JAVA).writeText("Поток: ${t.name}\n$sw")
      } catch (_: Throwable) {}
      try { FLog.flushSync("НЕПЕРЕХВАЧЕННОЕ ИСКЛЮЧЕНИЕ в потоке ${t.name}", e) } catch (_: Throwable) {}
      prev?.uncaughtException(t, e)
    }
  }

  private var exitLogged = false

  /**
   * Logs why previous processes ended (ApplicationExitInfo, API 30+): crash, low memory, killed
   * by the OEM shell (OTHER/SIGNALED), normal exit (EXIT_SELF) and so on. This is the main way to
   * tell on a device whether the app crashed in the background or was killed. Runs once per
   * process.
   */
  fun logExitHistory(ctx: Context) {
    if (exitLogged || Build.VERSION.SDK_INT < 30) return
    exitLogged = true
    try {
      val am = ctx.getSystemService(ActivityManager::class.java) ?: return
      val prefs = ctx.getSharedPreferences("crash", Context.MODE_PRIVATE)
      val seen = prefs.getLong("exit_logged", 0L)
      val list = am.getHistoricalProcessExitReasons(ctx.packageName, 0, 5)
      val fresh = RecoveryLogic.unseen(list.map { it.timestamp }, seen)
      val fmt = SimpleDateFormat("dd.MM HH:mm:ss", Locale.ROOT)
      for (info in list.filter { it.timestamp in fresh }.sortedBy { it.timestamp }) {
        val msg = "прошлый процесс (pid ${info.pid}) завершён ${fmt.format(Date(info.timestamp))}: " +
          "${RecoveryLogic.exitReason(info.reason)}, статус ${info.status}, важность ${info.importance}, " +
          "pss ${info.pss / 1024} МБ, ${info.description ?: "без описания"}"
        if (RecoveryLogic.killedBySystem(info.reason)) FLog.w("$msg [убит системой/оболочкой]") else FLog.i(msg)
      }
      list.maxOfOrNull { it.timestamp }?.let { prefs.edit().putLong("exit_logged", maxOf(it, seen)).apply() }
    } catch (e: Throwable) { FLog.w("история выхода процессов", e) }
  }

  /** Returns the report of the last crash, or null if there was none. */
  fun pending(ctx: Context): String? {
    val dir = ctx.filesDir
    val sb = StringBuilder()
    for (n in listOf(RUST, JAVA)) {
      val f = File(dir, n)
      if (f.exists()) sb.append(if (n == RUST) "== Rust panic ==\n" else "== Java/Kotlin ==\n").append(f.readText().take(12000)).append("\n\n")
    }
    if (Build.VERSION.SDK_INT >= 30) {
      try {
        val am = ctx.getSystemService(ActivityManager::class.java)
        val info = am.getHistoricalProcessExitReasons(ctx.packageName, 0, 1).firstOrNull()
        val prefs = ctx.getSharedPreferences("crash", Context.MODE_PRIVATE)
        if (info != null && info.timestamp > prefs.getLong("seen", 0L) &&
          (info.reason == ApplicationExitInfo.REASON_CRASH || info.reason == ApplicationExitInfo.REASON_CRASH_NATIVE ||
           info.reason == ApplicationExitInfo.REASON_ANR || info.reason == ApplicationExitInfo.REASON_INITIALIZATION_FAILURE)) {
          val kind = when (info.reason) {
            ApplicationExitInfo.REASON_CRASH -> "CRASH (Java)"
            ApplicationExitInfo.REASON_CRASH_NATIVE -> "CRASH_NATIVE"
            ApplicationExitInfo.REASON_ANR -> "ANR"
            else -> "INITIALIZATION_FAILURE"
          }
          val time = SimpleDateFormat("dd.MM HH:mm:ss", Locale.ROOT).format(Date(info.timestamp))
          sb.append("== Системная причина выхода ==\n$kind, $time\n${info.description ?: ""}\n")
          if (info.reason == ApplicationExitInfo.REASON_CRASH_NATIVE) {
            info.traceInputStream?.use { s ->
              val raw = s.readBytes()
              // Tombstones are protobuf; extract the readable strings.
              val text = String(raw.map { b -> val c = b.toInt() and 0xff; if (c in 32..126 || c == 10) c.toChar() else '\n' }.toCharArray())
              val lines = text.split('\n').map { it.trim() }.filter { it.length >= 6 }.distinct().take(80)
              sb.append(lines.joinToString("\n")).append("\n")
            }
          }
          if (info.reason == ApplicationExitInfo.REASON_ANR) {
            info.traceInputStream?.use { s -> sb.append(String(s.readBytes()).take(6000)) }
          }
        }
      } catch (e: Throwable) { sb.append("(не удалось прочитать причину выхода: $e)\n") }
    }
    return if (sb.isEmpty()) null else
      "FOCA-rs 2.0.0-beta.2 · Android ${Build.VERSION.RELEASE} (API ${Build.VERSION.SDK_INT}) · ${Build.MANUFACTURER} ${Build.MODEL} · ${Build.SUPPORTED_ABIS.joinToString()}\n\n$sb"
  }

  fun clear(ctx: Context) {
    File(ctx.filesDir, JAVA).delete(); File(ctx.filesDir, RUST).delete()
    ctx.getSharedPreferences("crash", Context.MODE_PRIVATE).edit().putLong("seen", System.currentTimeMillis()).apply()
  }
}

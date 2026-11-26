package app.sinon.focars.platform

import android.content.Context
import android.util.Log
import java.io.File
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.concurrent.Executors

/** Log file rotation `name` → `name.1` → … → `name.(keep-1)`; pure java.io logic (covered by JUnit). */
object LogRotation {
  /** Returns whether the file must be rotated before writing `incoming` bytes. */
  fun needsRotate(currentSize: Long, incoming: Int, maxBytes: Long): Boolean =
    currentSize > 0 && currentSize + incoming > maxBytes

  /** Rotates the file: the oldest is deleted, keeping at most `keep` files including the current one. */
  fun rotate(file: File, keep: Int) {
    if (keep <= 1) { file.delete(); return }
    File(file.path + "." + (keep - 1)).delete()
    for (i in keep - 2 downTo 1) {
      val src = File(file.path + "." + i)
      if (src.exists()) src.renameTo(File(file.path + "." + (i + 1)))
    }
    if (file.exists()) file.renameTo(File(file.path + ".1"))
  }

  /** Appends a line, rotating as needed. */
  fun append(file: File, line: String, maxBytes: Long, keep: Int) {
    val bytes = line.toByteArray(Charsets.UTF_8)
    file.parentFile?.mkdirs()
    if (needsRotate(if (file.exists()) file.length() else 0L, bytes.size, maxBytes)) rotate(file, keep)
    file.appendBytes(bytes)
  }
}

/**
 * Kotlin layer log: logcat (tag `FOCA`) plus `<data>/logs/android.log` (1 MB × 3), in the same
 * directory as the Rust core's `foca.log` (`app_data_dir` = `Context.dataDir`). File writes run on
 * a dedicated thread; [flushSync] is for the crash handler. Never throws: logging must not crash
 * the app.
 */
object FLog {
  const val TAG = "FOCA"
  const val FILE = "android.log"
  const val MAX_BYTES = 1024L * 1024
  const val KEEP = 3

  @Volatile private var file: File? = null
  private val io = Executors.newSingleThreadExecutor { r -> Thread(r, "foca-flog").apply { isDaemon = true } }
  private val fmt = object : ThreadLocal<SimpleDateFormat>() {
    override fun initialValue() = SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSS", Locale.ROOT)
  }

  fun logDir(ctx: Context): File = File(dataDir(ctx), "logs")

  fun dataDir(ctx: Context): File =
    if (android.os.Build.VERSION.SDK_INT >= 24) ctx.applicationContext.dataDir
    else File(ctx.applicationContext.applicationInfo.dataDir)

  fun init(ctx: Context) {
    if (file != null) return
    try { file = File(logDir(ctx), FILE) } catch (_: Throwable) {}
  }

  fun d(msg: String) = log(Log.DEBUG, "D", msg, null)
  fun i(msg: String) = log(Log.INFO, "I", msg, null)
  fun w(msg: String, e: Throwable? = null) = log(Log.WARN, "W", msg, e)
  fun e(msg: String, e: Throwable? = null) = log(Log.ERROR, "E", msg, e)

  private fun line(lv: String, msg: String, e: Throwable?): String {
    val t = requireNotNull(fmt.get()) { "ThreadLocal.initialValue() never returns null" }.format(Date())
    val th = Thread.currentThread().name
    val err = if (e != null) " | " + Log.getStackTraceString(e).replace("\n", "\n    ") else ""
    return "$t $lv [$th] $msg$err\n"
  }

  private fun log(prio: Int, lv: String, msg: String, e: Throwable?) {
    try { if (e != null) Log.println(prio, TAG, msg + "\n" + Log.getStackTraceString(e)) else Log.println(prio, TAG, msg) } catch (_: Throwable) {}
    val f = file ?: return
    val l = try { line(lv, msg, e) } catch (_: Throwable) { return }
    try { io.execute { write(f, l) } } catch (_: Throwable) {}
  }

  /** Writes synchronously (crash handler: the process is about to die). */
  fun flushSync(msg: String, e: Throwable?) {
    try { Log.e(TAG, msg, e) } catch (_: Throwable) {}
    val f = file ?: return
    write(f, try { line("E", msg, e) } catch (_: Throwable) { return })
  }

  @Synchronized private fun write(f: File, l: String) {
    try { LogRotation.append(f, l, MAX_BYTES, KEEP) } catch (_: Throwable) {}
  }
}

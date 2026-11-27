package app.sinon.focars.platform

import android.content.Context
import android.os.Handler
import android.os.Looper
import android.widget.Toast
import androidx.annotation.Keep
import app.tauri.plugin.JSObject
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Direct JNI entry point from Rust (`src-tauri/src/native.rs`, `direct_call`), without an
 * Activity or the main thread. Tauri's `run_mobile_plugin` goes through the Activity: if it was
 * destroyed during a scan (while the process was kept alive), the foreground service could no
 * longer be updated or stopped through the plugin and would hold its WAKE_LOCK until the limit.
 * Handles the scan service commands, toasts and `render_fetch` (the hidden search engine
 * WebView, [RenderFetcher], which blocks the calling thread and is therefore JNI only).
 * Also hosts the reverse JNI bridge (`runHeadlessMonitor`, `keystoreGet`) invoked by background
 * [MonitorWorker] when WorkManager starts without an Activity or Tauri runtime.
 * Returns a JSON string and never lets exceptions escape.
 */
@Keep
object FocaDirect {
  private val main = Handler(Looper.getMainLooper())
  private val nativeLoaded = AtomicBoolean(false)

  private fun ensureNative(): Boolean {
    if (nativeLoaded.get()) return true
    return try {
      System.loadLibrary("foca_rs_lib")
      nativeLoaded.set(true)
      true
    } catch (e: Throwable) {
      FLog.e("FocaDirect: System.loadLibrary(foca_rs_lib) не удался", e)
      false
    }
  }

  /** Reads an API key from AndroidKeyStore during autonomous headless monitoring (no FocaPlugin needed). */
  @JvmStatic
  @Keep
  fun keystoreGet(ctx: Context, service: String): String? = try {
    KeyVault(ctx.applicationContext).get(service)
  } catch (e: Throwable) {
    FLog.w("FocaDirect.keystoreGet($service)", e)
    null
  }

  @JvmStatic
  @Keep
  private external fun nativeRunHeadlessMonitor(
    ctx: Context,
    dataDir: String,
    project: String,
    profile: String,
    budgetSec: Int,
    utcOffsetSec: Int,
  ): String?

  @JvmStatic
  @Keep
  private external fun nativeCancelHeadlessMonitor()

  /** Runs a bounded scheduled scan inside Rust without `MainActivity` or Tauri WebView. */
  fun runHeadlessMonitor(
    ctx: Context,
    dataDir: String,
    project: String,
    profile: String,
    budgetSec: Int,
    utcOffsetSec: Int,
  ): String {
    if (!ensureNative()) {
      return JSObject()
        .put("ok", false)
        .put("status", "error")
        .put("error", "не удалось загрузить libfoca_rs_lib.so")
        .toString()
    }
    return try {
      nativeRunHeadlessMonitor(
        ctx.applicationContext,
        dataDir,
        project,
        profile,
        MonitorLogic.clampBudgetSec(budgetSec),
        utcOffsetSec,
      ) ?: JSObject()
        .put("ok", false)
        .put("status", "error")
        .put("error", "пустой ответ headless-ядра")
        .toString()
    } catch (e: Throwable) {
      FLog.e("FocaDirect.runHeadlessMonitor($project)", e)
      JSObject()
        .put("ok", false)
        .put("status", "error")
        .put("error", e.toString())
        .toString()
    }
  }

  @JvmStatic
  @Keep
  private external fun nativeResumeInterruptedScan(ctx: Context, dataDir: String, utcOffsetSec: Int): String?

  @JvmStatic
  @Keep
  private external fun nativeHeadlessEvent(json: String): Boolean

  /** A scan resumed without the UI runs in this process; device events and notification actions go to it. */
  @Volatile var headlessScan = false

  /**
   * Resumes the scan interrupted by a process kill inside Rust, without `MainActivity` (the scan service
   * must already be in the foreground). Returns the outcome JSON (`status`: resumed / none / disabled /
   * too_many / busy / error); the scan keeps running after the call returns.
   */
  fun resumeInterruptedScan(ctx: Context, dataDir: String, utcOffsetSec: Int): String {
    if (!ensureNative()) return JSObject().put("status", "error").put("error", "libfoca_rs_lib.so").toString()
    val raw = try {
      nativeResumeInterruptedScan(ctx.applicationContext, dataDir, utcOffsetSec)
    } catch (e: Throwable) {
      FLog.e("FocaDirect.resumeInterruptedScan", e)
      null
    } ?: return JSObject().put("status", "error").put("error", "no answer").toString()
    headlessScan = RecoveryLogic.headlessRunning(statusOf(raw))
    return raw
  }

  /** Returns the `status` field of an outcome JSON, or `error`. */
  fun statusOf(raw: String): String = try { JSObject(raw).optString("status", "error") } catch (_: Throwable) { "error" }

  /** Hands an event to the headless resume; `false` when none runs. */
  fun headlessEvent(ev: JSObject): Boolean {
    if (!headlessScan || !nativeLoaded.get()) return false
    return try { nativeHeadlessEvent(ev.toString()) } catch (e: Throwable) {
      FLog.w("FocaDirect.headlessEvent", e)
      false
    }
  }

  /** Signals the active headless scan to stop cleanly and save a `resume_from` checkpoint. */
  fun cancelHeadlessMonitor() {
    if (!nativeLoaded.get()) return
    try {
      nativeCancelHeadlessMonitor()
    } catch (e: Throwable) {
      FLog.w("FocaDirect.cancelHeadlessMonitor", e)
    }
  }

  @JvmStatic
  @Keep
  fun call(ctx: Context, cmd: String, json: String): String = try {
    val a = try { JSObject(json) } catch (_: Throwable) { JSObject() }
    val app = ctx.applicationContext
    when (cmd) {
      "scan_service_start" -> {
        val err = ScanService.start(app, ScanNote.from(a))
        JSObject().put("running", err == null).put("error", err).toString()
      }
      "scan_service_update" -> {
        ScanService.update(app, ScanNote.from(a))
        JSObject().put("running", ScanService.running).toString()
      }
      "scan_service_stop" -> {
        ScanService.stop(app)
        JSObject().put("running", false).toString()
      }
      // Scan result (tap opens the project) and monitoring schedule (WorkManager), no Activity needed.
      "scan_done_notify" -> {
        MonitorWorker.notifyDone(app, a)
        JSObject().put("ok", true).toString()
      }
      "monitor_schedule" -> MonitorWorker.schedule(app, a).toString()
      "status_notify" -> JSObject().put("ok", MonitorWorker.notifyStatus(app, a)).toString()
      // Long blocking hidden WebView script (up to minutes); the calling Rust thread waits.
      "render_fetch" -> RenderFetcher.call(app, json)
      "report_sign", "report_sig_verify" -> ReportSigner.call(cmd, a).toString()
      "ocr_recognize" -> OcrEngine.recognize(app, a).toString()
      "web_screenshot" -> WebScreenshotter.capture(app, a).toString()
      "keystore_get" -> {
        val svc = a.getString("service", null)?.trim() ?: ""
        val v = if (svc.isNotEmpty()) keystoreGet(app, svc) else null
        JSObject().put("value", v).toString()
      }
      "toast" -> {
        val text = a.getString("text", null) ?: ""
        main.post { try { Toast.makeText(app, text, Toast.LENGTH_LONG).show() } catch (_: Throwable) {} }
        JSObject().put("ok", true).toString()
      }
      else -> JSObject().put("error", "unknown: $cmd").toString()
    }
  } catch (e: Throwable) {
    FLog.e("FocaDirect.$cmd", e)
    JSObject().put("error", e.toString()).toString()
  }
}

package app.sinon.focars.platform

import android.Manifest
import android.app.Activity
import android.content.ActivityNotFoundException
import android.content.ClipData
import android.content.ClipboardManager
import android.content.ContentValues
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import android.os.CancellationSignal
import android.os.Environment
import android.os.Handler
import android.os.Looper
import android.os.ParcelFileDescriptor
import android.os.PersistableBundle
import android.os.PowerManager
import android.print.PdfPrintDriver
import android.print.PrintAttributes
import android.print.PrintManager
import android.provider.DocumentsContract
import android.provider.MediaStore
import android.view.WindowManager
import android.webkit.WebResourceRequest
import android.webkit.WebView
import android.webkit.WebViewClient
import android.widget.Toast
import androidx.activity.result.ActivityResult
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.core.app.ActivityCompat
import androidx.core.app.NotificationManagerCompat
import androidx.core.content.ContextCompat
import androidx.core.content.FileProvider
import androidx.fragment.app.FragmentActivity
import app.tauri.annotation.ActivityCallback
import app.tauri.annotation.Command
import app.tauri.annotation.InvokeArg
import app.tauri.annotation.TauriPlugin
import app.tauri.plugin.Channel
import app.tauri.plugin.Invoke
import app.tauri.plugin.JSObject
import app.tauri.plugin.Plugin
import app.tauri.plugin.PluginManager
import java.io.File
import java.util.TimeZone
import java.util.concurrent.atomic.AtomicBoolean

@InvokeArg
class WatchArgs {
  lateinit var channel: Channel
}

/**
 * Native commands for the Rust bridge (`src-tauri/src/native.rs`). Called only from Rust: JS has
 * no ACL permissions for the `foca-native` plugin. Commands run on the main thread; any
 * exception would become a reject (PluginManager), so commands return meaningful replies instead.
 */
@TauriPlugin
class FocaPlugin(private val created: Activity) : Plugin(created) {
  /** The current Activity. The plugin is created once per process while the Activity may be recreated
   *  (the process survived the screen closing during a scan), so take the live one from PluginManager. */
  private val activity: Activity get() = PluginManager.activity?.takeUnless { it.isDestroyed } ?: created
  private val ctx: Context get() = created.applicationContext
  private val vault by lazy { KeyVault(ctx) }
  private var pendingSave: File? = null
  /** WebView of the print job, referenced until the system takes the document (otherwise GC collects it). */
  private var printView: WebView? = null
  /** Off-screen WebView of the running direct PDF export (one at a time; destroyed when it ends). */
  private var pdfView: WebView? = null

  // Search engine WebViews attach to the Activity window (the page is "visible", like a normal tab).
  init { try { RenderFetcher.bindActivity(created) } catch (e: Throwable) { FLog.w("render: bindActivity $e") } }

  companion object {
    const val PREFS = "foca_platform"
    /**
     * FLAG_SECURE preference. The key differs from the legacy "secure" one (which defaulted to on) so
     * existing installs start with screenshots allowed until the user opts in again.
     */
    const val PREF_SECURE = "block_screenshots"
    /** Upper bound for a direct PDF export (load + layout + write); a stuck WebView is cancelled. */
    const val PDF_TIMEOUT_MS = 90_000L
    private const val PREF_ASKED_NOTIF = "asked_notifications"
    private const val REQ_NOTIF = 4108

    fun prefs(c: Context) = c.applicationContext.getSharedPreferences(PREFS, Context.MODE_PRIVATE)

    /** Toggles FLAG_SECURE: blocks screenshots and recording and blanks the Recents card. */
    fun applySecure(a: Activity, on: Boolean) {
      if (on) a.window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
      else a.window.clearFlags(WindowManager.LayoutParams.FLAG_SECURE)
      if (Build.VERSION.SDK_INT >= 33) {
        try { a.setRecentsScreenshotEnabled(!on) } catch (_: Throwable) {}
      }
    }
  }

  // Device events.
  /** Manual search engine verification (captcha) in a visible WebView sharing the hidden browser's
   *  profile; replies `{ ok, closed }` after closing. Startpage/Mojeek/Brave URLs only. */
  @Command
  fun render_verify(invoke: Invoke) {
    val a = invoke.getArgs()
    val url = a.getString("url", null) ?: ""
    if (!VerifyDialog.allowed(url)) { invoke.reject("Адрес проверки не из списка поисковиков", "bad_args"); return }
    try {
      VerifyDialog.show(activity, url, a.getString("title", null) ?: "Проверка поисковика") { how ->
        invoke.resolve(JSObject().put("ok", true).put("closed", how == "closed"))
      }
    } catch (e: Throwable) {
      FLog.e("verify", e)
      invoke.reject("Не удалось открыть браузер: $e", "platform")
    }
  }

  /** Opens an external `http`/`https` link in the system browser (`platform_open_url`);
   *  any other scheme is rejected, a device without a browser gets a `platform` error. */
  @Command
  fun open_url(invoke: Invoke) {
    val url = invoke.getArgs().getString("url", null)
    if (!LinkLogic.isWebUrl(url)) { invoke.reject("Открыть можно только ссылку http/https", "bad_args"); return }
    try {
      val i = Intent(Intent.ACTION_VIEW, Uri.parse(url)).addCategory(Intent.CATEGORY_BROWSABLE)
        .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
      activity.startActivity(i)
      invoke.resolve(JSObject().put("ok", true))
    } catch (e: ActivityNotFoundException) {
      invoke.reject("Нет приложения, которое может открыть ссылку", "platform")
    } catch (e: Throwable) {
      FLog.w("open_url", e)
      invoke.reject("Не удалось открыть ссылку: ${e.message ?: e}", "platform")
    }
  }

  /** Shows a short system message (scan auto-resume and the like). */
  @Command
  fun toast(invoke: Invoke) {
    val text = invoke.getArgs().getString("text", null) ?: ""
    try { Toast.makeText(ctx, text, Toast.LENGTH_LONG).show() } catch (e: Throwable) { FLog.w("toast", e) }
    invoke.resolve(JSObject().put("ok", true))
  }

  @Command
  fun watch(invoke: Invoke) {
    val args = invoke.parseArgs(WatchArgs::class.java)
    FocaBus.attach(args.channel)
    DeviceMonitor.start(ctx)
    DeviceMonitor.resend()
    invoke.resolve(JSObject().put("ok", true))
  }

  @Command
  fun device_info(invoke: Invoke) {
    val tz = TimeZone.getDefault()
    invoke.resolve(JSObject()
      .put("utc_offset", tz.getOffset(System.currentTimeMillis()) / 1000)
      .put("tz", tz.id)
      .put("locale", java.util.Locale.getDefault().toLanguageTag())
      .put("sdk", Build.VERSION.SDK_INT)
      .put("release", Build.VERSION.RELEASE)
      .put("manufacturer", Build.MANUFACTURER)
      .put("brand", Build.BRAND)
      .put("model", Build.MODEL)
      .put("abi", Build.SUPPORTED_ABIS.joinToString(", "))
      .put("app_version", try { ctx.packageManager.getPackageInfo(ctx.packageName, 0).versionName } catch (_: Throwable) { "" })
      .put("flavor", app.sinon.focars.BuildConfig.FLAVOR.ifEmpty { "foss" })
      .put("mem_total_mb", memInfo().first)
      .put("mem_avail_mb", memInfo().second)
      .put("disk_free_mb", try { android.os.StatFs(ctx.filesDir.path).availableBytes / 1048576 } catch (_: Throwable) { -1L })
      .put("service_running", ScanService.running)
      .put("last_interrupt", ScanService.lastInterrupt(ctx))
      .put("battery_ignoring", ignoring())
      .put("notifications", notifGranted())
      .put("rom", Oem.rom(sysProp("ro.mi.os.version.name"), sysProp("ro.miui.ui.version.name"))))
  }

  private fun memInfo(): Pair<Long, Long> = try {
    val am = ctx.getSystemService(Context.ACTIVITY_SERVICE) as android.app.ActivityManager
    val mi = android.app.ActivityManager.MemoryInfo(); am.getMemoryInfo(mi)
    Pair(mi.totalMem / 1048576, mi.availMem / 1048576)
  } catch (_: Throwable) { Pair(-1L, -1L) }

  // ------------------------------------------------------------------ Keystore
  @Command
  fun keystore_get(invoke: Invoke) {
    val service = invoke.getArgs().getString("service", null)
    if (service.isNullOrBlank()) { invoke.reject("нет service", "bad_args"); return }
    try {
      invoke.resolve(JSObject().put("value", vault.get(service)))
    } catch (e: Exception) {
      FLog.w("keystore_get $service", e)
      invoke.reject("Keystore: ${e.message ?: e}", "keystore")
    }
  }

  @Command
  fun keystore_set(invoke: Invoke) {
    val a = invoke.getArgs()
    val service = a.getString("service", null)
    val value = a.getString("value", null)
    if (service.isNullOrBlank() || value == null) { invoke.reject("нет service/value", "bad_args"); return }
    try {
      vault.put(service, value)
      invoke.resolve(JSObject().put("ok", true))
    } catch (e: Exception) {
      invoke.reject("Keystore: ${e.message ?: e}", "keystore")
    }
  }

  @Command
  fun keystore_delete(invoke: Invoke) {
    val service = invoke.getArgs().getString("service", null)
    if (service.isNullOrBlank()) { invoke.reject("нет service", "bad_args"); return }
    try {
      vault.delete(service)
      invoke.resolve(JSObject().put("ok", true))
    } catch (e: Exception) {
      invoke.reject("Keystore: ${e.message ?: e}", "keystore")
    }
  }

  // Scan service.
  private fun noteOf(a: JSObject) = ScanNote.from(a)

  @Command
  fun scan_service_start(invoke: Invoke) {
    askNotificationsOnce()
    val err = ScanService.start(ctx, noteOf(invoke.getArgs()))
    if (err != null) FLog.e("scan_service_start: $err")
    invoke.resolve(JSObject().put("running", err == null).put("error", err))
  }

  @Command
  fun scan_service_update(invoke: Invoke) {
    ScanService.update(ctx, noteOf(invoke.getArgs()))
    invoke.resolve(JSObject().put("running", ScanService.running))
  }

  @Command
  fun scan_service_stop(invoke: Invoke) {
    ScanService.stop(ctx)
    invoke.resolve(JSObject().put("running", false))
  }

  /** Quiet fallback: asks for POST_NOTIFICATIONS (Android 13+) on the first scan, only if the user skipped
   *  the permissions screen and never answered the prompt. A refusal does not affect the scan. */
  private fun askNotificationsOnce() {
    if (Build.VERSION.SDK_INT < 33) return
    try {
      if (notifGranted()) return
      val p = prefs(ctx)
      if (p.getBoolean(PREF_ASKED_NOTIF, false)) return
      p.edit().putBoolean(PREF_ASKED_NOTIF, true).apply()
      ActivityCompat.requestPermissions(activity, arrayOf(Manifest.permission.POST_NOTIFICATIONS), REQ_NOTIF)
    } catch (e: Throwable) {
      FLog.w("notifications permission", e)
    }
  }

  private fun notifGranted(): Boolean = try {
    NotificationManagerCompat.from(ctx).areNotificationsEnabled() &&
      (Build.VERSION.SDK_INT < 33 || ContextCompat.checkSelfPermission(ctx, Manifest.permission.POST_NOTIFICATIONS) == PackageManager.PERMISSION_GRANTED)
  } catch (_: Throwable) { false }

  /** Returns true if permanently denied: already asked and the system will not show the dialog again (no rationale). */
  private fun notifBlocked(): Boolean = try {
    Build.VERSION.SDK_INT >= 33 && !notifGranted() && prefs(ctx).getBoolean(PREF_ASKED_NOTIF, false) &&
      !ActivityCompat.shouldShowRequestPermissionRationale(activity, Manifest.permission.POST_NOTIFICATIONS)
  } catch (_: Throwable) { false }

  private fun openNotificationSettings(): Boolean = try {
    val i = if (Build.VERSION.SDK_INT >= 26) Intent("android.settings.APP_NOTIFICATION_SETTINGS").putExtra("android.provider.extra.APP_PACKAGE", ctx.packageName)
      else Intent("android.settings.APPLICATION_DETAILS_SETTINGS").setData(Uri.parse("package:${ctx.packageName}"))
    activity.startActivity(i); true
  } catch (e: Throwable) { FLog.w("notification settings", e); false }

  /** Permissions screen: requests notifications. If granted, does nothing; on Android 13+ while the dialog
   *  is still possible, shows the system prompt (the answer arrives on return to the app and the UI rereads
   *  the status); if permanently denied, or Android < 13 with notifications off, opens notification settings. */
  @Command
  fun request_notifications(invoke: Invoke) {
    val granted = notifGranted()
    var action = "none"
    if (!granted) {
      if (Build.VERSION.SDK_INT >= 33 && !notifBlocked()) {
        try {
          prefs(ctx).edit().putBoolean(PREF_ASKED_NOTIF, true).apply()
          ActivityCompat.requestPermissions(activity, arrayOf(Manifest.permission.POST_NOTIFICATIONS), REQ_NOTIF)
          action = "requested"
        } catch (e: Throwable) { FLog.w("request_notifications", e) }
      } else if (openNotificationSettings()) action = "settings"
    }
    FLog.i("request_notifications: granted=$granted action=$action")
    invoke.resolve(JSObject().put("enabled", granted).put("granted", granted).put("action", action))
  }

  /** Returns statuses for the permissions screen and the Debug tab. */
  @Command
  fun permissions_status(invoke: Invoke) {
    val oem = Oem.detect(Build.MANUFACTURER, Build.BRAND)
    invoke.resolve(JSObject()
      .put("notifications", notifGranted())
      .put("notifications_runtime", Build.VERSION.SDK_INT >= 33)
      .put("notifications_blocked", notifBlocked())
      .put("battery", ignoring())
      .put("oem", oem)
      .put("manufacturer", Build.MANUFACTURER)
      .put("brand", Build.BRAND)
      .put("sdk", Build.VERSION.SDK_INT))
  }

  /** Closes the app when the user declines the terms. */
  @Command
  fun app_exit(invoke: Invoke) {
    FLog.i("app_exit: пользователь не принял условия")
    invoke.resolve(JSObject().put("ok", true))
    activity.runOnUiThread { try { activity.finishAffinity() } catch (e: Throwable) { FLog.w("finishAffinity", e) } }
  }

  // Share / Save.
  private fun safeName(n: String): String =
    n.replace(Regex("[\\\\/:*?\"<>|\\u0000-\\u001f]"), "_").trim().ifEmpty { "foca-export" }.take(120)

  private fun srcFile(a: JSObject): File? {
    val path = a.getString("path", null) ?: return null
    return try {
      val f = File(path).canonicalFile
      if (!f.isFile) return null
      val roots = listOfNotNull(
        try { activity.filesDir.canonicalFile } catch (_: Throwable) { null },
        try { activity.dataDir.canonicalFile } catch (_: Throwable) { null },
        try { activity.cacheDir.canonicalFile } catch (_: Throwable) { null },
      )
      val subdirs = listOf("exports", "reports", "clean", "files")
      val allowed = roots.any { r ->
        subdirs.any { sub ->
          val base = File(r, sub).canonicalPath + File.separator
          f.canonicalPath.startsWith(base)
        }
      }
      if (allowed) f else null
    } catch (_: Throwable) {
      null
    }
  }

  @Command
  fun share_file(invoke: Invoke) {
    val a = invoke.getArgs()
    val src = srcFile(a) ?: run { invoke.reject("файл не найден", "not_found"); return }
    val name = safeName(a.getString("name", null) ?: src.name)
    val mime = a.getString("mime", null) ?: "application/octet-stream"
    try {
      // Copy into cache/share: FileProvider exposes only this directory, not the app data.
      val dir = File(activity.cacheDir, "share")
      dir.mkdirs()
      dir.listFiles()?.forEach { if (System.currentTimeMillis() - it.lastModified() > 10 * 60_000) it.delete() }
      val copy = File(dir, name)
      src.copyTo(copy, overwrite = true)
      val uri = FileProvider.getUriForFile(activity, activity.packageName + ".fileprovider", copy)
      val send = Intent(Intent.ACTION_SEND)
        .setType(mime)
        .putExtra(Intent.EXTRA_STREAM, uri)
        .putExtra(Intent.EXTRA_TITLE, name)
        .addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
      send.clipData = ClipData.newRawUri(name, uri)
      val chooser = Intent.createChooser(send, "Поделиться: $name")
        .addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
      activity.startActivity(chooser)
      invoke.resolve(JSObject().put("ok", true).put("name", name))
    } catch (e: Exception) {
      invoke.reject("Не удалось поделиться: ${e.message ?: e}", "platform")
    }
  }

  /**
   * Report "PDF": the report HTML (self-contained, no network or scripts) is loaded into a separate
   * WebView and handed to system printing, where the user picks "Save as PDF". The `{ ok, name }`
   * reply arrives once the print dialog is open (the system saves the PDF itself).
   */
  @Command
  fun print_html(invoke: Invoke) {
    val a = invoke.getArgs()
    val src = srcFile(a) ?: run { invoke.reject("файл не найден", "not_found"); return }
    val name = a.getString("name", null) ?: src.name
    if (!PrintLogic.isHtml(name)) { invoke.reject("печать доступна только для HTML-отчёта", "bad_args"); return }
    val job = PrintLogic.jobName(name)
    try {
      val html = src.readText(Charsets.UTF_8)
      val wv = WebView(activity)
      wv.settings.javaScriptEnabled = false
      wv.settings.blockNetworkLoads = true
      wv.settings.allowFileAccess = false
      wv.settings.allowContentAccess = false
      var done = false
      wv.webViewClient = object : WebViewClient() {
        override fun shouldOverrideUrlLoading(view: WebView, request: WebResourceRequest): Boolean = true
        override fun onPageFinished(view: WebView, url: String?) {
          if (done) return
          done = true
          try {
            val pm = activity.getSystemService(Context.PRINT_SERVICE) as PrintManager
            val attrs = PrintAttributes.Builder()
              .setMediaSize(PrintAttributes.MediaSize.ISO_A4)
              .setColorMode(PrintAttributes.COLOR_MODE_COLOR)
              .build()
            pm.print(job, view.createPrintDocumentAdapter(job), attrs)
            invoke.resolve(JSObject().put("ok", true).put("name", job))
          } catch (e: Exception) {
            printView = null
            invoke.reject("Не удалось открыть печать: ${e.message ?: e}", "platform")
          }
        }
      }
      printView?.destroy()
      printView = wv
      wv.loadDataWithBaseURL(null, html, "text/html", "UTF-8", null)
    } catch (e: Exception) {
      invoke.reject("Не удалось открыть печать: ${e.message ?: e}", "platform")
    }
  }

  /** Validates a destination path: an allowed export directory (same roots as [srcFile]) and a `.pdf` name. */
  private fun destFile(path: String?): File? {
    if (path.isNullOrBlank()) return null
    return try {
      val f = File(path).canonicalFile
      if (!f.name.lowercase().endsWith(".pdf")) return null
      val roots = listOfNotNull(
        try { activity.filesDir.canonicalFile } catch (_: Throwable) { null },
        try { activity.dataDir.canonicalFile } catch (_: Throwable) { null },
        try { activity.cacheDir.canonicalFile } catch (_: Throwable) { null },
      )
      val allowed = roots.any { r -> f.canonicalPath.startsWith(File(r, "exports").canonicalPath + File.separator) }
      if (allowed) f else null
    } catch (_: Throwable) {
      null
    }
  }

  /**
   * Report "PDF" without the print dialog: the HTML report is rendered in an off-screen WebView and its
   * print adapter writes an A4 PDF straight into `out` (an export directory). Page margins come from the
   * report's print stylesheet (`@page`). Replies `{ ok, path, name, size }`; the system print path
   * ([print_html]) stays as a fallback.
   */
  @Command
  fun pdf_html(invoke: Invoke) {
    val a = invoke.getArgs()
    val src = srcFile(a) ?: run { invoke.reject("файл не найден", "not_found"); return }
    val name = a.getString("name", null) ?: src.name
    if (!PrintLogic.isHtml(name) && !PrintLogic.isHtml(src.name)) { invoke.reject("PDF доступен только для HTML-отчёта", "bad_args"); return }
    val out = destFile(a.getString("out", null)) ?: run { invoke.reject("недопустимый путь PDF", "bad_args"); return }
    val html = try { src.readText(Charsets.UTF_8) } catch (e: Exception) { invoke.reject("Не удалось прочитать отчёт: ${e.message ?: e}", "platform"); return }
    activity.runOnUiThread {
      if (pdfView != null) { invoke.reject("PDF уже создаётся", "busy"); return@runOnUiThread }
      val main = Handler(Looper.getMainLooper())
      val cancel = CancellationSignal()
      val tmp = File(out.parentFile, out.name + ".part")
      var pfd: ParcelFileDescriptor? = null
      var settled = false
      var timeout: Runnable? = null
      val wv = try { WebView(activity) } catch (e: Throwable) { invoke.reject("WebView недоступен: ${e.message ?: e}", "platform"); return@runOnUiThread }
      pdfView = wv
      // Runs once on the main thread: closes the descriptor, frees the WebView, then replies.
      fun settle(err: String?) {
        if (settled) return
        settled = true
        timeout?.let { main.removeCallbacks(it) }
        try { pfd?.close() } catch (_: Throwable) {}
        pfd = null
        if (pdfView === wv) pdfView = null
        // Destroy after the current callback returns: the adapter may still be on the stack.
        main.post { try { wv.stopLoading(); wv.destroy() } catch (_: Throwable) {} }
        if (err == null && tmp.length() > 0 && (out.delete() || !out.exists()) && tmp.renameTo(out)) {
          FLog.i("pdf_html: ${out.name} ${out.length()} B")
          invoke.resolve(JSObject().put("ok", true).put("path", out.path).put("name", out.name).put("size", out.length()))
        } else {
          tmp.delete()
          FLog.w("pdf_html: ${err ?: "пустой файл"}")
          invoke.reject("Не удалось создать PDF: ${err ?: "пустой файл"}", if (err == "timeout") "timeout" else "platform")
        }
      }
      timeout = Runnable { cancel.cancel(); settle("timeout") }
      main.postDelayed(timeout, PDF_TIMEOUT_MS)
      try {
        out.parentFile?.mkdirs()
        wv.settings.javaScriptEnabled = false
        wv.settings.blockNetworkLoads = true
        wv.settings.allowFileAccess = false
        wv.settings.allowContentAccess = false
        var started = false
        wv.webViewClient = object : WebViewClient() {
          override fun shouldOverrideUrlLoading(view: WebView, request: WebResourceRequest): Boolean = true
          override fun onPageFinished(view: WebView, url: String?) {
            if (started || settled) return
            started = true
            try {
              val attrs = PrintAttributes.Builder()
                .setMediaSize(PrintAttributes.MediaSize.ISO_A4)
                .setResolution(PrintAttributes.Resolution("pdf", "pdf", 300, 300))
                .setColorMode(PrintAttributes.COLOR_MODE_COLOR)
                .setMinMargins(PrintAttributes.Margins.NO_MARGINS)
                .build()
              pfd = ParcelFileDescriptor.open(
                tmp,
                ParcelFileDescriptor.MODE_CREATE or ParcelFileDescriptor.MODE_TRUNCATE or ParcelFileDescriptor.MODE_READ_WRITE,
              )
              val adapter = view.createPrintDocumentAdapter(PrintLogic.jobName(name))
              PdfPrintDriver.write(adapter, attrs, pfd!!, cancel) { err -> settle(err) }
            } catch (e: Throwable) {
              settle(e.message ?: e.toString())
            }
          }
        }
        wv.loadDataWithBaseURL(null, html, "text/html", "UTF-8", null)
      } catch (e: Throwable) {
        settle(e.message ?: e.toString())
      }
    }
  }

  @Command
  fun save_to_downloads(invoke: Invoke) {
    val a = invoke.getArgs()
    val src = srcFile(a) ?: run { invoke.reject("файл не найден", "not_found"); return }
    val name = safeName(a.getString("name", null) ?: src.name)
    val mime = a.getString("mime", null) ?: "application/octet-stream"
    if (Build.VERSION.SDK_INT >= 29) {
      val resolver = activity.contentResolver
      var uri: Uri? = null
      try {
        val cv = ContentValues().apply {
          put(MediaStore.MediaColumns.DISPLAY_NAME, name)
          put(MediaStore.MediaColumns.MIME_TYPE, mime)
          put(MediaStore.MediaColumns.RELATIVE_PATH, Environment.DIRECTORY_DOWNLOADS + "/FOCA-rs")
          put(MediaStore.MediaColumns.IS_PENDING, 1)
        }
        uri = resolver.insert(MediaStore.Downloads.EXTERNAL_CONTENT_URI, cv) ?: throw IllegalStateException("MediaStore отказал")
        resolver.openOutputStream(uri)?.use { out -> src.inputStream().use { it.copyTo(out) } }
          ?: throw IllegalStateException("нет потока записи")
        resolver.update(uri, ContentValues().apply { put(MediaStore.MediaColumns.IS_PENDING, 0) }, null, null)
        // MediaStore may rename the file on a name clash ("name (1).ext").
        var shown = name
        resolver.query(uri, arrayOf(MediaStore.MediaColumns.DISPLAY_NAME), null, null, null)?.use { c ->
          if (c.moveToFirst()) shown = c.getString(0) ?: name
        }
        invoke.resolve(JSObject().put("ok", true).put("path", "Download/FOCA-rs/$shown").put("uri", uri.toString()))
      } catch (e: Exception) {
        uri?.let { try { resolver.delete(it, null, null) } catch (_: Throwable) {} }
        invoke.reject("Не удалось сохранить: ${e.message ?: e}", "platform")
      }
    } else {
      // Android 7-9 without WRITE_EXTERNAL_STORAGE: the system "Save as" dialog (SAF).
      pendingSave = src
      val i = Intent(Intent.ACTION_CREATE_DOCUMENT)
        .addCategory(Intent.CATEGORY_OPENABLE)
        .setType(mime)
        .putExtra(Intent.EXTRA_TITLE, name)
      try {
        startActivityForResult(invoke, i, "onSaveDocument")
      } catch (e: ActivityNotFoundException) {
        invoke.reject("Нет приложения для сохранения файлов", "platform")
      }
    }
  }

  @ActivityCallback
  private fun onSaveDocument(invoke: Invoke, result: ActivityResult) {
    val src = pendingSave
    pendingSave = null
    val uri = result.data?.data
    if (result.resultCode != Activity.RESULT_OK || uri == null || src == null) {
      invoke.resolve(JSObject().put("ok", false).put("cancelled", true)); return
    }
    try {
      activity.contentResolver.openOutputStream(uri)?.use { out -> src.inputStream().use { it.copyTo(out) } }
      invoke.resolve(JSObject().put("ok", true).put("path", uri.lastPathSegment ?: src.name).put("uri", uri.toString()))
    } catch (e: Exception) {
      invoke.reject("Не удалось сохранить: ${e.message ?: e}", "platform")
    }
  }

  // File and photo picking (no permissions needed).
  // platform_pick_files uses the Storage Access Framework (ACTION_OPEN_DOCUMENT); platform_pick_image uses
  // the system photo picker (Android 13+: ACTION_PICK_IMAGES, earlier ACTION_GET_CONTENT image/*) or the
  // camera (ACTION_IMAGE_CAPTURE into external-files/Pictures via FileProvider). Picked files are copied
  // into the private files/picked directory; the core (doc_import, finding_photo_add, preflight) reads the copy.
  private var pendingCamera: File? = null

  private fun pickedDir(): File = File(activity.filesDir, "picked").apply { mkdirs() }

  private fun displayName(uri: Uri): String {
    var n: String? = null
    try {
      activity.contentResolver.query(uri, arrayOf(android.provider.OpenableColumns.DISPLAY_NAME), null, null, null)?.use { c ->
        if (c.moveToFirst()) n = c.getString(0)
      }
    } catch (_: Throwable) {}
    return safeName(n ?: uri.lastPathSegment ?: "file")
  }

  private fun copyPicked(uri: Uri): JSObject? = try {
    val name = displayName(uri)
    val dir = pickedDir()
    var f = File(dir, name)
    var k = 1
    while (f.exists()) { k++; val dot = name.lastIndexOf('.'); f = File(dir, if (dot > 0) name.substring(0, dot) + "_$k" + name.substring(dot) else "${name}_$k") }
    activity.contentResolver.openInputStream(uri)?.use { inp -> f.outputStream().use { inp.copyTo(it) } } ?: throw IllegalStateException("нет потока")
    JSObject().put("path", f.absolutePath).put("name", f.name).put("size", f.length())
      .put("mime", activity.contentResolver.getType(uri) ?: "application/octet-stream")
  } catch (e: Exception) { null }

  private fun resolvePicked(invoke: Invoke, uris: List<Uri>) {
    val arr = app.tauri.plugin.JSArray()
    uris.forEach { u -> copyPicked(u)?.let { arr.put(it) } }
    invoke.resolve(JSObject().put("ok", arr.length() > 0).put("cancelled", arr.length() == 0).put("files", arr))
  }

  private fun urisOf(result: ActivityResult): List<Uri> {
    val d = result.data ?: return emptyList()
    if (result.resultCode != Activity.RESULT_OK) return emptyList()
    val clip = d.clipData
    if (clip != null) return (0 until clip.itemCount).mapNotNull { clip.getItemAt(it).uri }
    return listOfNotNull(d.data)
  }

  @Command
  fun pick_files(invoke: Invoke) {
    val a = invoke.getArgs()
    val i = Intent(Intent.ACTION_OPEN_DOCUMENT)
      .addCategory(Intent.CATEGORY_OPENABLE)
      .setType("*/*")
      .putExtra(Intent.EXTRA_ALLOW_MULTIPLE, a.getBoolean("multiple", true))
    try { startActivityForResult(invoke, i, "onPickFiles") } catch (e: ActivityNotFoundException) { invoke.reject("Нет приложения для выбора файлов", "platform") }
  }

  @ActivityCallback
  private fun onPickFiles(invoke: Invoke, result: ActivityResult) = resolvePicked(invoke, urisOf(result))

  // Offline import: a whole folder through the Storage Access Framework tree picker. The
  // tree is walked and copied in a background thread into files/picked/tree-<time>/ with limits
  // (file count, total size, per-file size, depth); names are flattened and deduplicated, so
  // nothing from the source tree becomes a path. The core reads the copies (import_offline);
  // platform_pick_clear removes them afterwards.
  @Command
  fun pick_folder(invoke: Invoke) {
    try {
      startActivityForResult(invoke, Intent(Intent.ACTION_OPEN_DOCUMENT_TREE), "onPickFolder")
    } catch (e: ActivityNotFoundException) {
      invoke.reject("Нет приложения для выбора папки", "platform")
    }
  }

  @ActivityCallback
  private fun onPickFolder(invoke: Invoke, result: ActivityResult) {
    val tree = if (result.resultCode == Activity.RESULT_OK) result.data?.data else null
    if (tree == null) {
      invoke.resolve(JSObject().put("ok", false).put("cancelled", true).put("files", app.tauri.plugin.JSArray()).put("skipped", 0))
      return
    }
    val a = invoke.getArgs()
    val budget = PickLogic.Budget(
      a.getInteger("max_files", PickLogic.MAX_FILES).coerceIn(1, 2000),
      (a.getInteger("max_mb", (PickLogic.MAX_BYTES / (1024 * 1024)).toInt()).toLong() * 1024 * 1024)
        .coerceIn(1024L * 1024, 2048L * 1024 * 1024),
    )
    val resolver = activity.contentResolver
    val dir = File(pickedDir(), "tree-${System.currentTimeMillis()}").apply { mkdirs() }
    Thread {
      val arr = app.tauri.plugin.JSArray()
      val taken = HashSet<String>()
      var truncated = false
      fun walk(docId: String, depth: Int) {
        val children = DocumentsContract.buildChildDocumentsUriUsingTree(tree, docId)
        val cols = arrayOf(
          DocumentsContract.Document.COLUMN_DOCUMENT_ID,
          DocumentsContract.Document.COLUMN_DISPLAY_NAME,
          DocumentsContract.Document.COLUMN_MIME_TYPE,
          DocumentsContract.Document.COLUMN_SIZE,
        )
        try {
          resolver.query(children, cols, null, null, null)?.use { c ->
            while (c.moveToNext()) {
              val id = c.getString(0) ?: continue
              val mime = c.getString(2) ?: "application/octet-stream"
              if (mime == DocumentsContract.Document.MIME_TYPE_DIR) {
                if (depth < PickLogic.MAX_DEPTH) walk(id, depth + 1) else truncated = true
                continue
              }
              val size = if (c.isNull(3)) -1L else c.getLong(3)
              if (budget.admit(size) != null) { truncated = true; continue }
              val name = PickLogic.uniqueName(taken, PickLogic.safeName(c.getString(1) ?: "file"))
              val f = File(dir, name)
              val copied = try {
                resolver.openInputStream(DocumentsContract.buildDocumentUriUsingTree(tree, id))?.use { inp ->
                  f.outputStream().use { PickLogic.copyCapped(inp, it, budget.room()) }
                } ?: -1L
              } catch (e: Exception) { -1L }
              if (copied < 0) { f.delete(); budget.drop(); truncated = true; continue }
              taken += name
              budget.add(copied)
              arr.put(JSObject().put("path", f.absolutePath).put("name", name).put("size", copied).put("mime", mime))
            }
          }
        } catch (e: Exception) {
          FLog.w("pick_folder: $e")
          truncated = true
        }
      }
      walk(DocumentsContract.getTreeDocumentId(tree), 0)
      invoke.resolve(
        JSObject().put("ok", arr.length() > 0).put("cancelled", false).put("files", arr)
          .put("skipped", budget.skipped).put("truncated", truncated).put("bytes", budget.bytes)
      )
    }.start()
  }

  /** Files shared into the app (ShareInbox), handed out once: `{ files, skipped, truncated }`. */
  @Command
  fun shared_files(invoke: Invoke) {
    invoke.resolve(ShareInbox.drain())
  }

  /** Removes every picked copy (after the import the core has its own copies by SHA-256). */
  @Command
  fun pick_clear(invoke: Invoke) {
    var removed = 0
    val root = pickedDir()
    root.walkBottomUp().forEach { f ->
      if (f == root) return@forEach
      val file = f.isFile
      if (f.delete() && file) removed++
    }
    invoke.resolve(JSObject().put("ok", true).put("removed", removed))
  }

  @Command
  fun pick_image(invoke: Invoke) {
    val a = invoke.getArgs()
    try {
      if (a.getBoolean("camera", false)) {
        val dir = File(activity.getExternalFilesDir(Environment.DIRECTORY_PICTURES), "").apply { mkdirs() }
        val f = File(dir, "IMG_${System.currentTimeMillis()}.jpg")
        pendingCamera = f
        val uri = FileProvider.getUriForFile(activity, activity.packageName + ".fileprovider", f)
        val i = Intent(MediaStore.ACTION_IMAGE_CAPTURE).putExtra(MediaStore.EXTRA_OUTPUT, uri)
          .addFlags(Intent.FLAG_GRANT_WRITE_URI_PERMISSION or Intent.FLAG_GRANT_READ_URI_PERMISSION)
        startActivityForResult(invoke, i, "onCamera"); return
      }
      val i = if (Build.VERSION.SDK_INT >= 33) Intent(MediaStore.ACTION_PICK_IMAGES)
        else Intent(Intent.ACTION_GET_CONTENT).addCategory(Intent.CATEGORY_OPENABLE).setType("image/*")
      startActivityForResult(invoke, i, "onPickImage")
    } catch (e: ActivityNotFoundException) {
      invoke.reject("Нет приложения для выбора фото", "platform")
    }
  }

  @ActivityCallback
  private fun onPickImage(invoke: Invoke, result: ActivityResult) = resolvePicked(invoke, urisOf(result).take(1))

  @ActivityCallback
  private fun onCamera(invoke: Invoke, result: ActivityResult) {
    val f = pendingCamera
    pendingCamera = null
    if (result.resultCode != Activity.RESULT_OK || f == null || !f.isFile || f.length() == 0L) {
      invoke.resolve(JSObject().put("ok", false).put("cancelled", true).put("files", app.tauri.plugin.JSArray())); return
    }
    val dst = File(pickedDir(), f.name)
    f.copyTo(dst, overwrite = true); f.delete()
    val arr = app.tauri.plugin.JSArray().put(JSObject().put("path", dst.absolutePath).put("name", dst.name).put("size", dst.length()).put("mime", "image/jpeg"))
    invoke.resolve(JSObject().put("ok", true).put("cancelled", false).put("files", arr))
  }

  // Biometrics.
  @Command
  fun biometric_prompt(invoke: Invoke) {
    val a = invoke.getArgs()
    val fa = activity as? FragmentActivity
    val auth = BiometricManager.Authenticators.BIOMETRIC_WEAK
    val can = try { BiometricManager.from(activity).canAuthenticate(auth) } catch (_: Throwable) { -1 }
    if (fa == null || can != BiometricManager.BIOMETRIC_SUCCESS) {
      // No sensor or no enrolled fingerprint: the UI falls back to the app PIN.
      val why = when (can) {
        BiometricManager.BIOMETRIC_ERROR_NONE_ENROLLED -> "none_enrolled"
        BiometricManager.BIOMETRIC_ERROR_NO_HARDWARE -> "no_hardware"
        BiometricManager.BIOMETRIC_ERROR_HW_UNAVAILABLE -> "hw_unavailable"
        BiometricManager.BIOMETRIC_ERROR_SECURITY_UPDATE_REQUIRED -> "security_update"
        else -> "unavailable"
      }
      invoke.resolve(JSObject().put("ok", false).put("available", false).put("error", why)); return
    }
    val done = AtomicBoolean(false)
    fun finish(o: JSObject) { if (done.compareAndSet(false, true)) invoke.resolve(o) }
    try {
      val prompt = BiometricPrompt(fa, ContextCompat.getMainExecutor(activity), object : BiometricPrompt.AuthenticationCallback() {
        override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
          finish(JSObject().put("ok", true).put("available", true))
        }
        override fun onAuthenticationError(code: Int, msg: CharSequence) {
          val err = when (code) {
            BiometricPrompt.ERROR_USER_CANCELED, BiometricPrompt.ERROR_NEGATIVE_BUTTON, BiometricPrompt.ERROR_CANCELED -> "cancel"
            BiometricPrompt.ERROR_LOCKOUT, BiometricPrompt.ERROR_LOCKOUT_PERMANENT -> "lockout"
            BiometricPrompt.ERROR_NO_BIOMETRICS, BiometricPrompt.ERROR_HW_NOT_PRESENT, BiometricPrompt.ERROR_HW_UNAVAILABLE -> "unavailable"
            else -> msg.toString()
          }
          // Lockout after failed attempts or a vanished sensor also fall back to the PIN.
          val available = err != "lockout" && err != "unavailable"
          finish(JSObject().put("ok", false).put("available", available).put("error", err))
        }
      })
      val info = BiometricPrompt.PromptInfo.Builder()
        .setTitle(a.getString("title", null) ?: "Подтвердите личность")
        .apply { a.getString("subtitle", null)?.takeIf { it.isNotBlank() }?.let { setSubtitle(it) } }
        .setNegativeButtonText("Отмена")
        .setAllowedAuthenticators(auth)
        .setConfirmationRequired(false)
        .build()
      prompt.authenticate(info)
    } catch (e: Throwable) {
      finish(JSObject().put("ok", false).put("available", false).put("error", e.toString()))
    }
  }

  // ------------------------------------------------------------------ FLAG_SECURE
  @Command
  fun set_secure(invoke: Invoke) {
    val on = invoke.getArgs().getBoolean("on", false)
    prefs(ctx).edit().remove("secure").putBoolean(PREF_SECURE, on).apply()
    activity.runOnUiThread { try { applySecure(activity, on) } catch (_: Throwable) {} }
    invoke.resolve(JSObject().put("ok", true).put("applied", true))
  }

  // Battery.
  private fun sysProp(name: String): String? = try {
    val c = Class.forName("android.os.SystemProperties")
    (c.getMethod("get", String::class.java).invoke(null, name) as? String)?.takeIf { it.isNotBlank() }
  } catch (_: Throwable) { null }

  private fun ignoring(): Boolean = try {
    val pm = ctx.getSystemService(Context.POWER_SERVICE) as PowerManager
    pm.isIgnoringBatteryOptimizations(ctx.packageName)
  } catch (_: Throwable) { false }

  @Command
  fun battery_optimization_status(invoke: Invoke) {
    val oem = Oem.detect(Build.MANUFACTURER, Build.BRAND)
    val rom = Oem.rom(sysProp("ro.mi.os.version.name"), sysProp("ro.miui.ui.version.name"))
    invoke.resolve(JSObject()
      .put("ignoring", ignoring())
      .put("supported", true)
      .put("oem", oem)
      .put("rom", rom)
      .put("manufacturer", Build.MANUFACTURER)
      .put("model", Build.MODEL)
      .put("android", Build.VERSION.RELEASE)
      .put("sdk", Build.VERSION.SDK_INT)
      .put("label", Oem.label(Build.MANUFACTURER, Build.MODEL, rom, Build.VERSION.RELEASE))
      .put("notifications", NotificationManagerCompat.from(ctx).areNotificationsEnabled()))
  }

  /** Background status for Settings › Background (`platform_bg_status`). */
  @Command
  fun bg_status(invoke: Invoke) {
    val auto = RecentsGuard.autostart(ctx)
    FLog.i("фон: прошивка=${RecentsGuard.family()} автозапуск=$auto батарея без ограничений=${ignoring()}")
    invoke.resolve(JSObject()
      .put("oem", RecentsGuard.family())
      .put("autostart", auto)
      .put("battery_unrestricted", ignoring())
      .put("hide_recents", RecentsGuard.enabled(ctx))
      .put("hide_recents_default", RecentsGuard.aggressive())
      .put("hide_recents_chosen", RecentsGuard.stored(ctx) != null))
  }

  /** Stores background options from the UI (`platform_bg_set { hide_recents }`). */
  @Command
  fun bg_set(invoke: Invoke) {
    val a = invoke.getArgs()
    if (a.has("hide_recents")) RecentsGuard.setEnabled(ctx, a.getBoolean("hide_recents", false))
    bg_status(invoke)
  }

  // Clipboard. The WebView cannot read it (no async Clipboard API read grant), so the UI goes through
  // ClipboardManager. Decisions live in ClipLogic (unit tested).
  private val clipboard: ClipboardManager? get() = ctx.getSystemService(ClipboardManager::class.java)
  /** SHA-256 of the last clip this app wrote; null after a clear or a foreign change. */
  private var clipWritten: String? = null
  /** A clip change not made by this app was seen after [clipWritten] (only reported while focused). */
  private var clipChanged = false
  private var clipListening = false
  private var clipClearTask: Runnable? = null
  private val clipHandler by lazy { Handler(Looper.getMainLooper()) }

  /** Text of the primary clip, or null when there is none or the system hides it from the app. */
  private fun clipText(cm: ClipboardManager): String? {
    val clip = cm.primaryClip ?: return null
    for (i in 0 until clip.itemCount) {
      val t = clip.getItemAt(i).coerceToText(ctx)
      if (!t.isNullOrEmpty()) return ClipLogic.capText(t)
    }
    return ""
  }

  private fun clipListen(cm: ClipboardManager) {
    if (clipListening) return
    clipListening = true
    cm.addPrimaryClipChangedListener {
      // Android 10+ delivers this only while the app may read the clipboard; our own writes match.
      val t = try { clipText(cm) } catch (_: Throwable) { null } ?: return@addPrimaryClipChangedListener
      if (clipWritten != null && ClipLogic.digest(t) != clipWritten) clipChanged = true
    }
  }

  /** Clears the clipboard if [ClipLogic.shouldClear] allows it; returns whether it was cleared. */
  private fun clipClearIf(cm: ClipboardManager, expectedDigest: String?): Boolean {
    val focused = activity.hasWindowFocus()
    val cur = if (focused) clipText(cm) else null
    // Focused and no clip at all is readable too (nothing there); a hidden clip is not.
    val readable = focused && (cur != null || !cm.hasPrimaryClip())
    val ok = ClipLogic.shouldClear(expectedDigest, readable, cur?.let { ClipLogic.digest(it) }, clipWritten, clipChanged)
    if (!ok) return false
    if (ClipLogic.canClearNatively(Build.VERSION.SDK_INT)) cm.clearPrimaryClip()
    else cm.setPrimaryClip(ClipData.newPlainText("", ""))
    clipWritten = null
    clipChanged = false
    return true
  }

  /** `platform_clipboard_read`: `{ ok, text, available, error? }`. `error`: `no_focus` (the app has no
   *  window focus, Android 10+ hides the clipboard), `blocked` (a clip exists but the system or the
   *  ROM privacy setting withholds it), `unavailable` (no ClipboardManager). */
  @Command
  fun clipboard_read(invoke: Invoke) {
    val out = JSObject().put("text", "").put("available", false)
    try {
      val cm = clipboard ?: run { invoke.resolve(out.put("ok", false).put("error", "unavailable")); return }
      clipListen(cm)
      if (!activity.hasWindowFocus()) { invoke.resolve(out.put("ok", false).put("error", "no_focus")); return }
      val t = clipText(cm)
      if (t == null) {
        if (cm.hasPrimaryClip()) { FLog.w("буфер обмена: клип есть, но система его не отдаёт"); out.put("ok", false).put("error", "blocked") }
        else out.put("ok", true)
      } else {
        out.put("ok", true).put("text", t).put("available", t.isNotEmpty())
      }
    } catch (e: Throwable) {
      FLog.w("clipboard_read", e)
      out.put("ok", false).put("error", "platform")
    }
    invoke.resolve(out)
  }

  /** `platform_clipboard_write { text, sensitive?, clear_after_ms? }`: `{ ok }`. `sensitive` sets
   *  `EXTRA_IS_SENSITIVE` (Android 13+ hides the value in the copy preview); `clear_after_ms` schedules
   *  the conditional auto-clear here, so it runs even if the WebView timers are throttled. */
  @Command
  fun clipboard_write(invoke: Invoke) {
    val a = invoke.getArgs()
    val text = a.getString("text", null) ?: ""
    try {
      val cm = clipboard ?: run { invoke.resolve(JSObject().put("ok", false).put("error", "unavailable")); return }
      clipListen(cm)
      val clip = ClipData.newPlainText(ClipLogic.LABEL, text)
      if (a.getBoolean("sensitive", false)) {
        clip.description.extras = PersistableBundle().apply { putBoolean(ClipLogic.EXTRA_IS_SENSITIVE, true) }
      }
      val d = ClipLogic.digest(text)
      clipWritten = d
      clipChanged = false
      cm.setPrimaryClip(clip)
      clipClearTask?.let { clipHandler.removeCallbacks(it) }
      clipClearTask = null
      val ms = a.getInteger("clear_after_ms", 0)
      if (ms > 0) {
        val task = Runnable {
          clipClearTask = null
          val done = try { clipClearIf(cm, d) } catch (e: Throwable) { FLog.w("clipboard auto-clear", e); false }
          FLog.i("буфер обмена: автоочистка ${if (done) "выполнена" else "пропущена (там уже другое)"}")
        }
        clipClearTask = task
        clipHandler.postDelayed(task, ms.toLong())
      }
      invoke.resolve(JSObject().put("ok", true).put("scheduled", ms > 0))
    } catch (e: Throwable) {
      FLog.w("clipboard_write", e)
      invoke.resolve(JSObject().put("ok", false).put("error", "platform"))
    }
  }

  /** `platform_clipboard_clear { expected? }`: `{ ok, cleared }`. With `expected` the clipboard is wiped
   *  only while it still holds that value (see ClipLogic.shouldClear). */
  @Command
  fun clipboard_clear(invoke: Invoke) {
    val a = invoke.getArgs()
    val expected = if (a.has("expected")) a.getString("expected", null) else null
    try {
      val cm = clipboard ?: run { invoke.resolve(JSObject().put("ok", false).put("cleared", false)); return }
      val cleared = clipClearIf(cm, expected?.let { ClipLogic.digest(it) })
      if (cleared) clipClearTask?.let { clipHandler.removeCallbacks(it); clipClearTask = null }
      invoke.resolve(JSObject().put("ok", true).put("cleared", cleared))
    } catch (e: Throwable) {
      FLog.w("clipboard_clear", e)
      invoke.resolve(JSObject().put("ok", false).put("cleared", false).put("error", "platform"))
    }
  }

  @Command
  fun open_battery_settings(invoke: Invoke) {
    val what = invoke.getArgs().getString("what", null)
    val oem = Oem.detect(Build.MANUFACTURER, Build.BRAND)
    val pkg = ctx.packageName
    val targets = SettingsTargets.forWhat(what, oem, ignoring(), Build.VERSION.SDK_INT, pkg)
    for ((n, t) in targets.withIndex()) {
      val i = Intent()
      t.action?.let { i.action = it }
      if (t.pkg != null && t.cls != null) i.setClassName(t.pkg, t.cls)
      if (t.withPackageUri) i.data = Uri.parse("package:$pkg")
      t.extras.forEach { (k, v) -> i.putExtra(k, v) }
      try {
        activity.startActivity(i)
        FLog.i("фон: открыть ${what ?: "battery"} → ${t.target}${if (n > 0) " (запасной вариант $n)" else ""}")
        invoke.resolve(JSObject().put("opened", t.key)); return
      } catch (e: ActivityNotFoundException) {
        FLog.d("фон: открыть ${what ?: "battery"}: нет ${t.target}")
      } catch (e: SecurityException) {
        // Some MIUI screens are not exported; try the next candidate.
        FLog.d("фон: открыть ${what ?: "battery"}: ${t.target} закрыт")
      } catch (e: Throwable) {
        FLog.d("фон: открыть ${what ?: "battery"}: ${t.target}, $e")
      }
    }
    FLog.w("фон: открыть ${what ?: "battery"} → ничего не открылось")
    invoke.resolve(JSObject().put("opened", null as String?))
  }
}

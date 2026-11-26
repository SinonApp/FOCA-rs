package app.sinon.focars.platform

import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.os.Build
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat
import androidx.work.Constraints
import androidx.work.Data
import androidx.work.ExistingPeriodicWorkPolicy
import androidx.work.NetworkType
import androidx.work.PeriodicWorkRequestBuilder
import androidx.work.WorkManager
import androidx.work.Worker
import androidx.work.WorkerParameters
import app.tauri.plugin.JSObject
import app.sinon.focars.MainActivity
import app.sinon.focars.R
import java.util.Calendar
import java.util.TimeZone
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

/**
 * Monitoring: the "scan finished" notification and scheduled rescans via WorkManager.
 *
 * * The schedule comes from Rust (`monitor_schedule`, whenever `settings.monitor` changes): one
 *   unique periodic work per project, once a day around the configured time; the worker checks
 *   the weekday itself. Constraints: "Wi-Fi only" → unmetered network, "only while charging" →
 *   charging; battery not low is always required.
 * * The worker: if the Rust core is alive in this process (app in the background, [FocaBus]
 *   subscribed), it sends `{ kind: "monitor", project, profile, budget_sec }` (passive or standard
 *   profile only) and waits up to 8 minutes for the result. Otherwise (process started by
 *   WorkManager without a window), it boots the Rust engine headlessly via
 *   [FocaDirect.runHeadlessMonitor] within the same 8-minute budget, skipping WebView sources as
 *   `skipped_headless`, persists the diff and `monitor_status`, and posts the result notification.
 */
class MonitorWorker(ctx: Context, params: WorkerParameters) : Worker(ctx, params) {
  companion object {
    const val CHANNEL = "scan_done"
    private const val PREFS = "foca_monitor"
    private const val K_IDS = "ids"
    private const val WAIT_MIN = 8L
    private val latches = ConcurrentHashMap<String, CountDownLatch>()

    fun ensureChannel(ctx: Context) {
      if (Build.VERSION.SDK_INT < 26) return
      val nm = ctx.getSystemService(NotificationManager::class.java) ?: return
      if (nm.getNotificationChannel(CHANNEL) != null) return
      val ch = NotificationChannel(
        CHANNEL,
        ctx.getString(R.string.monitor_channel_name),
        NotificationManager.IMPORTANCE_DEFAULT,
      ).apply {
        description = ctx.getString(R.string.monitor_channel_description)
        setShowBadge(true)
      }
      nm.createNotificationChannel(ch)
    }

    private fun open(ctx: Context, route: String, code: Int): PendingIntent {
      val i = Intent(ctx, MainActivity::class.java)
        .putExtra(ScanService.EXTRA_ROUTE, route)
        .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_SINGLE_TOP)
      return PendingIntent.getActivity(ctx, code, i, PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT)
    }

    private fun notify(ctx: Context, id: Int, title: String, text: String, route: String?) {
      ensureChannel(AppLocale.wrap(ctx))
      val b = NotificationCompat.Builder(ctx, CHANNEL)
        .setSmallIcon(R.drawable.ic_stat_scan)
        .setContentTitle(title)
        .setContentText(text)
        .setStyle(NotificationCompat.BigTextStyle().bigText(text))
        .setAutoCancel(true)
        .setCategory(NotificationCompat.CATEGORY_STATUS)
        .setPriority(NotificationCompat.PRIORITY_DEFAULT)
        .setVisibility(NotificationCompat.VISIBILITY_PRIVATE)
      if (route != null && MonitorLogic.routeAllowed(route)) b.setContentIntent(open(ctx, route, id))
      try {
        NotificationManagerCompat.from(ctx).notify(id, b.build())
      } catch (e: SecurityException) {
        FLog.w("MonitorWorker: уведомления запрещены, $title")
      }
    }

    /** Posts the scan result (`scan_done_notify` from Rust) with document and finding counts; tapping opens the project. */
    fun notifyDone(ctx: Context, a: JSObject) {
      val project = a.getString("project", null) ?: ""
      val silent = a.optBoolean("silent", false)
      if (!silent) {
        val title = a.getString("title", null) ?: AppLocale.wrap(ctx).getString(R.string.monitor_done_default)
        val text = a.getString("text", null) ?: ""
        notify(ctx, 4200 + (project.hashCode() and 0x3ff), title, text, MonitorLogic.openRoute(project))
      }
      // Release only the matching project's latch (or all if project is blank).
      if (project.isNotEmpty()) {
        latches.remove(project)?.countDown()
      } else {
        latches.keys.toList().forEach { k -> latches.remove(k)?.countDown() }
      }
    }

    /** Schedules all projects (`monitor_schedule { items: [...] }`). */
    fun schedule(ctx: Context, a: JSObject): JSObject {
      val app = ctx.applicationContext
      val wm = WorkManager.getInstance(app)
      val prefs = app.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
      val old = prefs.getStringSet(K_IDS, emptySet()) ?: emptySet()
      val now = HashSet<String>()
      val arr = try { a.getJSONArray("items") } catch (_: Throwable) { null }
      var on = 0
      for (k in 0 until (arr?.length() ?: 0)) {
        val o = arr?.optJSONObject(k) ?: continue
        val project = MonitorLogic.safeId(o.optString("project")) ?: continue
        val mode = o.optString("mode", "off")
        if (mode != "daily" && mode != "weekly") continue
        val days = HashSet<Int>()
        val d = o.optJSONArray("days")
        for (j in 0 until (d?.length() ?: 0)) d?.optInt(j)?.takeIf { it in 1..7 }?.let { days.add(it) }
        val time = o.optString("time", "03:00")
        val cal = Calendar.getInstance()
        val delay = MonitorLogic.initialDelayMinutes(cal.get(Calendar.HOUR_OF_DAY) * 60 + cal.get(Calendar.MINUTE), time)
        val c = Constraints.Builder()
          .setRequiredNetworkType(if (o.optBoolean("wifi", true)) NetworkType.UNMETERED else NetworkType.CONNECTED)
          .setRequiresCharging(o.optBoolean("charge", false))
          .setRequiresBatteryNotLow(true)
          .build()
        val data = Data.Builder()
          .putString("project", project)
          .putString("name", o.optString("name", project))
          .putString("mode", mode)
          .putIntArray("days", days.toIntArray())
          .putString("profile", MonitorLogic.safeProfile(o.optString("profile")))
          .build()
        val req = PeriodicWorkRequestBuilder<MonitorWorker>(24, TimeUnit.HOURS, 1, TimeUnit.HOURS)
          .setInitialDelay(delay, TimeUnit.MINUTES)
          .setConstraints(c)
          .setInputData(data)
          .addTag("monitor")
          .build()
        wm.enqueueUniquePeriodicWork(MonitorLogic.workName(project), ExistingPeriodicWorkPolicy.UPDATE, req)
        now.add(project)
        on++
      }
      for (p in old - now) wm.cancelUniqueWork(MonitorLogic.workName(p))
      prefs.edit().putStringSet(K_IDS, now).apply()
      FLog.i("MonitorWorker: расписание, $on проект(ов), снято ${(old - now).size}")
      return JSObject().put("ok", true).put("scheduled", on)
    }
  }

  override fun doWork(): Result {
    val project = inputData.getString("project") ?: return Result.success()
    val name = inputData.getString("name") ?: project
    val mode = inputData.getString("mode") ?: "off"
    val days = (inputData.getIntArray("days") ?: intArrayOf()).toSet()
    val profile = MonitorLogic.safeProfile(inputData.getString("profile"))
    val wd = MonitorLogic.isoWeekday(Calendar.getInstance().get(Calendar.DAY_OF_WEEK))
    if (!MonitorLogic.dueToday(mode, days, wd)) return Result.success()
    val ctx = applicationContext
    FLog.init(ctx)
    app.sinon.focars.CrashLog.install(ctx)

    if (FocaBus.hasListener()) {
      FLog.i("MonitorWorker: плановый скан $project ($profile): ядро живо, запускаем")
      val l = CountDownLatch(1)
      latches[project] = l
      try {
        val sent = FocaBus.send(
          JSObject()
            .put("kind", "monitor")
            .put("project", project)
            .put("profile", profile)
            .put("budget_sec", MonitorLogic.DEFAULT_BUDGET_SEC),
        )
        if (sent) {
          // Hold the process while the scan runs (the result arrives via notifyDone); capped safely under WorkManager's limit.
          try { l.await(WAIT_MIN, TimeUnit.MINUTES) } catch (_: InterruptedException) {}
          return Result.success()
        }
      } finally {
        latches.remove(project, l)
      }
    }

    // No active Tauri bridge: run the Rust core directly via JNI with no WebView/Activity.
    val dataDir = FLog.dataDir(ctx).absolutePath
    val utcOffsetSec = TimeZone.getDefault().getOffset(System.currentTimeMillis()) / 1000
    FLog.i("MonitorWorker: headless-ядро старт $project ($profile), бюджет ${MonitorLogic.DEFAULT_BUDGET_SEC}с, dir=$dataDir")
    val raw = FocaDirect.runHeadlessMonitor(
      ctx,
      dataDir,
      project,
      profile,
      MonitorLogic.DEFAULT_BUDGET_SEC,
      utcOffsetSec,
    )
    val res = try { JSObject(raw) } catch (_: Throwable) { null }
    val status = res?.optString("status", "error") ?: "error"
    val title = res?.optString("title", "") ?: ""
    val text = res?.optString("text", "") ?: ""
    val uiAttached = res?.optBoolean("ui_attached", false) ?: false
    val error = res?.optString("error", "") ?: ""

    when (status) {
      "done", "busy" -> FLog.i("MonitorWorker: headless $project → $status (uiAttached=$uiAttached)")
      "budget", "cancelled" -> FLog.w("MonitorWorker: headless $project → $status (uiAttached=$uiAttached)")
      else -> FLog.e("MonitorWorker: headless $project → $status: $error")
    }

    if (MonitorLogic.shouldNotifyHeadless(status, uiAttached)) {
      val res = AppLocale.wrap(ctx)
      when (status) {
        "done" -> notifyDone(
          ctx,
          JSObject()
            .put("project", project)
            .put("title", title.ifEmpty { res.getString(R.string.monitor_done_project, name) })
            .put("text", text),
        )
        "budget", "cancelled" -> notify(
          ctx,
          4200 + (project.hashCode() and 0x3ff),
          title.ifEmpty { res.getString(R.string.monitor_paused_project, name) },
          text.ifEmpty { res.getString(R.string.monitor_budget_text) },
          MonitorLogic.headlessRoute(project, status),
        )
        else -> notify(
          ctx,
          4600 + (project.hashCode() and 0x3ff),
          res.getString(R.string.monitor_reminder_title, name),
          res.getString(
            R.string.monitor_error_text,
            if (profile == "std") res.getString(R.string.monitor_profile_std) else res.getString(R.string.monitor_profile_passive),
            error.ifEmpty { res.getString(R.string.monitor_error_fallback) },
          ),
          MonitorLogic.reminderRoute(project),
        )
      }
    }
    return Result.success()
  }

  override fun onStopped() {
    FLog.w("MonitorWorker.onStopped: WorkManager останавливает фоновую задачу")
    FocaDirect.cancelHeadlessMonitor()
    // Release the latch held by this worker so doWork() returns promptly instead of waiting out WAIT_MIN.
    inputData.getString("project")?.takeIf { it.isNotEmpty() }?.let { latches.remove(it)?.countDown() }
    super.onStopped()
  }
}

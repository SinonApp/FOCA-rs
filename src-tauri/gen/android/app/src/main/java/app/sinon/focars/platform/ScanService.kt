package app.sinon.focars.platform

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.os.Build
import android.os.IBinder
import android.os.PowerManager
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat
import androidx.core.app.ServiceCompat
import androidx.core.content.ContextCompat
import app.tauri.plugin.JSObject
import app.sinon.focars.MainActivity
import app.sinon.focars.R

/** Contents of the scan notification (built by Rust: title, stage, percent, pause). */
data class ScanNote(
  val title: String = "",
  val text: String = "",
  val progress: Int = 0,
  val paused: Boolean = false,
  val route: String = "/p/scan",
) {
  companion object {
    fun from(a: JSObject) = ScanNote(
      title = a.getString("title", null) ?: "",
      text = a.getString("text", null) ?: "",
      progress = a.getInteger("progress", 0),
      paused = a.getBoolean("paused", false),
      route = a.getString("route", null) ?: "/p/scan",
    )
  }
}

/**
 * Scan foreground service (type `dataSync`): a persistent "scanning … N%" notification with Open
 * and Stop actions and a partial WAKE_LOCK for the duration of the scan. The scan itself runs in
 * the Rust tokio runtime in the same process; the service only keeps the system from killing the
 * process.
 *
 * Android 14+: the type is declared in the manifest and in startForeground. Android 15+: dataSync
 * is limited to 6 h per day; [onTimeout] reports to Rust (`service/timeout` → pause with reason
 * `android`) and stops the service.
 *
 * While a scan runs the service is START_STICKY and sets `scan_active` in settings: if the OEM
 * shell (HyperOS/MIUI) kills the process anyway and the system restarts the service, the engine is
 * gone, so [ScanResumeWorker] tries to resume the scan in the background (headless core in this
 * service) and falls back to a "scan interrupted, tap to resume" notification; when the app opens,
 * Rust resumes the scan itself (`foca_engine::resume`) or the UI attaches to the running one.
 */
class ScanService : Service() {
  companion object {
    /** Progress channel. A new id because channel settings of existing installs cannot be changed:
     *  the old silent `scan` channel (IMPORTANCE_LOW) kept the notification off the lock screen. */
    const val CHANNEL = LockscreenLogic.CHANNEL
    private const val OLD_CHANNEL = "scan"
    const val NOTIF_ID = 4107
    const val NOTIF_INTERRUPTED = 4109
    private const val PREF_SCAN_ACTIVE = "scan_active"
    const val PREF_INTERRUPT_REASON = "interrupt_reason"
    const val PREF_INTERRUPT_AT = "interrupt_at"
    const val ACTION_START = "app.sinon.focars.SCAN_START"
    const val ACTION_STOP_SERVICE = "app.sinon.focars.SCAN_SERVICE_STOP"
    const val ACTION_STOP_SCAN = "app.sinon.focars.SCAN_STOP"
    const val EXTRA_ROUTE = "route"
    private const val WAKE_TIMEOUT_MS = 6L * 60 * 60 * 1000

    @Volatile var running = false
      private set
    @Volatile var note = ScanNote()
    /** A scan is still running (stop may arrive before the system calls onStartCommand). */
    @Volatile private var wanted = false
    /** A scan is running in this process (between Rust's start and stop calls). */
    val scanRunning: Boolean get() = wanted
    @Volatile private var instance: ScanService? = null
    private val main = android.os.Handler(android.os.Looper.getMainLooper())

    fun ensureChannel(ctx: Context) {
      if (Build.VERSION.SDK_INT < 26) return
      val nm = ctx.getSystemService(NotificationManager::class.java) ?: return
      try { if (nm.getNotificationChannel(OLD_CHANNEL) != null) nm.deleteNotificationChannel(OLD_CHANNEL) } catch (_: Throwable) {}
      if (nm.getNotificationChannel(CHANNEL) != null) return
      // Default importance without sound or vibration: Android and HyperOS hide "silent" (low)
      // notifications on the lock screen. The lock screen gets the public version (no project name).
      val ch = NotificationChannel(
        CHANNEL,
        ctx.getString(R.string.scan_channel_name),
        NotificationManager.IMPORTANCE_DEFAULT,
      ).apply {
        description = ctx.getString(R.string.scan_channel_description)
        setShowBadge(false)
        setSound(null, null)
        enableVibration(false)
        enableLights(false)
        lockscreenVisibility = android.app.Notification.VISIBILITY_PRIVATE
      }
      nm.createNotificationChannel(ch)
    }

    private fun markScan(ctx: Context, on: Boolean) {
      try { FocaPlugin.prefs(ctx).edit().putBoolean(PREF_SCAN_ACTIVE, on).apply() } catch (_: Throwable) {}
    }

    fun scanMarked(ctx: Context): Boolean =
      try { FocaPlugin.prefs(ctx).getBoolean(PREF_SCAN_ACTIVE, false) } catch (_: Throwable) { false }

    /** Clears the "scan running" marker once the interruption has been reported. */
    fun clearMark(ctx: Context) = markScan(ctx, false)

    /** Stores the interruption reason (shown in Debug › Device and in the log). */
    fun noteInterrupt(ctx: Context, reason: String) {
      try {
        FocaPlugin.prefs(ctx).edit().putString(PREF_INTERRUPT_REASON, reason)
          .putLong(PREF_INTERRUPT_AT, System.currentTimeMillis()).apply()
      } catch (_: Throwable) {}
    }

    /** Returns the last stored interruption reason as `"<reason> @<unix ms>"`, or `null`. */
    fun lastInterrupt(ctx: Context): String? = try {
      val p = FocaPlugin.prefs(ctx)
      p.getString(PREF_INTERRUPT_REASON, null)?.let { "$it @${p.getLong(PREF_INTERRUPT_AT, 0)}" }
    } catch (_: Throwable) { null }

    /** Removes the interrupted-scan notification (the app is open and Rust resumes the scan). */
    fun clearInterrupted(ctx: Context) {
      try { NotificationManagerCompat.from(ctx).cancel(NOTIF_INTERRUPTED) } catch (_: Throwable) {}
    }

    /** Clears the scan marker and notification when the app opens; Rust resumes the interrupted scan. */
    fun onAppOpened(ctx: Context) {
      if (!wanted) {
        markScan(ctx, false)
        ScanResumeWorker.cancel(ctx)
      }
      clearInterrupted(ctx)
    }

    /** Posts a regular (non-foreground) notification: scan interrupted by the system, tap or Continue opens
     *  the app on the scan screen and the core resumes the scan. */
    fun notifyInterrupted(ctx: Context) {
      try {
        ensureChannel(ctx)
        val res = AppLocale.wrap(ctx)
        val tip = RecoveryLogic.interruptedTip(Oem.detect(Build.MANUFACTURER, Build.BRAND))
        val open = openIntent(ctx, "/p/scan")
        val n = NotificationCompat.Builder(ctx, CHANNEL)
          .setSmallIcon(R.drawable.ic_stat_scan)
          .setContentTitle(res.getString(R.string.scan_interrupted_title))
          .setContentText(res.getString(R.string.scan_interrupted_text))
          .setStyle(NotificationCompat.BigTextStyle().bigText(
            res.getString(R.string.scan_interrupted_body) + " " + res.getString(tip)))
          .setAutoCancel(true)
          .setCategory(NotificationCompat.CATEGORY_STATUS)
          .setContentIntent(open)
          .addAction(0, res.getString(R.string.scan_action_continue), open)
          .build()
        NotificationManagerCompat.from(ctx).notify(NOTIF_INTERRUPTED, n)
        FLog.w("ScanService: процесс был убит во время скана, показано уведомление «Скан прерван»")
      } catch (e: Throwable) {
        FLog.w("ScanService: уведомление о прерванном скане не показано", e)
      }
    }

    /** Opens the existing task (singleTask MainActivity, even when hidden from Recents) on [route]; the UI
     *  queues the route behind the PIN lock screen. */
    fun openIntent(ctx: Context, route: String): PendingIntent {
      val i = Intent(ctx, MainActivity::class.java)
        .putExtra(EXTRA_ROUTE, route)
        .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_SINGLE_TOP)
      return PendingIntent.getActivity(ctx, 1, i, PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT)
    }

    fun build(ctx: Context, n: ScanNote, stopping: Boolean = false): Notification {
      ensureChannel(ctx)
      val res = AppLocale.wrap(ctx)
      val stop = PendingIntent.getService(ctx, 2,
        Intent(ctx, ScanService::class.java).setAction(ACTION_STOP_SCAN),
        PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT)
      val open = openIntent(ctx, n.route)
      val text = if (stopping) res.getString(R.string.scan_stopping) else n.text
      val b = NotificationCompat.Builder(ctx, CHANNEL)
        .setSmallIcon(R.drawable.ic_stat_scan)
        .setContentTitle(n.title.ifBlank { res.getString(R.string.scan_title_default) })
        .setContentText(text)
        .setOngoing(true)
        // Alerts once without sound (the channel has none); setSilent would mark it silent again and
        // keep it off the lock screen.
        .setOnlyAlertOnce(true)
        .setCategory(NotificationCompat.CATEGORY_PROGRESS)
        .setPriority(NotificationCompat.PRIORITY_DEFAULT)
        .setVisibility(NotificationCompat.VISIBILITY_PRIVATE)
        .setPublicVersion(NotificationCompat.Builder(ctx, CHANNEL)
          .setSmallIcon(R.drawable.ic_stat_scan)
          .setContentTitle(res.getString(R.string.scan_title_default))
          .setContentText(res.getString(R.string.scan_public_text, n.progress.coerceIn(0, 100)))
          .setOngoing(true)
          .setOnlyAlertOnce(true)
          .setCategory(NotificationCompat.CATEGORY_PROGRESS)
          .setProgress(100, n.progress.coerceIn(0, 100), false)
          .build())
        .setForegroundServiceBehavior(NotificationCompat.FOREGROUND_SERVICE_IMMEDIATE)
        .setContentIntent(open)
        .setProgress(100, n.progress.coerceIn(0, 100), false)
        .addAction(0, res.getString(R.string.scan_action_open), open)
      if (!stopping) b.addAction(0, res.getString(R.string.scan_action_stop), stop)
      // The card is gone from Recents during the scan: tell the user the way back.
      if (!stopping && RecentsGuard.enabled(ctx)) {
        val hint = res.getString(R.string.scan_hidden_hint)
        b.setStyle(NotificationCompat.BigTextStyle().bigText(if (text.isBlank()) hint else "$text\n$hint"))
      }
      return b.build()
    }

    /** Updates the notification without restarting the service. */
    fun update(ctx: Context, n: ScanNote) {
      note = n
      if (!running) return
      try {
        NotificationManagerCompat.from(ctx).notify(NOTIF_ID, build(ctx, n))
      } catch (_: SecurityException) {
        // POST_NOTIFICATIONS not granted: the FGS notification is still visible in the task manager.
      } catch (_: Throwable) {}
    }

    /** Starts the service from Rust on the `started` event; returns `null` on success, otherwise the error text. */
    fun start(ctx: Context, n: ScanNote): String? {
      note = n
      wanted = true
      markScan(ctx, true)
      clearInterrupted(ctx)
      return try {
        ContextCompat.startForegroundService(ctx, Intent(ctx, ScanService::class.java).setAction(ACTION_START))
        FLog.i("ScanService.start: startForegroundService ок (running=$running)")
        RecentsGuard.onEvent(ctx, RecentsEvent.SCAN_START)
        null
      } catch (e: Throwable) {
        // ForegroundServiceStartNotAllowedException (Android 12+, app in the background) and similar.
        FLog.e("ScanService.start: startForegroundService отклонён", e)
        e.toString()
      }
    }

    fun stop(ctx: Context) {
      wanted = false
      FocaDirect.headlessScan = false
      markScan(ctx, false)
      FLog.i("ScanService.stop (running=$running)")
      RecentsGuard.onEvent(ctx, RecentsEvent.SCAN_END)
      main.post {
        val s = instance
        if (s != null) s.shutdown()
        else try { NotificationManagerCompat.from(ctx).cancel(NOTIF_ID) } catch (_: Throwable) {}
      }
    }
  }

  private var wake: PowerManager.WakeLock? = null

  override fun onBind(intent: Intent?): IBinder? = null

  override fun onCreate() {
    super.onCreate()
    FLog.init(this)
    FLog.i("ScanService.onCreate")
  }

  override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
    val decision = RecoveryLogic.onStart(intent?.action, wanted, scanMarked(this))
    FLog.i("ScanService.onStartCommand action=${intent?.action} flags=$flags startId=$startId → $decision")
    when (decision) {
      ServiceStart.STOP_SERVICE -> { shutdown(); return START_NOT_STICKY }
      ServiceStart.STOP_SCAN -> {
        // Stop from the notification: Rust stops the scan and then stops the service.
        val delivered = FocaBus.send(JSObject().put("kind", "service").put("action", "stop"))
        if (!delivered) { markScan(this, false); shutdown(); return START_NOT_STICKY }
        if (running) {
          try { NotificationManagerCompat.from(this).notify(NOTIF_ID, build(this, note, stopping = true)) } catch (_: Throwable) {}
        }
        return START_NOT_STICKY
      }
      ServiceStart.RESTARTED_NOTIFY -> {
        // The process was killed during a scan and the system restarted the service; there is no engine
        // (Rust starts only from the Activity). Do not keep "scanning": remove the notification and marker
        // and store the reason; on app open the core records stopped/restart and resumes if enabled.
        if (RecoveryLogic.restartedWithoutCore(decision)) {
          try { NotificationManagerCompat.from(this).cancel(NOTIF_ID) } catch (_: Throwable) {}
          noteInterrupt(this, RecoveryLogic.REASON_RESTARTED_NO_CORE)
        }
        RecentsGuard.onEvent(this, RecentsEvent.RECOVERY)
        // The resume worker reports it (and clears the marker); post directly if WorkManager refuses.
        if (!ScanResumeWorker.schedule(this, 0, "сервис перезапущен системой без ядра")) {
          markScan(this, false)
          notifyInterrupted(this)
        }
        stopSelf()
        return START_NOT_STICKY
      }
      ServiceStart.RESTARTED_QUIET -> { stopSelf(); return START_NOT_STICKY }
      ServiceStart.FOREGROUND, ServiceStart.FOREGROUND_THEN_STOP -> {}
    }
    // Start from the app: startForeground must be called within 5 s.
    try {
      val type = if (Build.VERSION.SDK_INT >= 29) ServiceInfo.FOREGROUND_SERVICE_TYPE_DATA_SYNC else 0
      ServiceCompat.startForeground(this, NOTIF_ID, build(this, note), type)
      running = true
      instance = this
      FLog.i("ScanService: startForeground(dataSync) ок, уведомления ${if (NotificationManagerCompat.from(this).areNotificationsEnabled()) "разрешены" else "ЗАПРЕЩЕНЫ (сервис работает, но уведомления не видно)"}")
    } catch (e: Throwable) {
      // ForegroundServiceStartNotAllowedException / missing type permission: without the service the process is killed in the background.
      FLog.e("ScanService: startForeground не удался", e)
      running = false
      stopSelf()
      return START_NOT_STICKY
    }
    if (decision == ServiceStart.FOREGROUND_THEN_STOP) { shutdown(); return START_NOT_STICKY } // the scan ended before the service started
    acquireWake()
    return if (RecoveryLogic.sticky(wanted)) START_STICKY else START_NOT_STICKY
  }

  private fun acquireWake() {
    if (wake?.isHeld == true) return
    try {
      val pm = getSystemService(Context.POWER_SERVICE) as PowerManager
      wake = pm.newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "FOCA-rs:scan").apply {
        setReferenceCounted(false)
        acquire(WAKE_TIMEOUT_MS)
      }
    } catch (e: Throwable) {
      FLog.w("ScanService: wakelock", e)
    }
  }

  private fun releaseWake() {
    try { wake?.let { if (it.isHeld) it.release() } } catch (_: Throwable) {}
    wake = null
  }

  private fun shutdown() {
    if (!wanted) RecentsGuard.onEvent(this, RecentsEvent.SCAN_END)
    releaseWake()
    running = false
    if (instance === this) instance = null
    try { ServiceCompat.stopForeground(this, ServiceCompat.STOP_FOREGROUND_REMOVE) } catch (_: Throwable) {}
    stopSelf()
  }

  /** Called when the task is swiped from Recents. The scan runs in this process and the service holds it, but
   *  HyperOS/MIUI usually kill the whole process after a swipe, so the reason is stored to explain what happened
   *  on the next start (the core records stopped/restart itself). */
  override fun onTaskRemoved(rootIntent: Intent?) {
    val reason = RecoveryLogic.taskRemovedReason(wanted)
    FLog.w("ScanService.onTaskRemoved: смахнули из «Недавних» (скан идёт: $wanted, сервис: $running)")
    if (reason != null) {
      noteInterrupt(this, reason)
      // OEM shells usually kill the process right after the swipe: check later whether the scan survived.
      ScanResumeWorker.schedule(this, RecoveryLogic.RESUME_DELAY_SEC, "смахнули из «Недавних» во время скана")
    }
    super.onTaskRemoved(rootIntent)
  }

  /** Android 15+: the dataSync time limit is exhausted and we have a few seconds to stop. */
  override fun onTimeout(startId: Int, fgsType: Int) {
    FLog.w("ScanService.onTimeout(fgsType=$fgsType): лимит dataSync исчерпан")
    FocaBus.send(JSObject().put("kind", "service").put("action", "timeout"))
    shutdown()
  }

  /** Android 14 (shortService type); handled the same way just in case. */
  @Suppress("OVERRIDE_DEPRECATION")
  override fun onTimeout(startId: Int) {
    FLog.w("ScanService.onTimeout: лимит времени")
    FocaBus.send(JSObject().put("kind", "service").put("action", "timeout"))
    shutdown()
  }

  override fun onTrimMemory(level: Int) {
    FLog.w("ScanService.onTrimMemory($level)")
    super.onTrimMemory(level)
  }

  override fun onDestroy() {
    FLog.i("ScanService.onDestroy (running=$running, wanted=$wanted)")
    val was = running
    releaseWake()
    running = false
    if (instance === this) instance = null
    if (was) FocaBus.send(JSObject().put("kind", "service").put("action", "destroyed"))
    super.onDestroy()
  }
}

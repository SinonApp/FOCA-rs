package app.sinon.focars.platform

import android.content.Context
import android.os.Build
import androidx.work.ExistingWorkPolicy
import androidx.work.OneTimeWorkRequestBuilder
import androidx.work.OutOfQuotaPolicy
import androidx.work.WorkManager
import androidx.work.Worker
import androidx.work.WorkerParameters
import java.util.TimeZone
import java.util.concurrent.TimeUnit

/**
 * Recovery after the system or an OEM shell killed the process during a scan. Scheduled from
 * [ScanService.onTaskRemoved] (with a short delay, the kill follows the swipe) and when the system
 * restarts the sticky service without the core. When WorkManager is allowed to run it, the worker
 * checks whether the scan survived. If the process died, it starts the scan service and resumes the
 * scan in a headless core (the same path as background monitoring); the UI attaches to it when the
 * app opens. When Android refuses the background service start or the core does not resume, it
 * posts "scan interrupted: Continue", whose tap opens the app on the scan screen.
 */
class ScanResumeWorker(ctx: Context, params: WorkerParameters) : Worker(ctx, params) {
  companion object {
    private const val WORK = "scan_resume"

    /** Enqueues the check; returns false when WorkManager refused. */
    fun schedule(ctx: Context, delaySec: Long, why: String): Boolean = try {
      val b = OneTimeWorkRequestBuilder<ScanResumeWorker>().addTag("scan")
      val fast = RecoveryLogic.expedite(Build.VERSION.SDK_INT, delaySec)
      if (fast) b.setExpedited(OutOfQuotaPolicy.RUN_AS_NON_EXPEDITED_WORK_REQUEST)
      else if (delaySec > 0) b.setInitialDelay(delaySec, TimeUnit.SECONDS)
      WorkManager.getInstance(ctx.applicationContext).enqueueUniqueWork(WORK, ExistingWorkPolicy.REPLACE, b.build())
      FLog.i("resume: проверка скана запланирована через WorkManager ($why; задержка ${delaySec} с, ${if (fast) "expedited" else "обычная"})")
      true
    } catch (e: Throwable) {
      FLog.e("resume: WorkManager не принял задачу ($why)", e)
      false
    }

    /** Drops a pending check (the app was opened, the core resumes the scan itself). */
    fun cancel(ctx: Context) {
      try { WorkManager.getInstance(ctx.applicationContext).cancelUniqueWork(WORK) } catch (_: Throwable) {}
    }
  }

  override fun doWork(): Result {
    val ctx = applicationContext
    FLog.init(ctx)
    val action = RecoveryLogic.resume(FocaBus.hasListener(), ScanService.scanRunning, ScanService.scanMarked(ctx))
    when (action) {
      RecoveryLogic.Resume.CONTINUES -> FLog.i("resume: процесс жив, скан продолжается, ничего не делаю")
      RecoveryLogic.Resume.HANDLED -> FLog.i("resume: ядро запущено, скан уже продолжен или завершён, ничего не делаю")
      RecoveryLogic.Resume.NOTHING -> FLog.i("resume: прерванного скана нет")
      RecoveryLogic.Resume.NOTIFY -> recover(ctx)
    }
    return Result.success()
  }

  /** Starts the scan service and resumes the scan in a headless core; falls back to the notification. */
  private fun recover(ctx: Context) {
    app.sinon.focars.CrashLog.install(ctx)
    DeviceMonitor.start(ctx)
    val err = ScanService.start(ctx, ScanNote())
    if (err != null) {
      ScanService.stop(ctx)
      interrupted(ctx, "сервис скана не запущен в фоне: $err")
      return
    }
    val dataDir = FLog.dataDir(ctx).absolutePath
    val utcOffsetSec = TimeZone.getDefault().getOffset(System.currentTimeMillis()) / 1000
    val raw = FocaDirect.resumeInterruptedScan(ctx, dataDir, utcOffsetSec)
    val status = FocaDirect.statusOf(raw)
    when (RecoveryLogic.headless(status, FocaBus.hasListener())) {
      RecoveryLogic.Headless.RUNNING -> {
        FocaBus.replayHeadless()
        FLog.i("resume: скан продолжен в фоне без окна, $raw")
      }
      RecoveryLogic.Headless.STOP_QUIET -> {
        ScanService.stop(ctx)
        FLog.i("resume: ядро не нашло прерванного скана, сервис остановлен")
      }
      RecoveryLogic.Headless.LEAVE -> FLog.i("resume: приложение открыто, скан ведёт интерфейс")
      RecoveryLogic.Headless.NOTIFY -> {
        ScanService.stop(ctx)
        interrupted(ctx, raw)
      }
    }
  }

  private fun interrupted(ctx: Context, why: String) {
    // Android blocks starting the Activity from the background: ask the user.
    RecentsGuard.onEvent(ctx, RecentsEvent.RECOVERY)
    ScanService.clearMark(ctx)
    ScanService.notifyInterrupted(ctx)
    FLog.w("resume: скан прерван системой, сам продолжить не могу ($why): показано «Продолжить»")
  }
}

package app.sinon.focars.platform

import android.app.ApplicationExitInfo
import app.sinon.focars.R

/** What the scan service does in onStartCommand. */
enum class ServiceStart {
  /** Stop the service (requested by Rust). */
  STOP_SERVICE,
  /** Stop from the notification: forward to Rust. */
  STOP_SCAN,
  /** Normal start from the app: startForeground + WAKE_LOCK, START_STICKY. */
  FOREGROUND,
  /** Start arrived after the scan already finished: startForeground (mandatory), then stop right away. */
  FOREGROUND_THEN_STOP,
  /** The system restarted the service after killing the process during a scan. There is no engine, so post
   *  the "scan interrupted, tap to resume" notification and stop the service. */
  RESTARTED_NOTIFY,
  /** Restart without a scan marker: just stop. */
  RESTARTED_QUIET,
}

/** Pure background and recovery logic (JUnit, no Android). */
object RecoveryLogic {
  /**
   * @param action the Intent action (`null` for a system restart after START_STICKY)
   * @param wanted a scan is running in this process (Rust called start and not yet stop)
   * @param scanMarked settings record that a scan was running (survives process death)
   */
  fun onStart(action: String?, wanted: Boolean, scanMarked: Boolean): ServiceStart = when (action) {
    ScanService.ACTION_STOP_SERVICE -> ServiceStart.STOP_SERVICE
    ScanService.ACTION_STOP_SCAN -> ServiceStart.STOP_SCAN
    null -> when {
      wanted -> ServiceStart.FOREGROUND // process alive (rare repeated call): keep the scan
      scanMarked -> ServiceStart.RESTARTED_NOTIFY
      else -> ServiceStart.RESTARTED_QUIET
    }
    else -> if (wanted) ServiceStart.FOREGROUND else ServiceStart.FOREGROUND_THEN_STOP
  }

  /** Returns the onStartCommand mode: STICKY while a scan runs, so the system restarts the service after
   *  the process is killed and we can at least post the interrupted-scan notification. */
  fun sticky(wanted: Boolean): Boolean = wanted

  /** Returns a human-readable reason why the previous process ended (ApplicationExitInfo, API 30+). */
  fun exitReason(reason: Int): String = when (reason) {
    ApplicationExitInfo.REASON_EXIT_SELF -> "EXIT_SELF (процесс завершился сам)"
    ApplicationExitInfo.REASON_SIGNALED -> "SIGNALED (убит сигналом)"
    ApplicationExitInfo.REASON_LOW_MEMORY -> "LOW_MEMORY (нехватка памяти, lmkd)"
    ApplicationExitInfo.REASON_CRASH -> "CRASH (Java/Kotlin)"
    ApplicationExitInfo.REASON_CRASH_NATIVE -> "CRASH_NATIVE (Rust/натив)"
    ApplicationExitInfo.REASON_ANR -> "ANR (не отвечало)"
    ApplicationExitInfo.REASON_INITIALIZATION_FAILURE -> "INITIALIZATION_FAILURE"
    ApplicationExitInfo.REASON_PERMISSION_CHANGE -> "PERMISSION_CHANGE (изменены разрешения)"
    ApplicationExitInfo.REASON_EXCESSIVE_RESOURCE_USAGE -> "EXCESSIVE_RESOURCE_USAGE (лимит ресурсов/батареи)"
    ApplicationExitInfo.REASON_USER_REQUESTED -> "USER_REQUESTED (смахнули/остановили)"
    ApplicationExitInfo.REASON_USER_STOPPED -> "USER_STOPPED (принудительно остановлено)"
    ApplicationExitInfo.REASON_DEPENDENCY_DIED -> "DEPENDENCY_DIED"
    ApplicationExitInfo.REASON_OTHER -> "OTHER (система/оболочка производителя)"
    ApplicationExitInfo.REASON_FREEZER -> "FREEZER (заморожено в фоне)"
    ApplicationExitInfo.REASON_PACKAGE_STATE_CHANGE -> "PACKAGE_STATE_CHANGE"
    ApplicationExitInfo.REASON_PACKAGE_UPDATED -> "PACKAGE_UPDATED (обновление)"
    else -> "UNKNOWN($reason)"
  }

  /** Returns whether the system or OEM shell killed the process (not a crash or a normal exit), which is a
   *  reason to resume the scan and suggest autostart/battery settings. */
  fun killedBySystem(reason: Int): Boolean = reason in setOf(
    ApplicationExitInfo.REASON_SIGNALED,
    ApplicationExitInfo.REASON_LOW_MEMORY,
    ApplicationExitInfo.REASON_EXCESSIVE_RESOURCE_USAGE,
    ApplicationExitInfo.REASON_OTHER,
    ApplicationExitInfo.REASON_FREEZER,
  )

  /** Scan interruption reasons stored by the service (`interrupt_reason` in settings). */
  const val REASON_TASK_REMOVED = "task_removed"
  const val REASON_RESTARTED_NO_CORE = "service_restarted_without_core"

  /**
   * Returns what to record when the task is swiped from Recents, or `null` if no scan was running.
   * Afterwards the process may live on (held by the foreground service) or be killed by the OEM
   * shell (HyperOS/MIUI); in that case the core turns the running scan file into `stopped/restart`
   * on the next start.
   */
  fun taskRemovedReason(wanted: Boolean): String? = if (wanted) REASON_TASK_REMOVED else null

  /**
   * Returns whether the service was restarted by the system without the core (the engine lives only
   * in a process started by the Activity). The "scanning" notification must not stay, since it would
   * be false: remove it, clear the scan marker, keep the reason and show "scan interrupted".
   */
  fun restartedWithoutCore(d: ServiceStart): Boolean = d == ServiceStart.RESTARTED_NOTIFY

  /** Returns the string resource with the "how to avoid it" tip for the "scan interrupted" notification. */
  fun interruptedTip(oem: String): Int =
    if (Oem.needsRecentsLock(oem)) R.string.scan_tip_recents_lock else R.string.scan_tip_battery_unrestricted

  /** What the scan resume worker does once the system lets it run. */
  enum class Resume {
    /** The process survived and the scan still runs: nothing to do. */
    CONTINUES,
    /** The core is up without a running scan (the app was opened and resumed or ended it). */
    HANDLED,
    /** The process died during the scan and no core runs here: resume it in the background (see
     *  [headless]) or post "interrupted: Continue". */
    NOTIFY,
    /** No scan was interrupted. */
    NOTHING,
  }

  /** Delay of the resume check after a swipe: the OEM kill lands within a second or two, and a check that
   *  ran in the still-alive process would see the scan running and never look again. */
  const val RESUME_DELAY_SEC = 15L

  /**
   * Decides the resume worker's action. Android blocks background Activity starts, so a scan killed
   * with its process is resumed by a headless core under the scan service when Android lets the
   * service start; otherwise the user continues it by opening the app.
   *
   * @param coreAlive the Rust core is subscribed in this process
   * @param scanRunning a scan is running in this process
   * @param scanMarked settings record that a scan was running (survives process death)
   */
  fun resume(coreAlive: Boolean, scanRunning: Boolean, scanMarked: Boolean): Resume = when {
    scanRunning -> Resume.CONTINUES
    coreAlive -> Resume.HANDLED
    scanMarked -> Resume.NOTIFY
    else -> Resume.NOTHING
  }

  /** What the resume worker does with the headless core's answer. */
  enum class Headless {
    /** The scan runs in this process under the scan service. */
    RUNNING,
    /** Nothing was left to resume: stop the service quietly. */
    STOP_QUIET,
    /** The UI owns the data now and handles the scan: leave the service alone. */
    LEAVE,
    /** Not resumed (setting off, repeated kills, error): stop the service, post "interrupted: Continue". */
    NOTIFY,
  }

  /** Returns whether the headless core's answer means the scan now runs in this process. */
  fun headlessRunning(status: String): Boolean = status == "resumed"

  /**
   * Maps the headless resume answer (`FocaDirect.resumeInterruptedScan`) to the worker's action.
   *
   * @param status resumed / none / disabled / too_many / busy / error
   * @param coreAlive the UI core subscribed in this process meanwhile
   */
  fun headless(status: String, coreAlive: Boolean): Headless = when {
    headlessRunning(status) -> Headless.RUNNING
    status == "none" -> Headless.STOP_QUIET
    status == "busy" && coreAlive -> Headless.LEAVE
    else -> Headless.NOTIFY
  }

  /** Expedited work needs API 31+ (older versions would run it as a foreground service) and cannot be
   *  delayed, so only an immediate check (service restarted by the system) is expedited. */
  fun expedite(sdk: Int, delaySec: Long): Boolean = sdk >= 31 && delaySec <= 0

  /** Returns exit history entries not yet logged (`seenMs` is the time of the last one logged). */
  fun unseen(timestamps: List<Long>, seenMs: Long): List<Long> = timestamps.filter { it > seenMs }.sorted()
}

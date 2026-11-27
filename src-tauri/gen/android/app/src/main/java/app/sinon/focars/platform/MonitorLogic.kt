package app.sinon.focars.platform

/**
 * Pure monitoring logic (no Android API, covered by JUnit): a project's rescan schedule
 * (`settings.monitor[project]` → [MonitorItem]), the delay until the first run, whether today is
 * a scan day, and notification routes.
 */
data class MonitorItem(
  val project: String,
  val name: String,
  /** `off` | `daily` | `weekly` */
  val mode: String,
  /** `HH:MM` */
  val time: String,
  /** Weekdays 1 (Mon) … 7 (Sun), used by `weekly`. */
  val days: Set<Int>,
  val wifi: Boolean,
  val charge: Boolean,
  /** Only `passive` | `std`; monitoring never runs the active profile. */
  val profile: String,
)

object MonitorLogic {
  /** Returns the scheduled scan profile: active (`full`/`custom`) and unknown profiles become passive. */
  fun safeProfile(p: String?): String = if (p == "std") "std" else "passive"

  /** Converts `HH:MM` to minutes after midnight (invalid input gives 03:00). */
  fun minutesOf(time: String): Int {
    val m = Regex("^(\\d{1,2}):(\\d{2})$").find(time.trim()) ?: return 180
    val h = m.groupValues[1].toInt()
    val mm = m.groupValues[2].toInt()
    return if (h in 0..23 && mm in 0..59) h * 60 + mm else 180
  }

  /** Returns the minutes until the next `time` (today if it has not passed yet, otherwise tomorrow). */
  fun initialDelayMinutes(nowMinutes: Int, time: String): Long {
    val t = minutesOf(time)
    val d = t - nowMinutes
    return (if (d > 0) d else d + 24 * 60).toLong()
  }

  /** Returns whether to scan on this day (`weekday` 1 = Mon … 7 = Sun). */
  fun dueToday(mode: String, days: Set<Int>, weekday: Int): Boolean = when (mode) {
    "daily" -> true
    "weekly" -> (if (days.isEmpty()) setOf(1) else days).contains(weekday)
    else -> false
  }

  /** Converts `java.util.Calendar.DAY_OF_WEEK` (1 = Sun … 7 = Sat) to 1 = Mon … 7 = Sun. */
  fun isoWeekday(calendarDay: Int): Int = if (calendarDay == 1) 7 else calendarDay - 1

  /** Returns the project id for a notification route (safe characters only, like the core's slug). */
  fun safeId(id: String): String? = if (Regex("^[a-z0-9][a-z0-9._-]{0,63}$").matches(id) && !id.contains("..")) id else null

  /** Route for tapping the "scan finished" notification: opens the project. */
  fun openRoute(project: String): String? = safeId(project)?.let { "/open/$it" }

  /**
   * Notification id of a status notice from the core (`status_notify { tag }`): one fixed id per
   * known tag, so a repeated notice replaces the previous one; `null` for an unknown tag.
   */
  fun statusId(tag: String): Int? = when (tag) {
    "mobile_cap" -> 4190
    else -> null
  }

  /** Route for tapping the rescan reminder: opens the project and the new scan wizard. */
  fun reminderRoute(project: String): String? = safeId(project)?.let { "/open/$it/scan" }

  /** Returns whether a notification route may be passed to the UI by MainActivity. */
  fun routeAllowed(r: String): Boolean = Regex("^/[a-z0-9/._-]{1,96}$").matches(r) && !r.contains("..")


  /** Default autonomous WorkManager scan budget in seconds (8 min, safely under the 10 min limit). */
  const val DEFAULT_BUDGET_SEC = 480

  /** Clamps requested headless monitoring budget into `[30, 480]` seconds. */
  fun clampBudgetSec(sec: Int): Int = sec.coerceIn(30, DEFAULT_BUDGET_SEC)

  /** Returns true when headless Worker should show a user notification (`busy` and UI-attached completions are silent). */
  fun shouldNotifyHeadless(status: String, uiAttached: Boolean): Boolean =
    status != "busy" && !(status == "done" && uiAttached)

  /** Notification destination route for a headless Worker outcome. */
  fun headlessRoute(project: String, status: String): String? =
    if (status == "done") openRoute(project) else reminderRoute(project)

  /** Returns the unique periodic work name for a project. */
  fun workName(project: String): String = "monitor:$project"
}

package app.sinon.focars.platform

/** Lifecycle moments at which the Recents visibility of the app task is decided. */
enum class RecentsEvent {
  /** Cold start of an Activity: always visible first, so nothing can leave the app hidden for good. */
  COLD_START,
  RESUME,
  PAUSE,
  STOP,
  /** The scan service started while the app was already in the background. */
  SCAN_START,
  /** The scan finished, was stopped or the service shut down. */
  SCAN_END,
  /** Recovery code ran in a process without a running scan (service restart, resume worker). */
  RECOVERY,
}

/**
 * Pure logic of "hide from Recents during scans" and of the OEM background helper (no Android
 * APIs; JVM unit tests). Aggressive OEM shells kill the whole process when its card is swiped
 * away or "clear all" is pressed, even while a foreground service runs; a task excluded from
 * Recents has no card, and the user comes back through the scan notification or the launcher.
 */
object RecentsLogic {
  const val PREF_HIDE = "hide_recents"
  const val ON = "on"
  const val OFF = "off"

  /** OEM families whose shells are known to kill swiped-away apps despite a foreground service. */
  private val AGGRESSIVE = listOf(
    "xiaomi", "redmi", "poco",
    "samsung",
    "huawei", "honor",
    "oppo", "realme", "oneplus",
    "vivo", "iqoo",
  )

  /** Returns whether the device belongs to an aggressive OEM family (manufacturer, brand or MIUI/HyperOS props). */
  fun aggressiveOem(manufacturer: String?, brand: String?, hyperOs: String? = null, miui: String? = null): Boolean {
    if (!hyperOs.isNullOrBlank() || !miui.isNullOrBlank()) return true
    val m = (manufacturer ?: "").lowercase()
    val b = (brand ?: "").lowercase()
    return AGGRESSIVE.any { m.contains(it) || b.contains(it) }
  }

  /** Returns the OEM family id for the UI (`xiaomi`, `samsung`, `huawei`, `oppo`, `vivo` or `other`). */
  fun family(manufacturer: String?, brand: String?, hyperOs: String? = null, miui: String? = null): String {
    val s = ((manufacturer ?: "") + " " + (brand ?: "")).lowercase()
    return when {
      !hyperOs.isNullOrBlank() || !miui.isNullOrBlank() -> "xiaomi"
      listOf("xiaomi", "redmi", "poco").any { s.contains(it) } -> "xiaomi"
      s.contains("samsung") -> "samsung"
      s.contains("huawei") || s.contains("honor") -> "huawei"
      listOf("oppo", "realme", "oneplus").any { s.contains(it) } -> "oppo"
      s.contains("vivo") || s.contains("iqoo") -> "vivo"
      else -> "other"
    }
  }

  /** Returns whether hiding is enabled: the stored choice (`on`/`off`) or, when never chosen, the OEM default. */
  fun enabled(pref: String?, aggressive: Boolean): Boolean = when (pref) {
    ON -> true
    OFF -> false
    else -> aggressive
  }

  /** Returns the value to store for a toggle choice. */
  fun prefValue(on: Boolean): String = if (on) ON else OFF

  /**
   * Returns `true` to exclude the task from Recents, `false` to show it again, or `null` to leave
   * it as is.
   *
   * @param scanRunning a scan is running in this process
   * @param enabled the "hide from Recents during scans" setting
   * @param foreground an Activity of the app is resumed
   * @param changingConfig the Activity is only being recreated (rotation, theme)
   */
  fun decide(event: RecentsEvent, scanRunning: Boolean, enabled: Boolean, foreground: Boolean, changingConfig: Boolean = false): Boolean? =
    when (event) {
      RecentsEvent.COLD_START, RecentsEvent.RESUME, RecentsEvent.SCAN_END, RecentsEvent.RECOVERY -> false
      RecentsEvent.PAUSE, RecentsEvent.STOP ->
        if (scanRunning && enabled && !changingConfig) true else null
      RecentsEvent.SCAN_START -> if (scanRunning && enabled && !foreground) true else null
    }

  /** MIUI/HyperOS app-op id of "Autostart" (not public; queried by reflection). */
  const val OP_MIUI_AUTOSTART = 10008

  /** Maps an app-op mode to `on` / `off` / `unknown` (`null` = the query failed or is unsupported). */
  fun autostart(mode: Int?): String = when (mode) {
    0 -> "on" // MODE_ALLOWED
    1 -> "off" // MODE_IGNORED
    2 -> "off" // MODE_ERRORED
    else -> "unknown"
  }
}

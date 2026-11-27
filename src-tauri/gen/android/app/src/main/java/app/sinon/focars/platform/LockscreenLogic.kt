package app.sinon.focars.platform

/**
 * Whether the scan progress notification can show on the lock screen. Pure decision over values the
 * platform layer reads (notifications enabled, channel importance and lock screen visibility, and the
 * optional Settings.Secure flags), so it is JVM-tested. There is no runtime permission for this: the
 * user changes it in the channel settings.
 */
object LockscreenLogic {
  /** Progress notification channel (replaces the old silent `scan` channel). */
  const val CHANNEL = "scan_progress_v2"

  // android.app.NotificationManager / Notification constants, copied to keep this file Android-free.
  const val IMPORTANCE_DEFAULT = 3
  const val VISIBILITY_SECRET = -1

  /**
   * Returns `on`, `off` or `unknown`.
   * @param notifications app notifications enabled, null when unknown
   * @param importance channel importance, null when the channel does not exist yet (it is created with
   *   the right values on the first scan) or the API is missing
   * @param lockVisibility channel lock screen visibility, null when unknown
   * @param showOnLock Settings.Secure `lock_screen_show_notifications` (1/0), null when not readable
   * @param showSilent Settings.Secure `lock_screen_show_silent_notifications` (1/0), null when not readable
   */
  fun state(
    notifications: Boolean?,
    importance: Int?,
    lockVisibility: Int?,
    showOnLock: Int?,
    showSilent: Int?,
  ): String {
    if (notifications == false) return "off"
    if (showOnLock == 0) return "off"
    if (importance != null && importance < IMPORTANCE_DEFAULT) return if (showSilent == 1) "on" else "off"
    if (lockVisibility == VISIBILITY_SECRET) return "off"
    if (notifications == null) return "unknown"
    // Channel not created yet: it is created as default importance, private (public version shown).
    return "on"
  }
}

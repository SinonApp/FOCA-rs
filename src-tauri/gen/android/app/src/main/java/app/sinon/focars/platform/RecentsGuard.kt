package app.sinon.focars.platform

import android.app.ActivityManager
import android.app.AppOpsManager
import android.content.Context
import android.os.Build
import android.os.Process

/**
 * Applies [RecentsLogic] to the app task: while a scan runs and the app is in the background the
 * task is excluded from Recents (no card to swipe away or "clear all"), and it is shown again on
 * resume, at the end of the scan and on every cold start. Nothing is persisted except the user's
 * toggle choice, so a killed process can never leave the app hidden.
 */
object RecentsGuard {
  /** An Activity of the app is resumed. */
  @Volatile var foreground = false
    private set
  /** Last applied state (`null` before the first decision in this process); only for the log. */
  @Volatile private var hidden: Boolean? = null

  private fun sysProp(name: String): String? = try {
    val c = Class.forName("android.os.SystemProperties")
    (c.getMethod("get", String::class.java).invoke(null, name) as? String)?.takeIf { it.isNotBlank() }
  } catch (_: Throwable) { null }

  fun hyperOs(): String? = sysProp("ro.mi.os.version.name")
  fun miui(): String? = sysProp("ro.miui.ui.version.name")

  private val aggr by lazy { RecentsLogic.aggressiveOem(Build.MANUFACTURER, Build.BRAND, hyperOs(), miui()) }

  /** The device belongs to an OEM family where hiding is on by default. */
  fun aggressive(): Boolean = aggr

  /** OEM family for the background helper (`xiaomi`, `samsung`, `huawei`, `oppo`, `vivo`, `other`). */
  fun family(): String = RecentsLogic.family(Build.MANUFACTURER, Build.BRAND, hyperOs(), miui())

  /** MIUI/HyperOS Autostart permission: `on` / `off` / `unknown` (other OEMs and failed queries). */
  fun autostart(ctx: Context): String {
    if (family() != "xiaomi") return "unknown"
    val mode = try {
      val ops = ctx.getSystemService(Context.APP_OPS_SERVICE) as AppOpsManager
      val m = AppOpsManager::class.java.getMethod(
        "checkOpNoThrow", Int::class.javaPrimitiveType, Int::class.javaPrimitiveType, String::class.java)
      m.invoke(ops, RecentsLogic.OP_MIUI_AUTOSTART, Process.myUid(), ctx.packageName) as? Int
    } catch (e: Throwable) {
      FLog.d("autostart: запрос app-op не удался: $e")
      null
    }
    return RecentsLogic.autostart(mode)
  }

  /** The stored toggle choice (`on`/`off`) or `null` when the user never chose. */
  fun stored(ctx: Context): String? =
    try { FocaPlugin.prefs(ctx).getString(RecentsLogic.PREF_HIDE, null) } catch (_: Throwable) { null }

  fun enabled(ctx: Context): Boolean = RecentsLogic.enabled(stored(ctx), aggressive())

  /** Stores the toggle; turning it off shows the task again right away. */
  fun setEnabled(ctx: Context, on: Boolean) {
    try { FocaPlugin.prefs(ctx).edit().putString(RecentsLogic.PREF_HIDE, RecentsLogic.prefValue(on)).apply() } catch (_: Throwable) {}
    FLog.i("recents: настройка «скрывать из недавних во время скана» = $on")
    if (!on) apply(ctx, false, "настройка выключена")
  }

  /** Decides and applies the Recents visibility for a lifecycle [event]. Safe on any thread. */
  fun onEvent(ctx: Context, event: RecentsEvent, changingConfig: Boolean = false) {
    when (event) {
      RecentsEvent.RESUME -> foreground = true
      RecentsEvent.PAUSE, RecentsEvent.STOP, RecentsEvent.COLD_START -> foreground = false
      else -> {}
    }
    val scan = ScanService.scanRunning
    val on = try { enabled(ctx) } catch (_: Throwable) { false }
    val d = RecentsLogic.decide(event, scan, on, foreground, changingConfig)
    if (d == null) {
      if (event == RecentsEvent.STOP && scan) FLog.i("recents: $event, скан идёт, но скрытие выключено (настройка=$on, смена конфигурации=$changingConfig)")
      return
    }
    apply(ctx, d, "$event (скан=$scan, настройка=$on)")
  }

  private fun apply(ctx: Context, exclude: Boolean, why: String) {
    val tasks = try {
      (ctx.applicationContext.getSystemService(Context.ACTIVITY_SERVICE) as ActivityManager).appTasks
    } catch (e: Throwable) {
      FLog.w("recents: getAppTasks не удался ($why)", e)
      return
    }
    if (tasks.isNullOrEmpty()) {
      if (exclude) FLog.w("recents: задач приложения нет, скрывать нечего ($why)")
      hidden = false
      return
    }
    var ok = 0
    for (t in tasks) {
      try { t.setExcludeFromRecents(exclude); ok++ } catch (e: Throwable) { FLog.w("recents: setExcludeFromRecents($exclude)", e) }
    }
    val changed = hidden != exclude
    hidden = exclude
    val msg = "recents: ${if (exclude) "СКРЫТО из «Недавних»" else "снова видно в «Недавних»"}: $why, задач $ok/${tasks.size}"
    if (changed || exclude) FLog.i(msg) else FLog.d(msg)
  }
}

package app.sinon.focars

import android.content.Intent
import android.graphics.Color
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.webkit.JavascriptInterface
import android.webkit.WebView
import androidx.activity.OnBackPressedCallback
import androidx.core.view.ViewCompat
import androidx.core.view.WindowCompat
import androidx.core.view.WindowInsetsCompat
import app.tauri.plugin.JSObject
import app.sinon.focars.platform.AppLocale
import app.sinon.focars.platform.BackLogic
import app.sinon.focars.platform.FLog
import app.sinon.focars.platform.FocaBus
import app.sinon.focars.platform.FocaPlugin
import app.sinon.focars.platform.RecentsEvent
import app.sinon.focars.platform.RecentsGuard
import app.sinon.focars.platform.ScanService
import app.sinon.focars.platform.ShareInbox
import kotlin.math.roundToInt

/**
 * The app screen (Tauri WebView). Tauri ends the process when its last Activity is destroyed,
 * which would kill a background scan, so:
 * - Back is decided by the UI (`FOCA.back()`: sheet → previous screen → parent); only on the
 *   root screen (answer "root") is the app moved to the background (moveTaskToBack). The
 *   Activity is never finished;
 * - if the Activity is destroyed during a scan anyway (swiped from Recents, killed by the
 *   system), Rust cancels the process exit and the new Activity asks Rust to recreate the window
 *   (`ui/created`). If that does not happen within 8 s, the process restarts and the scan
 *   resumes automatically.
 */
class MainActivity : TauriActivity() {
  private var web: WebView? = null
  private var insets = IntArray(4)
  /** Route from the scan notification (#/p/scan), opened once the UI has loaded. */
  @Volatile private var pendingRoute: String? = null
  @Volatile private var uiReady = false

  private val main = Handler(Looper.getMainLooper())

  private var backPending = false
  private val backCallback = object : OnBackPressedCallback(true) {
    override fun handleOnBackPressed() = onBack()
  }

  /** Registers our callback last so it is invoked first (Tauri's AppPlugin adds its own later). */
  private fun attachBack(where: String) {
    try {
      backCallback.remove()
      onBackPressedDispatcher.addCallback(this, backCallback)
      FLog.d("«Назад»: колбэк подключён ($where)")
    } catch (e: Throwable) { FLog.w("«Назад»: подключение колбэка ($where)", e) }
  }

  /**
   * Handles Back and predictive back by asking the UI (`FOCA.back()`) to close a sheet, go back a
   * screen or go to the parent; the task is moved to the background only on a "root" answer. On
   * no answer within 300 ms or an error nothing happens: the Activity is never finished, because
   * finishing it ends the Tauri process and loses the scan.
   */
  private fun onBack() {
    val w = web
    if (w == null || !uiReady) { FLog.w("«Назад»: UI не готов, остаюсь"); return }
    if (backPending) { FLog.d("«Назад»: прошлое нажатие ещё обрабатывается"); return }
    backPending = true
    var answered = false
    val timeout = Runnable {
      if (!answered) { answered = true; backPending = false; FLog.w("«Назад»: UI не ответил за ${BackLogic.TIMEOUT_MS} мс, не сворачиваю") }
    }
    main.postDelayed(timeout, BackLogic.TIMEOUT_MS)
    try {
      w.evaluateJavascript(BackLogic.SCRIPT) { r ->
        if (answered) { FLog.w("«Назад»: поздний ответ UI ($r): игнорирую"); return@evaluateJavascript }
        answered = true; backPending = false; main.removeCallbacks(timeout)
        when (BackLogic.decide(r)) {
          BackLogic.Action.HANDLED -> FLog.d("«Назад»: обработано UI")
          BackLogic.Action.MINIMIZE -> {
            FLog.i("«Назад» на корневом экране → свернуть (moveTaskToBack)")
            if (!moveTaskToBack(true)) FLog.w("moveTaskToBack вернул false")
          }
          BackLogic.Action.STAY -> FLog.w("«Назад»: ответ UI $r, не сворачиваю")
        }
      }
    } catch (e: Throwable) {
      answered = true; backPending = false; main.removeCallbacks(timeout)
      FLog.e("«Назад»: evaluateJavascript", e)
    }
  }

  override fun onCreate(savedInstanceState: Bundle?) {
    FLog.init(this)
    CrashLog.install(this)
    val recreate = FocaBus.uiGone && FocaBus.hasListener()
    FLog.i("MainActivity.onCreate (restore=${savedInstanceState != null}, процесс уже работал=$recreate, сервис=${ScanService.running})")
    CrashLog.logExitHistory(this)
    // Apply the opt-in "Block screenshots" before the first frame (Rust re-applies it once settings load).
    try { if (FocaPlugin.prefs(this).getBoolean(FocaPlugin.PREF_SECURE, false)) FocaPlugin.applySecure(this, true) } catch (_: Throwable) {}
    super.onCreate(savedInstanceState)
    // Visible in Recents first: a task hidden by a previous process must never stay hidden.
    RecentsGuard.onEvent(this, RecentsEvent.COLD_START)
    ScanService.onAppOpened(this)
    // Back goes through our callback on top of Tauri's AppPlugin, which relied on
    // WebView.canGoBack and a history trap and raced on rapid presses; the UI decides (FOCA.back()).
    attachBack("onCreate")
    if (recreate) {
      FocaBus.uiGone = false
      FLog.w("MainActivity: процесс пережил закрытие прошлой Activity (идёт скан): прошу Rust пересоздать окно")
      FocaBus.send(JSObject().put("kind", "ui").put("action", "created"))
      main.postDelayed({
        if (web == null && !isFinishing && !isDestroyed) restartProcess()
      }, 8000)
    }
    takeRoute(intent)
    ShareInbox.take(this, intent)
  }

  /** Restarts the process when the window did not appear; Rust resumes the interrupted scan (resume_from). */
  private fun restartProcess() {
    FLog.e("MainActivity: окно Tauri не создано за 8 с, перезапуск процесса")
    try {
      startActivity(Intent(this, LauncherActivity::class.java)
        .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TASK))
    } catch (e: Throwable) { FLog.e("перезапуск: startActivity", e) }
    android.os.Process.killProcess(android.os.Process.myPid())
  }

  override fun onStart() { super.onStart(); FLog.i("MainActivity.onStart") }
  override fun onResume() {
    super.onResume()
    FLog.d("MainActivity.onResume")
    attachBack("onResume")
    RecentsGuard.onEvent(this, RecentsEvent.RESUME)
  }
  override fun onPause() {
    super.onPause()
    FLog.d("MainActivity.onPause")
    // Hide already on pause: the Recents screen opens while the Activity is only paused.
    RecentsGuard.onEvent(this, RecentsEvent.PAUSE, isChangingConfigurations)
  }
  override fun onStop() {
    super.onStop()
    FLog.i("MainActivity.onStop (в фоне; сервис скана=${ScanService.running})")
    RecentsGuard.onEvent(this, RecentsEvent.STOP, isChangingConfigurations)
  }

  override fun onDestroy() {
    val config = isChangingConfigurations
    FLog.w("MainActivity.onDestroy (finishing=$isFinishing, смена конфигурации=$config, сервис=${ScanService.running})")
    // Not a configuration change: Tauri will remove the window; if Rust cancels the exit (scan running), the process stays.
    if (!config) FocaBus.uiGone = true
    main.removeCallbacksAndMessages(null)
    web = null
    super.onDestroy()
  }

  override fun onTrimMemory(level: Int) {
    super.onTrimMemory(level)
    FLog.w("MainActivity.onTrimMemory($level)")
  }

  @Deprecated("Deprecated in Java")
  override fun onLowMemory() {
    super.onLowMemory()
    FLog.w("MainActivity.onLowMemory")
  }

  override fun onNewIntent(intent: Intent) {
    super.onNewIntent(intent)
    setIntent(intent)
    takeRoute(intent)
    ShareInbox.take(this, intent)
  }

  private fun takeRoute(i: Intent?) {
    val r = try { i?.getStringExtra(ScanService.EXTRA_ROUTE) } catch (_: Throwable) { null } ?: return
    // UI routes only, no quotes or scripts (dots are allowed for project ids like example.ua).
    if (!app.sinon.focars.platform.MonitorLogic.routeAllowed(r)) return
    i?.removeExtra(ScanService.EXTRA_ROUTE)
    pendingRoute = r
    if (uiReady) pushRoute()
  }

  /** Shared files copied before the UI was loaded: tell the UI to ask for them (platform_shared_files). */
  private fun pushShared() {
    val w = web ?: return
    if (!ShareInbox.hasPending()) return
    w.post { try { w.evaluateJavascript("window.FOCA&&FOCA.emit&&FOCA.emit('shared',{})", null) } catch (_: Throwable) {} }
  }

  private fun pushRoute() {
    val w = web ?: return
    val r = pendingRoute ?: return
    pendingRoute = null
    // While the page is still hidden (tap on a notification from the background) wait for it to become
    // visible: the autolock check runs on that event first, so the route is queued behind /lock.
    val js = "(function(r){if(!window.FOCA||!FOCA.go)return;if(!document.hidden){FOCA.go(r);return}" +
      "var f=function(){if(document.hidden)return;document.removeEventListener('visibilitychange',f);" +
      "setTimeout(function(){FOCA.go(r)},0)};document.addEventListener('visibilitychange',f)})('$r')"
    FLog.i("маршрут из уведомления: $r")
    w.post { try { w.evaluateJavascript(js, null) } catch (_: Throwable) {} }
  }

  override fun onWebViewCreate(webView: WebView) {
    super.onWebViewCreate(webView)
    web = webView
    FLog.i("MainActivity: WebView создан")
    // Tauri plugins (AppPlugin with its own Back callback) are created around the WebView; register on top of them.
    main.post { attachBack("onWebViewCreate") }
    try {
      // Respect the system font size, but cap it at 130%; beyond that the layout scales on its own.
      val scale = resources.configuration.fontScale
      webView.settings.textZoom = (scale * 100).roundToInt().coerceIn(100, 130)
    } catch (_: Throwable) {}
    try {
      // The app is not a web page: no pinch or double-tap zoom (text size is an in-app setting).
      webView.settings.setSupportZoom(false)
      webView.settings.builtInZoomControls = false
      webView.settings.displayZoomControls = false
    } catch (_: Throwable) {}
    try {
      WindowCompat.setDecorFitsSystemWindows(window, false)
      window.statusBarColor = Color.TRANSPARENT
      window.navigationBarColor = Color.TRANSPARENT
      webView.addJavascriptInterface(Bridge(), "FocaNative")
      // System bar insets go to CSS variables; the WebView itself draws edge to edge.
      ViewCompat.setOnApplyWindowInsetsListener(webView) { _, wi ->
        val b = wi.getInsets(WindowInsetsCompat.Type.systemBars() or WindowInsetsCompat.Type.displayCutout())
        val d = resources.displayMetrics.density
        insets = intArrayOf((b.top / d).roundToInt(), (b.bottom / d).roundToInt(), (b.left / d).roundToInt(), (b.right / d).roundToInt())
        pushInsets()
        wi
      }
      ViewCompat.requestApplyInsets(webView)
    } catch (e: Throwable) {
      FLog.w("insets", e)
    }
  }

  private fun pushInsets() {
    val w = web ?: return
    val js = "window.__setInsets&&window.__setInsets(${insets[0]},${insets[1]},${insets[2]},${insets[3]})"
    w.post { try { w.evaluateJavascript(js, null) } catch (_: Throwable) {} }
  }

  inner class Bridge {
    /** Sets the system bar icon color for the theme: dark=true means light icons. */
    @JavascriptInterface fun setBars(dark: Boolean, color: String) {
      runOnUiThread {
        try {
          WindowCompat.getInsetsController(window, window.decorView).apply {
            isAppearanceLightStatusBars = !dark
            isAppearanceLightNavigationBars = !dark
          }
          window.decorView.setBackgroundColor(Color.parseColor(color))
        } catch (_: Throwable) {}
      }
    }
    /** Stores the UI language so native notifications and dialogs follow the app setting. */
    @JavascriptInterface fun setLang(lang: String?) { try { AppLocale.save(this@MainActivity, lang) } catch (_: Throwable) {} }
    /** Called when the page has loaded and needs the current insets. */
    @JavascriptInterface fun ready() { FLog.i("UI загружен"); uiReady = true; pushInsets(); pushRoute(); pushShared(); main.post { attachBack("ready") } }
  }
}

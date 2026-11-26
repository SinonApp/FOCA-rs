package app.sinon.focars.platform

import android.annotation.SuppressLint
import android.app.Activity
import android.app.Application
import android.app.Dialog
import android.content.res.ColorStateList
import android.graphics.Bitmap
import android.graphics.Color
import android.graphics.Typeface
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.os.SystemClock
import android.text.TextUtils
import android.view.Gravity
import android.view.View
import android.view.ViewGroup
import android.view.WindowManager
import android.webkit.CookieManager
import android.webkit.WebChromeClient
import android.webkit.WebResourceError
import android.webkit.WebResourceRequest
import android.webkit.WebView
import android.webkit.WebViewClient
import android.widget.Button
import android.widget.FrameLayout
import android.widget.LinearLayout
import android.widget.ProgressBar
import android.widget.TextView
import androidx.core.view.ViewCompat
import androidx.core.view.WindowCompat
import androidx.core.view.WindowInsetsCompat
import androidx.core.view.WindowInsetsControllerCompat
import app.sinon.focars.R
import org.json.JSONObject
import org.json.JSONTokener

/**
 * Manual search engine captcha solving (Startpage, Mojeek, Brave): a visible full-screen WebView
 * with the same profile as the hidden [RenderFetcher]. `CookieManager` and DOM storage are shared by
 * all WebViews of the process, as is the proxy (`ProxyController`), and the UA is the same mobile
 * one. The user solves the check and taps Done; the page is checked for the engine's challenge
 * markers and only a solved page flushes cookies, so the hidden browser's next request already
 * carries them. Cancel, Back, any dismiss and the app leaving the foreground report `cancelled`; a
 * page that fails or does not finish loading in [VerifyLogic.LOAD_TIMEOUT_MS] shows Retry. There is
 * no automatic captcha bypass.
 *
 * Main thread only (plugin command `render_verify`). [show]'s `onClose` is called exactly once.
 */
object VerifyDialog {
  /** Hosts allowed for the verification page: dork search engines only (no arbitrary URLs from the UI). */
  private val ALLOWED = setOf("www.startpage.com", "startpage.com", "www.mojeek.com", "mojeek.com", "search.brave.com", "search.yahoo.com")

  fun allowed(url: String): Boolean {
    val u = try { android.net.Uri.parse(url) } catch (_: Throwable) { return false }
    return u.scheme == "https" && (u.host ?: "") in ALLOWED
  }

  /** Result of the dialog: [outcome] plus the matched challenge marker or the load error, if any. */
  data class Result(val outcome: VerifyLogic.Outcome, val detail: String? = null)

  @SuppressLint("SetJavaScriptEnabled")
  fun show(activity: Activity, url: String, title: String, markers: List<String>, onClose: (Result) -> Unit) {
    val res = AppLocale.wrap(activity)
    val once = VerifyLogic.Once()
    val main = Handler(Looper.getMainLooper())
    var phase = VerifyLogic.Phase.LOADING
    var loadStarted = 0L
    var failure: String? = null
    var checking = false
    val d = Dialog(activity, android.R.style.Theme_DeviceDefault_NoActionBar)
    val wv = WebView(activity)
    lateinit var lifecycle: Application.ActivityLifecycleCallbacks

    // Settles the result exactly once: flushes cookies only on a solved check, unregisters the
    // lifecycle watcher, closes the dialog and frees the WebView.
    fun settle(r: Result) {
      if (!once.settle(r.outcome)) return
      main.removeCallbacksAndMessages(null)
      try { activity.application.unregisterActivityLifecycleCallbacks(lifecycle) } catch (_: Throwable) {}
      if (VerifyLogic.flushCookies(r.outcome)) CookieManager.getInstance().flush()
      FLog.i("verify: result ${r.outcome.wire}" + (r.detail?.let { " ($it)" } ?: ""))
      try { if (d.isShowing) d.dismiss() } catch (_: Throwable) {}
      try { wv.stopLoading(); wv.destroy() } catch (_: Throwable) {}
      onClose(r)
    }
    fun exit(how: VerifyLogic.Exit) = settle(Result(VerifyLogic.exitOutcome(how, phase), failure))

    // The same honest mobile profile as the hidden browser (UA, images, no X-Requested-With).
    RenderFetcher.applyProfile(activity, wv, UaForm.MOBILE)
    wv.settings.apply {
      allowFileAccess = false
      allowContentAccess = false
      // A third-party page (small captcha images): pinch zoom stays available here, unlike the app UI.
      builtInZoomControls = true
      displayZoomControls = false
    }
    val dp = activity.resources.displayMetrics.density
    fun px(v: Int) = (v * dp).toInt()
    // Top bar: Cancel on the left, page title and a short hint in the middle, Done on the right. It
    // sits below the status bar and display cutout (padding from window insets); its background also
    // fills the area behind the status bar.
    val barColor = Color.parseColor("#1F2430")
    val bar = LinearLayout(activity).apply {
      orientation = LinearLayout.HORIZONTAL
      gravity = Gravity.CENTER_VERTICAL
      minimumHeight = px(56)
      setBackgroundColor(barColor)
    }
    fun barButton(label: String, primary: Boolean) = Button(activity, null, if (primary) android.R.attr.buttonStyle else android.R.attr.borderlessButtonStyle).apply {
      text = label
      isAllCaps = false
      minWidth = px(64)
      minimumWidth = px(64)
      minHeight = px(48)
      minimumHeight = px(48)
      if (!primary) setTextColor(Color.parseColor("#B8C0CC"))
    }
    val cancel = barButton(res.getString(R.string.verify_cancel), primary = false)
    cancel.contentDescription = res.getString(R.string.verify_cancel)
    cancel.setOnClickListener { exit(VerifyLogic.Exit.CANCEL_BUTTON) }
    bar.addView(cancel, LinearLayout.LayoutParams(ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT).apply { marginEnd = px(8) })
    val texts = LinearLayout(activity).apply { orientation = LinearLayout.VERTICAL }
    texts.addView(TextView(activity).apply {
      text = title
      setTextColor(Color.WHITE)
      textSize = 16f
      setTypeface(typeface, Typeface.BOLD)
      maxLines = 1
      ellipsize = TextUtils.TruncateAt.END
    })
    val hint = TextView(activity).apply {
      text = res.getString(R.string.verify_hint)
      setTextColor(Color.parseColor("#B8C0CC"))
      textSize = 13f
      maxLines = 2
      ellipsize = TextUtils.TruncateAt.END
    }
    texts.addView(hint)
    bar.addView(texts, LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f))
    val done = barButton(res.getString(R.string.verify_done), primary = true)
    bar.addView(done, LinearLayout.LayoutParams(ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT).apply { marginStart = px(8) })

    // Thin progress bar under the top bar while the page loads.
    val progress = ProgressBar(activity, null, android.R.attr.progressBarStyleHorizontal).apply {
      max = 100
      isIndeterminate = false
      progressTintList = ColorStateList.valueOf(Color.parseColor("#5B9BFF"))
    }

    // Error state over the page: message plus Retry (a failed or stuck load is never a silent hang).
    val errText = TextView(activity).apply {
      setTextColor(Color.WHITE)
      textSize = 15f
      gravity = Gravity.CENTER
    }
    val retry = barButton(res.getString(R.string.verify_retry), primary = true)
    val errBox = LinearLayout(activity).apply {
      orientation = LinearLayout.VERTICAL
      gravity = Gravity.CENTER
      setBackgroundColor(barColor)
      setPadding(px(24), px(24), px(24), px(24))
      visibility = View.GONE
      addView(errText, LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT))
      addView(retry, LinearLayout.LayoutParams(ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT).apply { topMargin = px(16) })
    }

    fun showError(kind: VerifyLogic.Failure, detail: String?) {
      if (once.outcome != null) return
      phase = VerifyLogic.Phase.ERROR
      failure = when (kind) {
        VerifyLogic.Failure.TIMEOUT -> "timeout"
        VerifyLogic.Failure.LOAD_ERROR -> detail ?: "load_error"
      }
      errText.text = when (kind) {
        VerifyLogic.Failure.TIMEOUT -> res.getString(R.string.verify_err_timeout)
        VerifyLogic.Failure.LOAD_ERROR -> res.getString(R.string.verify_err_load, detail ?: "")
      }
      progress.visibility = View.GONE
      errBox.visibility = View.VISIBLE
      done.isEnabled = false
      try { wv.stopLoading() } catch (_: Throwable) {}
      FLog.w("verify: page failed ($failure)")
    }
    val timeoutCheck = object : Runnable {
      override fun run() {
        if (VerifyLogic.timedOut(phase, loadStarted, SystemClock.elapsedRealtime())) showError(VerifyLogic.Failure.TIMEOUT, null)
        else if (phase == VerifyLogic.Phase.LOADING) main.postDelayed(this, 1_000)
      }
    }
    fun startLoading() {
      phase = VerifyLogic.Phase.LOADING
      failure = null
      loadStarted = SystemClock.elapsedRealtime()
      errBox.visibility = View.GONE
      progress.visibility = View.VISIBLE
      progress.progress = 0
      done.isEnabled = true
      main.removeCallbacks(timeoutCheck)
      main.postDelayed(timeoutCheck, 1_000)
    }
    retry.setOnClickListener {
      startLoading()
      val cur = wv.url
      if (cur.isNullOrEmpty() || cur == "about:blank") wv.loadUrl(url) else wv.reload()
    }

    wv.webViewClient = object : WebViewClient() {
      override fun shouldOverrideUrlLoading(view: WebView?, request: WebResourceRequest?): Boolean {
        val u = request?.url?.toString() ?: return true
        return !u.startsWith("https://")
      }
      override fun onPageStarted(view: WebView?, u: String?, favicon: Bitmap?) {
        if (phase != VerifyLogic.Phase.ERROR && once.outcome == null) startLoading()
      }
      override fun onPageFinished(view: WebView?, u: String?) {
        if (phase == VerifyLogic.Phase.LOADING) {
          phase = VerifyLogic.Phase.READY
          progress.visibility = View.GONE
          main.removeCallbacks(timeoutCheck)
        }
      }
      override fun onReceivedError(view: WebView?, request: WebResourceRequest?, error: WebResourceError?) {
        // Only the page itself counts; a broken image or tracker does not stop the check.
        if (request?.isForMainFrame != true) return
        showError(VerifyLogic.Failure.LOAD_ERROR, error?.description?.toString())
      }
    }
    wv.webChromeClient = object : WebChromeClient() {
      override fun onProgressChanged(view: WebView?, p: Int) {
        if (phase == VerifyLogic.Phase.LOADING) progress.progress = p
      }
    }

    // Done: only a page that no longer shows the engine's challenge counts as solved.
    done.setOnClickListener {
      if (checking || once.outcome != null) return@setOnClickListener
      if (phase == VerifyLogic.Phase.ERROR) { settle(Result(VerifyLogic.Outcome.FAILED, failure)); return@setOnClickListener }
      checking = true
      done.isEnabled = false
      done.text = res.getString(R.string.verify_checking)
      var answered = false
      val give = Runnable {
        if (!answered) { answered = true; settle(Result(VerifyLogic.doneOutcome(phase, null), "no_answer")) }
      }
      main.postDelayed(give, VerifyLogic.CHECK_TIMEOUT_MS)
      try {
        wv.evaluateJavascript(CHECK_JS) { raw ->
          if (answered) return@evaluateJavascript
          answered = true
          main.removeCallbacks(give)
          val c = parseCheck(raw, markers)
          settle(Result(VerifyLogic.doneOutcome(phase, c), c?.challenge))
        }
      } catch (e: Throwable) {
        FLog.w("verify: page check failed: $e")
        main.removeCallbacks(give)
        give.run()
      }
    }

    val content = FrameLayout(activity)
    content.addView(wv, FrameLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.MATCH_PARENT))
    content.addView(errBox, FrameLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.MATCH_PARENT))
    val root = LinearLayout(activity).apply {
      orientation = LinearLayout.VERTICAL
      setBackgroundColor(barColor)
    }
    root.addView(bar, LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT))
    root.addView(progress, LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, px(3)))
    root.addView(content, LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, 0, 1f))
    d.setContentView(root)
    d.window?.let { w ->
      w.setLayout(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.MATCH_PARENT)
      @Suppress("DEPRECATION")
      w.setSoftInputMode(WindowManager.LayoutParams.SOFT_INPUT_ADJUST_RESIZE)
      // Draw edge to edge on every Android version and pad by the insets ourselves (Android 15+
      // enforces edge to edge, which put the bar under the status bar).
      WindowCompat.setDecorFitsSystemWindows(w, false)
      @Suppress("DEPRECATION")
      w.statusBarColor = Color.TRANSPARENT
      @Suppress("DEPRECATION")
      w.navigationBarColor = Color.TRANSPARENT
      WindowInsetsControllerCompat(w, w.decorView).apply {
        isAppearanceLightStatusBars = false
        isAppearanceLightNavigationBars = false
      }
    }
    ViewCompat.setOnApplyWindowInsetsListener(root) { _, wi ->
      val sys = wi.getInsets(WindowInsetsCompat.Type.systemBars() or WindowInsetsCompat.Type.displayCutout())
      val ime = wi.getInsets(WindowInsetsCompat.Type.ime())
      root.setPadding(sys.left, 0, sys.right, maxOf(sys.bottom, ime.bottom))
      bar.setPadding(px(4), sys.top + px(6), px(8), px(6))
      WindowInsetsCompat.CONSUMED
    }
    ViewCompat.requestApplyInsets(root)
    d.setCanceledOnTouchOutside(false)
    // Back is Cancel; any other dismiss (system, window loss) is Cancel too, never success.
    d.setOnCancelListener { exit(VerifyLogic.Exit.BACK) }
    d.setOnDismissListener { exit(VerifyLogic.Exit.DISMISS) }
    // The app leaving the foreground or being swiped away from Recents closes the dialog as
    // cancelled, so the invoke always resolves and nothing is treated as verified.
    lifecycle = object : Application.ActivityLifecycleCallbacks {
      private fun on(x: Activity, how: VerifyLogic.Exit) {
        if (x === activity && VerifyLogic.lifecycleCloses(how, x.isFinishing)) exit(how)
      }
      override fun onActivityPaused(x: Activity) = on(x, VerifyLogic.Exit.ACTIVITY_PAUSED)
      override fun onActivityStopped(x: Activity) = on(x, VerifyLogic.Exit.ACTIVITY_STOPPED)
      override fun onActivityDestroyed(x: Activity) = on(x, VerifyLogic.Exit.ACTIVITY_DESTROYED)
      override fun onActivityCreated(x: Activity, b: Bundle?) {}
      override fun onActivityStarted(x: Activity) {}
      override fun onActivityResumed(x: Activity) {}
      override fun onActivitySaveInstanceState(x: Activity, b: Bundle) {}
    }
    activity.application.registerActivityLifecycleCallbacks(lifecycle)
    FLog.i("verify: open visible WebView $url")
    d.show()
    startLoading()
    wv.loadUrl(url)
  }

  /** Collects what [VerifyLogic.challengeShown] needs from the current page. */
  private const val CHECK_JS = "(function(){var b=document.body;var h=document.documentElement?document.documentElement.outerHTML:'';" +
    "return JSON.stringify({t:b?(b.innerText||''):'',u:String(location.href),h:h.length>${VerifyLogic.MAX_HTML_CHARS}?h.substring(0,${VerifyLogic.MAX_HTML_CHARS}):h});})()"

  /** Parses the [CHECK_JS] answer (a JSON string literal holding the JSON object); null if broken. */
  private fun parseCheck(raw: String?, markers: List<String>): VerifyLogic.PageCheck? = try {
    val inner = JSONTokener(raw ?: "").nextValue() as? String ?: return null
    val o = JSONObject(inner)
    val t = o.optString("t"); val u = o.optString("u"); val h = o.optString("h")
    VerifyLogic.PageCheck(VerifyLogic.challengeShown(t, u, h, markers), VerifyLogic.pageEmpty(u, h))
  } catch (_: Throwable) { null }
}

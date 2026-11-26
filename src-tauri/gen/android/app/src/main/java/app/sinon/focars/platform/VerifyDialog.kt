package app.sinon.focars.platform

import android.annotation.SuppressLint
import android.app.Activity
import android.app.Dialog
import android.graphics.Color
import android.graphics.Typeface
import android.text.TextUtils
import android.view.Gravity
import android.view.ViewGroup
import android.view.WindowManager
import android.webkit.CookieManager
import android.webkit.WebResourceRequest
import android.webkit.WebView
import android.webkit.WebViewClient
import android.widget.Button
import android.widget.LinearLayout
import android.widget.TextView
import androidx.core.view.ViewCompat
import androidx.core.view.WindowCompat
import androidx.core.view.WindowInsetsCompat
import androidx.core.view.WindowInsetsControllerCompat
import app.sinon.focars.R

/**
 * Manual search engine captcha solving (Startpage, Mojeek, Brave): a visible full-screen WebView
 * with the same profile as the hidden [RenderFetcher]. `CookieManager` and DOM storage are shared by
 * all WebViews of the process, as is the proxy (`ProxyController`), and the UA is the same mobile
 * one. The user solves the check and taps Done; cookies are flushed, so the hidden browser's next
 * request already carries them. There is no automatic captcha bypass.
 *
 * Main thread only (plugin command `render_verify`). [onClose] is called exactly once.
 */
object VerifyDialog {
  /** Hosts allowed for the verification page: dork search engines only (no arbitrary URLs from the UI). */
  private val ALLOWED = setOf("www.startpage.com", "startpage.com", "www.mojeek.com", "mojeek.com", "search.brave.com", "search.yahoo.com")

  fun allowed(url: String): Boolean {
    val u = try { android.net.Uri.parse(url) } catch (_: Throwable) { return false }
    return u.scheme == "https" && (u.host ?: "") in ALLOWED
  }

  @SuppressLint("SetJavaScriptEnabled")
  fun show(activity: Activity, url: String, title: String, onClose: (String) -> Unit) {
    var done = false
    val finish = { how: String -> if (!done) { done = true; CookieManager.getInstance().flush(); onClose(how) } }
    val d = Dialog(activity, android.R.style.Theme_DeviceDefault_NoActionBar)
    val wv = WebView(activity)
    // The same honest mobile profile as the hidden browser (UA, images, no X-Requested-With).
    RenderFetcher.applyProfile(activity, wv, UaForm.MOBILE)
    wv.settings.apply {
      allowFileAccess = false
      allowContentAccess = false
      // A third-party page (small captcha images): pinch zoom stays available here, unlike the app UI.
      builtInZoomControls = true
      displayZoomControls = false
    }
    wv.webViewClient = object : WebViewClient() {
      override fun shouldOverrideUrlLoading(view: WebView?, request: WebResourceRequest?): Boolean {
        val u = request?.url?.toString() ?: return true
        return !u.startsWith("https://")
      }
    }
    val dp = activity.resources.displayMetrics.density
    fun px(v: Int) = (v * dp).toInt()
    // Top bar: page title and a short hint on the left, Done on the right. It sits below the status
    // bar and display cutout (padding from window insets); its background also fills the area behind
    // the status bar.
    val barColor = Color.parseColor("#1F2430")
    val bar = LinearLayout(activity).apply {
      orientation = LinearLayout.HORIZONTAL
      gravity = Gravity.CENTER_VERTICAL
      minimumHeight = px(56)
      setBackgroundColor(barColor)
    }
    val texts = LinearLayout(activity).apply { orientation = LinearLayout.VERTICAL }
    texts.addView(TextView(activity).apply {
      text = title
      setTextColor(Color.WHITE)
      textSize = 16f
      setTypeface(typeface, Typeface.BOLD)
      maxLines = 1
      ellipsize = TextUtils.TruncateAt.END
    })
    texts.addView(TextView(activity).apply {
      text = AppLocale.wrap(activity).getString(R.string.verify_hint)
      setTextColor(Color.parseColor("#B8C0CC"))
      textSize = 13f
      maxLines = 2
      ellipsize = TextUtils.TruncateAt.END
    })
    bar.addView(texts, LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f))
    val btn = Button(activity).apply {
      text = AppLocale.wrap(activity).getString(R.string.verify_done)
      isAllCaps = false
      minWidth = px(64)
      minimumWidth = px(64)
      minHeight = px(48)
      minimumHeight = px(48)
    }
    btn.setOnClickListener { d.dismiss() }
    bar.addView(btn, LinearLayout.LayoutParams(ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT).apply { marginStart = px(12) })
    val root = LinearLayout(activity).apply {
      orientation = LinearLayout.VERTICAL
      setBackgroundColor(barColor)
    }
    root.addView(bar, LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT))
    root.addView(wv, LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, 0, 1f))
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
      bar.setPadding(px(16), sys.top + px(6), px(8), px(6))
      WindowInsetsCompat.CONSUMED
    }
    ViewCompat.requestApplyInsets(root)
    d.setOnDismissListener {
      try { wv.stopLoading(); wv.destroy() } catch (_: Throwable) {}
      finish("closed")
    }
    FLog.i("verify: открыть видимый WebView $url")
    d.show()
    wv.loadUrl(url)
  }
}

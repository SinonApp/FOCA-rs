package app.sinon.focars.platform

import android.annotation.SuppressLint
import android.app.Activity
import android.app.Application
import android.content.Context
import android.graphics.Bitmap
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.view.View
import android.view.ViewGroup
import android.widget.FrameLayout
import android.webkit.CookieManager
import android.webkit.WebResourceError
import android.webkit.WebResourceRequest
import android.webkit.WebResourceResponse
import android.webkit.WebSettings
import android.webkit.WebView
import android.webkit.WebViewClient
import androidx.annotation.Keep
import androidx.webkit.ProxyConfig
import androidx.webkit.ProxyController
import androidx.webkit.WebSettingsCompat
import androidx.webkit.WebViewFeature
import org.json.JSONArray
import org.json.JSONObject
import org.json.JSONTokener
import java.lang.ref.WeakReference
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Semaphore
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference

/**
 * Render fetcher for the core (`foca-search::render`, bridged by `NativeRender` in
 * `src-tauri/src/bridge.rs`): a hidden `WebView` loads a search engine page and runs a step script
 * (`wait`, `submit`, `click`, `sleep`), returning `outerHTML` and the final URL. Needed for
 * Startpage (a JS proof-of-work "Verifying your request"), Brave Search and Mojeek, which reject
 * plain HTTP from the core but let a browser pass on its own; cookies (CookieManager) persist
 * between requests, so the check is passed once.
 *
 * - The WebView is created from `applicationContext` on the main looper. While the Activity is
 *   shown, it is attached to the Activity window BELOW the app's main WebView (invisible to the
 *   user, touches go to the top WebView), so the page is `visible` and `requestAnimationFrame`
 *   runs as in a normal tab. When the app is in the background, the WebView is detached and works
 *   without a window (sized to the phone screen) for as long as the process lives (foreground
 *   ScanService).
 * - Always an honest mobile profile: this WebView's real UA without `; wv`, images enabled, and
 *   the `X-Requested-With: <package>` header disabled (empty androidx.webkit allow-list). The
 *   decision logic is in [RenderLogic] (JUnit).
 * - One task at a time (fair queue); one WebView per session (`startpage`, `brave`, `mojeek`), so
 *   "Next" pagination continues from the previous request's page.
 * - The call blocks and is allowed only from a background thread (Rust → JNI `FocaDirect.call`);
 *   on the main thread it fails instead of deadlocking.
 * - A proxy from settings is applied through `ProxyController` (androidx.webkit); if unsupported,
 *   the request is refused rather than sent directly.
 * - After 10 idle minutes the WebViews are destroyed (cookies are kept).
 * - Technology signals (site recon): an `eval` step runs one read-only probe script from the core
 *   and returns its string answer (size-capped); with `collect_hosts` the hosts of the requests
 *   the page makes are recorded in `shouldInterceptRequest` (observed only, never altered).
 */
@Keep
object RenderFetcher {
  private val main = Handler(Looper.getMainLooper())
  private val queue = Semaphore(1, true)
  /** Main thread only. */
  private val sessions = HashMap<String, Session>()
  /** The proxy applied to WebViews; `null` if not overridden. */
  @Volatile private var proxyApplied: String? = null
  private const val IDLE_MS = 10 * 60 * 1000L
  private const val POLL_MS = 700L
  private val idle = Runnable { destroyAll("простой") }
  /** The app Activity used to attach WebViews to its window (main thread only). */
  private var host: WeakReference<Activity>? = null
  private var hostStarted = false
  private var callbacksOn = false
  private var appCtx: Context? = null

  private class Session(val wv: WebView) {
    @Volatile var finished = 0
    @Volatile var status: Int = 0
    @Volatile var error: String? = null
    /** Request hosts of the running request when it asked for `collect_hosts`, else `null`. */
    @Volatile var hosts: MutableSet<String>? = null
  }

  private fun err(msg: String): String = JSONObject().put("error", msg).toString()

  /** Entry point from [FocaDirect]: a `RenderRequest` JSON in, a `RenderPage` JSON or `{error}` out. */
  fun call(ctx: Context, json: String): String {
    if (Looper.myLooper() == Looper.getMainLooper()) return err("render_fetch на главном потоке")
    val req = try { JSONObject(json) } catch (e: Throwable) { return err("запрос: $e") }
    val timeout = req.optLong("timeout_ms", 60_000L).coerceIn(5_000L, 300_000L)
    val t0 = System.currentTimeMillis()
    val deadline = t0 + timeout
    if (!queue.tryAcquire(timeout, TimeUnit.MILLISECONDS)) return err("очередь встроенного браузера занята дольше ${timeout / 1000} с")
    main.removeCallbacks(idle)
    return try {
      run(ctx.applicationContext, req, t0, deadline)
    } catch (e: Throwable) {
      FLog.e("render: сбой сценария", e)
      err("сбой встроенного браузера: $e")
    } finally {
      main.postDelayed(idle, IDLE_MS)
      queue.release()
    }
  }

  private fun run(app: Context, req: JSONObject, t0: Long, deadline: Long): String {
    val name = req.optString("session", "default").ifEmpty { "default" }
    val ua = req.optString("ua", "")
    applyProxy(req.optString("proxy", ""), deadline)?.let { return err(it) }
    val s = onMain(10_000) { session(app, name, ua) } ?: return err("WebView не создан (нет WebView в системе?)")
    val out = JSONObject()
    s.hosts = if (req.optBoolean("collect_hosts", false)) java.util.Collections.synchronizedSet(LinkedHashSet()) else null
    val url = req.optString("url", "")
    val inline = req.optString("html", "")
    if (inline.isNotEmpty()) {
      // Local page (fingerprint diagnostics): no network, origin = base (https).
      val base = req.optString("base", "https://fingerprint.foca.invalid/")
      val mark = s.finished
      s.status = 0; s.error = null
      main.post { s.wv.loadDataWithBaseURL(base, inline, "text/html", "utf-8", null) }
      waitUntil(deadline) { s.finished > mark || s.error != null }
    } else if (url.isNotEmpty()) {
      FLog.i("render[$name]: открыть $url")
      val mark = s.finished
      s.status = 0; s.error = null
      main.post { s.wv.loadUrl(url) }
      waitUntil(deadline) { s.finished > mark || s.error != null }
    }
    val steps = req.optJSONArray("steps") ?: JSONArray()
    var i = 0
    while (i < steps.length()) {
      val st = steps.getJSONObject(i)
      val op = st.optString("op")
      if (System.currentTimeMillis() >= deadline) { out.put("wait_timeout", true); break }
      when (op) {
        "wait" -> {
          val lim = minOf(deadline, System.currentTimeMillis() + st.optLong("timeout_ms", 30_000L))
          val got = waitCond(s, condJs(st.optJSONArray("gone"), st.optString("present", ""), st.optJSONArray("abort")), lim)
          if (got != null && got.startsWith("abort:")) {
            // Captcha: return to the core right away (verification needed) instead of waiting for the step timeout.
            FLog.w("render[$name]: шаг ${i + 1} прерван, на странице «${got.removePrefix("abort:")}»")
            out.put("aborted", got.removePrefix("abort:")); break
          }
          if (got == null) {
            FLog.w("render[$name]: не дождались условия шага ${i + 1} за ${st.optLong("timeout_ms")} мс")
            out.put("wait_timeout", true); break
          }
        }
        "submit" -> {
          val r = js(s, submitJs(st.optString("form"), st.optString("field"), st.optString("value")), 10_000)
          if (r != "ok") { out.put("missing", "submit ${st.optString("form")}"); break }
          waitNewDoc(s, deadline)
        }
        "click" -> {
          val r = js(s, clickJs(st.optString("sel"), st.optString("text", "")), 10_000)
          if (r != "ok") { out.put("missing", "click ${st.optString("sel")} «${st.optString("text", "")}»"); break }
          waitNewDoc(s, deadline)
        }
        "sleep" -> Thread.sleep(st.optLong("ms", 1000L).coerceIn(0L, maxOf(0L, deadline - System.currentTimeMillis())))
        "eval" -> {
          val lim = RenderLogic.evalTimeout(st.optLong("timeout_ms", 3_000L), deadline - System.currentTimeMillis())
          RenderLogic.capEval(js(s, st.optString("code"), lim))?.let { out.put("eval", it) }
        }
        else -> { out.put("missing", "неизвестный шаг $op"); break }
      }
      i++
    }
    val html = js(s, "document.documentElement ? document.documentElement.outerHTML : ''", 15_000) ?: ""
    val href = js(s, "location.href", 5_000) ?: ""
    val ms = System.currentTimeMillis() - t0
    out.put("html", html).put("url", href).put("ms", ms)
    if (s.status > 0) out.put("status", s.status)
    s.hosts?.let { h -> out.put("hosts", JSONArray(synchronized(h) { h.toList() })) }
    s.hosts = null
    CookieManager.getInstance().flush()
    FLog.i("render[$name]: $href → ${html.length} симв. за $ms мс" +
      (if (out.optBoolean("wait_timeout")) ", проверка/загрузка не завершилась" else "") +
      (out.optString("missing", "").let { if (it.isNotEmpty()) ", нет элемента: $it" else "" }) +
      (s.error?.let { ", ошибка загрузки: $it" } ?: ""))
    return out.toString()
  }

  /**
   * Applies the honest mobile profile to a search engine WebView (shared with [VerifyDialog]): JS,
   * DOM storage, images, the real mobile UA without `; wv`, no `X-Requested-With` header.
   */
  @SuppressLint("SetJavaScriptEnabled")
  fun applyProfile(ctx: Context, wv: WebView, requestedUa: String) {
    wv.settings.apply {
      javaScriptEnabled = true
      domStorageEnabled = true
      allowFileAccess = false
      allowContentAccess = false
      blockNetworkImage = false
      loadsImagesAutomatically = true
      val real = try { WebSettings.getDefaultUserAgent(ctx) } catch (_: Throwable) { userAgentString ?: "" }
      val finalUa = UaForm.forRender(RenderLogic.uaMode(requestedUa), real)
      if (finalUa.isNotEmpty()) userAgentString = finalUa
    }
    if (WebViewFeature.isFeatureSupported(WebViewFeature.REQUESTED_WITH_HEADER_ALLOW_LIST)) {
      try { WebSettingsCompat.setRequestedWithHeaderOriginAllowList(wv.settings, emptySet()) }
      catch (e: Throwable) { FLog.w("render: X-Requested-With не отключён: $e") }
    }
    CookieManager.getInstance().setAcceptCookie(true)
    CookieManager.getInstance().setAcceptThirdPartyCookies(wv, true)
  }

  /** Binds the app Activity (from [FocaPlugin]); search engine WebViews attach to its window. */
  fun bindActivity(a: Activity) {
    main.post {
      appCtx = a.applicationContext
      host = WeakReference(a)
      hostStarted = !a.isFinishing
      if (!callbacksOn) {
        callbacksOn = true
        a.application.registerActivityLifecycleCallbacks(object : Application.ActivityLifecycleCallbacks {
          override fun onActivityStarted(x: Activity) { host = WeakReference(x); hostStarted = true; placeAll() }
          override fun onActivityStopped(x: Activity) { if (host?.get() === x) { hostStarted = false; placeAll() } }
          override fun onActivityDestroyed(x: Activity) { if (host?.get() === x) { hostStarted = false; placeAll(); host = null } }
          override fun onActivityCreated(x: Activity, b: Bundle?) {}
          override fun onActivityResumed(x: Activity) {}
          override fun onActivityPaused(x: Activity) {}
          override fun onActivitySaveInstanceState(x: Activity, b: Bundle) {}
        })
      }
      placeAll()
    }
  }

  private fun placeAll() { for (s in sessions.values) place(s.wv) }

  /** Places the WebView in the Activity window (below the main WebView) or detaches it. Main thread only. */
  private fun place(wv: WebView) {
    val a = host?.get()
    val where = RenderLogic.placement(a != null, hostStarted, a?.isFinishing ?: true)
    val decor = if (where == RenderLogic.Placement.WINDOW) a?.window?.decorView as? ViewGroup else null
    if (decor != null) {
      if (wv.parent !== decor) {
        (wv.parent as? ViewGroup)?.removeView(wv)
        // Index 0 is below the Activity content (the Tauri WebView): invisible and receives no touches.
        decor.addView(wv, 0, FrameLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.MATCH_PARENT))
        FLog.i("render: WebView поисковика прикреплён к окну (страница видима)")
      }
    } else {
      if (wv.parent != null) {
        (wv.parent as? ViewGroup)?.removeView(wv)
        FLog.i("render: WebView поисковика без окна (приложение свёрнуто)")
      }
      val dm = (appCtx ?: wv.context).resources.displayMetrics
      val (w, h) = RenderLogic.detachedSize(dm.widthPixels, dm.heightPixels)
      wv.measure(View.MeasureSpec.makeMeasureSpec(w, View.MeasureSpec.EXACTLY), View.MeasureSpec.makeMeasureSpec(h, View.MeasureSpec.EXACTLY))
      wv.layout(0, 0, w, h)
    }
    wv.onResume(); wv.resumeTimers()
  }

  private fun session(app: Context, name: String, ua: String): Session {
    sessions[name]?.let { return it }
    if (appCtx == null) appCtx = app
    val wv = WebView(app)
    val s = Session(wv)
    applyProfile(app, wv, ua)
    // Invisible layer: not focusable and hidden from accessibility (TalkBack must not read it).
    wv.isFocusable = false
    wv.isFocusableInTouchMode = false
    wv.importantForAccessibility = View.IMPORTANT_FOR_ACCESSIBILITY_NO_HIDE_DESCENDANTS
    wv.webViewClient = object : WebViewClient() {
      override fun shouldOverrideUrlLoading(view: WebView?, request: WebResourceRequest?): Boolean {
        val u = request?.url?.scheme?.lowercase() ?: return true
        return u != "http" && u != "https"
      }
      override fun onPageStarted(view: WebView?, url: String?, favicon: Bitmap?) {
        if (s.status == 0) s.status = 200
      }
      override fun onPageFinished(view: WebView?, url: String?) { s.finished++ }
      override fun shouldInterceptRequest(view: WebView?, request: WebResourceRequest?): WebResourceResponse? {
        // Observe only: the request goes on unchanged (null = default loading).
        s.hosts?.let { RenderLogic.addHost(it, request?.url?.host) }
        return null
      }
      override fun onReceivedHttpError(view: WebView?, request: WebResourceRequest?, resp: WebResourceResponse?) {
        if (request?.isForMainFrame == true) s.status = resp?.statusCode ?: 0
      }
      override fun onReceivedError(view: WebView?, request: WebResourceRequest?, error: WebResourceError?) {
        if (request?.isForMainFrame == true) { s.error = error?.description?.toString() ?: "ошибка"; s.status = 0 }
      }
    }
    sessions[name] = s
    place(wv)
    FLog.i("render[$name]: создан WebView поисковика (${wv.settings.userAgentString})")
    return s
  }

  private fun destroyAll(why: String) {
    if (sessions.isEmpty()) return
    FLog.i("render: уничтожить ${sessions.size} WebView ($why)")
    for (s in sessions.values) try { (s.wv.parent as? ViewGroup)?.removeView(s.wv); s.wv.stopLoading(); s.wv.destroy() } catch (_: Throwable) {}
    sessions.clear()
    CookieManager.getInstance().flush()
  }

  /** Public wrapper for [WebScreenshotter] so all process WebViews share ProxyController state. */
  fun ensureProxy(p: String, deadline: Long): String? = applyProxy(p, deadline)

  /** Applies a proxy to all WebViews of the process; returns `null` on success, otherwise the refusal reason. */
  private fun applyProxy(p: String, deadline: Long): String? {
    val want = p.trim().replace("socks5h://", "socks5://").replace("socks4a://", "socks4://").ifEmpty { null }
    if (want == proxyApplied) return null
    if (!WebViewFeature.isFeatureSupported(WebViewFeature.PROXY_OVERRIDE)) {
      return if (want == null) null else "WebView не поддерживает прокси: запрос напрямую не отправлен"
    }
    val done = CountDownLatch(1)
    val fail = AtomicReference<String?>(null)
    main.post {
      try {
        val pc = ProxyController.getInstance()
        if (want == null) pc.clearProxyOverride({ it.run() }) { done.countDown() }
        else {
          val b = ProxyConfig.Builder().addProxyRule(want)
          RenderLogic.PROXY_BYPASS.forEach { b.addBypassRule(it) }
          pc.setProxyOverride(b.build(), { it.run() }) { done.countDown() }
        }
      } catch (e: Throwable) { fail.set("прокси WebView: $e"); done.countDown() }
    }
    done.await(maxOf(1000L, minOf(10_000L, deadline - System.currentTimeMillis())), TimeUnit.MILLISECONDS)
    fail.get()?.let { FLog.w(it); return it }
    proxyApplied = want
    FLog.i("render: прокси WebView ${want ?: "снят"}")
    return null
  }

  private fun <T> onMain(timeoutMs: Long, f: () -> T): T? {
    val r = AtomicReference<T?>(null)
    val l = CountDownLatch(1)
    main.post { try { r.set(f()) } catch (e: Throwable) { FLog.e("render: main", e) } finally { l.countDown() } }
    l.await(timeoutMs, TimeUnit.MILLISECONDS)
    return r.get()
  }

  /** Runs `evaluateJavascript` and returns the decoded JSON value as a string; `null` on timeout or error. */
  private fun js(s: Session, code: String, timeoutMs: Long): String? {
    val r = AtomicReference<String?>(null)
    val l = CountDownLatch(1)
    main.post {
      try { s.wv.evaluateJavascript("(function(){try{return ($code);}catch(e){return 'jserr:'+e;}})()") { v -> r.set(v); l.countDown() } }
      catch (e: Throwable) { l.countDown() }
    }
    if (!l.await(timeoutMs, TimeUnit.MILLISECONDS)) return null
    val raw = r.get() ?: return null
    return try {
      when (val v = JSONTokener(raw).nextValue()) { JSONObject.NULL -> null; is String -> v; else -> v.toString() }
    } catch (_: Throwable) { raw }
  }

  private fun waitUntil(deadline: Long, cond: () -> Boolean): Boolean {
    while (System.currentTimeMillis() < deadline) {
      if (cond()) return true
      Thread.sleep(200)
    }
    return cond()
  }

  /** Waits for a condition: `"true"` when met, `"abort:<text>"` when the fast exit fired, `null` on timeout. */
  private fun waitCond(s: Session, cond: String, lim: Long): String? {
    while (System.currentTimeMillis() < lim) {
      val r = js(s, cond, 5_000)
      if (r == "true" || (r != null && r.startsWith("abort:"))) return r
      Thread.sleep(POLL_MS)
    }
    return null
  }

  /** After submit/click the old document is marked `__focaOld`; waits for the new one to load. */
  private fun waitNewDoc(s: Session, deadline: Long) {
    val lim = minOf(deadline, System.currentTimeMillis() + 30_000L)
    waitCond(s, "window.__focaOld === undefined && document.readyState === 'complete'", lim)
    Unit
  }

  private fun q(v: String): String = JSONObject.quote(v)

  private fun condJs(gone: JSONArray?, present: String, abort: JSONArray? = null): String {
    val g = gone ?: JSONArray()
    val a = abort ?: JSONArray()
    val sel = if (present.isNotEmpty()) "if(!document.querySelector(${q(present)})) return false;" else ""
    return "(function(){if(document.readyState!=='complete'||!document.body) return false;" +
      "var t=document.body.innerText||'';var a=$a;var tl=t.toLowerCase()+' '+String(location.href).toLowerCase();" +
      "for(var j=0;j<a.length;j++){if(tl.indexOf(a[j])>=0) return 'abort:'+a[j];}" +
      "var g=$g;for(var i=0;i<g.length;i++){if(t.indexOf(g[i])>=0) return false;}" +
      "$sel return true;})()"
  }

  private fun submitJs(form: String, field: String, value: String): String =
    "(function(){var f=document.querySelector(${q(form)});if(!f) return 'missing';" +
      "var i=f.querySelector(${q(field)});if(!i) return 'missing';i.value=${q(value)};" +
      "window.__focaOld=1;f.submit();return 'ok';})()"

  private fun clickJs(sel: String, text: String): String =
    "(function(){var t=${q(text.lowercase())};var els=document.querySelectorAll(${q(sel)});" +
      "for(var i=0;i<els.length;i++){var e=els[i];var x=((e.innerText||e.value||e.getAttribute('aria-label')||'')+'').toLowerCase();" +
      "if(t&&x.indexOf(t)<0) continue;window.__focaOld=1;" +
      "if(e.form&&(e.tagName==='BUTTON'||e.type==='submit')){e.form.submit();}else{e.click();}return 'ok';}" +
      "return 'missing';})()"
}

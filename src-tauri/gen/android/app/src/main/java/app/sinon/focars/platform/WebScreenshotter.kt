package app.sinon.focars.platform

import android.content.Context
import android.graphics.Bitmap
import android.graphics.Canvas
import android.graphics.Color
import android.os.Handler
import android.os.Looper
import android.util.Base64
import android.webkit.WebResourceRequest
import android.webkit.WebResourceResponse
import android.webkit.WebSettings
import android.webkit.WebView
import android.webkit.WebViewClient
import app.tauri.plugin.JSArray
import app.tauri.plugin.JSObject
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicReference

/**
 * Isolated offscreen WebView snapshotter.
 *
 * Captures a compact thumbnail and downsampled 9x8 grayscale luminance grid for 64-bit perceptual
 * hashing (`dHash`). Runs with JS and file/content access disabled, no-cache, and without mutating
 * process-wide CookieManager state. Every host (page, redirects, sub-resources) must be public: names
 * are resolved and checked by [SsrfGuard] (loopback, link-local, private, CGNAT, ULA, multicast).
 */
object WebScreenshotter {
  private val main = Handler(Looper.getMainLooper())

  /** Redirect hops re-issued after an off-main-thread host check (guards against redirect loops). */
  private const val MAX_REDIRECTS = 5

  private fun blockedResponse(): WebResourceResponse =
    WebResourceResponse("text/plain", "utf-8", 403, "Blocked", emptyMap(), ByteArrayInputStream(ByteArray(0)))

  /** Blocking (resolves names); call from a background thread only. */
  fun capture(ctx: Context, args: JSObject): JSObject {
    val url = args.getString("url", null)?.trim() ?: ""
    val proxy = args.getString("proxy", null)?.trim() ?: ""
    // Behind a proxy the proxy resolves names: a local lookup would leak the target to the local
    // resolver, so only IP literals are judged there. Direct connections resolve and check every host.
    val hostOk = ConcurrentHashMap<String, Boolean>()
    val resolver: ((String) -> List<ByteArray>)? = if (proxy.isEmpty()) SsrfGuard.systemResolver else null
    fun blocked(u: String): Boolean {
      val host = SsrfGuard.hostOf(u) ?: return true
      hostOk[host]?.let { return !it }
      val b = SsrfGuard.isBlockedUrl(u, resolver)
      hostOk[host] = !b
      return b
    }
    // Main-thread variant: never resolves; unknown names are reported as null.
    fun blockedCached(u: String): Boolean? {
      val host = SsrfGuard.hostOf(u) ?: return true
      return when (SsrfGuard.literalVerdict(host)) {
        SsrfGuard.Verdict.BLOCKED -> true
        SsrfGuard.Verdict.ALLOWED -> false
        SsrfGuard.Verdict.NEEDS_DNS -> if (resolver == null) false else hostOk[host]?.let { !it }
      }
    }
    if (url.isEmpty() || blocked(url)) {
      return JSObject().put("error", "bad_url")
    }
    val width = args.getInteger("width", 360)?.coerceIn(120, 1280) ?: 360
    val height = args.getInteger("height", 640)?.coerceIn(120, 1280) ?: 640
    val timeoutMs = (args.getInteger("timeout_ms", 8000) ?: 8000).coerceIn(1000, 30000).toLong()

    RenderFetcher.ensureProxy(proxy, System.currentTimeMillis() + timeoutMs)?.let { reason ->
      return JSObject().put("error", reason)
    }

    val latch = CountDownLatch(1)
    val done = AtomicBoolean(false)
    // Written on the main thread and read by the caller after latch.await(); AtomicReference provides the
    // happens-before edge that @Volatile cannot (it is not applicable to local variables).
    val outRef = AtomicReference<JSObject?>(null)
    val wvHolder = AtomicReference<WebView?>(null)
    val redirects = AtomicInteger(0)

    main.post {
      try {
        val wv = WebView(ctx.applicationContext)
        wvHolder.set(wv)
        wv.settings.apply {
          javaScriptEnabled = false
          allowFileAccess = false
          allowContentAccess = false
          cacheMode = WebSettings.LOAD_NO_CACHE
          blockNetworkImage = false
        }
        wv.layout(0, 0, width, height)
        wv.webViewClient = object : WebViewClient() {
          // Sub-resources (and the first request) are checked on the WebView's network thread, where
          // a blocking lookup is allowed; non-public hosts get an empty 403.
          override fun shouldInterceptRequest(view: WebView?, request: WebResourceRequest?): WebResourceResponse? {
            val u = request?.url ?: return blockedResponse()
            return when (u.scheme?.lowercase()) {
              "data", "blob", "about" -> null
              "http", "https" -> if (blocked(u.toString())) blockedResponse() else null
              else -> blockedResponse()
            }
          }

          // Navigations and redirects run on the main thread: known hosts are decided at once, an unknown
          // name is checked on a background thread and the navigation re-issued only if it is public.
          override fun shouldOverrideUrlLoading(view: WebView?, request: WebResourceRequest?): Boolean {
            val u = request?.url?.toString() ?: return true
            if (request?.isForMainFrame != true) return blockedCached(u) != false
            return when (blockedCached(u)) {
              false -> false
              true -> true
              null -> {
                if (redirects.incrementAndGet() > MAX_REDIRECTS) return true
                Thread({
                  val ok = !blocked(u)
                  main.post { if (ok && !done.get()) try { view?.loadUrl(u) } catch (_: Throwable) {} }
                }, "foca-shot-dns").apply { isDaemon = true }.start()
                true
              }
            }
          }

          override fun onPageFinished(view: WebView?, loadedUrl: String?) {
            if (!done.compareAndSet(false, true)) return
            try {
              val bmp = Bitmap.createBitmap(width, height, Bitmap.Config.ARGB_8888)
              val canvas = Canvas(bmp)
              canvas.drawColor(Color.WHITE)
              view?.draw(canvas)

              // Downsample to 9x8 luminance grid for 64-bit dHash
              val small = Bitmap.createScaledBitmap(bmp, 9, 8, true)
              val luma = JSArray()
              for (y in 0 until 8) {
                for (x in 0 until 9) {
                  val px = small.getPixel(x, y)
                  val r = Color.red(px)
                  val g = Color.green(px)
                  val b = Color.blue(px)
                  val yVal = ((77 * r + 150 * g + 29 * b) shr 8).coerceIn(0, 255)
                  luma.put(yVal)
                }
              }
              small.recycle()

              val bos = ByteArrayOutputStream()
              bmp.compress(Bitmap.CompressFormat.PNG, 85, bos)
              bmp.recycle()
              val b64 = Base64.encodeToString(bos.toByteArray(), Base64.NO_WRAP)

              outRef.set(JSObject()
                .put("width", width)
                .put("height", height)
                .put("luma_9x8", luma)
                .put("image_b64", b64)
                .put("title", view?.title ?: ""))
            } catch (e: Throwable) {
              outRef.set(JSObject().put("error", e.toString()))
            } finally {
              latch.countDown()
            }
          }
        }
        wv.loadUrl(url)
      } catch (e: Throwable) {
        if (done.compareAndSet(false, true)) {
          outRef.set(JSObject().put("error", e.toString()))
          latch.countDown()
        }
      }
    }

    val ok = latch.await(timeoutMs, TimeUnit.MILLISECONDS)
    main.post {
      try {
        wvHolder.getAndSet(null)?.apply {
          stopLoading()
          clearHistory()
          clearCache(true)
          destroy()
        }
      } catch (_: Throwable) {}
    }
    if (!ok) {
      return JSObject().put("error", "timeout")
    }
    return outRef.get() ?: JSObject().put("error", "capture_failed")
  }
}

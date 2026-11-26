package app.sinon.focars.platform

/**
 * Pure profile logic for the hidden search engine browser ([RenderFetcher]), without Android APIs
 * and covered by JUnit (`RenderLogicTest`).
 *
 * The goal is for the real WebView on the phone to behave consistently like an ordinary mobile
 * browser: a mobile UA of the same version (without `; wv`), window size equal to the phone
 * screen, a "visible" page (the WebView is attached to the Activity window), images loaded and no
 * `X-Requested-With`. No impersonation of other devices: only this phone's real values.
 */
object RenderLogic {
  /** Localhost / loopback bypass rules for WebView ProxyConfig so internal app assets stay direct. */
  val PROXY_BYPASS = listOf("localhost", "127.0.0.1", "*.localhost", "::1")

  /** Where to keep the search engine WebView. */
  enum class Placement {
    /** Below the app's main WebView in the Activity window: invisible, yet `visibilityState=visible`. */
    WINDOW,
    /** Without a window (app in the background or no Activity), sized to the screen. */
    DETACHED,
  }

  /** Attaches to the window if an Activity exists and is shown (started); otherwise detached. */
  fun placement(hasActivity: Boolean, started: Boolean, finishing: Boolean): Placement =
    if (hasActivity && started && !finishing) Placement.WINDOW else Placement.DETACHED

  /**
   * Returns the UA mode for search engines: always this WebView's honest mobile UA. A legacy
   * `desktop` request (core ≤ 1.0.1) or an empty one also yields mobile: a desktop UA combined with
   * a touch phone screen, `navigator.platform=Linux armv8l` and mobile Client Hints is an
   * inconsistent fingerprint, which is exactly how anti-bot systems spot automation. An explicit
   * string is used as is.
   */
  fun uaMode(requested: String): String = when (requested.trim()) {
    "", UaForm.DESKTOP, UaForm.MOBILE -> UaForm.MOBILE
    else -> requested.trim()
  }

  /**
   * Returns the detached WebView size: the phone screen in pixels (portrait) rather than a 1280×2400
   * "desktop", so `innerWidth`/`screen.width` match the mobile UA. Zero or broken metrics fall back
   * to a typical 1080×2400 phone.
   */
  fun detachedSize(widthPx: Int, heightPx: Int): Pair<Int, Int> {
    if (widthPx <= 0 || heightPx <= 0) return 1080 to 2400
    val w = minOf(widthPx, heightPx)
    val h = maxOf(widthPx, heightPx)
    return w to h
  }

  /** Summarizes the fingerprint for the log in one line: which signs of a "broken" browser are visible. */
  fun fingerprintIssues(
    ua: String,
    visibility: String,
    webdriver: Boolean,
    touchPoints: Int,
    innerWidth: Int,
    mobileHint: Boolean?,
  ): List<String> {
    val out = ArrayList<String>()
    if (ua.contains("; wv)")) out += "UA содержит маркер WebView «; wv»"
    if (visibility != "visible") out += "страница не видима (visibilityState=$visibility)"
    if (webdriver) out += "navigator.webdriver=true"
    val mobileUa = ua.contains("Mobile")
    if (mobileUa && touchPoints == 0) out += "мобильный UA без сенсора"
    if (!mobileUa && touchPoints > 0) out += "десктопный UA на сенсорном экране"
    if (mobileUa && innerWidth > 1000) out += "мобильный UA при ширине окна $innerWidth"
    if (mobileHint != null && mobileHint != mobileUa) out += "Client Hints mobile=$mobileHint не совпадает с UA"
    return out
  }
}

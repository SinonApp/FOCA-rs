package app.sinon.focars.platform

/**
 * User-Agent forms for the embedded browser. The version is never spoofed: the real
 * `WebSettings.getDefaultUserAgent(ctx)` string is used with the WebView markers `; wv` and
 * `Version/4.0` removed. For desktop mode a desktop Chrome UA with the SAME major version is built
 * (reduced form `Chrome/<major>.0.0.0`, like real Chrome).
 *
 * The `ua` value from the core request: `desktop` gives the desktop form, `mobile` or empty gives the
 * real mobile UA without `; wv`, any other string is used as is.
 */
object UaForm {
  const val DESKTOP = "desktop"
  const val MOBILE = "mobile"

  private val CHROME = Regex("""Chrome/(\d+)[\d.]*""")

  /** Returns the Chrome major version from a UA, or null. */
  fun chromeMajor(ua: String): Int? = CHROME.find(ua)?.groupValues?.get(1)?.toIntOrNull()

  /** Returns the real WebView UA without WebView markers (`; wv`, `Version/4.0`). */
  fun stripWebView(real: String): String =
    real.replace("; wv)", ")")
      .replace(Regex("""\s*Version/4\.0"""), "")
      .replace(Regex("""\s{2,}"""), " ")
      .trim()

  /** Returns a desktop Windows Chrome UA with the same major version, or null if the source has no version. */
  fun desktop(real: String): String? {
    val major = chromeMajor(real) ?: return null
    return "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/$major.0.0.0 Safari/537.36"
  }

  /** Returns the final string for `WebSettings.userAgentString`; empty means keep the default UA. */
  fun forRender(requested: String, real: String): String = when (requested.trim()) {
    DESKTOP -> desktop(real) ?: stripWebView(real)
    MOBILE, "" -> stripWebView(real)
    else -> requested.trim()
  }
}

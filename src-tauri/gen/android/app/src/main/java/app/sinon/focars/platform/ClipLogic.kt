package app.sinon.focars.platform

import java.security.MessageDigest

/**
 * Pure clipboard decisions for the `clipboard_*` plugin commands (no Android APIs, JVM tested).
 *
 * Why native at all: Android System WebView never grants the async Clipboard API read
 * (`navigator.clipboard.readText()` rejects, there is no clipboard resource in `PermissionRequest`),
 * so the UI reads, writes and clears the clipboard through `ClipboardManager` instead.
 */
object ClipLogic {
  /** Label of the clips the app writes (shown by some keyboards in the clipboard history). */
  const val LABEL = "FOCA-rs"

  /** `ClipDescription.EXTRA_IS_SENSITIVE`; the literal also works before API 33 (ignored there). */
  const val EXTRA_IS_SENSITIVE = "android.content.extra.IS_SENSITIVE"

  /** Upper bound of the text handed to the WebView (a pasted key or a target list is far smaller). */
  const val MAX_READ_CHARS = 256 * 1024

  /** `ClipboardManager.clearPrimaryClip()` exists since Android 9 (API 28). */
  fun canClearNatively(sdk: Int): Boolean = sdk >= 28

  /** Text returned to the UI: null becomes empty, oversized text is cut to [MAX_READ_CHARS]. */
  fun capText(text: CharSequence?): String {
    val s = text?.toString() ?: return ""
    return if (s.length > MAX_READ_CHARS) s.substring(0, MAX_READ_CHARS) else s
  }

  /** SHA-256 of the last written secret: the plain value is never kept in memory by the plugin. */
  fun digest(text: String): String =
    Codec.hex(MessageDigest.getInstance("SHA-256").digest(text.toByteArray(Charsets.UTF_8)))

  /**
   * Whether a clear may wipe the clipboard. Values are compared as [digest]s so the plugin never has
   * to keep a secret in memory for the delayed auto-clear.
   *
   * - no `expectedDigest`: an explicit clear (after a key was pasted), always allowed;
   * - readable clipboard: only if it still holds the expected value (a value the user copied
   *   later is kept);
   * - unreadable clipboard (Android 10+ hides it while the app has no window focus, e.g. the 30 s
   *   timer fired in the background): only if the expected value is what this app wrote last and
   *   no foreign clip change was observed since that write.
   */
  fun shouldClear(
    expectedDigest: String?,
    readable: Boolean,
    currentDigest: String?,
    lastWrittenDigest: String?,
    changedSinceWrite: Boolean,
  ): Boolean = when {
    expectedDigest == null -> true
    readable -> currentDigest == expectedDigest
    else -> !changedSinceWrite && lastWrittenDigest == expectedDigest
  }
}

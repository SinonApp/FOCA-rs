package app.sinon.focars.platform

import java.io.File

/**
 * Pure JVM validation and bounding helpers for on-device offline OCR (`ocr_recognize`).
 */
object OcrLogic {
  const val MAX_TEXT_BYTES = 65_536
  const val MIN_PAGES = 1
  const val MAX_PAGES = 50
  const val DEFAULT_PAGES = 10
  const val MAX_BITMAP_EDGE = 1600

  fun clampMaxPages(n: Int): Int = n.coerceIn(MIN_PAGES, MAX_PAGES)

  /** ML Kit rejects images under 32 px on a side ("InputImage width and height should be at least 32"). */
  const val MIN_EDGE = 32

  /** Whether an image is too small to hold readable text (OCR is skipped, not an error). */
  fun tooSmall(width: Int, height: Int): Boolean = width < MIN_EDGE || height < MIN_EDGE

  fun isSupportedMime(mime: String?): Boolean {
    val m = mime?.trim()?.lowercase() ?: return false
    return m == "application/pdf" || m.startsWith("image/")
  }

  /**
   * Ensures [target] resides strictly inside one of [allowedRoots] after canonical resolution.
   */
  fun isSafeLocalPath(target: File, allowedRoots: List<File>): Boolean {
    return try {
      if (!target.exists() || !target.isFile) return false
      val canon = target.canonicalPath
      allowedRoots.any { root ->
        val r = root.canonicalPath.trimEnd(File.separatorChar)
        canon == r || canon.startsWith("$r${File.separator}")
      }
    } catch (_: Throwable) {
      false
    }
  }

  /** Computes `BitmapFactory.Options.inSampleSize` (power of two) so neither dimension exceeds [maxEdge]. */
  fun sampleSize(width: Int, height: Int, maxEdge: Int = MAX_BITMAP_EDGE): Int {
    if (width <= 0 || height <= 0 || maxEdge <= 0) return 1
    var sample = 1
    while (width / sample > maxEdge || height / sample > maxEdge) {
      sample *= 2
    }
    return sample
  }

  /** Scales `(width, height)` down proportionally so the longer edge is at most [maxEdge]. */
  fun scaledDimensions(width: Int, height: Int, maxEdge: Int = MAX_BITMAP_EDGE): Pair<Int, Int> {
    if (width <= 0 || height <= 0) return 1 to 1
    val longest = maxOf(width, height)
    if (longest <= maxEdge) return width to height
    val scale = maxEdge.toDouble() / longest.toDouble()
    return maxOf(1, (width * scale).toInt()) to maxOf(1, (height * scale).toInt())
  }

  /** Truncates [text] to at most [maxBytes] UTF-8 bytes without splitting multi-byte characters. */
  fun truncateUtf8(text: String, maxBytes: Int = MAX_TEXT_BYTES): String {
    val trimmed = text.trim()
    val utf8 = trimmed.toByteArray(Charsets.UTF_8)
    if (utf8.size <= maxBytes) return trimmed
    var end = maxBytes
    while (end > 0 && (utf8[end].toInt() and 0xC0) == 0x80) {
      end--
    }
    return String(utf8, 0, end, Charsets.UTF_8)
  }
}

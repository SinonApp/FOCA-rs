package app.sinon.focars.platform

/**
 * Rules for files shared into the app from other apps ("Share → FOCA-rs", ACTION_SEND /
 * ACTION_SEND_MULTIPLE): which files are taken (documents, photos, archives only), how many and how
 * large, and how they are named in the private cache. Pure JVM code, unit-tested; the copying itself
 * is in [ShareInbox].
 */
object ShareLogic {
  const val MAX_FILES = 20
  const val MAX_TOTAL = 256L * 1024 * 1024
  /** Copies older than this are removed before a new batch is stored. */
  const val KEEP_MS = 6L * 60 * 60 * 1000

  /** Extensions the core can parse (metadata, hygiene grade, cleaning for some of them). */
  val DOC_EXT = setOf(
    "pdf", "doc", "docx", "docm", "dotx", "xls", "xlsx", "xlsm", "ppt", "pptx", "pptm", "rtf",
    "odt", "ods", "odp", "odg", "sxw", "sxc", "sxi", "vsd", "vsdx",
    "jpg", "jpeg", "png", "tif", "tiff", "heic", "heif", "webp", "svg",
    "zip", "eml", "msg", "ics", "vcf", "lnk", "rdp", "ica", "mp4", "mov",
  )

  /** MIME types (or `type/` prefixes) accepted when the name has no known extension. */
  private val DOC_MIME = listOf(
    "application/pdf", "application/msword", "application/rtf", "application/zip",
    "application/x-zip-compressed", "application/vnd.openxmlformats-officedocument.",
    "application/vnd.oasis.opendocument.", "application/vnd.ms-excel", "application/vnd.ms-powerpoint",
    "application/vnd.ms-outlook", "application/vnd.visio", "message/rfc822", "text/calendar",
    "text/vcard", "text/x-vcard", "image/", "video/mp4", "video/quicktime",
  )

  private val MIME_EXT = mapOf(
    "application/pdf" to "pdf",
    "application/msword" to "doc",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document" to "docx",
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet" to "xlsx",
    "application/vnd.openxmlformats-officedocument.presentationml.presentation" to "pptx",
    "application/vnd.oasis.opendocument.text" to "odt",
    "application/vnd.oasis.opendocument.spreadsheet" to "ods",
    "application/vnd.oasis.opendocument.presentation" to "odp",
    "application/vnd.oasis.opendocument.graphics" to "odg",
    "application/vnd.ms-excel" to "xls",
    "application/vnd.ms-powerpoint" to "ppt",
    "application/zip" to "zip",
    "image/jpeg" to "jpg",
    "image/png" to "png",
    "image/heic" to "heic",
    "image/webp" to "webp",
    "image/tiff" to "tif",
    "message/rfc822" to "eml",
  )

  fun ext(name: String): String = name.substringAfterLast('.', "").lowercase()

  /** `true` for document-like files: a known extension, or a document MIME type. */
  fun accepted(name: String, mime: String?): Boolean {
    if (ext(name) in DOC_EXT) return true
    val m = (mime ?: "").lowercase().substringBefore(';').trim()
    if (m.isEmpty() || m == "application/octet-stream" || m.startsWith("text/plain")) return false
    return DOC_MIME.any { if (it.endsWith("/") || it.endsWith(".")) m.startsWith(it) else m == it }
  }

  /**
   * Flat, safe file name for the cache: the display name without any path, with an extension taken
   * from the MIME type when the name has none (Telegram may send "file_123").
   */
  fun nameFor(display: String?, mime: String?, index: Int): String {
    var n = PickLogic.safeName(display ?: "")
    if (n == "file") n = "shared_${index + 1}"
    if (ext(n) !in DOC_EXT) {
      val e = MIME_EXT[(mime ?: "").lowercase().substringBefore(';').trim()]
      if (e != null) n = "$n.$e"
    }
    return n.take(120)
  }

  /** A batch stored at `stamp` (directory `in-<stamp>`) is stale at `now`. */
  fun stale(dirName: String, now: Long): Boolean {
    val stamp = dirName.removePrefix("in-").toLongOrNull() ?: return true
    return now - stamp > KEEP_MS || stamp > now + 60_000
  }
}

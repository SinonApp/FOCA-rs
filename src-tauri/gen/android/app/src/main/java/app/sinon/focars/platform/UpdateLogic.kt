package app.sinon.focars.platform

import java.io.File
import java.security.MessageDigest

/**
 * Pure checks of the in-app update (no Android types, unit-tested on the JVM): the downloaded APK
 * must be signed with the installed app's certificate, carry the same package name and a higher
 * versionCode, and live in the update cache directory.
 */
object UpdateLogic {
  /** Reasons an install is refused; `code` is the wire value the UI translates. */
  enum class Verdict(val code: String) {
    OK("ok"),
    DISABLED("update_disabled"),
    UNREADABLE("update_apk_unreadable"),
    PACKAGE("update_package_mismatch"),
    NOT_NEWER("update_not_newer"),
    CERT("update_cert_mismatch"),
  }

  fun sha256Hex(b: ByteArray): String =
    MessageDigest.getInstance("SHA-256").digest(b).joinToString("") { "%02x".format(it) }

  /** Both sides have at least one certificate and the same set of certificate digests. */
  fun certsMatch(installed: List<ByteArray>, apk: List<ByteArray>): Boolean {
    if (installed.isEmpty() || apk.isEmpty()) return false
    return installed.map(::sha256Hex).toSet() == apk.map(::sha256Hex).toSet()
  }

  /** The first failing check, in the order the user can act on. */
  fun verdict(
    enabled: Boolean,
    installedPackage: String,
    apkPackage: String?,
    installedCode: Long,
    apkCode: Long,
    certsOk: Boolean,
  ): Verdict = when {
    !enabled -> Verdict.DISABLED
    apkPackage == null -> Verdict.UNREADABLE
    apkPackage != installedPackage -> Verdict.PACKAGE
    !certsOk -> Verdict.CERT
    apkCode <= installedCode -> Verdict.NOT_NEWER
    else -> Verdict.OK
  }

  /** The APK path is a `.apk` file directly inside `<cache>/update` (no traversal, no symlink escape). */
  fun pathAllowed(cacheDir: File, path: String): Boolean = try {
    val dir = File(cacheDir, "update").canonicalFile
    val f = File(path).canonicalFile
    f.parentFile == dir && f.name.endsWith(".apk") && f.isFile
  } catch (_: Throwable) {
    false
  }

  /** Download progress in whole percent (0 when the size is unknown). */
  fun percent(received: Long, total: Long): Int =
    if (total <= 0) 0 else ((received.coerceIn(0, total) * 100) / total).toInt()
}

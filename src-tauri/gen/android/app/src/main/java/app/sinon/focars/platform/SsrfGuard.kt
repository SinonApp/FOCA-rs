package app.sinon.focars.platform

import java.net.InetAddress
import java.net.URI

/**
 * Pure (Android-free) SSRF policy for the off-screen web screenshotter: only http(s) URLs whose host
 * is a public address may be loaded. Covers IP literals in every form a browser accepts (dotted,
 * short, octal/hex IPv4, bracketed IPv6) and hostnames through an injected resolver, so tests run on
 * the JVM without network access.
 *
 * Limitation: the WebView resolves the name again when it connects, so a DNS rebinding answer that
 * changes between the check and the connection is not caught here.
 */
object SsrfGuard {
  enum class Verdict { ALLOWED, BLOCKED, NEEDS_DNS }

  /** Lower-cased host of an http(s) URL without brackets and trailing dot, or null when unusable. */
  fun hostOf(url: String): String? {
    val uri = try { URI(url.trim()) } catch (_: Throwable) { return null }
    val scheme = uri.scheme?.lowercase() ?: return null
    if (scheme != "http" && scheme != "https") return null
    // URI.host is null for hosts it cannot parse (e.g. underscores); fall back to the raw authority.
    val raw = uri.host ?: uri.rawAuthority?.substringAfterLast('@')?.let { a ->
      if (a.startsWith("[")) a.substringBefore(']') + "]" else a.substringBefore(':')
    } ?: return null
    val h = raw.trim().lowercase().removePrefix("[").removeSuffix("]").trimEnd('.')
    return h.ifEmpty { null }
  }

  /** Verdict for a host without DNS: literals are decided here, names need a lookup. */
  fun literalVerdict(host: String): Verdict {
    val h = host.lowercase().removePrefix("[").removeSuffix("]").trimEnd('.')
    if (h.isEmpty() || h == "localhost" || h.endsWith(".localhost")) return Verdict.BLOCKED
    parseIpv4(h)?.let { return if (isBlockedAddress(it)) Verdict.BLOCKED else Verdict.ALLOWED }
    if (h.contains(':')) {
      // Only an IPv6 literal can contain ':' here; anything unparsable is refused.
      if (!h.all { it.isDigit() || it in 'a'..'f' || it == ':' || it == '.' || it == '%' }) return Verdict.BLOCKED
      val bytes = try { InetAddress.getByName(h.substringBefore('%')).address } catch (_: Throwable) { return Verdict.BLOCKED }
      return if (isBlockedAddress(bytes)) Verdict.BLOCKED else Verdict.ALLOWED
    }
    return Verdict.NEEDS_DNS
  }

  /**
   * Returns true when [url] must not be loaded. [resolve] maps a hostname to its addresses (null when
   * name lookups are not allowed, e.g. behind a proxy that resolves names itself); a failed or empty
   * lookup blocks the URL.
   */
  fun isBlockedUrl(url: String, resolve: ((String) -> List<ByteArray>)?): Boolean {
    val host = hostOf(url) ?: return true
    return when (literalVerdict(host)) {
      Verdict.BLOCKED -> true
      Verdict.ALLOWED -> false
      Verdict.NEEDS_DNS -> {
        if (resolve == null) return false
        val addrs = try { resolve(host) } catch (_: Throwable) { return true }
        addrs.isEmpty() || addrs.any { isBlockedAddress(it) }
      }
    }
  }

  /**
   * Parses IPv4 the way URL parsers do: 1-4 parts, each decimal, octal (leading 0) or hex (0x), the
   * last part filling the remaining bytes ("127.1", "2130706433", "0x7f.0.0.1"). Null if not IPv4.
   */
  fun parseIpv4(host: String): ByteArray? {
    val parts = host.split('.')
    if (parts.isEmpty() || parts.size > 4 || parts.any { it.isEmpty() }) return null
    val nums = parts.map { p ->
      val (digits, radix) = when {
        p.startsWith("0x") || p.startsWith("0X") -> p.substring(2) to 16
        p.length > 1 && p.startsWith("0") -> p.substring(1) to 8
        else -> p to 10
      }
      if (digits.isEmpty()) {
        if (radix == 16) 0L else return null
      } else {
        if (digits.length > 12) return null
        digits.toLongOrNull(radix) ?: return null
      }
    }
    val last = nums.last()
    val head = nums.dropLast(1)
    if (head.any { it > 255 }) return null
    val lastBytes = 4 - head.size
    if (last >= (1L shl (8 * lastBytes))) return null
    var v = 0L
    head.forEach { v = (v shl 8) or it }
    v = (v shl (8 * lastBytes)) or last
    return byteArrayOf((v shr 24).toByte(), (v shr 16).toByte(), (v shr 8).toByte(), v.toByte())
  }

  /** True for non-public addresses: loopback, link-local, private, CGNAT, ULA, multicast, reserved. */
  fun isBlockedAddress(b: ByteArray): Boolean = when (b.size) {
    4 -> isBlockedV4(b)
    16 -> isBlockedV6(b)
    else -> true
  }

  private fun u(b: Byte) = b.toInt() and 0xFF

  private fun isBlockedV4(b: ByteArray): Boolean {
    val a0 = u(b[0]); val a1 = u(b[1]); val a2 = u(b[2])
    return a0 == 0 || // "this network"
      a0 == 10 || // RFC 1918
      a0 == 127 || // loopback
      (a0 == 100 && a1 in 64..127) || // CGNAT
      (a0 == 169 && a1 == 254) || // link-local
      (a0 == 172 && a1 in 16..31) || // RFC 1918
      (a0 == 192 && a1 == 0 && a2 == 0) || // IETF protocol assignments
      (a0 == 192 && a1 == 168) || // RFC 1918
      (a0 == 198 && a1 in 18..19) || // benchmarking
      a0 >= 224 // multicast, reserved, broadcast
  }

  private fun isBlockedV6(b: ByteArray): Boolean {
    val first10 = (0 until 10).all { b[it].toInt() == 0 }
    // IPv4-mapped (::ffff:a.b.c.d) and IPv4-compatible (::a.b.c.d) forms.
    if (first10 && u(b[10]) == 0xFF && u(b[11]) == 0xFF) return isBlockedV4(b.copyOfRange(12, 16))
    if (first10 && b[10].toInt() == 0 && b[11].toInt() == 0) return true // ::, ::1, deprecated ::a.b.c.d
    val a0 = u(b[0]); val a1 = u(b[1])
    if (a0 == 0xFF) return true // multicast
    if (a0 and 0xFE == 0xFC) return true // ULA fc00::/7
    if (a0 == 0xFE && (a1 and 0xC0) == 0x80) return true // link-local fe80::/10
    if (a0 == 0xFE && (a1 and 0xC0) == 0xC0) return true // site-local fec0::/10 (deprecated)
    // NAT64 64:ff9b::/96 and 6to4 2002::/16 embed an IPv4 address.
    if (a0 == 0x00 && a1 == 0x64 && u(b[2]) == 0xFF && u(b[3]) == 0x9B && (4 until 12).all { b[it].toInt() == 0 }) {
      return isBlockedV4(b.copyOfRange(12, 16))
    }
    if (a0 == 0x20 && a1 == 0x02) return isBlockedV4(b.copyOfRange(2, 6))
    if (a0 == 0x20 && a1 == 0x01 && u(b[2]) == 0x0D && u(b[3]) == 0xB8) return true // documentation
    return false
  }

  /** Default resolver: every address of the name via the system resolver (blocking; never on the main thread). */
  val systemResolver: (String) -> List<ByteArray> = { host ->
    InetAddress.getAllByName(host).map { it.address }
  }
}

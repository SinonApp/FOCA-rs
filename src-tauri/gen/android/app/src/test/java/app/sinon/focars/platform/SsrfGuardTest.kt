package app.sinon.focars.platform

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class SsrfGuardTest {
  private fun ip(vararg b: Int) = ByteArray(b.size) { b[it].toByte() }
  private val publicDns: (String) -> List<ByteArray> = { listOf(ip(93, 184, 216, 34)) }

  @Test fun schemesAndHosts() {
    assertEquals("example.com", SsrfGuard.hostOf("https://Example.COM./path"))
    assertEquals("::1", SsrfGuard.hostOf("http://[::1]:8080/"))
    assertEquals(null, SsrfGuard.hostOf("file:///etc/hosts"))
    assertEquals(null, SsrfGuard.hostOf("javascript:alert(1)"))
    assertTrue(SsrfGuard.isBlockedUrl("ftp://example.com/", publicDns))
    assertTrue(SsrfGuard.isBlockedUrl("http://localhost:8080/", publicDns))
    assertTrue(SsrfGuard.isBlockedUrl("http://api.localhost/", publicDns))
  }

  @Test fun ipv4LiteralsInEveryForm() {
    for (u in listOf(
      "http://127.0.0.1/", "http://127.1/", "http://2130706433/", "http://0x7f.0.0.1/", "http://0177.0.0.1/",
      "http://10.1.2.3/", "http://172.16.0.1/", "http://172.31.255.255/", "http://192.168.1.1/",
      "http://169.254.169.254/latest/meta-data/", "http://100.64.0.1/", "http://100.127.255.255/",
      "http://0.0.0.0/", "http://224.0.0.1/", "http://255.255.255.255/", "http://198.18.0.1/",
    )) assertTrue(u, SsrfGuard.isBlockedUrl(u, publicDns))
    for (u in listOf("http://8.8.8.8/", "http://172.32.0.1/", "http://100.128.0.1/", "http://1.1.1.1:443/")) {
      assertFalse(u, SsrfGuard.isBlockedUrl(u, null))
    }
  }

  @Test fun ipv6Literals() {
    for (u in listOf(
      "http://[::1]/", "http://[::]/", "http://[fe80::1]/", "http://[fd00::1]/", "http://[fc12::1]/",
      "http://[ff02::1]/", "http://[::ffff:127.0.0.1]/", "http://[::ffff:10.0.0.1]/", "http://[64:ff9b::a00:1]/",
      "http://[2002:c0a8:101::1]/", "http://[fec0::1]/",
    )) assertTrue(u, SsrfGuard.isBlockedUrl(u, publicDns))
    assertFalse(SsrfGuard.isBlockedUrl("http://[2606:4700:4700::1111]/", null))
    assertFalse(SsrfGuard.isBlockedUrl("http://[::ffff:8.8.8.8]/", null))
  }

  @Test fun hostnamesGoThroughTheResolver() {
    assertFalse(SsrfGuard.isBlockedUrl("https://example.com/", publicDns))
    assertTrue(SsrfGuard.isBlockedUrl("https://intranet.example/", { listOf(ip(192, 168, 0, 10)) }))
    // One private answer among public ones is enough to refuse.
    assertTrue(SsrfGuard.isBlockedUrl("https://mixed.example/", { listOf(ip(8, 8, 8, 8), ip(127, 0, 0, 1)) }))
    assertTrue(SsrfGuard.isBlockedUrl("https://v6.example/", { listOf(ByteArray(15) + byteArrayOf(1)) }))
    assertTrue(SsrfGuard.isBlockedUrl("https://nx.example/", { throw java.net.UnknownHostException(it) }))
    assertTrue(SsrfGuard.isBlockedUrl("https://empty.example/", { emptyList() }))
    // Without a resolver (proxy resolves names) only literals are judged.
    assertFalse(SsrfGuard.isBlockedUrl("https://example.com/", null))
    assertEquals(SsrfGuard.Verdict.NEEDS_DNS, SsrfGuard.literalVerdict("example.com"))
  }
}

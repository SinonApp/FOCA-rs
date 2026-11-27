package app.sinon.focars.platform

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class RenderLogicTest {
  /** Window placement only when the Activity exists, is shown and is not finishing. */
  @Test fun placement() {
    assertEquals(RenderLogic.Placement.WINDOW, RenderLogic.placement(true, true, false))
    assertEquals(RenderLogic.Placement.DETACHED, RenderLogic.placement(true, false, false))
    assertEquals(RenderLogic.Placement.DETACHED, RenderLogic.placement(true, true, true))
    assertEquals(RenderLogic.Placement.DETACHED, RenderLogic.placement(false, true, false))
  }

  /** Search engines always get the mobile UA; a legacy `desktop` from the core is mobile too. */
  @Test fun uaAlwaysMobile() {
    assertEquals(UaForm.MOBILE, RenderLogic.uaMode("desktop"))
    assertEquals(UaForm.MOBILE, RenderLogic.uaMode(""))
    assertEquals(UaForm.MOBILE, RenderLogic.uaMode(" mobile "))
    assertEquals("X/1", RenderLogic.uaMode("X/1"))
    val real = "Mozilla/5.0 (Linux; Android 14; 23078PND5G Build/UP1A; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/141.0.7390.122 Mobile Safari/537.36"
    val ua = UaForm.forRender(RenderLogic.uaMode("desktop"), real)
    assertTrue(ua.contains("Android 14") && ua.contains("Mobile") && !ua.contains("; wv"))
  }

  /** Detached size is the phone screen (portrait), not a 1280×2400 desktop. */
  @Test fun detachedSizeIsPhoneScreen() {
    assertEquals(1080 to 2400, RenderLogic.detachedSize(1080, 2400))
    assertEquals(1080 to 2400, RenderLogic.detachedSize(2400, 1080))
    assertEquals(1080 to 2400, RenderLogic.detachedSize(0, 0))
  }

  @Test fun fingerprintIssues() {
    val ok = RenderLogic.fingerprintIssues("Mozilla/5.0 (Linux; Android 14; X) Chrome/141 Mobile Safari/537.36", "visible", false, 5, 412, true)
    assertTrue(ok.toString(), ok.isEmpty())
    val bad = RenderLogic.fingerprintIssues("Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/141 Safari/537.36", "hidden", false, 5, 1280, true)
    assertEquals(3, bad.size)
    val wv = RenderLogic.fingerprintIssues("Mozilla/5.0 (Linux; Android 14; X; wv) Chrome/141 Mobile Safari/537.36", "visible", true, 0, 412, null)
    assertEquals(3, wv.size)
  }

  @Test fun proxyBypassIncludesLoopback() {
    assertTrue(RenderLogic.PROXY_BYPASS.containsAll(listOf("localhost", "127.0.0.1", "*.localhost", "::1")))
  }

  /** Probe answers pass through unless they are a script error or too large. */
  @Test fun evalAnswerIsCapped() {
    assertEquals("{\"j\":{}}", RenderLogic.capEval("{\"j\":{}}"))
    assertEquals(null, RenderLogic.capEval(null))
    assertEquals(null, RenderLogic.capEval("jserr:ReferenceError"))
    assertEquals(null, RenderLogic.capEval("x".repeat(RenderLogic.MAX_EVAL + 1)))
    assertEquals(3_000L, RenderLogic.evalTimeout(3_000L, 60_000L))
    assertEquals(10_000L, RenderLogic.evalTimeout(99_000L, 60_000L))
    assertEquals(800L, RenderLogic.evalTimeout(3_000L, 800L))
    assertEquals(500L, RenderLogic.evalTimeout(3_000L, -5L))
  }

  /** Request hosts are normalised, deduplicated and capped. */
  @Test fun requestHostsAreCapped() {
    val set = LinkedHashSet<String>()
    assertTrue(RenderLogic.addHost(set, "CDN.Example."))
    assertEquals(false, RenderLogic.addHost(set, "cdn.example"))
    assertEquals(false, RenderLogic.addHost(set, null))
    assertEquals(false, RenderLogic.addHost(set, " "))
    for (i in 0 until 500) RenderLogic.addHost(set, "h$i.example")
    assertEquals(RenderLogic.MAX_HOSTS, set.size)
    assertTrue(set.contains("cdn.example"))
  }
}

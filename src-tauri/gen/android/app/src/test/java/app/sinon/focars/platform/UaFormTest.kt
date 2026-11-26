package app.sinon.focars.platform

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class UaFormTest {
  private val real = "Mozilla/5.0 (Linux; Android 14; 23078PND5G Build/UP1A.231005.007; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/141.0.7390.122 Mobile Safari/537.36"

  /** WebView markers are removed; version and model stay real. */
  @Test fun mobileKeepsRealVersion() {
    val m = UaForm.forRender(UaForm.MOBILE, real)
    assertEquals("Mozilla/5.0 (Linux; Android 14; 23078PND5G Build/UP1A.231005.007) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.7390.122 Mobile Safari/537.36", m)
    assertFalse(m.contains("; wv"))
    assertFalse(m.contains("Version/4.0"))
    assertEquals(m, UaForm.forRender("", real))
  }

  /** The desktop form keeps the Chrome major version and drops Android/Mobile. */
  @Test fun desktopSameMajor() {
    val d = UaForm.forRender(UaForm.DESKTOP, real)
    assertEquals("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36", d)
    assertEquals(141, UaForm.chromeMajor(d))
    assertFalse(d.contains("Android") || d.contains("Mobile"))
  }

  @Test fun explicitAndBroken() {
    assertEquals("X/1", UaForm.forRender(" X/1 ", real))
    assertNull(UaForm.desktop("Mozilla/5.0 (Linux; Android 14; wv)"))
    // Without a Chrome version, at least `; wv` is removed.
    assertEquals("Mozilla/5.0 (Linux; Android 14)", UaForm.forRender(UaForm.DESKTOP, "Mozilla/5.0 (Linux; Android 14; wv)"))
    assertTrue(UaForm.forRender(UaForm.DESKTOP, "").isEmpty())
  }
}

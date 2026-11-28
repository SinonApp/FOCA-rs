package app.sinon.focars.platform

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File
import java.nio.file.Files

class UpdateLogicTest {
  private val a = byteArrayOf(1, 2, 3)
  private val b = byteArrayOf(4, 5, 6)

  @Test
  fun certificatesMustBeTheSameSet() {
    assertTrue(UpdateLogic.certsMatch(listOf(a), listOf(a.copyOf())))
    assertTrue(UpdateLogic.certsMatch(listOf(a, b), listOf(b, a)))
    assertFalse(UpdateLogic.certsMatch(listOf(a), listOf(b)))
    assertFalse(UpdateLogic.certsMatch(listOf(a), listOf(a, b)))
    assertFalse(UpdateLogic.certsMatch(emptyList(), listOf(a)))
    assertFalse(UpdateLogic.certsMatch(listOf(a), emptyList()))
  }

  @Test
  fun verdictOrder() {
    val p = "app.sinon.focars"
    fun v(enabled: Boolean = true, pkg: String? = p, code: Long = 11, certs: Boolean = true) =
      UpdateLogic.verdict(enabled, p, pkg, 10, code, certs)
    assertEquals(UpdateLogic.Verdict.OK, v())
    assertEquals(UpdateLogic.Verdict.DISABLED, v(enabled = false))
    assertEquals(UpdateLogic.Verdict.UNREADABLE, v(pkg = null))
    assertEquals(UpdateLogic.Verdict.PACKAGE, v(pkg = "com.example.other"))
    assertEquals(UpdateLogic.Verdict.CERT, v(certs = false))
    assertEquals(UpdateLogic.Verdict.NOT_NEWER, v(code = 10))
    assertEquals(UpdateLogic.Verdict.NOT_NEWER, v(code = 9))
    assertEquals("update_cert_mismatch", UpdateLogic.Verdict.CERT.code)
  }

  @Test
  fun onlyApksInsideTheUpdateCache() {
    val cache = Files.createTempDirectory("cache").toFile()
    val dir = File(cache, "update").apply { mkdirs() }
    val apk = File(dir, "FOCA-rs-2.0.0-beta.5-foss-arm64.apk").apply { writeText("x") }
    val other = File(cache, "x.apk").apply { writeText("x") }
    val txt = File(dir, "a.txt").apply { writeText("x") }
    assertTrue(UpdateLogic.pathAllowed(cache, apk.path))
    assertFalse(UpdateLogic.pathAllowed(cache, other.path))
    assertFalse(UpdateLogic.pathAllowed(cache, txt.path))
    assertFalse(UpdateLogic.pathAllowed(cache, File(dir, "../x.apk").path))
    assertFalse(UpdateLogic.pathAllowed(cache, File(dir, "missing.apk").path))
    cache.deleteRecursively()
  }

  @Test
  fun percentIsClamped() {
    assertEquals(0, UpdateLogic.percent(5, 0))
    assertEquals(50, UpdateLogic.percent(50, 100))
    assertEquals(100, UpdateLogic.percent(150, 100))
    assertEquals(0, UpdateLogic.percent(-3, 100))
  }
}

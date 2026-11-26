package app.sinon.focars.platform

import java.io.File
import java.nio.file.Files
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class OcrLogicTest {
  @Test fun clampAndMimeChecks() {
    assertEquals(1, OcrLogic.clampMaxPages(0))
    assertEquals(10, OcrLogic.clampMaxPages(10))
    assertEquals(50, OcrLogic.clampMaxPages(999))
    assertTrue(OcrLogic.isSupportedMime("application/pdf"))
    assertTrue(OcrLogic.isSupportedMime("IMAGE/JPEG"))
    assertFalse(OcrLogic.isSupportedMime("application/zip"))
    assertFalse(OcrLogic.isSupportedMime(null))
  }

  @Test fun scalingAndUtf8Truncation() {
    assertEquals(1, OcrLogic.sampleSize(800, 600, 1600))
    assertEquals(2, OcrLogic.sampleSize(2400, 1800, 1600))
    assertEquals(1600 to 800, OcrLogic.scaledDimensions(3200, 1600, 1600))
    assertEquals("ІП", OcrLogic.truncateUtf8("ІПНїєґ", 5))
  }

  @Test fun safeLocalPathRejectsOutsideRoots() {
    val root = Files.createTempDirectory("foca_ocr_test").toFile()
    try {
      val inside = File(root, "doc.pdf").apply { writeBytes(byteArrayOf(1, 2, 3)) }
      val outside = Files.createTempFile("foca_outside", ".pdf").toFile()
      try {
        assertTrue(OcrLogic.isSafeLocalPath(inside, listOf(root)))
        assertFalse(OcrLogic.isSafeLocalPath(outside, listOf(root)))
      } finally {
        outside.delete()
      }
    } finally {
      root.deleteRecursively()
    }
  }
}

package app.sinon.focars.platform

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class ShareLogicTest {
  @Test fun documentsAreAcceptedByExtensionOrMime() {
    assertTrue(ShareLogic.accepted("Договір.pdf", null))
    assertTrue(ShareLogic.accepted("report.DOCX", "application/octet-stream"))
    assertTrue(ShareLogic.accepted("scan", "image/jpeg"))
    assertTrue(ShareLogic.accepted("x", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"))
    assertTrue(ShareLogic.accepted("x", "application/vnd.oasis.opendocument.text; charset=binary"))
    assertTrue(ShareLogic.accepted("letter", "message/rfc822"))
  }

  @Test fun otherFilesAreRefused() {
    assertFalse(ShareLogic.accepted("app.apk", "application/vnd.android.package-archive"))
    assertFalse(ShareLogic.accepted("notes.txt", "text/plain"))
    assertFalse(ShareLogic.accepted("blob", "application/octet-stream"))
    assertFalse(ShareLogic.accepted("blob", null))
    assertFalse(ShareLogic.accepted("lib.so", "application/x-sharedlib"))
  }

  @Test fun namesAreFlatAndGetAnExtension() {
    assertEquals("Отчёт.pdf", ShareLogic.nameFor("/storage/emulated/0/Download/Отчёт.pdf", "application/pdf", 0))
    assertEquals("ab.docx", ShareLogic.nameFor("..\\..\\a:b.docx", null, 0))
    assertEquals("file_42.pdf", ShareLogic.nameFor("file_42", "application/pdf", 0))
    assertEquals("shared_3.jpg", ShareLogic.nameFor(null, "image/jpeg", 2))
    assertEquals("shared_1", ShareLogic.nameFor("", "application/x-unknown", 0))
    assertTrue(ShareLogic.nameFor("x".repeat(300) + ".pdf", "application/pdf", 0).length <= 120)
    assertFalse(ShareLogic.nameFor("../../etc/passwd", null, 0).contains("/"))
    assertFalse(ShareLogic.nameFor(".hidden.pdf", null, 0).startsWith("."))
  }

  @Test fun batchLimits() {
    val b = PickLogic.Budget(ShareLogic.MAX_FILES, ShareLogic.MAX_TOTAL)
    repeat(ShareLogic.MAX_FILES) {
      assertNull(b.admit(1024))
      b.add(1024)
    }
    assertNotNull("21st file is refused", b.admit(1024))
    val big = PickLogic.Budget(ShareLogic.MAX_FILES, ShareLogic.MAX_TOTAL)
    assertEquals("file_too_large", big.admit(PickLogic.MAX_FILE + 1))
    big.add(PickLogic.MAX_FILE)
    big.add(PickLogic.MAX_FILE)
    assertEquals("total_too_large", big.admit(PickLogic.MAX_FILE))
    assertEquals(2, big.skipped)
  }

  @Test fun staleBatches() {
    val now = 1_800_000_000_000L
    assertFalse(ShareLogic.stale("in-${now - 1000}", now))
    assertTrue(ShareLogic.stale("in-${now - ShareLogic.KEEP_MS - 1}", now))
    assertTrue(ShareLogic.stale("in-${now + 3_600_000}", now))
    assertTrue(ShareLogic.stale("junk", now))
  }
}

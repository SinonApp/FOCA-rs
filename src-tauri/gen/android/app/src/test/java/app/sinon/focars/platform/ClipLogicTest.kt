package app.sinon.focars.platform

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class ClipLogicTest {
  @Test fun nativeClearNeedsApi28() {
    assertFalse(ClipLogic.canClearNatively(27))
    assertTrue(ClipLogic.canClearNatively(28))
    assertTrue(ClipLogic.canClearNatively(37))
  }

  @Test fun capText() {
    assertEquals("", ClipLogic.capText(null))
    assertEquals("key", ClipLogic.capText("key"))
    val big = "x".repeat(ClipLogic.MAX_READ_CHARS + 10)
    assertEquals(ClipLogic.MAX_READ_CHARS, ClipLogic.capText(big).length)
  }

  @Test fun digestIsStableAndDistinct() {
    assertEquals(64, ClipLogic.digest("s3cr3t").length)
    assertEquals(ClipLogic.digest("s3cr3t"), ClipLogic.digest("s3cr3t"))
    assertNotEquals(ClipLogic.digest("s3cr3t"), ClipLogic.digest("s3cr3t "))
  }

  @Test fun explicitClearAlwaysWipes() {
    assertTrue(ClipLogic.shouldClear(null, readable = true, currentDigest = ClipLogic.digest("x"), lastWrittenDigest = null, changedSinceWrite = true))
    assertTrue(ClipLogic.shouldClear(null, readable = false, currentDigest = null, lastWrittenDigest = null, changedSinceWrite = true))
  }

  @Test fun readableClipboardIsComparedWithExpected() {
    val d = ClipLogic.digest("key")
    assertTrue(ClipLogic.shouldClear(d, readable = true, currentDigest = d, lastWrittenDigest = d, changedSinceWrite = false))
    // The user copied something else after the secret: keep it.
    assertFalse(ClipLogic.shouldClear(d, readable = true, currentDigest = ClipLogic.digest("other"), lastWrittenDigest = d, changedSinceWrite = true))
    // Nothing on the clipboard any more: nothing to wipe.
    assertFalse(ClipLogic.shouldClear(d, readable = true, currentDigest = null, lastWrittenDigest = d, changedSinceWrite = false))
  }

  @Test fun unreadableClipboardTrustsOwnLastWrite() {
    val d = ClipLogic.digest("key")
    assertTrue(ClipLogic.shouldClear(d, readable = false, currentDigest = null, lastWrittenDigest = d, changedSinceWrite = false))
    assertFalse(ClipLogic.shouldClear(d, readable = false, currentDigest = null, lastWrittenDigest = d, changedSinceWrite = true))
    assertFalse(ClipLogic.shouldClear(d, readable = false, currentDigest = null, lastWrittenDigest = null, changedSinceWrite = false))
    assertFalse(ClipLogic.shouldClear(d, readable = false, currentDigest = null, lastWrittenDigest = ClipLogic.digest("newer"), changedSinceWrite = false))
  }
}

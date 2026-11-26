package app.sinon.focars.platform

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File
import java.nio.file.Files

class RecoveryLogicTest {
  /** A service restarted without the core drops "scanning" and records the reason; a swipe records a reason only during a scan. */
  @Test fun restartWithoutCoreAndTaskRemoved() {
    val d = RecoveryLogic.onStart(null, wanted = false, scanMarked = true)
    assertTrue(RecoveryLogic.restartedWithoutCore(d))
    assertFalse(RecoveryLogic.restartedWithoutCore(RecoveryLogic.onStart(null, wanted = true, scanMarked = true)))
    assertFalse(RecoveryLogic.restartedWithoutCore(RecoveryLogic.onStart(null, wanted = false, scanMarked = false)))
    assertEquals(RecoveryLogic.REASON_TASK_REMOVED, RecoveryLogic.taskRemovedReason(wanted = true))
    assertEquals(null, RecoveryLogic.taskRemovedReason(wanted = false))
    assertEquals(app.sinon.focars.R.string.scan_tip_recents_lock, RecoveryLogic.interruptedTip("xiaomi"))
    assertEquals(app.sinon.focars.R.string.scan_tip_battery_unrestricted, RecoveryLogic.interruptedTip("pixel"))
  }

  @Test fun resumeWorkerDecisions() {
    assertEquals(RecoveryLogic.Resume.CONTINUES, RecoveryLogic.resume(coreAlive = true, scanRunning = true, scanMarked = true))
    assertEquals(RecoveryLogic.Resume.HANDLED, RecoveryLogic.resume(coreAlive = true, scanRunning = false, scanMarked = true))
    // New process started by WorkManager after the OEM killed the app during a scan.
    assertEquals(RecoveryLogic.Resume.NOTIFY, RecoveryLogic.resume(coreAlive = false, scanRunning = false, scanMarked = true))
    assertEquals(RecoveryLogic.Resume.NOTHING, RecoveryLogic.resume(coreAlive = false, scanRunning = false, scanMarked = false))
    assertTrue(RecoveryLogic.expedite(31, 0))
    assertFalse(RecoveryLogic.expedite(30, 0))
    assertFalse(RecoveryLogic.expedite(34, RecoveryLogic.RESUME_DELAY_SEC))
  }

  /** The worker resumes the scan in a headless core under the service, or falls back to the notification. */
  @Test fun headlessResumeDecisions() {
    assertEquals(RecoveryLogic.Headless.RUNNING, RecoveryLogic.headless("resumed", coreAlive = false))
    assertTrue(RecoveryLogic.headlessRunning("resumed"))
    assertFalse(RecoveryLogic.headlessRunning("busy"))
    // The run file was already consumed: nothing to tell the user.
    assertEquals(RecoveryLogic.Headless.STOP_QUIET, RecoveryLogic.headless("none", coreAlive = false))
    // The app was opened meanwhile and its core owns the data: the UI handles the scan.
    assertEquals(RecoveryLogic.Headless.LEAVE, RecoveryLogic.headless("busy", coreAlive = true))
    // Busy with no UI core (background monitoring holds the data), setting off, crash loop, errors.
    for (s in listOf("busy", "disabled", "too_many", "error", "")) {
      assertEquals(s, RecoveryLogic.Headless.NOTIFY, RecoveryLogic.headless(s, coreAlive = false))
    }
    assertEquals(RecoveryLogic.Headless.NOTIFY, RecoveryLogic.headless("disabled", coreAlive = true))
  }

  @Test fun serviceStartDecisions() {
    // Normal start from the app while a scan runs.
    assertEquals(ServiceStart.FOREGROUND, RecoveryLogic.onStart(ScanService.ACTION_START, wanted = true, scanMarked = true))
    // The scan finished before the system called onStartCommand.
    assertEquals(ServiceStart.FOREGROUND_THEN_STOP, RecoveryLogic.onStart(ScanService.ACTION_START, wanted = false, scanMarked = false))
    // System restart (START_STICKY) after the process was killed during a scan.
    assertEquals(ServiceStart.RESTARTED_NOTIFY, RecoveryLogic.onStart(null, wanted = false, scanMarked = true))
    assertEquals(ServiceStart.RESTARTED_QUIET, RecoveryLogic.onStart(null, wanted = false, scanMarked = false))
    assertEquals(ServiceStart.FOREGROUND, RecoveryLogic.onStart(null, wanted = true, scanMarked = true))
    assertEquals(ServiceStart.STOP_SCAN, RecoveryLogic.onStart(ScanService.ACTION_STOP_SCAN, wanted = true, scanMarked = true))
    assertEquals(ServiceStart.STOP_SERVICE, RecoveryLogic.onStart(ScanService.ACTION_STOP_SERVICE, wanted = true, scanMarked = true))
    assertTrue(RecoveryLogic.sticky(true))
    assertFalse(RecoveryLogic.sticky(false))
  }

  @Test fun exitReasons() {
    // ApplicationExitInfo constant values (API 30+).
    assertTrue(RecoveryLogic.exitReason(1).startsWith("EXIT_SELF"))
    assertTrue(RecoveryLogic.exitReason(5).startsWith("CRASH_NATIVE"))
    assertTrue(RecoveryLogic.exitReason(13).startsWith("OTHER"))
    assertEquals("UNKNOWN(999)", RecoveryLogic.exitReason(999))
    assertTrue(RecoveryLogic.killedBySystem(3))   // LOW_MEMORY
    assertTrue(RecoveryLogic.killedBySystem(13))  // OTHER: MIUI/HyperOS
    assertFalse(RecoveryLogic.killedBySystem(4)) // CRASH is a crash
    assertFalse(RecoveryLogic.killedBySystem(1)) // EXIT_SELF is a normal exit
    assertEquals(listOf(20L, 30L), RecoveryLogic.unseen(listOf(30L, 10L, 20L), 15L))
  }
}

class LogRotationTest {
  private fun tmp(): File = Files.createTempDirectory("flog").toFile()

  @Test fun rotatesAtLimitAndKeepsThreeFiles() {
    val dir = tmp()
    val f = File(dir, "android.log")
    val line = "x".repeat(99) + "\n" // 100 bytes
    repeat(35) { LogRotation.append(f, line, maxBytes = 1000, keep = 3) }
    assertTrue(f.exists())
    assertTrue(File(dir, "android.log.1").exists())
    assertTrue(File(dir, "android.log.2").exists())
    assertFalse(File(dir, "android.log.3").exists())
    assertTrue(f.length() <= 1000)
    assertEquals(1000L, File(dir, "android.log.1").length())
    // 35 lines: 10 + 10 in .2/.1 and 5 in the current file; the oldest 10 were deleted.
    assertEquals(500L, f.length())
    dir.deleteRecursively()
  }

  @Test fun needsRotate() {
    assertFalse(LogRotation.needsRotate(0, 5000, 1000)) // empty file: a long line is still written
    assertFalse(LogRotation.needsRotate(900, 100, 1000))
    assertTrue(LogRotation.needsRotate(901, 100, 1000))
  }

  @Test fun keepOneJustTruncates() {
    val dir = tmp()
    val f = File(dir, "a.log")
    f.writeText("old")
    LogRotation.rotate(f, 1)
    assertFalse(f.exists())
    assertFalse(File(dir, "a.log.1").exists())
    dir.deleteRecursively()
  }
}

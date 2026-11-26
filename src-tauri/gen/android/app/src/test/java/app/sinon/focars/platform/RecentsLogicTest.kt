package app.sinon.focars.platform

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class RecentsLogicTest {
  @Test fun aggressiveOemDetection() {
    assertTrue(RecentsLogic.aggressiveOem("Xiaomi", "Redmi"))
    assertTrue(RecentsLogic.aggressiveOem("Xiaomi", "POCO"))
    assertTrue(RecentsLogic.aggressiveOem("samsung", "samsung"))
    assertTrue(RecentsLogic.aggressiveOem("HUAWEI", "HUAWEI"))
    assertTrue(RecentsLogic.aggressiveOem("HONOR", "HONOR"))
    assertTrue(RecentsLogic.aggressiveOem("OPPO", "OPPO"))
    assertTrue(RecentsLogic.aggressiveOem("realme", "realme"))
    assertTrue(RecentsLogic.aggressiveOem("OnePlus", "OnePlus"))
    assertTrue(RecentsLogic.aggressiveOem("vivo", "iQOO"))
    assertFalse(RecentsLogic.aggressiveOem("Google", "google"))
    assertFalse(RecentsLogic.aggressiveOem("motorola", "motorola"))
    assertFalse(RecentsLogic.aggressiveOem(null, null))
    // A rebranded MIUI/HyperOS build is recognised by its system properties.
    assertTrue(RecentsLogic.aggressiveOem("Unknown", "generic", hyperOs = "OS2.0"))
    assertTrue(RecentsLogic.aggressiveOem("Unknown", "generic", miui = "V14"))
  }

  @Test fun defaultFollowsOemUntilChosen() {
    assertTrue(RecentsLogic.enabled(null, aggressive = true))
    assertFalse(RecentsLogic.enabled(null, aggressive = false))
    assertFalse(RecentsLogic.enabled("off", aggressive = true))
    assertTrue(RecentsLogic.enabled("on", aggressive = false))
    assertTrue(RecentsLogic.enabled("garbage", aggressive = true))
    assertEquals("on", RecentsLogic.prefValue(true))
    assertEquals("off", RecentsLogic.prefValue(false))
  }

  @Test fun showAgainOnColdStartResumeAndScanEnd() {
    for (e in listOf(RecentsEvent.COLD_START, RecentsEvent.RESUME, RecentsEvent.SCAN_END, RecentsEvent.RECOVERY)) {
      // Unconditional, so a stale hidden task can never survive these moments.
      assertEquals(e.name, false, RecentsLogic.decide(e, scanRunning = true, enabled = true, foreground = false))
      assertEquals(e.name, false, RecentsLogic.decide(e, scanRunning = false, enabled = false, foreground = true))
    }
  }

  @Test fun hideWhenGoingToBackgroundDuringScan() {
    for (e in listOf(RecentsEvent.PAUSE, RecentsEvent.STOP)) {
      assertEquals(true, RecentsLogic.decide(e, scanRunning = true, enabled = true, foreground = false))
      assertNull(RecentsLogic.decide(e, scanRunning = false, enabled = true, foreground = false))
      assertNull(RecentsLogic.decide(e, scanRunning = true, enabled = false, foreground = false))
      // Rotation or theme change recreates the Activity but does not leave the app.
      assertNull(RecentsLogic.decide(e, scanRunning = true, enabled = true, foreground = false, changingConfig = true))
    }
  }

  @Test fun scanStartedInBackground() {
    assertEquals(true, RecentsLogic.decide(RecentsEvent.SCAN_START, scanRunning = true, enabled = true, foreground = false))
    assertNull(RecentsLogic.decide(RecentsEvent.SCAN_START, scanRunning = true, enabled = true, foreground = true))
    assertNull(RecentsLogic.decide(RecentsEvent.SCAN_START, scanRunning = true, enabled = false, foreground = false))
  }

  @Test fun oemFamilyForTheHelper() {
    assertEquals("xiaomi", RecentsLogic.family("Xiaomi", "Redmi"))
    assertEquals("xiaomi", RecentsLogic.family("Unknown", "generic", hyperOs = "OS2.0"))
    assertEquals("samsung", RecentsLogic.family("samsung", "samsung"))
    assertEquals("huawei", RecentsLogic.family("HONOR", "HONOR"))
    assertEquals("oppo", RecentsLogic.family("OnePlus", "OnePlus"))
    assertEquals("vivo", RecentsLogic.family("vivo", "vivo"))
    assertEquals("other", RecentsLogic.family("Google", "google"))
  }

  @Test fun autostartModes() {
    assertEquals("on", RecentsLogic.autostart(0))
    assertEquals("off", RecentsLogic.autostart(1))
    assertEquals("off", RecentsLogic.autostart(2))
    assertEquals("unknown", RecentsLogic.autostart(5))
    assertEquals("unknown", RecentsLogic.autostart(null))
    assertEquals(10008, RecentsLogic.OP_MIUI_AUTOSTART)
  }
}

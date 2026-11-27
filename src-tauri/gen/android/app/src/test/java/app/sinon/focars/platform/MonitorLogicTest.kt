package app.sinon.focars.platform

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class MonitorLogicTest {
  @Test
  fun profileNeverActive() {
    assertEquals("passive", MonitorLogic.safeProfile("full"))
    assertEquals("passive", MonitorLogic.safeProfile("custom"))
    assertEquals("passive", MonitorLogic.safeProfile(null))
    assertEquals("std", MonitorLogic.safeProfile("std"))
  }

  @Test
  fun delayAndDays() {
    assertEquals(180, MonitorLogic.minutesOf("03:00"))
    assertEquals(180, MonitorLogic.minutesOf("25:99"))
    // 02:00 → 03:00 is one hour away; 04:00 → 03:00 tomorrow.
    assertEquals(60L, MonitorLogic.initialDelayMinutes(120, "03:00"))
    assertEquals(23L * 60, MonitorLogic.initialDelayMinutes(240, "03:00"))
    assertEquals(24L * 60, MonitorLogic.initialDelayMinutes(180, "03:00"))
    assertTrue(MonitorLogic.dueToday("daily", emptySet(), 3))
    assertTrue(MonitorLogic.dueToday("weekly", setOf(1, 5), 5))
    assertFalse(MonitorLogic.dueToday("weekly", setOf(1, 5), 2))
    assertTrue(MonitorLogic.dueToday("weekly", emptySet(), 1))
    assertFalse(MonitorLogic.dueToday("off", setOf(1), 1))
    assertEquals(7, MonitorLogic.isoWeekday(1))
    assertEquals(1, MonitorLogic.isoWeekday(2))
  }

  @Test
  fun statusNoticeIds() {
    assertEquals(4190, MonitorLogic.statusId("mobile_cap"))
    assertNull(MonitorLogic.statusId("other"))
    assertNull(MonitorLogic.statusId(""))
  }

  @Test
  fun routesSafe() {
    assertEquals("/open/contoso.example", MonitorLogic.openRoute("contoso.example"))
    assertEquals("/open/example.test/scan", MonitorLogic.reminderRoute("example.test"))
    assertNull(MonitorLogic.openRoute("a'b"))
    assertNull(MonitorLogic.openRoute("../x"))
    assertTrue(MonitorLogic.routeAllowed("/p/scan"))
    assertTrue(MonitorLogic.routeAllowed("/open/example.test/scan"))
    assertFalse(MonitorLogic.routeAllowed("/open/x');alert(1)//"))
    assertFalse(MonitorLogic.routeAllowed("/open/../x"))
    assertEquals("monitor:abc", MonitorLogic.workName("abc"))
  }

  @Test
  fun headlessBudgetAndNotifications() {
    assertEquals(30, MonitorLogic.clampBudgetSec(5))
    assertEquals(180, MonitorLogic.clampBudgetSec(180))
    assertEquals(480, MonitorLogic.clampBudgetSec(900))
    assertFalse(MonitorLogic.shouldNotifyHeadless("busy", false))
    assertFalse(MonitorLogic.shouldNotifyHeadless("done", true))
    assertTrue(MonitorLogic.shouldNotifyHeadless("done", false))
    assertTrue(MonitorLogic.shouldNotifyHeadless("budget", false))
    assertTrue(MonitorLogic.shouldNotifyHeadless("error", false))
    assertEquals("/open/contoso", MonitorLogic.headlessRoute("contoso", "done"))
    assertEquals("/open/contoso/scan", MonitorLogic.headlessRoute("contoso", "budget"))
  }
}

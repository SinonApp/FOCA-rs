package app.sinon.focars.platform

import org.junit.Assert.assertEquals
import org.junit.Test

class LockscreenLogicTest {
  private val def = LockscreenLogic.IMPORTANCE_DEFAULT
  private val low = 2
  private val private_ = 0
  private val public_ = 1

  @Test fun defaultChannelWithNotificationsIsOn() {
    assertEquals("on", LockscreenLogic.state(true, def, private_, null, null))
    assertEquals("on", LockscreenLogic.state(true, def, public_, 1, 0))
  }

  @Test fun channelNotCreatedYetCountsAsOn() {
    // The channel is created with default importance on the first scan.
    assertEquals("on", LockscreenLogic.state(true, null, null, null, null))
  }

  @Test fun notificationsOffOrHiddenOnLockScreenIsOff() {
    assertEquals("off", LockscreenLogic.state(false, def, private_, null, null))
    assertEquals("off", LockscreenLogic.state(true, def, private_, 0, null))
    assertEquals("off", LockscreenLogic.state(true, def, LockscreenLogic.VISIBILITY_SECRET, null, null))
  }

  @Test fun silentChannelIsOffUnlessSilentNotificationsAreShown() {
    // The old IMPORTANCE_LOW channel: hidden on the lock screen unless the user shows silent ones.
    assertEquals("off", LockscreenLogic.state(true, low, private_, null, null))
    assertEquals("off", LockscreenLogic.state(true, low, private_, 1, 0))
    assertEquals("on", LockscreenLogic.state(true, low, private_, 1, 1))
  }

  @Test fun unknownNotificationStateIsUnknown() {
    assertEquals("unknown", LockscreenLogic.state(null, def, private_, null, null))
  }

  @Test fun lockscreenStepOpensTheChannelSettingsFirst() {
    val t = SettingsTargets.forWhat("lockscreen", "xiaomi", ignoring = true, sdk = 36, pkg = "app.sinon.focars")
    assertEquals(listOf("lockscreen_channel", "notifications", "app_details"), t.map { it.key })
    assertEquals(LockscreenLogic.CHANNEL, t[0].extras["android.provider.extra.CHANNEL_ID"])
    assertEquals(SettingsTargets.ACTION_CHANNEL_NOTIFICATIONS, t[0].action)
    assertEquals(listOf("app_details"),
      SettingsTargets.forWhat("lockscreen", "pixel", ignoring = true, sdk = 25, pkg = "p").map { it.key })
  }
}

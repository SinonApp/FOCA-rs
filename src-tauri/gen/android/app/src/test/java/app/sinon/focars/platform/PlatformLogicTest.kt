package app.sinon.focars.platform

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class PlatformLogicTest {
  @Test fun hexRoundTrip() {
    val b = ByteArray(256) { it.toByte() }
    assertArrayEquals(b, Codec.unhex(Codec.hex(b)))
    assertNull(Codec.unhex("abc"))
    assertNull(Codec.unhex("zz"))
  }

  @Test fun packUnpack() {
    val iv = ByteArray(12) { 7 }
    val ct = ByteArray(40) { (it * 3).toByte() }
    val (iv2, ct2) = Codec.unpack(Codec.pack(iv, ct))!!
    assertArrayEquals(iv, iv2)
    assertArrayEquals(ct, ct2)
    assertNull(Codec.unpack(null))
    assertNull(Codec.unpack("v0:00:00"))
    assertNull(Codec.unpack("v1:" + Codec.hex(ByteArray(8)) + ":" + Codec.hex(ct))) // IV is not 12 bytes
    assertNull(Codec.unpack("v1:" + Codec.hex(iv) + ":" + Codec.hex(ByteArray(4)))) // shorter than the tag
  }

  @Test fun prefKeySanitized() {
    assertEquals("k_brave", Codec.prefKey("Brave"))
    assertEquals("k_etcpasswd", Codec.prefKey("../etc/passwd"))
  }

  @Test fun oemDetect() {
    assertEquals("xiaomi", Oem.detect("Xiaomi", "Redmi"))
    assertEquals("xiaomi", Oem.detect("unknown", "POCO"))
    assertEquals("samsung", Oem.detect("samsung", "samsung"))
    assertEquals("pixel", Oem.detect("Google", "google"))
    assertEquals("pixel", Oem.detect(null, null))
  }

  @Test fun oemLabel() {
    assertEquals("Xiaomi 23127PN0CG · HyperOS 1.0.5 (Android 14)",
      Oem.label("Xiaomi", "23127PN0CG", Oem.rom("OS1.0.5", null), "14"))
    assertEquals("Google Pixel 8 (Android 15)", Oem.label("Google", "Pixel 8", null, "15"))
    assertEquals("Samsung SM-S918B", Oem.label("samsung", "SM-S918B", null, null))
    assertEquals("MIUI 14", Oem.rom(null, "V14"))
  }

  @Test fun settingsTargets() {
    val pkg = "app.sinon.focars"
    val b = SettingsTargets.forWhat("battery", "pixel", ignoring = false, sdk = 34, pkg = pkg)
    assertEquals(listOf("battery_optimization", "battery_optimization_list", "app_details"), b.map { it.key })
    assertTrue(b[0].withPackageUri)
    // Already exempt: go straight to the exemption list.
    assertEquals("battery_optimization_list",
      SettingsTargets.forWhat("Аккумулятор", "samsung", ignoring = true, sdk = 34, pkg = pkg).first().key)
    val auto = SettingsTargets.forWhat("Приложения", "xiaomi", ignoring = false, sdk = 34, pkg = pkg)
    assertEquals("com.miui.securitycenter", auto.first().pkg)
    assertEquals("app_details", auto.last().key)
    // The "Apps" step on a non-Xiaomi device opens the app details page.
    assertEquals(listOf("app_details"), SettingsTargets.forWhat("Приложения", "pixel", false, 34, pkg).map { it.key })
    assertEquals("notifications", SettingsTargets.forWhat("Уведомления", "pixel", false, 33, pkg).first().key)
    assertEquals("app_details", SettingsTargets.forWhat("Уведомления", "pixel", false, 24, pkg).first().key)
    assertEquals("network", SettingsTargets.forWhat("Сеть → Частный DNS", "pixel", false, 34, pkg).first().key)
    assertEquals(pkg, SettingsTargets.forWhat("Контроль активности", "xiaomi", false, 34, pkg).first().extras["package_name"])
    assertEquals(listOf("app_details"), SettingsTargets.forWhat("что-то", "pixel", false, 34, pkg).map { it.key })
  }

  @Test fun xiaomiBackgroundStepsOpenTheirOwnScreens() {
    val pkg = "app.sinon.focars"
    // Battery saver: MIUI power keeper per-app screen, then the battery exemption, then app details.
    val power = SettingsTargets.forWhat("activity_control", "xiaomi", ignoring = false, sdk = 36, pkg = pkg)
    assertEquals(listOf("miui_power", "battery_optimization", "app_details"), power.map { it.key })
    assertEquals("com.miui.powerkeeper/com.miui.powerkeeper.ui.HiddenAppsConfigActivity", power[0].target)
    assertEquals("FOCA-rs", power[0].extras["package_label"])
    assertTrue(power.none { it.action == SettingsTargets.ACTION_APP_NOTIFICATIONS })
    assertEquals(listOf("miui_power", "app_details"),
      SettingsTargets.forWhat("Контроль активности", "xiaomi", ignoring = true, sdk = 36, pkg = pkg).map { it.key })
    // Background pop-ups: "Other permissions" editor, its action, then app details.
    val perm = SettingsTargets.forWhat("permissions", "xiaomi", ignoring = false, sdk = 36, pkg = pkg)
    assertEquals(listOf("miui_permissions", "miui_permissions", "app_details"), perm.map { it.key })
    assertEquals("com.miui.securitycenter/com.miui.permcenter.permissions.PermissionsEditorActivity", perm[0].target)
    assertEquals(pkg, perm[0].extras["extra_pkgname"])
    assertEquals(pkg, perm[1].extras["extra_pkgname"])
    assertTrue(perm.none { it.action == SettingsTargets.ACTION_APP_NOTIFICATIONS })
    assertEquals("miui_autostart", SettingsTargets.forWhat("autostart", "xiaomi", false, 36, pkg).first().key)
  }

  @Test fun recentsLockHintOnlyForXiaomi() {
    assertTrue(Oem.needsRecentsLock("xiaomi"))
    assertFalse(Oem.needsRecentsLock("samsung"))
    assertFalse(Oem.needsRecentsLock("pixel"))
  }

  @Test fun appLocaleAcceptsOnlyUiLanguages() {
    assertEquals("uk", AppLocale.normalize("uk"))
    assertEquals("en", AppLocale.normalize("en-US"))
    assertEquals("ru", AppLocale.normalize(" RU_ru "))
    assertEquals(null, AppLocale.normalize("auto"))
    assertEquals(null, AppLocale.normalize("de"))
    assertEquals(null, AppLocale.normalize(null))
  }

  @Test fun printJobNameAndHtmlOnly() {
    assertEquals("Звіт_пентест_r2_v8", PrintLogic.jobName("Звіт_пентест_r2_v8.html"))
    assertEquals("Report_x_v1", PrintLogic.jobName("/data/reports/p/Report_x_v1.HTM"))
    assertEquals("ab", PrintLogic.jobName("a<b>.html"))
    assertEquals("FOCA-rs report", PrintLogic.jobName(".html"))
    assertTrue(PrintLogic.isHtml("r.html"))
    assertTrue(!PrintLogic.isHtml("r.md"))
  }

  @Test fun pickNamesAreFlatAndUnique() {
    assertEquals("passwd", PickLogic.safeName("../../etc/passwd"))
    assertEquals("b.docx", PickLogic.safeName("a\\b.docx"))
    assertEquals("file", PickLogic.safeName("..."))
    assertEquals("img.pdf", PickLogic.safeName("<img>.pdf"))
    assertEquals("a_2.pdf", PickLogic.uniqueName(setOf("a.pdf"), "a.pdf"))
    assertEquals("a_3.pdf", PickLogic.uniqueName(setOf("a.pdf", "a_2.pdf"), "a.pdf"))
    assertEquals("x", PickLogic.uniqueName(emptySet(), "x"))
  }

  @Test fun pickBudget() {
    val b = PickLogic.Budget(maxFiles = 2, maxBytes = 100)
    assertNull(b.admit(60)); b.add(60)
    assertEquals("total_too_large", b.admit(50))
    assertNull(b.admit(40)); b.add(40)
    assertEquals("too_many_files", b.admit(1))
    assertEquals("file_too_large", PickLogic.Budget().admit(PickLogic.MAX_FILE + 1))
    assertEquals(2, b.skipped)
  }

  @Test fun copyCappedStopsOverLimit() {
    val src = ByteArray(1000) { 1 }
    val out = java.io.ByteArrayOutputStream()
    assertEquals(1000L, PickLogic.copyCapped(src.inputStream(), out, 1000))
    assertEquals(-1L, PickLogic.copyCapped(src.inputStream(), java.io.ByteArrayOutputStream(), 999))
  }

  @Test fun webUrlWhitelist() {
    assertTrue(LinkLogic.isWebUrl("https://example.org/key?x=1"))
    assertTrue(LinkLogic.isWebUrl("HTTP://example.org"))
    for (bad in listOf(null, "", "javascript:alert(1)", "file:///etc/hosts", "intent://x#Intent;end",
        "content://a/b", "https://", "https://user:pw@example.org/", "https://exa mple.org", "mailto:a@b.c")) {
      assertTrue("accepted $bad", !LinkLogic.isWebUrl(bad))
    }
  }
}

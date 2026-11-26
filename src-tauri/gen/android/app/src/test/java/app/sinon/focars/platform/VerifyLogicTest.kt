package app.sinon.focars.platform

import app.sinon.focars.platform.VerifyLogic.Exit
import app.sinon.focars.platform.VerifyLogic.Outcome
import app.sinon.focars.platform.VerifyLogic.PageCheck
import app.sinon.focars.platform.VerifyLogic.Phase
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class VerifyLogicTest {
  @Test fun wireNames() {
    assertEquals(listOf("done", "cancelled", "failed", "not_solved"), Outcome.values().map { it.wire })
  }

  @Test fun everyNonDoneExitIsCancelled() {
    for (e in Exit.values()) {
      assertEquals(e.name, Outcome.CANCELLED, VerifyLogic.exitOutcome(e, Phase.READY))
      assertEquals(e.name, Outcome.CANCELLED, VerifyLogic.exitOutcome(e, Phase.LOADING))
    }
  }

  @Test fun leavingTheErrorStateIsFailedButLifecycleStaysCancelled() {
    assertEquals(Outcome.FAILED, VerifyLogic.exitOutcome(Exit.CANCEL_BUTTON, Phase.ERROR))
    assertEquals(Outcome.FAILED, VerifyLogic.exitOutcome(Exit.BACK, Phase.ERROR))
    assertEquals(Outcome.FAILED, VerifyLogic.exitOutcome(Exit.DISMISS, Phase.ERROR))
    assertEquals(Outcome.CANCELLED, VerifyLogic.exitOutcome(Exit.ACTIVITY_DESTROYED, Phase.ERROR))
    assertEquals(Outcome.CANCELLED, VerifyLogic.exitOutcome(Exit.ACTIVITY_STOPPED, Phase.ERROR))
    assertEquals(Outcome.CANCELLED, VerifyLogic.exitOutcome(Exit.ACTIVITY_PAUSED, Phase.ERROR))
  }

  @Test fun lifecycleClosesOnStopDestroyAndFinishingPause() {
    assertTrue(VerifyLogic.lifecycleCloses(Exit.ACTIVITY_DESTROYED, finishing = false))
    assertTrue(VerifyLogic.lifecycleCloses(Exit.ACTIVITY_STOPPED, finishing = false))
    assertTrue(VerifyLogic.lifecycleCloses(Exit.ACTIVITY_PAUSED, finishing = true))
    assertFalse(VerifyLogic.lifecycleCloses(Exit.ACTIVITY_PAUSED, finishing = false))
    assertFalse(VerifyLogic.lifecycleCloses(Exit.BACK, finishing = true))
  }

  @Test fun doneNeedsASolvedPage() {
    assertEquals(Outcome.DONE, VerifyLogic.doneOutcome(Phase.READY, PageCheck(null, empty = false)))
    assertEquals(Outcome.DONE, VerifyLogic.doneOutcome(Phase.LOADING, PageCheck(null, empty = false)))
    assertEquals(Outcome.NOT_SOLVED, VerifyLogic.doneOutcome(Phase.READY, PageCheck("altcha", empty = false)))
    assertEquals(Outcome.NOT_SOLVED, VerifyLogic.doneOutcome(Phase.READY, PageCheck(null, empty = true)))
    // The check script did not answer (stuck page): never success.
    assertEquals(Outcome.NOT_SOLVED, VerifyLogic.doneOutcome(Phase.READY, null))
    assertEquals(Outcome.FAILED, VerifyLogic.doneOutcome(Phase.ERROR, PageCheck(null, empty = false)))
  }

  @Test fun challengeDetection() {
    // Startpage Anubis proof of work page.
    assertNotNull(VerifyLogic.challengeShown("Verifying your request…", "https://www.startpage.com/", "<div id=\"anubis_challenge\"></div>"))
    assertEquals("anubis_challenge", VerifyLogic.challengeShown("", "https://www.startpage.com/", "<script id=\"anubis_challenge\" type=\"application/json\">"))
    // Mojeek ALTCHA and the Yahoo consent wall.
    assertEquals("altcha", VerifyLogic.challengeShown("Please complete ALTCHA", "https://www.mojeek.com/search?q=foca", ""))
    assertEquals("consent.yahoo.com", VerifyLogic.challengeShown("Before you continue", "https://consent.yahoo.com/v2/collectConsent", "<html>"))
    // Turnstile widget.
    assertEquals("challenges.cloudflare.com/turnstile", VerifyLogic.challengeShown("", "https://search.brave.com/", "<script src=\"https://challenges.cloudflare.com/turnstile/v0/api.js\">"))
    // Regular result and home pages pass, even with the word captcha somewhere in the markup.
    assertNull(VerifyLogic.challengeShown("Startpage Search", "https://www.startpage.com/", "<html><body><form id=\"search\"></form><script>var t='Switch to traditional CAPTCHA'</script></body></html>"))
    assertNull(VerifyLogic.challengeShown("foca results", "https://www.mojeek.com/search?q=foca", "<ul class=\"results-standard\">"))
  }

  @Test fun coreMarkersAreUsedAndDefaultsKept() {
    assertEquals(VerifyLogic.DEFAULT_MARKERS, VerifyLogic.markers(null))
    assertEquals(VerifyLogic.DEFAULT_MARKERS, VerifyLogic.markers(listOf(" ", "")))
    val m = VerifyLogic.markers(listOf("Special Wall"))
    assertEquals("special wall", m.first())
    assertTrue(m.containsAll(VerifyLogic.DEFAULT_MARKERS))
    assertEquals("special wall", VerifyLogic.challengeShown("A SPECIAL WALL here", "https://search.brave.com/", "", m))
  }

  @Test fun blankPageIsEmpty() {
    assertTrue(VerifyLogic.pageEmpty("about:blank", "<html></html>"))
    assertTrue(VerifyLogic.pageEmpty("", "<html></html>"))
    assertTrue(VerifyLogic.pageEmpty("https://www.startpage.com/", " "))
    assertFalse(VerifyLogic.pageEmpty("https://www.startpage.com/", "<html></html>"))
  }

  @Test fun loadTimeout() {
    assertFalse(VerifyLogic.timedOut(Phase.LOADING, 1_000, 1_000 + VerifyLogic.LOAD_TIMEOUT_MS - 1))
    assertTrue(VerifyLogic.timedOut(Phase.LOADING, 1_000, 1_000 + VerifyLogic.LOAD_TIMEOUT_MS))
    assertFalse(VerifyLogic.timedOut(Phase.READY, 1_000, 1_000 + 10 * VerifyLogic.LOAD_TIMEOUT_MS))
    assertFalse(VerifyLogic.timedOut(Phase.ERROR, 1_000, 1_000 + 10 * VerifyLogic.LOAD_TIMEOUT_MS))
    assertFalse(VerifyLogic.timedOut(Phase.LOADING, 0, 10 * VerifyLogic.LOAD_TIMEOUT_MS))
    assertEquals(30_000L, VerifyLogic.LOAD_TIMEOUT_MS)
  }

  @Test fun cookiesFlushOnlyOnDone() {
    assertTrue(VerifyLogic.flushCookies(Outcome.DONE))
    assertFalse(VerifyLogic.flushCookies(Outcome.CANCELLED))
    assertFalse(VerifyLogic.flushCookies(Outcome.FAILED))
    assertFalse(VerifyLogic.flushCookies(Outcome.NOT_SOLVED))
  }

  @Test fun settlesExactlyOnce() {
    val once = VerifyLogic.Once()
    // Done, then the dismiss it triggers, then the Activity being destroyed.
    assertTrue(once.settle(Outcome.DONE))
    assertFalse(once.settle(VerifyLogic.exitOutcome(Exit.DISMISS, Phase.READY)))
    assertFalse(once.settle(VerifyLogic.exitOutcome(Exit.ACTIVITY_DESTROYED, Phase.READY)))
    assertEquals(Outcome.DONE, once.outcome)
    // Swipe from Recents first: cancelled sticks even if a late check answer arrives.
    val o2 = VerifyLogic.Once()
    assertTrue(o2.settle(VerifyLogic.exitOutcome(Exit.ACTIVITY_DESTROYED, Phase.LOADING)))
    assertFalse(o2.settle(Outcome.DONE))
    assertEquals(Outcome.CANCELLED, o2.outcome)
  }
}

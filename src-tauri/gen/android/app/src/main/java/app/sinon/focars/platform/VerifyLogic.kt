package app.sinon.focars.platform

/**
 * Pure decisions of the manual search engine check ([VerifyDialog]), without Android APIs and
 * covered by JUnit (`VerifyLogicTest`).
 *
 * The dialog ends with exactly one [Outcome]. Only an explicit Done on a page that no longer shows
 * the engine's challenge counts as [Outcome.DONE]; Cancel, Back, any other dismiss and the app
 * leaving the foreground are [Outcome.CANCELLED], so swiping the app away never looks like a solved
 * captcha.
 */
object VerifyLogic {
  /** A page load that has not finished after this long shows the error state with Retry. */
  const val LOAD_TIMEOUT_MS = 30_000L

  /** How long Done waits for the page check script before treating the page as unsolved. */
  const val CHECK_TIMEOUT_MS = 4_000L

  /** Upper bound of the page HTML handed to [challengeShown] (challenge pages are small). */
  const val MAX_HTML_CHARS = 400_000

  /** Result sent to the UI as `state`. */
  enum class Outcome(val wire: String) {
    DONE("done"),
    CANCELLED("cancelled"),
    FAILED("failed"),
    NOT_SOLVED("not_solved"),
  }

  /** What the page is doing right now. */
  enum class Phase { LOADING, READY, ERROR }

  /** How the dialog is being closed (anything except [DONE]). */
  enum class Exit { CANCEL_BUTTON, BACK, DISMISS, ACTIVITY_PAUSED, ACTIVITY_STOPPED, ACTIVITY_DESTROYED }

  /** Why the error state is shown. */
  enum class Failure { LOAD_ERROR, TIMEOUT }

  /**
   * Challenge markers matched against the lowercase visible text plus URL. The core sends its own
   * list (`foca_search` `CAPTCHA_ABORT` plus the challenge phrases); this is the fallback when the
   * argument is missing.
   */
  val DEFAULT_MARKERS = listOf(
    "/captcha",
    "altcha",
    "complete the captcha",
    "solve the captcha",
    "captcha challenge",
    "verify you are human",
    "i'm not a robot",
    "verifying you're not a bot",
    "quick check before you continue",
    "verifying your request",
  )

  /**
   * Structural challenge markers looked up in the lowercase HTML (the same widgets the core's
   * `detect_captcha_signals` treats as a challenge): Anubis (Startpage), Turnstile, reCAPTCHA,
   * hCaptcha, ALTCHA (Mojeek) and the Yahoo consent wall.
   */
  val HTML_MARKERS = listOf(
    "anubis_challenge",
    "challenges.cloudflare.com/turnstile",
    "/cdn-cgi/challenge-platform",
    "class=\"cf-turnstile",
    "class=\"g-recaptcha",
    "class=\"h-captcha",
    "<altcha-widget",
    "g-recaptcha-response",
    "h-captcha-response",
    "cf-turnstile-response",
  )

  /** URL fragments of challenge or consent pages. */
  val URL_MARKERS = listOf("/captcha", "/challenge", "/sorry/", "consent.yahoo.com", "guce.yahoo.com")

  /**
   * Returns the first challenge marker found on the page, or null when the page looks like the
   * engine accepts us. [text] is the visible text, [url] the current address, [html] the markup.
   */
  fun challengeShown(text: String, url: String, html: String, markers: List<String> = DEFAULT_MARKERS): String? {
    val u = url.lowercase()
    val tl = text.lowercase() + " " + u
    markers.map { it.trim().lowercase() }.filter { it.isNotEmpty() }.firstOrNull { tl.contains(it) }?.let { return it }
    URL_MARKERS.firstOrNull { u.contains(it) }?.let { return it }
    val h = (if (html.length > MAX_HTML_CHARS) html.substring(0, MAX_HTML_CHARS) else html).lowercase()
    return HTML_MARKERS.firstOrNull { h.contains(it) }
  }

  /** A page that is still blank (nothing loaded yet) cannot prove the check passed. */
  fun pageEmpty(url: String, html: String): Boolean {
    val u = url.trim().lowercase()
    return u.isEmpty() || u == "about:blank" || html.isBlank()
  }

  /**
   * Outcome of the Done button. [check] is the page check result (null when the script did not
   * answer in time): `challenge` is the matched marker, `empty` a blank page.
   */
  fun doneOutcome(phase: Phase, check: PageCheck?): Outcome = when {
    phase == Phase.ERROR -> Outcome.FAILED
    check == null -> Outcome.NOT_SOLVED
    check.empty || check.challenge != null -> Outcome.NOT_SOLVED
    else -> Outcome.DONE
  }

  /** Page check result for [doneOutcome]. */
  data class PageCheck(val challenge: String?, val empty: Boolean)

  /**
   * Outcome of every other way out. The user leaving while the error state is shown reports
   * [Outcome.FAILED] (the UI then says the page did not load); the app leaving the foreground is
   * always [Outcome.CANCELLED].
   */
  fun exitOutcome(exit: Exit, phase: Phase): Outcome = when (exit) {
    Exit.ACTIVITY_PAUSED, Exit.ACTIVITY_STOPPED, Exit.ACTIVITY_DESTROYED -> Outcome.CANCELLED
    Exit.CANCEL_BUTTON, Exit.BACK, Exit.DISMISS -> if (phase == Phase.ERROR) Outcome.FAILED else Outcome.CANCELLED
  }

  /**
   * Whether an Activity lifecycle event closes the dialog. Stop and destroy always do (the app left
   * the foreground or was swiped away from Recents). A plain pause does not (split screen focus or a
   * system sheet over the app pause it while the user still sees the page), unless the Activity is
   * finishing.
   */
  fun lifecycleCloses(exit: Exit, finishing: Boolean): Boolean = when (exit) {
    Exit.ACTIVITY_STOPPED, Exit.ACTIVITY_DESTROYED -> true
    Exit.ACTIVITY_PAUSED -> finishing
    else -> false
  }

  /** Whether the load that started at [startedAt] ran out of time at [now]. */
  fun timedOut(phase: Phase, startedAt: Long, now: Long, limit: Long = LOAD_TIMEOUT_MS): Boolean =
    phase == Phase.LOADING && startedAt > 0 && now - startedAt >= limit

  /** Cookies are flushed for the hidden browser only after a solved check. */
  fun flushCookies(o: Outcome): Boolean = o == Outcome.DONE

  /** Parses the core's marker list (JSON array of strings); empty or broken input gives the defaults. */
  fun markers(raw: List<String>?): List<String> {
    val l = raw?.map { it.trim().lowercase() }?.filter { it.isNotEmpty() }.orEmpty()
    return if (l.isEmpty()) DEFAULT_MARKERS else (l + DEFAULT_MARKERS).distinct()
  }

  /** Settles a result exactly once; later calls are ignored. Main thread only. */
  class Once {
    var outcome: Outcome? = null
      private set

    /** Returns true for the first call only. */
    fun settle(o: Outcome): Boolean {
      if (outcome != null) return false
      outcome = o
      return true
    }
  }
}

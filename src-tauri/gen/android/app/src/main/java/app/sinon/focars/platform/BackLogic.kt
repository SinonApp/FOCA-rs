package app.sinon.focars.platform

/**
 * Maps Android Back to JS `FOCA.back()` and decides from the `evaluateJavascript` result. The
 * app is moved to the background ONLY if the UI explicitly says there is nowhere to go
 * (`"root"`); an error, missing JS, a timeout or an unknown answer keeps it in place (closing by
 * mistake is worse than not reacting).
 */
object BackLogic {
  enum class Action { HANDLED, MINIMIZE, STAY }

  /** Script result: `"ok"` means the UI handled it (sheet or previous screen), `"root"` means the root screen. */
  const val SCRIPT = "(function(){try{if(!window.FOCA||!FOCA.back)return 'nojs';" +
    "return FOCA.back()===false?'root':'ok'}catch(e){return 'err'}})()"

  /** JS answer timeout in ms; a slower answer never moves the app to the background. */
  const val TIMEOUT_MS = 300L

  /** Decides from `raw`, the evaluateJavascript callback string (JSON, e.g. `"\"ok\""`); `null` means timeout. */
  fun decide(raw: String?): Action = when (raw?.trim()?.removeSurrounding("\"")) {
    "ok" -> Action.HANDLED
    "root" -> Action.MINIMIZE
    else -> Action.STAY
  }
}

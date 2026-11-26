package app.sinon.focars.platform

import android.content.Context
import app.tauri.plugin.JSObject

/**
 * FOSS flavor stub (`distribution = foss`, GPL-3.0 / F-Droid clean build without Google ML Kit).
 * All other document metadata, forensics, and scanning features work identically without ML Kit.
 */
object OcrEngine {
  fun recognize(ctx: Context, a: JSObject): JSObject =
    JSObject()
      .put("ok", false)
      .put("error", "unavailable_in_foss_build")
      .put("flavor", "foss")
}

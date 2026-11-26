package app.sinon.focars.platform

import android.content.Context
import android.content.res.Configuration
import java.util.Locale

/**
 * The UI language chosen in the app, mirrored for native texts (notifications, verify screen).
 * The web UI reports it through the `FocaNative.setLang` bridge; without it Android resources
 * follow the system locale.
 */
object AppLocale {
  private const val PREFS = "foca_ui"
  private const val KEY = "ui_lang"
  private val SUPPORTED = setOf("en", "ru", "uk")

  /** Returns a supported language code (`en`/`ru`/`uk`) or `null` for anything else. */
  fun normalize(lang: String?): String? =
    lang?.trim()?.lowercase()?.substringBefore('-')?.substringBefore('_')?.takeIf { it in SUPPORTED }

  /** Stores the UI language; an unsupported or empty value clears it (system locale applies). */
  fun save(ctx: Context, lang: String?) {
    val p = ctx.applicationContext.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
    val code = normalize(lang)
    if (code == p.getString(KEY, null)) return
    p.edit().apply { if (code == null) remove(KEY) else putString(KEY, code) }.apply()
  }

  /** Returns a context whose resources use the stored UI language, or `ctx` itself when none is stored. */
  fun wrap(ctx: Context): Context {
    val code = try {
      ctx.applicationContext.getSharedPreferences(PREFS, Context.MODE_PRIVATE).getString(KEY, null)
    } catch (_: Throwable) { null } ?: return ctx
    val cfg = Configuration(ctx.resources.configuration)
    cfg.setLocale(Locale.forLanguageTag(code))
    return try { ctx.createConfigurationContext(cfg) } catch (_: Throwable) { ctx }
  }
}

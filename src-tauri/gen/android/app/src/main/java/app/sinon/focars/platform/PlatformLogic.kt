package app.sinon.focars.platform

/**
 * Pure native-layer logic without Android APIs, covered by JVM unit tests (app/src/test).
 */
object Codec {
  private const val V = "v1"
  private val HEX = "0123456789abcdef".toCharArray()

  fun hex(b: ByteArray): String {
    val out = CharArray(b.size * 2)
    for (i in b.indices) {
      val v = b[i].toInt() and 0xff
      out[i * 2] = HEX[v ushr 4]
      out[i * 2 + 1] = HEX[v and 0x0f]
    }
    return String(out)
  }

  fun unhex(s: String): ByteArray? {
    if (s.length % 2 != 0) return null
    val out = ByteArray(s.length / 2)
    for (i in out.indices) {
      val hi = Character.digit(s[i * 2], 16)
      val lo = Character.digit(s[i * 2 + 1], 16)
      if (hi < 0 || lo < 0) return null
      out[i] = ((hi shl 4) or lo).toByte()
    }
    return out
  }

  /** Encodes a SharedPreferences entry as `v1:<iv hex>:<ciphertext+tag hex>`. */
  fun pack(iv: ByteArray, ct: ByteArray): String = "$V:${hex(iv)}:${hex(ct)}"

  fun unpack(s: String?): Pair<ByteArray, ByteArray>? {
    if (s == null) return null
    val p = s.split(':')
    if (p.size != 3 || p[0] != V) return null
    val iv = unhex(p[1]) ?: return null
    val ct = unhex(p[2]) ?: return null
    if (iv.size != 12 || ct.size < 16) return null
    return iv to ct
  }

  /** Returns the SharedPreferences key for a service (`brave`, `shodan`, …), safe characters only. */
  fun prefKey(service: String): String =
    "k_" + service.lowercase().filter { it.isLetterOrDigit() || it == '_' || it == '-' }.take(64)
}

object Oem {
  /** Returns whether the ROM needs the "lock in Recents" hint: on Xiaomi (MIUI/HyperOS) swiping the card away
   *  from Recents kills the whole process along with a running scan, even with "No restrictions" and autostart;
   *  the lock on the card prevents that. */
  fun needsRecentsLock(oem: String): Boolean = oem == "xiaomi"

  /** Detects the ROM family for the background work screen: `xiaomi` | `samsung` | `pixel` (stock Android and others). */
  fun detect(manufacturer: String?, brand: String?): String {
    val m = (manufacturer ?: "").lowercase()
    val b = (brand ?: "").lowercase()
    return when {
      listOf("xiaomi", "redmi", "poco").any { m.contains(it) || b.contains(it) } -> "xiaomi"
      m.contains("samsung") || b.contains("samsung") -> "samsung"
      else -> "pixel"
    }
  }

  /** Builds the "detected device" label. */
  fun label(manufacturer: String?, model: String?, rom: String?, release: String?): String {
    val man = (manufacturer ?: "").trim().replaceFirstChar { it.uppercase() }
    val mod = (model ?: "").trim()
    val dev = when {
      mod.isEmpty() -> man
      man.isEmpty() || mod.startsWith(man, ignoreCase = true) -> mod
      else -> "$man $mod"
    }
    val parts = mutableListOf<String>()
    if (dev.isNotBlank()) parts += dev
    if (!rom.isNullOrBlank()) parts += rom
    val android = if (release.isNullOrBlank()) "" else " (Android $release)"
    return parts.joinToString(" · ") + android
  }

  /** Detects HyperOS / MIUI from system properties. */
  fun rom(hyperOs: String?, miui: String?): String? = when {
    !hyperOs.isNullOrBlank() -> "HyperOS ${hyperOs.removePrefix("OS")}".trim()
    !miui.isNullOrBlank() -> "MIUI ${miui.removePrefix("V")}".trim()
    else -> null
  }
}

/** Where the "open Android settings" button leads (keyed by the step label from settings.js). */
data class SettingsTarget(
  val key: String,
  val action: String? = null,
  val pkg: String? = null,
  val cls: String? = null,
  /** Adds `package:<app>` as the intent data. */
  val withPackageUri: Boolean = false,
  val extras: Map<String, String> = emptyMap(),
) {
  /** Short description for the log: the component or the action. */
  val target: String get() = if (pkg != null && cls != null) "$pkg/$cls" else (action ?: key)
}

object SettingsTargets {
  const val ACTION_APP_DETAILS = "android.settings.APPLICATION_DETAILS_SETTINGS"
  const val ACTION_REQUEST_IGNORE = "android.settings.REQUEST_IGNORE_BATTERY_OPTIMIZATIONS"
  const val ACTION_IGNORE_LIST = "android.settings.IGNORE_BATTERY_OPTIMIZATION_SETTINGS"
  const val ACTION_APP_NOTIFICATIONS = "android.settings.APP_NOTIFICATION_SETTINGS"
  const val ACTION_WIRELESS = "android.settings.WIRELESS_SETTINGS"
  const val ACTION_POWER_USAGE = "android.intent.action.POWER_USAGE_SUMMARY"

  private fun appDetails() = SettingsTarget("app_details", ACTION_APP_DETAILS, withPackageUri = true)

  /** Returns candidates in order; the first one that opens is used. */
  fun forWhat(what: String?, oem: String, ignoring: Boolean, sdk: Int, pkg: String): List<SettingsTarget> {
    val w = (what ?: "battery").lowercase()
    val out = mutableListOf<SettingsTarget>()
    fun battery() {
      if (!ignoring) out += SettingsTarget("battery_optimization", ACTION_REQUEST_IGNORE, withPackageUri = true)
      out += SettingsTarget("battery_optimization_list", ACTION_IGNORE_LIST)
    }
    when {
      w.contains("dns") || w.contains("сеть") || w == "network" ->
        out += SettingsTarget("network", ACTION_WIRELESS)
      w.contains("автозапуск") || w == "autostart" || (w.contains("приложения") && oem == "xiaomi") -> {
        out += SettingsTarget("miui_autostart", pkg = "com.miui.securitycenter",
          cls = "com.miui.permcenter.autostart.AutoStartManagementActivity")
        out += SettingsTarget("miui_autostart", action = "miui.intent.action.OP_AUTO_START")
      }
      // MIUI/HyperOS battery saver ("Контроль активности" › "Без ограничений") for this app, then the
      // standard battery exemption. Never the notification screen.
      w.contains("контроль активности") || w == "activity_control" -> {
        out += SettingsTarget("miui_power", pkg = "com.miui.powerkeeper",
          cls = "com.miui.powerkeeper.ui.HiddenAppsConfigActivity",
          extras = mapOf("package_name" to pkg, "package_label" to "FOCA-rs"))
        if (!ignoring) out += SettingsTarget("battery_optimization", ACTION_REQUEST_IGNORE, withPackageUri = true)
      }
      // MIUI "Other permissions" (background pop-ups).
      w.contains("другие разрешения") || w == "permissions" -> {
        out += SettingsTarget("miui_permissions", pkg = "com.miui.securitycenter",
          cls = "com.miui.permcenter.permissions.PermissionsEditorActivity",
          extras = mapOf("extra_pkgname" to pkg))
        out += SettingsTarget("miui_permissions", action = "miui.intent.action.APP_PERM_EDITOR",
          extras = mapOf("extra_pkgname" to pkg))
      }
      w.contains("уведомл") || w.contains("notif") -> {
        if (sdk >= 26) out += SettingsTarget("notifications", ACTION_APP_NOTIFICATIONS,
          extras = mapOf("android.provider.extra.APP_PACKAGE" to pkg))
      }
      w.contains("ограничения в фоне") -> {
        battery()
        out += SettingsTarget("power_usage", ACTION_POWER_USAGE)
      }
      w.contains("аккумулятор") || w.contains("батаре") || w.contains("battery") -> battery()
      else -> {}
    }
    out += appDetails()
    return out
  }
}

/** Report printing to PDF via the system dialog: job name and a check that the file is an HTML report. */
object PrintLogic {
  /** Strips the extension from the report file name (the system proposes it as the PDF file name). */
  fun jobName(name: String): String {
    val base = name.substringAfterLast('/').substringAfterLast('\\')
    val stem = if (base.lowercase().endsWith(".html")) base.dropLast(5)
      else if (base.lowercase().endsWith(".htm")) base.dropLast(4) else base
    val clean = stem.filter { it >= ' ' && it !in "<>:\"|?*" }.trim()
    return clean.ifEmpty { "FOCA-rs report" }
  }

  /** Returns whether the file is HTML (a core report); only those are printed, anything else is an argument error. */
  fun isHtml(name: String): Boolean {
    val l = name.lowercase()
    return l.endsWith(".html") || l.endsWith(".htm")
  }
}

/**
 * Limits and helpers for copying user-picked files and folders into the app's private cache
 * before the offline import (the core reads only these copies). Pure JVM code, unit-tested.
 */
object PickLogic {
  const val MAX_FILES = 500
  const val MAX_BYTES = 512L * 1024 * 1024
  const val MAX_FILE = 100L * 1024 * 1024
  const val MAX_DEPTH = 6

  /** A display name safe as a file name in a flat directory: no separators, control or markup
   *  characters, at most 120 characters. */
  fun safeName(n: String): String {
    val last = n.substringAfterLast('/').substringAfterLast('\\')
    val clean = last.filter { it >= ' ' && it !in "\\/:*?\"<>|`" }.trim().trimStart('.')
    return clean.ifEmpty { "file" }.take(120)
  }

  /** `name`, or `name_2.ext`, `name_3.ext`… if already taken. */
  fun uniqueName(taken: Set<String>, name: String): String {
    if (name !in taken) return name
    val dot = name.lastIndexOf('.')
    var k = 2
    while (true) {
      val c = if (dot > 0) name.substring(0, dot) + "_$k" + name.substring(dot) else "${name}_$k"
      if (c !in taken) return c
      k++
    }
  }

  /** Running file count and size budget of one pick. `admit` returns `null` when the file fits or
   *  the reason it is skipped. */
  class Budget(private val maxFiles: Int = MAX_FILES, private val maxBytes: Long = MAX_BYTES) {
    var files = 0
      private set
    var bytes = 0L
      private set
    var skipped = 0
      private set

    /** Bytes still available for the next file (capped by the per-file limit). */
    fun room(): Long = minOf(MAX_FILE, maxBytes - bytes)

    fun admit(size: Long): String? {
      val reason = when {
        files >= maxFiles -> "too_many_files"
        size > MAX_FILE -> "file_too_large"
        size >= 0 && bytes + size > maxBytes -> "total_too_large"
        else -> null
      }
      if (reason != null) skipped++
      return reason
    }

    /** Records a copied file of `size` bytes. */
    fun add(size: Long) {
      files++
      bytes += size
    }

    /** Records a file dropped after the copy (the real size exceeded the room). */
    fun drop() {
      skipped++
    }
  }

  /** Copies at most `cap` bytes; returns the number copied or -1 if the input is longer. */
  fun copyCapped(input: java.io.InputStream, out: java.io.OutputStream, cap: Long): Long {
    val buf = ByteArray(64 * 1024)
    var total = 0L
    while (true) {
      val n = input.read(buf)
      if (n < 0) return total
      total += n
      if (total > cap) return -1
      out.write(buf, 0, n)
    }
  }
}

/** External links opened in the system browser: absolute `http`/`https` URLs with a host only
 *  (the core validates too; this is the native-side second check). */
object LinkLogic {
  fun isWebUrl(url: String?): Boolean {
    if (url.isNullOrBlank() || url.length > 2048) return false
    if (url.any { it <= ' ' }) return false
    return try {
      val u = java.net.URI(url)
      val scheme = u.scheme?.lowercase()
      (scheme == "http" || scheme == "https") && !u.host.isNullOrEmpty() && u.rawUserInfo == null
    } catch (_: Exception) {
      false
    }
  }
}

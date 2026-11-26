package app.sinon.focars.platform

import app.tauri.plugin.Channel
import app.tauri.plugin.JSObject
import java.util.concurrent.ConcurrentHashMap

/**
 * Device event channel into Rust (`Native::watch`): network, power, scan service.
 *
 * The channel lives at process level rather than in the Activity, so the notification's Stop
 * action and ConnectivityManager callbacks keep working while the UI is closed and the process
 * holds the foreground service. The last state of each kind is remembered and replayed to a new
 * subscriber.
 */
object FocaBus {
  @Volatile private var channel: Channel? = null
  /** The last Activity was destroyed for a reason other than a configuration change while the process
   *  may still be alive (Rust cancelled the exit during a scan); the next Activity asks to recreate the Tauri window. */
  @Volatile var uiGone = false
  private val last = ConcurrentHashMap<String, String>()

  fun attach(ch: Channel) {
    FLog.i("FocaBus: Rust подписан на события устройства")
    channel = ch
    for (json in last.values) {
      try { ch.send(JSObject(json)) } catch (_: Throwable) {}
    }
  }

  fun hasListener(): Boolean = channel != null

  /** Sends an event; without the UI it goes to a scan resumed in the background, if any. Returns `false`
   *  if nobody took it. */
  fun send(ev: JSObject): Boolean {
    val kind = ev.optString("kind")
    if (kind == "net" || kind == "power") last[kind] = ev.toString()
    val ch = channel ?: return FocaDirect.headlessEvent(ev)
    return try { ch.send(ev); true } catch (_: Throwable) { false }
  }

  /** Replays the last network and power state to a scan resumed in the background. */
  fun replayHeadless() {
    for (json in last.values) FocaDirect.headlessEvent(JSObject(json))
  }
}

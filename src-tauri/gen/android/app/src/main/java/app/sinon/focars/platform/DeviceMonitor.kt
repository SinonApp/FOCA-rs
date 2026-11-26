package app.sinon.focars.platform

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.os.BatteryManager
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.os.PowerManager
import androidx.core.content.ContextCompat
import app.tauri.plugin.JSObject

/**
 * Device monitor for the Rust pause policy: default network (up/down, Wi-Fi/cellular, VPN,
 * metered), battery level and charging, overheating (API 29+). Sends only changes to [FocaBus].
 * Registered once per process; system failures are swallowed so the monitor never crashes the UI.
 */
object DeviceMonitor {
  private var started = false
  private val main = Handler(Looper.getMainLooper())
  private var lastNet: String? = null
  private var lastPower: String? = null
  private var loggedPower: String? = null
  private var battery: Int? = null
  private var charging = false
  private var thermal = 0
  private var pendingOffline: Runnable? = null

  @Synchronized
  fun start(ctx: Context) {
    if (started) return
    started = true
    val app = ctx.applicationContext
    try { startNetwork(app) } catch (e: Throwable) { FLog.w("net monitor", e) }
    try { startBattery(app) } catch (e: Throwable) { FLog.w("battery monitor", e) }
    try { startThermal(app) } catch (e: Throwable) { FLog.w("thermal monitor", e) }
  }

  /** Re-sends the current state (for a new subscriber). */
  fun resend() {
    lastNet?.let { FocaBus.send(JSObject(it)) }
    lastPower?.let { FocaBus.send(JSObject(it)) }
  }

  // Network.
  private fun startNetwork(ctx: Context) {
    val cm = ctx.getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager ?: return
    val now = cm.activeNetwork?.let { cm.getNetworkCapabilities(it) }
    publishNet(now)
    cm.registerDefaultNetworkCallback(object : ConnectivityManager.NetworkCallback() {
      override fun onCapabilitiesChanged(network: Network, caps: NetworkCapabilities) {
        main.post { publishNet(caps) }
      }
      override fun onLost(network: Network) {
        // On a Wi-Fi → cellular switch the old network's onLost arrives first and the new one a moment later,
        // so "offline" is reported only if no other network appears within 2 s.
        main.post {
          pendingOffline?.let { main.removeCallbacks(it) }
          val r = Runnable { publishNet(null) }
          pendingOffline = r
          main.postDelayed(r, 2000)
        }
      }
    })
  }

  private fun publishNet(caps: NetworkCapabilities?) {
    if (caps != null) pendingOffline?.let { main.removeCallbacks(it); pendingOffline = null }
    val online = caps != null && caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
    val transport = when {
      caps == null || !online -> "none"
      caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) -> "wifi"
      caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) -> "cellular"
      caps.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET) -> "ethernet"
      else -> "other"
    }
    val vpn = caps?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) == true
    val metered = caps != null && !caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_METERED)
    val ev = JSObject()
      .put("kind", "net")
      .put("online", online)
      .put("transport", transport)
      .put("vpn", vpn)
      .put("metered", metered)
    val s = ev.toString()
    if (s == lastNet) return
    lastNet = s
    FLog.i("сеть: online=$online $transport vpn=$vpn metered=$metered")
    FocaBus.send(ev)
  }

  // Power.
  private fun startBattery(ctx: Context) {
    val r = object : BroadcastReceiver() {
      override fun onReceive(c: Context?, i: Intent?) { if (i != null) onBattery(i) }
    }
    val sticky = ContextCompat.registerReceiver(ctx, r, IntentFilter(Intent.ACTION_BATTERY_CHANGED),
      ContextCompat.RECEIVER_NOT_EXPORTED)
    if (sticky != null) onBattery(sticky)
  }

  private fun onBattery(i: Intent) {
    val level = i.getIntExtra(BatteryManager.EXTRA_LEVEL, -1)
    val scale = i.getIntExtra(BatteryManager.EXTRA_SCALE, -1)
    battery = if (level >= 0 && scale > 0) (level * 100 / scale) else null
    val status = i.getIntExtra(BatteryManager.EXTRA_STATUS, -1)
    val plugged = i.getIntExtra(BatteryManager.EXTRA_PLUGGED, 0)
    charging = plugged != 0 || status == BatteryManager.BATTERY_STATUS_CHARGING || status == BatteryManager.BATTERY_STATUS_FULL
    publishPower()
  }

  private fun startThermal(ctx: Context) {
    if (Build.VERSION.SDK_INT < 29) return
    val pm = ctx.getSystemService(Context.POWER_SERVICE) as? PowerManager ?: return
    thermal = pm.currentThermalStatus
    pm.addThermalStatusListener(ContextCompat.getMainExecutor(ctx)) { st ->
      thermal = st
      publishPower()
    }
    publishPower()
  }

  private fun publishPower() {
    val ev = JSObject().put("kind", "power").put("charging", charging).put("thermal", thermal)
    battery?.let { ev.put("battery", it) }
    val s = ev.toString()
    if (s == lastPower) return
    lastPower = s
    // The level changes in 1% steps; log only charging/thermal changes and 5% steps.
    val key = "$charging/$thermal/${(battery ?: -5) / 5}"
    if (key != loggedPower) { loggedPower = key; FLog.d("питание: заряд=$battery% зарядка=$charging перегрев=$thermal") }
    FocaBus.send(ev)
  }
}

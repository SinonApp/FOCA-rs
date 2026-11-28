package app.sinon.focars.platform

import android.app.Activity
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.pm.PackageInfo
import android.content.pm.PackageInstaller
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import android.provider.Settings
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat
import androidx.core.content.pm.PackageInfoCompat
import app.sinon.focars.BuildConfig
import app.sinon.focars.MainActivity
import app.sinon.focars.R
import app.tauri.plugin.JSObject
import java.io.File

/**
 * Installs an update APK the core downloaded and verified (SHA-256 against the signed
 * `SHA256SUMS.txt`). Before the PackageInstaller session it checks once more on the device: the
 * APK's signing certificate equals the installed app's, the package name is the same and the
 * versionCode is higher. Builds with `BuildConfig.SELF_UPDATE = false` refuse every install.
 */
object SelfUpdate {
  const val CHANNEL = "app_update"
  private const val NOTIF_ID = 4190
  const val ROUTE = "/settings/update"

  fun enabled(): Boolean = BuildConfig.SELF_UPDATE

  /** `{ enabled, can_install, sdk }`: whether this app may ask to install packages right now. */
  fun status(ctx: Context): JSObject = JSObject()
    .put("enabled", enabled())
    .put("can_install", canInstall(ctx))
    .put("sdk", Build.VERSION.SDK_INT)

  private fun canInstall(ctx: Context): Boolean =
    if (Build.VERSION.SDK_INT >= 26) ctx.packageManager.canRequestPackageInstalls() else true

  /** Opens "Install unknown apps" for this app; the UI rechecks `status` when it is visible again. */
  fun openPermission(activity: Activity): Boolean {
    if (Build.VERSION.SDK_INT < 26) return false
    return try {
      activity.startActivity(
        Intent(Settings.ACTION_MANAGE_UNKNOWN_APP_SOURCES, Uri.parse("package:${activity.packageName}")),
      )
      true
    } catch (e: Throwable) {
      FLog.w("update: настройки установки недоступны", e)
      try {
        activity.startActivity(Intent(Settings.ACTION_SECURITY_SETTINGS)); true
      } catch (_: Throwable) { false }
    }
  }

  @Suppress("DEPRECATION")
  private fun signers(info: PackageInfo?): List<ByteArray> {
    if (info == null) return emptyList()
    if (Build.VERSION.SDK_INT >= 28) {
      val si = info.signingInfo ?: return emptyList()
      return si.apkContentsSigners?.map { it.toByteArray() } ?: emptyList()
    }
    return info.signatures?.map { it.toByteArray() } ?: emptyList()
  }

  @Suppress("DEPRECATION")
  private fun certFlag(): Int =
    if (Build.VERSION.SDK_INT >= 28) PackageManager.GET_SIGNING_CERTIFICATES else PackageManager.GET_SIGNATURES

  /** Reads the archive and the installed package and returns the verdict with the APK's facts. */
  fun verify(ctx: Context, file: File): Pair<UpdateLogic.Verdict, JSObject> {
    val pm = ctx.packageManager
    val installed = try { pm.getPackageInfo(ctx.packageName, certFlag()) } catch (_: Throwable) { null }
    val apk = try { pm.getPackageArchiveInfo(file.path, certFlag()) } catch (_: Throwable) { null }
    apk?.applicationInfo?.let { it.sourceDir = file.path; it.publicSourceDir = file.path }
    val certsOk = UpdateLogic.certsMatch(signers(installed), signers(apk))
    val installedCode = installed?.let { PackageInfoCompat.getLongVersionCode(it) } ?: Long.MAX_VALUE
    val apkCode = apk?.let { PackageInfoCompat.getLongVersionCode(it) } ?: 0L
    val v = UpdateLogic.verdict(enabled(), ctx.packageName, apk?.packageName, installedCode, apkCode, certsOk)
    val facts = JSObject()
      .put("package", apk?.packageName ?: "")
      .put("version_name", apk?.versionName ?: "")
      .put("version_code", apkCode)
      .put("installed_version_code", if (installed == null) -1L else installedCode)
      .put("cert_match", certsOk)
    FLog.i("update: проверка APK ${file.name}: ${v.code} (код $apkCode > $installedCode, сертификат $certsOk)")
    return v to facts
  }

  /** Verifies and starts a PackageInstaller session; the system asks the user to confirm. */
  fun install(ctx: Context, file: File): JSObject {
    val (v, facts) = verify(ctx, file)
    if (v != UpdateLogic.Verdict.OK) return facts.put("ok", false).put("code", v.code)
    if (!canInstall(ctx)) return facts.put("ok", false).put("code", "update_permission")
    val installer = ctx.packageManager.packageInstaller
    val params = PackageInstaller.SessionParams(PackageInstaller.SessionParams.MODE_FULL_INSTALL)
    params.setAppPackageName(ctx.packageName)
    params.setSize(file.length())
    if (Build.VERSION.SDK_INT >= 31) params.setRequireUserAction(PackageInstaller.SessionParams.USER_ACTION_REQUIRED)
    val id = installer.createSession(params)
    try {
      installer.openSession(id).use { s ->
        file.inputStream().use { input ->
          s.openWrite("base.apk", 0, file.length()).use { out ->
            input.copyTo(out, 1 shl 16)
            s.fsync(out)
          }
        }
        val flags = PendingIntent.FLAG_UPDATE_CURRENT or
          (if (Build.VERSION.SDK_INT >= 31) PendingIntent.FLAG_MUTABLE else 0)
        val pi = PendingIntent.getBroadcast(
          ctx, id, Intent(ctx, UpdateReceiver::class.java).putExtra(UpdateReceiver.EXTRA_FILE, file.path), flags,
        )
        s.commit(pi.intentSender)
      }
    } catch (e: Throwable) {
      try { installer.abandonSession(id) } catch (_: Throwable) {}
      FLog.e("update: сессия установки", e)
      return facts.put("ok", false).put("code", "update_install_failed").put("message", e.message ?: e.toString())
    }
    cancelNotification(ctx)
    return facts.put("ok", true).put("code", "ok").put("session", id)
  }

  private fun ensureChannel(ctx: Context) {
    if (Build.VERSION.SDK_INT < 26) return
    val nm = ctx.getSystemService(NotificationManager::class.java) ?: return
    if (nm.getNotificationChannel(CHANNEL) != null) return
    val ch = NotificationChannel(CHANNEL, ctx.getString(R.string.update_channel_name), NotificationManager.IMPORTANCE_LOW)
    ch.description = ctx.getString(R.string.update_channel_description)
    ch.setShowBadge(false)
    nm.createNotificationChannel(ch)
  }

  /** `update_notify { phase, version, received, total }`: download progress, ready or gone. */
  fun notify(ctx: Context, a: JSObject): Boolean {
    val phase = a.getString("phase", null) ?: return false
    if (phase != "download" && phase != "verify" && phase != "ready") {
      cancelNotification(ctx); return true
    }
    val res = AppLocale.wrap(ctx)
    ensureChannel(res)
    val version = a.getString("version", null) ?: ""
    val pct = UpdateLogic.percent(a.optLong("received", 0), a.optLong("total", 0))
    val open = PendingIntent.getActivity(
      ctx, NOTIF_ID,
      Intent(ctx, MainActivity::class.java).putExtra(ScanService.EXTRA_ROUTE, ROUTE)
        .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_SINGLE_TOP),
      PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
    )
    val b = NotificationCompat.Builder(ctx, CHANNEL)
      .setSmallIcon(R.drawable.ic_stat_scan)
      .setContentTitle(res.getString(R.string.update_title, version))
      .setContentIntent(open)
      .setOnlyAlertOnce(true)
      .setCategory(NotificationCompat.CATEGORY_PROGRESS)
      .setVisibility(NotificationCompat.VISIBILITY_PUBLIC)
    when (phase) {
      "download" -> b.setContentText(res.getString(R.string.update_downloading, pct)).setProgress(100, pct, false).setOngoing(true)
      "verify" -> b.setContentText(res.getString(R.string.update_verifying)).setProgress(0, 0, true).setOngoing(true)
      else -> b.setContentText(res.getString(R.string.update_ready)).setAutoCancel(true)
    }
    return try {
      NotificationManagerCompat.from(ctx).notify(NOTIF_ID, b.build()); true
    } catch (_: SecurityException) { false }
  }

  fun cancelNotification(ctx: Context) {
    try { NotificationManagerCompat.from(ctx).cancel(NOTIF_ID) } catch (_: Throwable) {}
  }
}

/** Result of the PackageInstaller session: shows the system confirmation, reports failures to the UI. */
class UpdateReceiver : BroadcastReceiver() {
  companion object {
    const val EXTRA_FILE = "app.sinon.focars.UPDATE_FILE"
  }

  override fun onReceive(ctx: Context, intent: Intent) {
    val status = intent.getIntExtra(PackageInstaller.EXTRA_STATUS, PackageInstaller.STATUS_FAILURE)
    when (status) {
      PackageInstaller.STATUS_PENDING_USER_ACTION -> {
        @Suppress("DEPRECATION")
        val confirm = intent.getParcelableExtra<Intent>(Intent.EXTRA_INTENT) ?: return
        try {
          ctx.startActivity(confirm.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
        } catch (e: Throwable) {
          FLog.w("update: подтверждение установки", e)
        }
      }
      PackageInstaller.STATUS_SUCCESS -> {
        intent.getStringExtra(EXTRA_FILE)?.let { File(it).delete() }
        FLog.i("update: установлено")
      }
      else -> {
        val msg = intent.getStringExtra(PackageInstaller.EXTRA_STATUS_MESSAGE) ?: ""
        FLog.w("update: установка не удалась ($status): $msg")
        val code = if (status == PackageInstaller.STATUS_FAILURE_ABORTED) "update_install_cancelled" else "update_install_failed"
        FocaBus.send(JSObject().put("kind", "update_install").put("code", code).put("status", status).put("message", msg))
      }
    }
  }
}

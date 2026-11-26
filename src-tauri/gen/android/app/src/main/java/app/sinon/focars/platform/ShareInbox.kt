package app.sinon.focars.platform

import android.app.Activity
import android.content.ClipData
import android.content.Intent
import android.net.Uri
import android.os.Build
import android.provider.OpenableColumns
import app.tauri.plugin.JSArray
import app.tauri.plugin.JSObject
import java.io.File

/**
 * Files shared into the app ("Share → FOCA-rs" from Telegram, mail, a browser or a file manager).
 *
 * The share intent reaches the exported LauncherActivity, which forwards it (with the read grant) to
 * MainActivity; MainActivity calls [take] in onCreate (cold start) and onNewIntent (app already open).
 * The content URIs are copied in a background thread into `files/shared_in/in-<time>/` with the limits
 * of [ShareLogic] (documents only, count and size caps, flat names without the source path); `file://`
 * URIs are refused, so another app cannot point us at our own private files. The batch waits in memory
 * until the UI asks for it (`platform_shared_files` → [drain]); a "shared" event on [FocaBus] tells an
 * open UI to ask now. The UI checks and cleans the copies locally: no project, no network.
 */
object ShareInbox {
  private val lock = Any()
  private var pending: JSObject? = null

  fun isShare(i: Intent?): Boolean = i != null && (i.action == Intent.ACTION_SEND || i.action == Intent.ACTION_SEND_MULTIPLE)

  fun hasPending(): Boolean = synchronized(lock) { pending != null }

  /** The stored batch, handed out once: `{ files: [{ path, name, size, mime }], skipped, truncated }`. */
  fun drain(): JSObject = synchronized(lock) {
    val p = pending
    pending = null
    p ?: JSObject().put("files", JSArray()).put("skipped", 0).put("truncated", false)
  }

  @Suppress("DEPRECATION")
  private fun uris(i: Intent): List<Uri> {
    val out = ArrayList<Uri>()
    try {
      if (i.action == Intent.ACTION_SEND_MULTIPLE) {
        val l: ArrayList<Uri>? = if (Build.VERSION.SDK_INT >= 33) i.getParcelableArrayListExtra(Intent.EXTRA_STREAM, Uri::class.java)
          else i.getParcelableArrayListExtra(Intent.EXTRA_STREAM)
        l?.let { out.addAll(it) }
      } else {
        val u: Uri? = if (Build.VERSION.SDK_INT >= 33) i.getParcelableExtra(Intent.EXTRA_STREAM, Uri::class.java)
          else i.getParcelableExtra(Intent.EXTRA_STREAM)
        u?.let { out.add(it) }
      }
    } catch (e: Throwable) { FLog.w("share: EXTRA_STREAM $e") }
    i.clipData?.let { c -> for (k in 0 until c.itemCount) c.getItemAt(k).uri?.let { out.add(it) } }
    return out.distinct()
  }

  /** Builds the intent LauncherActivity forwards to MainActivity, keeping the URIs and their read grant. */
  fun forward(src: Intent, to: Intent): Intent {
    if (!isShare(src)) return to
    to.action = src.action
    to.type = src.type
    // Copy only share-related extras so untrusted third-party apps cannot inject internal extras (e.g. "route").
    src.getStringExtra(Intent.EXTRA_TEXT)?.let { to.putExtra(Intent.EXTRA_TEXT, it) }
    src.getStringExtra(Intent.EXTRA_SUBJECT)?.let { to.putExtra(Intent.EXTRA_SUBJECT, it) }
    val list = uris(src)
    if (list.isNotEmpty()) {
      if (src.action == Intent.ACTION_SEND_MULTIPLE) {
        to.putParcelableArrayListExtra(Intent.EXTRA_STREAM, ArrayList(list))
      } else {
        to.putExtra(Intent.EXTRA_STREAM, list[0])
      }
      val clip = ClipData.newRawUri("shared", list[0])
      for (k in 1 until list.size) clip.addItem(ClipData.Item(list[k]))
      to.clipData = clip
      to.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
    }
    return to
  }

  /** Takes a share intent (no-op for other intents) and copies its files in the background. */
  fun take(a: Activity, i: Intent?) {
    if (!isShare(i)) return
    val list = uris(i!!)
    // Forget the action: a recreated Activity (rotation, process restore) must not import it again.
    i.action = null
    if (list.isEmpty()) return
    val resolver = a.applicationContext.contentResolver
    val root = File(a.applicationContext.filesDir, "shared_in").apply { mkdirs() }
    FLog.i("share: получено файлов ${list.size}")
    Thread {
      val now = System.currentTimeMillis()
      root.listFiles()?.forEach { if (ShareLogic.stale(it.name, now)) it.deleteRecursively() }
      val dir = File(root, "in-$now").apply { mkdirs() }
      val budget = PickLogic.Budget(ShareLogic.MAX_FILES, ShareLogic.MAX_TOTAL)
      val taken = HashSet<String>()
      val arr = JSArray()
      var skipped = 0
      var truncated = false
      list.forEachIndexed { idx, u ->
        if (u.scheme != "content") { skipped++; return@forEachIndexed }
        var display: String? = null
        var size = -1L
        try {
          resolver.query(u, arrayOf(OpenableColumns.DISPLAY_NAME, OpenableColumns.SIZE), null, null, null)?.use { c ->
            if (c.moveToFirst()) {
              display = c.getString(0)
              if (!c.isNull(1)) size = c.getLong(1)
            }
          }
        } catch (_: Throwable) {}
        val mime = try { resolver.getType(u) } catch (_: Throwable) { null }
        val name0 = ShareLogic.nameFor(display ?: u.lastPathSegment, mime, idx)
        if (!ShareLogic.accepted(name0, mime)) { skipped++; return@forEachIndexed }
        if (budget.admit(size) != null) { truncated = true; return@forEachIndexed }
        val name = PickLogic.uniqueName(taken, name0)
        val f = File(dir, name)
        val copied = try {
          resolver.openInputStream(u)?.use { inp -> f.outputStream().use { PickLogic.copyCapped(inp, it, budget.room()) } } ?: -1L
        } catch (e: Exception) { FLog.w("share: копия $e"); -1L }
        if (copied < 0) { f.delete(); budget.drop(); truncated = true; return@forEachIndexed }
        taken += name
        budget.add(copied)
        arr.put(JSObject().put("path", f.absolutePath).put("name", name).put("size", copied).put("mime", mime ?: "application/octet-stream"))
      }
      skipped += budget.skipped
      if (arr.length() == 0) dir.delete()
      FLog.i("share: скопировано ${arr.length()}, пропущено $skipped")
      synchronized(lock) {
        pending = JSObject().put("files", arr).put("skipped", skipped).put("truncated", truncated)
      }
      FocaBus.send(JSObject().put("kind", "shared").put("n", arr.length()))
    }.start()
  }
}

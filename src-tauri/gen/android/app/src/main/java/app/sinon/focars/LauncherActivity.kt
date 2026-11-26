package app.sinon.focars

import android.app.Activity
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Intent
import android.graphics.Color
import android.graphics.Typeface
import android.os.Bundle
import android.view.ViewGroup.LayoutParams.MATCH_PARENT
import android.view.ViewGroup.LayoutParams.WRAP_CONTENT
import android.widget.Button
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import android.widget.Toast

/** Entry point without Rust or WebView: shows the report if the previous run crashed, otherwise opens the app right away. */
class LauncherActivity : Activity() {
  override fun onCreate(savedInstanceState: Bundle?) {
    super.onCreate(savedInstanceState)
    CrashLog.install(this)
    app.sinon.focars.platform.FLog.i("LauncherActivity.onCreate")
    app.sinon.focars.platform.RecentsGuard.onEvent(this, app.sinon.focars.platform.RecentsEvent.COLD_START)
    CrashLog.logExitHistory(this)
    val report = try { CrashLog.pending(this) } catch (e: Throwable) { null }
    if (report == null) { openApp(); return }

    val pad = (16 * resources.displayMetrics.density).toInt()
    val root = LinearLayout(this).apply {
      orientation = LinearLayout.VERTICAL
      setBackgroundColor(Color.parseColor("#202020"))
      setPadding(pad, pad * 3, pad, pad * 2)
    }
    root.addView(TextView(this).apply {
      text = "FOCA-rs упал при прошлом запуске"
      setTextColor(Color.WHITE); textSize = 20f; setTypeface(typeface, Typeface.BOLD)
    })
    root.addView(TextView(this).apply {
      text = "Сделайте скриншот или нажмите «Копировать» и отправьте текст разработчику."
      setTextColor(Color.parseColor("#BBBBBB")); textSize = 14f; setPadding(0, pad / 2, 0, pad)
    })
    val body = TextView(this).apply {
      text = report; setTextColor(Color.parseColor("#E6E6E6")); textSize = 11.5f
      typeface = Typeface.MONOSPACE; setTextIsSelectable(true)
    }
    root.addView(ScrollView(this).apply { addView(body) }, LinearLayout.LayoutParams(MATCH_PARENT, 0, 1f))
    val row = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL; setPadding(0, pad, 0, 0) }
    row.addView(Button(this).apply {
      text = "Копировать"
      setOnClickListener {
        getSystemService(ClipboardManager::class.java).setPrimaryClip(ClipData.newPlainText("FOCA-rs crash", report))
        Toast.makeText(this@LauncherActivity, "Скопировано", Toast.LENGTH_SHORT).show()
      }
    }, LinearLayout.LayoutParams(0, WRAP_CONTENT, 1f))
    row.addView(Button(this).apply {
      text = "Запустить снова"
      setOnClickListener { CrashLog.clear(this@LauncherActivity); openApp() }
    }, LinearLayout.LayoutParams(0, WRAP_CONTENT, 1f))
    root.addView(row)
    setContentView(root)
  }

  private fun openApp() {
    // "Share → FOCA-rs" lands here (the only exported Activity): the files and their read grant go on to MainActivity.
    val main = Intent(this, MainActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_NO_ANIMATION)
    startActivity(app.sinon.focars.platform.ShareInbox.forward(intent, main))
    finish()
    overridePendingTransition(0, 0)
  }
}

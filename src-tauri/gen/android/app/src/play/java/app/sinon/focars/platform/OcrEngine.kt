package app.sinon.focars.platform

import android.content.Context
import android.graphics.Bitmap
import android.graphics.BitmapFactory
import android.graphics.Color
import android.graphics.pdf.PdfRenderer
import android.os.ParcelFileDescriptor
import app.tauri.plugin.JSObject
import com.google.android.gms.tasks.Tasks
import com.google.mlkit.vision.common.InputImage
import com.google.mlkit.vision.text.TextRecognition
import com.google.mlkit.vision.text.latin.TextRecognizerOptions
import java.io.File
import java.util.concurrent.TimeUnit

/**
 * On-device offline OCR via Google ML Kit Text Recognition (`com.google.mlkit:text-recognition`).
 * Runs synchronously on the calling background JNI thread (`FocaDirect.call("ocr_recognize")`),
 * never touches the network, and recycles rendered bitmaps immediately after recognition.
 */
object OcrEngine {
  private const val PAGE_TIMEOUT_SEC = 20L

  fun recognize(ctx: Context, a: JSObject): JSObject {
    val rawPath = a.getString("path", null)?.trim() ?: ""
    val mime = a.getString("mime", null)?.trim()?.lowercase() ?: ""
    val maxPages = OcrLogic.clampMaxPages(a.getInteger("max_pages", OcrLogic.DEFAULT_PAGES) ?: OcrLogic.DEFAULT_PAGES)

    if (rawPath.isEmpty() || !OcrLogic.isSupportedMime(mime)) {
      return JSObject().put("error", "неподдерживаемый формат или пустой путь OCR")
    }
    val file = File(rawPath)
    val allowedRoots = listOfNotNull(ctx.filesDir, ctx.cacheDir, ctx.dataDir)
    if (!OcrLogic.isSafeLocalPath(file, allowedRoots)) {
      return JSObject().put("error", "файл OCR вне приватного каталога приложения")
    }

    val recognizer = TextRecognition.getClient(TextRecognizerOptions.DEFAULT_OPTIONS)
    return try {
      val (rawText, pages) = if (mime == "application/pdf") {
        recognizePdf(file, maxPages) { bmp -> recognizeBitmap(recognizer, bmp) }
      } else {
        recognizeImage(file) { bmp -> recognizeBitmap(recognizer, bmp) } to 1
      }
      JSObject()
        .put("ok", true)
        .put("text", OcrLogic.truncateUtf8(rawText))
        .put("pages", pages)
        .put("engine", "mlkit")
    } catch (e: Throwable) {
      FLog.w("OcrEngine.recognize(${file.name})", e)
      JSObject().put("error", e.message ?: e.toString())
    } finally {
      try {
        recognizer.close()
      } catch (_: Throwable) {}
    }
  }

  private fun recognizeBitmap(
    recognizer: com.google.mlkit.vision.text.TextRecognizer,
    bmp: Bitmap,
  ): String {
    val img = InputImage.fromBitmap(bmp, 0)
    val res = Tasks.await(recognizer.process(img), PAGE_TIMEOUT_SEC, TimeUnit.SECONDS)
    return res?.text ?: ""
  }

  private fun recognizeImage(file: File, run: (Bitmap) -> String): String {
    val bounds = BitmapFactory.Options().apply { inJustDecodeBounds = true }
    BitmapFactory.decodeFile(file.absolutePath, bounds)
    val opts = BitmapFactory.Options().apply {
      inSampleSize = OcrLogic.sampleSize(bounds.outWidth, bounds.outHeight)
      inPreferredConfig = Bitmap.Config.ARGB_8888
    }
    val bmp = BitmapFactory.decodeFile(file.absolutePath, opts)
      ?: throw IllegalArgumentException("не удалось декодировать изображение")
    return try {
      run(bmp)
    } finally {
      bmp.recycle()
    }
  }

  private fun recognizePdf(
    file: File,
    maxPages: Int,
    run: (Bitmap) -> String,
  ): Pair<String, Int> {
    val pfd = ParcelFileDescriptor.open(file, ParcelFileDescriptor.MODE_READ_ONLY)
    return pfd.use { desc ->
      PdfRenderer(desc).use { renderer ->
        val count = minOf(renderer.pageCount, maxPages)
        val sb = StringBuilder()
        for (i in 0 until count) {
          renderer.openPage(i).use { page ->
            val (w, h) = OcrLogic.scaledDimensions(page.width * 2, page.height * 2)
            val bmp = Bitmap.createBitmap(w, h, Bitmap.Config.ARGB_8888)
            try {
              bmp.eraseColor(Color.WHITE)
              page.render(bmp, null, null, PdfRenderer.Page.RENDER_MODE_FOR_PRINT)
              val pageText = run(bmp).trim()
              if (pageText.isNotEmpty()) {
                if (sb.isNotEmpty()) sb.append('\n')
                sb.append(pageText)
              }
            } finally {
              bmp.recycle()
            }
          }
          if (sb.length >= OcrLogic.MAX_TEXT_BYTES) break
        }
        sb.toString() to count
      }
    }
  }
}

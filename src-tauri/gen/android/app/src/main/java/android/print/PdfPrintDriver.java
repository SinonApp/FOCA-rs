package android.print;

import android.os.Bundle;
import android.os.CancellationSignal;
import android.os.ParcelFileDescriptor;

/**
 * Drives a {@link PrintDocumentAdapter} (e.g. {@code WebView.createPrintDocumentAdapter}) straight
 * into a file descriptor, without the system print dialog.
 *
 * <p>The constructors of {@link PrintDocumentAdapter.LayoutResultCallback} and {@link
 * PrintDocumentAdapter.WriteResultCallback} are package-private, so this helper has to live in the
 * {@code android.print} package (kept as is by the ProGuard rules). It is plain Java on purpose: the
 * app's Kotlin sources all stay under the application package. Must be called on the thread that
 * created the adapter's WebView (the main thread); {@code done} is invoked exactly once on that
 * thread with {@code null} on success or an error message.
 */
public final class PdfPrintDriver {
  /** Completion callback: {@code error} is null on success. */
  public interface Done {
    void onDone(String error);
  }

  private PdfPrintDriver() {}

  public static void write(
      final PrintDocumentAdapter adapter,
      PrintAttributes attrs,
      final ParcelFileDescriptor out,
      final CancellationSignal cancel,
      final Done done) {
    final boolean[] finished = {false};
    final Done finish =
        err -> {
          if (finished[0]) return;
          finished[0] = true;
          try {
            adapter.onFinish();
          } catch (Throwable ignored) {
            // The adapter is discarded anyway.
          }
          done.onDone(err);
        };
    try {
      adapter.onStart();
      adapter.onLayout(
          null,
          attrs,
          cancel,
          new PrintDocumentAdapter.LayoutResultCallback() {
            @Override
            public void onLayoutFinished(PrintDocumentInfo info, boolean changed) {
              if (cancel.isCanceled()) {
                finish.onDone("cancelled");
                return;
              }
              try {
                adapter.onWrite(
                    new PageRange[] {PageRange.ALL_PAGES},
                    out,
                    cancel,
                    new PrintDocumentAdapter.WriteResultCallback() {
                      @Override
                      public void onWriteFinished(PageRange[] pages) {
                        finish.onDone(null);
                      }

                      @Override
                      public void onWriteFailed(CharSequence error) {
                        finish.onDone(error != null ? error.toString() : "write failed");
                      }

                      @Override
                      public void onWriteCancelled() {
                        finish.onDone("cancelled");
                      }
                    });
              } catch (Throwable e) {
                finish.onDone(String.valueOf(e.getMessage() != null ? e.getMessage() : e));
              }
            }

            @Override
            public void onLayoutFailed(CharSequence error) {
              finish.onDone(error != null ? error.toString() : "layout failed");
            }

            @Override
            public void onLayoutCancelled() {
              finish.onDone("cancelled");
            }
          },
          new Bundle());
    } catch (Throwable e) {
      finish.onDone(String.valueOf(e.getMessage() != null ? e.getMessage() : e));
    }
  }
}

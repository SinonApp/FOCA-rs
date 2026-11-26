# Add project specific ProGuard rules here.
# You can control the set of applied configuration files using the
# proguardFiles setting in build.gradle.
#
# For more details, see
#   http://developer.android.com/guide/developing/tools/proguard.html

# If your project uses WebView with JS, uncomment the following
# and specify the fully qualified class name to the JavaScript interface
# class:
#-keepclassmembers class fqcn.of.javascript.interface.for.webview {
#   public *;
#}

# Uncomment this to preserve the line number information for
# debugging stack traces.
#-keepattributes SourceFile,LineNumberTable

# If you keep the line number information, uncomment this to
# hide the original source file name.
#-renamesourcefileattribute SourceFile
# FOCA native plugin: Rust looks the class up by name (JNI) and commands via @Command (reflection).
-keep class app.sinon.focars.platform.** { *; }
-keepclassmembers class app.sinon.focars.MainActivity$Bridge { @android.webkit.JavascriptInterface <methods>; }
# Direct PDF export: the driver subclasses package-private print callbacks, so it must stay in android.print.
-keep class android.print.PdfPrintDriver** { *; }

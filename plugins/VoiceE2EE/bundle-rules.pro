# Shrink-only pass over the plugin classes + bundled BouncyCastle (see build.gradle.kts).
-dontobfuscate
-dontoptimize
-keepattributes *

# The plugin itself is kept as compiled; it is only here so R8 knows which BouncyCastle code is reachable.
-keep class moe.lava.awoocord.voicee2ee.** { *; }

# bcmls decodes messages reflectively through each type's MLSInputStream constructor, and is small: keep all of it.
-keep class org.bouncycastle.mls.** { *; }
-keepclassmembers class org.bouncycastle.** { <init>(org.bouncycastle.mls.codec.MLSInputStream); }

# Provided at runtime by Discord / Aliucord (not passed to R8).
-dontwarn com.discord.**
-dontwarn com.aliucord.**
-dontwarn co.discord.**
-dontwarn de.robv.android.xposed.**
-dontwarn okhttp3.**
-dontwarn okio.**
-dontwarn rx.**
-dontwarn b.**
-dontwarn f0.**
-dontwarn d0.**
-dontwarn org.jetbrains.annotations.**
-dontwarn com.google.gson.**
# Kotlin lambdas / string concatenation; D8 desugars these when the plugin is dexed for API 21
-dontwarn java.lang.invoke.**
-dontwarn kotlin.jvm.internal.SourceDebugExtension

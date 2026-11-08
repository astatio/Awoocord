version = "0.1.1"
description = "End-to-end encrypted (DAVE) voice and video, so calls work again now that Discord requires it"

android {
    namespace = "moe.lava.awoocord.voicee2ee"
    testOptions {
        unitTests.isReturnDefaultValues = true
    }
}

aliucord {
    author("astatio", hyperlink = false)

    changelog.set("""
        # 0.1.1
        * Fix outgoing audio: detect how the voice engine encrypts its side of the local relay instead of assuming one layout
        * /voicee2ee shows packet counts for each direction and the detected engine layout

        # 0.1.0
        * Initial release: DAVE (MLS group key exchange + frame encryption) for voice calls, server voice channels and Go Live, via a local relay in front of the stock voice engine
    """.trimIndent())

    deploy.set(true)
}

// BouncyCastle's MLS implementation is bundled into the plugin. Only what the plugin actually reaches is kept (R8
// shrink, no obfuscation/optimisation so bcmls' reflective decoding keeps working), which keeps the dex small and
// far under the 64K method limit.
val bundled: Configuration by configurations.creating
val bcPatchedJarFile = layout.buildDirectory.file("intermediates/bc-patched.jar")

dependencies {
    compileOnly(libs.bcmls)
    bundled(libs.bcmls)

    // the same patched, unsigned BouncyCastle that gets bundled (see bcPatchedJar)
    testImplementation(files(bcPatchedJarFile).builtBy("bcPatchedJar"))
    testImplementation(libs.junit)
    testImplementation("org.json:json:20240303") // real org.json; android.jar only has stubs on the JVM
    // Aliucord provides this exact Kotlin stdlib at runtime, so the tests run on it too
    testImplementation(libs.kotlin.stdlib)
}

// The Discord jar also contains Discord's own shrunk, renamed copies of some kotlin.* classes (kotlin.Unit,
// kotlin.ranges.IntRange, ...). On device, plugins run against Aliucord's real Kotlin 1.5.21 stdlib, so resolve
// kotlin.* from the stdlib first; otherwise e.g. `for (i in 0 until n)` compiles to IntRange.iterator()Ld0/t/c0;.
configurations.named("compileOnly") {
    val deps = dependencies.toList()
    dependencies.clear()
    dependencies.addAll(deps.sortedBy { if (it.group == "org.jetbrains.kotlin") 0 else 1 })
}

val sdkDir = android.sdkDirectory

// bcmls' LifeTime.verify() uses java.time (Android 8+ only); bcpatch/ replaces that one class. The BouncyCastle jars
// are merged into one unsigned jar with the patched class swapped in, which is what gets bundled and tested.
val bcPatchClasses = layout.buildDirectory.dir("intermediates/bcpatch-classes")
val compileBcPatch by tasks.registering(JavaCompile::class) {
    source = fileTree("bcpatch") { include("**/*.java") }
    classpath = bundled
    destinationDirectory.set(bcPatchClasses)
    options.release.set(8)
}
val bcPatchedJar by tasks.registering(Jar::class) {
    dependsOn(compileBcPatch)
    from(bundled.elements.map { files -> files.map { zipTree(it) } }) {
        exclude("META-INF/**", "**/module-info.class", "org/bouncycastle/mls/TreeKEM/LifeTime.class")
    }
    from(bcPatchClasses)
    duplicatesStrategy = DuplicatesStrategy.EXCLUDE
    destinationDirectory.set(layout.buildDirectory.dir("intermediates"))
    archiveFileName.set("bc-patched.jar")
}
val bundleDir = layout.buildDirectory.dir("intermediates/voicee2ee-bundle")
val pluginClassesJar = layout.buildDirectory.file("intermediates/voicee2ee-plugin-classes.jar")

val jarPluginClasses by tasks.registering(Jar::class) {
    dependsOn("compileDebugKotlin")
    from(layout.buildDirectory.dir("tmp/kotlin-classes/debug"))
    destinationDirectory.set(layout.buildDirectory.dir("intermediates"))
    archiveFileName.set("voicee2ee-plugin-classes.jar")
}

val shrinkBundle by tasks.registering(JavaExec::class) {
    dependsOn(jarPluginClasses, bcPatchedJar)
    val rules = file("bundle-rules.pro")
    val buildTools = File(sdkDir, "build-tools").listFiles { f -> File(f, "lib/d8.jar").exists() }
        ?.maxByOrNull { it.name }
        ?: error("No Android build-tools with lib/d8.jar in $sdkDir")
    // API 21 platform: R8 then reports any bundled code that needs Java APIs missing on Android 5.
    val androidJar = File(sdkDir, "platforms/android-21/android.jar").takeIf { it.exists() }
        ?: File(sdkDir, "platforms").listFiles()!!.map { File(it, "android.jar") }.filter { it.exists() }.minByOrNull { it.path }!!
    val kotlinStdlib = configurations.getByName("debugCompileClasspath").incoming.artifactView {
        attributes { attribute(Attribute.of("artifactType", String::class.java), "jar") }
        lenient(true)
    }.files.filter { it.name.startsWith("kotlin-stdlib") }

    inputs.file(rules)
    inputs.files(bcPatchedJarFile, pluginClassesJar)
    outputs.dir(bundleDir)

    classpath = files(File(buildTools, "lib/d8.jar"))
    mainClass.set("com.android.tools.r8.R8")
    doFirst { bundleDir.get().asFile.deleteRecursively(); bundleDir.get().asFile.mkdirs() }
    argumentProviders.add(CommandLineArgumentProvider {
        listOf("--classfile", "--output", bundleDir.get().asFile.path, "--pg-conf", rules.path, "--lib", androidJar.path) +
            kotlinStdlib.files.flatMap { listOf("--classpath", it.path) } +
            pluginClassesJar.get().asFile.path +
            bcPatchedJarFile.get().asFile.path
    })
}

project.afterEvaluate {
    tasks.named("compileDex") {
        dependsOn(shrinkBundle)
        (this as com.aliucord.gradle.task.CompileDexTask).input.setFrom(bundleDir)
    }
}

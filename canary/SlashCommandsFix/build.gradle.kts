import com.github.jengelman.gradle.plugins.shadow.tasks.ShadowJar

version = "8.18.4"
description = "Beta backport of SlashCommandsFix"

aliucord {
    // Added after the shared "cilly" author from the root build file
    author("astatio", hyperlink = false)

    changelog.set("""
        # 8.18.4
        * Fix localized options still failing (INTERACTION_APPLICATION_COMMAND_OPTION_INVALID): send the name_default Discord provides
        * Fetch each command list once instead of twice (fewer rate limits)

        # 8.18.3
        * Fix 429 Too Many Requests loops: honor Retry-After, keep using cached commands while rate limited, back off after failures
        * If localized names can't be loaded, show default names and retry in 30 s

        # 8.18.2
        * Fix localized commands failing with "interaction failed": names are shown in your language but sent in the bot's default language
        * Credit astatio as co-author of this fixed build
        * Log diagnostics for failed commands and localized command names (debug log, tagged [diag])

        # 8.18.1
        * Fix role/@everyone denials being ignored in command permission checks
        * No more network requests while the command list is rendered
        * Thread-safe index cache; refresh after 10 minutes and on invalid command version (incl. user apps)
        * Null-safety fixes for missing API data, channels, guilds and error responses

        # 8.18.0
        * Don't use custom props anymore (core has them)

        # 7.16.2
        * Use new props

        # 7.16.1
        * Prompt restarts

        # 7.16.0
        * Initial port >w< thanks @jedenastka
    """.trimIndent())

    deploy.set(true)
}

apply {
    plugin(libs.plugins.shadow.get().pluginId)
}

val shadowDir = File(buildDir, "intermediates/shadowed")

tasks.register<ShadowJar>("relocateJar") {
    val javaTask = tasks.findByName("compileDebugJavaWithJavac")!!
    val kotlinTask = tasks.findByName("compileDebugKotlin")!!
    from(javaTask.outputs, kotlinTask.outputs)
    relocate("com.aliucord.coreplugins.slashcommandsfix", "moe.lava.corenary.slashcommandsfix")
    archiveClassifier.set("shadowed")
    destinationDirectory.set(File(buildDir, "intermediates"))
}

tasks.register<Sync>("copyShadowed") {
    val reloc = tasks.findByName("relocateJar")!! as ShadowJar
    dependsOn(reloc)
    from(zipTree(reloc.archiveFile))
    into(shadowDir)
}

project.afterEvaluate {
    tasks.compileDex {
        val copyShadowed = tasks.findByName("copyShadowed")!! as Sync
        dependsOn(copyShadowed)
        input.setFrom(shadowDir)
    }
}

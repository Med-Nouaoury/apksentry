import org.jetbrains.kotlin.gradle.dsl.JvmTarget

// محرك الفحص: Kotlin عادي بدون أندرويد، يشتغل على الهاتف وعلى الحاسوب.
plugins {
    id("org.jetbrains.kotlin.jvm")
}

java {
    sourceCompatibility = JavaVersion.VERSION_17
    targetCompatibility = JavaVersion.VERSION_17
}

kotlin {
    compilerOptions { jvmTarget.set(JvmTarget.JVM_17) }
}

dependencies {
    testImplementation(kotlin("test"))
}

tasks.test {
    useJUnitPlatform()
}

// نسخة سطر الأوامر للحاسوب: java -jar apksentry-cli.jar <ملف>
tasks.register<Jar>("cliJar") {
    archiveFileName.set("apksentry-cli.jar")
    manifest { attributes("Main-Class" to "io.github.mednouaoury.apksentry.core.Cli") }
    from(sourceSets.main.get().output)
    dependsOn(configurations.runtimeClasspath)
    from({ configurations.runtimeClasspath.get().filter { it.name.endsWith(".jar") }.map { zipTree(it) } })
    duplicatesStrategy = DuplicatesStrategy.EXCLUDE
}

// SPDX-License-Identifier: MIT
import org.jetbrains.kotlin.gradle.dsl.JvmTarget

plugins {
    kotlin("jvm") version "2.4.20"
}

group = "com.ebremer"
version = "0.1.0"
description = "The Kotlin adapter of the lws-client driver: runs the operations of the lws-driver/1 protocol " +
    "(driver/PROTOCOL.md), read as line-delimited JSON on stdin, with lws-client for Kotlin, and reports the results on stdout."

java {
    sourceCompatibility = JavaVersion.VERSION_17
    targetCompatibility = JavaVersion.VERSION_17
}

kotlin {
    compilerOptions {
        jvmTarget.set(JvmTarget.JVM_17)
        freeCompilerArgs.add("-Xjdk-release=17")
        allWarningsAsErrors.set(true)
    }
}

dependencies {
    implementation("com.ebremer:lws-client-kotlin:0.1.0")
}

// The runnable fat jar: build/libs/lws-driver-adapter-kotlin.jar (java -jar …).
tasks.jar {
    archiveFileName.set("lws-driver-adapter-kotlin.jar")
    manifest {
        attributes("Main-Class" to "com.ebremer.lws.driver.adapter.KotlinAdapterKt")
    }
    val runtime = configurations.runtimeClasspath
    dependsOn(runtime)
    from({ runtime.get().map { if (it.isDirectory) it else zipTree(it) } })
    duplicatesStrategy = DuplicatesStrategy.EXCLUDE
    exclude("module-info.class", "META-INF/versions/*/module-info.class", "META-INF/*.SF", "META-INF/*.DSA", "META-INF/*.RSA")
}

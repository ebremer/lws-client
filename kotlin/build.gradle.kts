// SPDX-License-Identifier: MIT
import org.jetbrains.kotlin.gradle.dsl.JvmTarget
import org.jetbrains.kotlin.gradle.dsl.KotlinVersion

plugins {
    kotlin("jvm") version "2.4.20"
    // For the tests' @Serializable classes only: the library itself uses the JsonElement tree, no generated code.
    kotlin("plugin.serialization") version "2.4.20"
    `java-library`
    `maven-publish`
}

group = "com.ebremer"
version = "0.1.0"
description = "Client for the W3C Linked Web Storage (LWS) Protocol 1.0, for Kotlin: discovery, resources, " +
    "containers, linksets, OAuth 2.0 token exchange with OpenID Connect / SAML / self-signed (CID, did:key) " +
    "credentials, webhook notifications, access requests and grants, and type index / search services."

val coroutinesVersion = "1.11.0"
val serializationVersion = "1.11.0"

java {
    sourceCompatibility = JavaVersion.VERSION_17
    targetCompatibility = JavaVersion.VERSION_17
    withSourcesJar()
}

kotlin {
    explicitApi()
    compilerOptions {
        jvmTarget.set(JvmTarget.JVM_17)
        // Usable from Kotlin 2.2 on (kotlinx.serialization 1.11, built with Kotlin 2.3, needs that much anyway).
        languageVersion.set(KotlinVersion.KOTLIN_2_2)
        apiVersion.set(KotlinVersion.KOTLIN_2_2)
        // Compile against the Java 17 API whatever the JDK running Gradle.
        freeCompilerArgs.add("-Xjdk-release=17")
        allWarningsAsErrors.set(true)
    }
}

dependencies {
    api("org.jetbrains.kotlinx:kotlinx-coroutines-core:$coroutinesVersion")
    api("org.jetbrains.kotlinx:kotlinx-serialization-json:$serializationVersion")

    testImplementation(kotlin("test"))
    testImplementation(platform("org.junit:junit-bom:5.14.4"))
    testImplementation("org.junit.jupiter:junit-jupiter")
    testImplementation("org.jetbrains.kotlinx:kotlinx-coroutines-test:$coroutinesVersion")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
}

// The example programs in src/examples/kotlin, compiled against the library (not packaged).
sourceSets.create("examples") {
    compileClasspath += sourceSets.main.get().output + configurations.runtimeClasspath.get()
    runtimeClasspath += output + compileClasspath
}

tasks.test {
    useJUnitPlatform()
    systemProperty("lws.conformance.dir", layout.projectDirectory.dir("../conformance").asFile.absolutePath)
    // The interop test runs against the mock server when LWS_TEST_SERVER is set.
    inputs.property("lwsTestServer", providers.environmentVariable("LWS_TEST_SERVER").orElse(""))
    testLogging {
        events("failed", "skipped")
        exceptionFormat = org.gradle.api.tasks.testing.logging.TestExceptionFormat.FULL
    }
}

tasks.check {
    dependsOn(tasks.named("compileExamplesKotlin"))
}

tasks.jar {
    manifest {
        attributes("Automatic-Module-Name" to "com.ebremer.lws.kotlin")
    }
    from(layout.projectDirectory.file("../LICENSE"))
}

publishing {
    publications {
        create<MavenPublication>("maven") {
            artifactId = "lws-client-kotlin"
            from(components["java"])
            pom {
                name.set("LWS Client for Kotlin")
                description.set(project.description)
                url.set("https://github.com/ebremer/lws-client")
                licenses {
                    license {
                        name.set("MIT License")
                        url.set("https://opensource.org/license/mit")
                        distribution.set("repo")
                    }
                }
                developers {
                    developer {
                        name.set("Erich Bremer")
                        url.set("https://github.com/ebremer")
                    }
                }
                scm {
                    url.set("https://github.com/ebremer/lws-client")
                    connection.set("scm:git:https://github.com/ebremer/lws-client.git")
                }
            }
        }
    }
}

// ./gradlew -q quickstart --args=http://localhost:8787/root/ (and selfSignedAuth, webhookReceiver)
for ((task, main) in listOf("quickstart" to "Quickstart", "selfSignedAuth" to "SelfSignedAuth", "webhookReceiver" to "WebhookReceiver")) {
    tasks.register<JavaExec>(task) {
        group = "examples"
        description = "Runs the $main example."
        classpath = sourceSets["examples"].runtimeClasspath
        mainClass.set("com.ebremer.lws.kotlin.examples.${main}Kt")
    }
}

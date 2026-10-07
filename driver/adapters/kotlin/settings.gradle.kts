// SPDX-License-Identifier: MIT
// The Kotlin adapter of the lws-client driver. It builds against the library in ../../../kotlin (a composite
// build), so nothing needs publishing first:
//
//   kotlin/gradlew -p driver/adapters/kotlin jar     ->  driver/adapters/kotlin/build/libs/lws-driver-adapter-kotlin.jar
rootProject.name = "lws-driver-adapter-kotlin"

includeBuild("../../../kotlin")

dependencyResolutionManagement {
    repositories {
        mavenCentral()
    }
}
